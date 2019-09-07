/*
 * Copyright (c) 2009, Joshua Wright <jwright@willhackforsushi.com>
 *
 * $Id: wlan2eth.c,v 1.2 2009/02/09 17:43:07 jwright Exp $
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation. See COPYING for more
 * details.
 *
 * cookfix is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * This tool accepts an input pcap file and writes a converted output file,
 * based on a payload offset and desired pcap link type.  In it's current form,
 * it will read in a Linux DLT_IEEE802_11 file, and copy the raw 802.11
 * framing information into a DLT_EN10MB capture file with a different
 * payload offset.  This allows us to remove the extra header information from
 * the wireless traffic encapsulation type so the data can be analyzed with
 * standard traffic analysis tools.
 */

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <ctype.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "ieee80211.h"
#include "radiotap.h"
#include "ppi.h"

#define PROGNAME "wlan2eth"

#define PCAPTYPE DLT_EN10MB
#define DLT_PRISM_HEADER_LEN 144

#define __swab16(x) \
({ \
        uint16_t __x = (x); \
        ((uint16_t)( \
                (((uint16_t)(__x) & (uint16_t)0x00ffU) << 8) | \
                (((uint16_t)(__x) & (uint16_t)0xff00U) >> 8) )); \
})

#ifdef WORDS_BIGENDIAN
#warning "Compiling for big-endian"
#define le16_to_cpu(x) __swab16(x)
#else
#define le16_to_cpu(x) (x)
#endif

/* A better version of hdump, from Lamont Granquist.  Modified slightly
   by Fyodor (fyodor@DHP.com) */
void hdump(unsigned char *bp, unsigned int length)
{

	/* stolen from tcpdump, then kludged extensively */

	static const char asciify[] =
	    "................................ !\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~.................................................................................................................................";

	const unsigned short *sp;
	const unsigned char *ap;
	unsigned int i, j;
	int nshorts, nshorts2;
	int padding;

	printf("\n\t");
	padding = 0;
	sp = (unsigned short *)bp;
	ap = (unsigned char *)bp;
	nshorts = (unsigned int)length / sizeof(unsigned short);
	nshorts2 = (unsigned int)length / sizeof(unsigned short);
	i = 0;
	j = 0;
	while (1) {
		while (--nshorts >= 0) {
			printf(" %04x", ntohs(*sp));
			sp++;
			if ((++i % 8) == 0)
				break;
		}
		if (nshorts < 0) {
			if ((length & 1) && (((i - 1) % 8) != 0)) {
				printf(" %02x  ", *(unsigned char *)sp);
				padding++;
			}
			nshorts = (8 - (nshorts2 - nshorts));
			while (--nshorts >= 0) {
				printf("     ");
			}
			if (!padding)
				printf("     ");
		}
		printf("  ");

		while (--nshorts2 >= 0) {
			printf("%c%c", asciify[*ap], asciify[*(ap + 1)]);
			ap += 2;
			if ((++j % 8) == 0) {
				printf("\n\t");
				break;
			}
		}
		if (nshorts2 < 0) {
			if ((length & 1) && (((j - 1) % 8) != 0)) {
				printf("%c", asciify[*ap]);
			}
			break;
		}
	}
	if ((length & 1) && (((i - 1) % 8) == 0)) {
		printf(" %02x", *(unsigned char *)sp);
		printf("                                       %c", asciify[*ap]);
	}
	printf("\n");
}

/* Return the length of the radiotap header, -1 on error */
int offset_rtap(uint8_t * packet, int plen)
{
	struct ieee80211_radiotap_header *rtaphdr;
	int rtaphdrlen;

	rtaphdr = (struct ieee80211_radiotap_header *)packet;
	/* RTAP is LE */
	rtaphdrlen = le16_to_cpu(rtaphdr->it_len);

	/* Sanity check on header length, 10 bytes is min 802.11 len */
	if (rtaphdrlen > (plen - 10)) {
		return -1;	/* Bad radiotap data */
	}
	return rtaphdrlen;
}

int offset_ppi(uint8_t * packet, int plen)
{
	struct ppi_header *ppihdr;
	if (plen < sizeof(struct ppi_header)) {
		return -1;
	}
	ppihdr = (struct ppi_header *)packet;
	if (ppihdr->hdrlen > plen) {
		return -1;
	}
	return ppihdr->hdrlen;
}

int main(int argc, char *argv[])
{

	pcap_t *p = NULL;
	pcap_t *pd = NULL;	/* pcap_open_dead */
	pcap_dumper_t *wp = NULL;
	u_char *packet;
	u_char *wpacket;
	struct pcap_pkthdr h;
	struct pcap_pkthdr wh;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct ieee80211 *dot11;
	int iphdroffset, plen, pcount = 0, pcaptype;
	int dloffset = 0; /* offset to accommodate other DLT link types */

	uint8_t *src, *dst;	/* pointers for source and destination addresses */

	memset(&h, 0, sizeof(h));
	memset(&wh, 0, sizeof(wh));

	if (argc < 3) {
		printf("wlan2eth 1.3 - Convert 802.11 captures into Ethernet format.\n"
		       "Questions/Comments/Concerns: jwright@willhackforsushi.com\n\n");
		printf("Usage: %s infile outfile\n", PROGNAME);
		exit(-1);
	}

	p = pcap_open_offline(argv[1], errbuf);
	if (p == NULL) {
		perror("Unable to open capture file");
		exit(-1);
	}

	pcaptype = pcap_datalink(p);

	pd = pcap_open_dead(PCAPTYPE, 65535);
	if (pd == NULL) {
		perror("Unable to open dead pcap");
		exit(-1);
	}
	wp = pcap_dump_open(pd, argv[2]);
	if (wp == NULL) {
		perror("Unable to open output file");
		exit(-1);
	}

	while (!(packet = (u_char *) pcap_next(p, &h)) == 0) {

		switch (pcaptype) {
		case DLT_IEEE802_11:
			dloffset = 0;
			break;
		case DLT_PRISM_HEADER:
			dloffset = DLT_PRISM_HEADER_LEN;
			break;
		case DLT_IEEE802_11_RADIO:
			dloffset = offset_rtap(packet, h.caplen);
			break;
		case DLT_PPI:
			dloffset = offset_ppi(packet, h.caplen);
			break;
		}
		if (dloffset == -1) {
			printf
			    ("Error calculating header offset for packet.  Skipping this packet.\n");
			continue;
		}
		plen = h.len;

		/* iphdroffset is calculated based on the size of the 802.11 header
		   and the 802.2 header */
		iphdroffset = dloffset + DOT11HDR_LEN + DOT2HDR_LEN;

		plen -= (DOT11HDR_LEN + DOT2HDR_LEN + dloffset);
		if (plen <= 20)
			continue;	/* min size for IP header */

		dot11 = (struct ieee80211 *)(packet + dloffset);

		/* Test for the data frame type */
		if (dot11->u1.fc.type != DOT11_FC_TYPE_DATA) {
			continue;
		}

		/* Ensure valid data frame type */
		switch (dot11->u1.fc.subtype) {
		case DOT11_FC_SUBTYPE_DATA:
			break;
		case DOT11_FC_SUBTYPE_QOSDATA:
			iphdroffset += DOT11HDR_QOS_LEN;
			plen -= DOT11HDR_QOS_LEN;
			if (plen <= 20)
				continue;	/* min size for IP header */
			break;
		default:
			continue;
		}

		/* Ignore encrypted frames */
		if (dot11->u1.fc.protected == 1) {
			continue;
		}

		/* Discard WDS frames */
		if (dot11->u1.fc.from_ds == 1 && dot11->u1.fc.to_ds == 1) {
			continue;
		} else if (dot11->u1.fc.from_ds == 1 && dot11->u1.fc.to_ds == 0) {
			/* From the DS */
			src = dot11->addr3;
			dst = dot11->addr1;
		} else if (dot11->u1.fc.from_ds == 0 && dot11->u1.fc.to_ds == 1) {
			/* To the DS */
			src = dot11->addr2;
			dst = dot11->addr3;
		} else {	/* Ad-hoc */
			src = dot11->addr2;
			dst = dot11->addr1;
		}

		/* Valid packet, copy it with a new Ethernet header to output pcap */
		wh.caplen = wh.len = (plen + 14);	/* Ethernet header added */
		wh.ts.tv_sec = h.ts.tv_sec;
		wh.ts.tv_usec = h.ts.tv_usec;

		/* Allocate the space for the output packet */
		wpacket = malloc(plen + 14);
		if (wpacket == NULL) {
			perror("malloc");
			exit(-1);
		}

		/* Extract desired payload from packet */
		memcpy(wpacket + 14, packet + iphdroffset, plen);
		memcpy(wpacket, dst, 6);
		memcpy(wpacket + 6, src, 6);

		/* hack - setup Ethernet type field */
		memcpy(wpacket + 12, packet + iphdroffset - 2, 2);

		/* debug */
#if 0
		printf("Packet (old -> new) :");
		hdump(packet, h.len);
		hdump(wpacket, plen + 14);
#endif

		/* Write the packet */
		pcap_dump((u_char *) wp, &wh, wpacket);
		pcount++;

		/* Cleanup */
		free(wpacket);
	}

	pcap_dump_flush(wp);
	pcap_dump_close(wp);
	pcap_close(p);
	pcap_close(pd);

	printf("Converted %d packets.\n", pcount);
	exit(0);
}
