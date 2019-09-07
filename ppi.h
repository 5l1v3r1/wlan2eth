/* PPI header.  Variable-length data follows the DLT value. */
struct ppi_header {
	uint8_t version;
	uint8_t flags;
	uint16_t hdrlen;
	uint32_t dlt;
};
