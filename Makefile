##################################
# <jwright> Well, I may be doing stupid things with make
# <jwright> OK, it was Makefile stupid'ness
# <jwright> I don't really understand what the hell I am doing with Make, I'm
#           just copying other files and seeing what works.
# <dragorn> heh
# <dragorn> i think thats all anyone does
# <dragorn> make is a twisted beast
##################################
LDLIBS		= -lpcap 
CFLAGS		= -g3 -ggdb -pipe -Wall
PROG		= wlan2eth

all: $(PROG) 

wlan2eth: wlan2eth.c 
	$(CC) $(CFLAGS) -o wlan2eth wlan2eth.c $(LDLIBS)

clean:
	$(RM) $(PROG) *~
