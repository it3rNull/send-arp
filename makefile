LDLIBS=-lpcap

all: send-arp

send-arp: main.o arphdr.o ethhdr.o mac.o ip.o send_arp.o pch.o 
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f send-arp *.o
