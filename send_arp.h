#pragma once
#include "pch.h"
int request(const char *dev, pcap_t *pcap, u_int8_t *dest_mac, u_int8_t *source_mac, u_int8_t *sender_mac, u_int8_t *sender_ip, u_int8_t *target_mac, u_int8_t *target_ip, int type);
int reply(const char *dev, pcap_t *pcap, u_int8_t *mac, u_int8_t *ip);