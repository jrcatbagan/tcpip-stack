/*
 * arp.c
 *
 * Created: 6/15/2013 8:49:35 PM
 *  Author: Jarielle
 */ 

#include "arp.h"

char arp_verify_request(unsigned char packet[], unsigned char destination_mac[],
                        unsigned char destination_ip[], unsigned char source_ip[]) {
	enum {NO_ERROR, ERROR} status;
	int hardware_type, protocol_type, operation;
	unsigned char hardware_address_length, protocol_address_length,
                target_protocol_address[4];
	unsigned char count;
		
	status = NO_ERROR;
	
	hardware_type = packet[14];
	hardware_type = (hardware_type << 8);
	hardware_type |= packet[15];
	
	protocol_type = packet[16];
	protocol_type = (protocol_type << 8);
	protocol_type |= packet[17];
	
	hardware_address_length = packet[18];
	protocol_address_length = packet[19];
	
	operation = packet[20];
	operation = (operation << 8);
	operation |= packet[21];
	
	for (count = 0; count < 6; ++count) {
                // Offset of 22 to access source MAC address of ARP request in the
                // Ethernet frame.
		destination_mac[count] = packet[count + 22];

	}

        for (count = 0; count < 4; ++count)	{
                // Offset of 28 to access source IP address of ARP request in the
                // Ethernet frame.
		destination_ip[count] = packet[count + 28];
		target_protocol_address[count] = packet[count + 38];
	}

        //Both values will be used for the destination addresses in ARP reply.
        
	if (hardware_type != 1) {
		status = ERROR;
	}
	if (protocol_type != 0x0800) {
		status = ERROR;
	}
	if (hardware_address_length != 6) {
		status = ERROR;
	}
	if (protocol_address_length != 4) {
		status = ERROR;
	}
	if (operation != 1) {
		status = ERROR;
	}
	for (count = 0; count < 4; ++count) {
		if (target_protocol_address[count] != source_ip[count]) {
			status = ERROR;
		}
	}
	return status;
}

void arp_construct_reply(unsigned char packet[], unsigned char destination_mac[],
                         unsigned char destination_ip[], unsigned char source_mac[],
                         unsigned char source_ip[], int *update_size) {
	int count;
	
	packet[14] = 0;
	packet[15] = 1;
	packet[16] = 0x08;
	packet[17] = 0x00;
	packet[18] = 6;
	packet[19] = 4;
	packet[20] = 0;
	packet[21] = 2;
	*update_size = *update_size + 8;
	for (count = 0; count < 6; ++count) {
		packet[count + 22] = source_mac[count];
		++(*update_size);
		packet[count + 32] = destination_mac[count];
		++(*update_size);
	}
	for (count = 0; count < 4; ++count) {
		packet[count + 28] = source_ip[count];
		++(*update_size);
		packet[count + 38] = destination_ip[count];
		++(*update_size);
	}
}
