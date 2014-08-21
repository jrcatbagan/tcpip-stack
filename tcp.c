// File: tcp.c
// Created: 01, June 2013

/* Copyright (C) 2013, Jarielle Catbagan
 *
 * BSD License
 *
 * Please refer to LICENSE.txt for license details
 *
 */

#include "tcp.h"

unsigned char tcp_verify_header_validity(unsigned char packet[], unsigned int s_port,
                                         unsigned int *d_port, unsigned int size) {
	enum {NO_ERROR, ERROR} status;
	unsigned char tcp_data_offset, ip_header_length, count;
	unsigned char tcp_segment[1480], psuedo_header[12];
        // these arrays will be used to save the source and destination IP from the
        // packet
	unsigned char source_ip_in_packet[4], destination_ip_in_packet[4];
        // where these IP addresses will be used to verify the TCP checksum
	unsigned int target_port, tcp_checksum, tcp_length = 0;
        	
	status = NO_ERROR;
	
	ip_header_length = packet[14];
	ip_header_length &= 0x0F;
        //IP header length in bytes
	ip_header_length *= 4;			
	
	for (count = 0; count < size; ++count) {
		tcp_segment[count] = packet[count + 14 + ip_header_length];
		++tcp_length;
	}
	
	for(count = 0; count < 4; ++count) {
		psuedo_header[count] = packet[count + 26];
		psuedo_header[count + 4] = packet[count + 30];
	}
	psuedo_header[8] = 0;
        // offset of 23 in packet to access protocol field in IP header
	psuedo_header[9] = packet[23];	
	psuedo_header[10] = (tcp_length >> 8);
	psuedo_header[11] = (tcp_length & 0x00FF);
	
	for (count = 0; count < 4; ++count) {
		source_ip_in_packet[count] = packet[count + 26];
		destination_ip_in_packet[count] = packet[count + 30];
	}

        // saving the destination port from packet array into target_port variable
        // which will be used to compare with own source port
	target_port = packet[14 + ip_header_length + 2];
	target_port = (target_port << 8);
        // offset of 14 for Ethernet header, ip_header_length for IP header, plus 2 to
        // access the destination port 
	target_port |= packet[14 + ip_header_length + 3];

        // saving the source port from packet array which will be used as destination
        *d_port = packet[14 + ip_header_length];
        // port for outgoing packet
	*d_port = (*d_port << 8);
	*d_port |= packet[14 + ip_header_length + 1];
	
	tcp_checksum = packet[14 + ip_header_length + 16];
	tcp_checksum = (tcp_checksum << 8);
	tcp_checksum |= packet[14 + ip_header_length + 17];
	
	
	
	if (target_port != 80) {
		status = ERROR;
	}
	if (tcp_verify_checksum(tcp_segment, psuedo_header, tcp_length) !=
            tcp_checksum) {
		status = ERROR;
	}
	
	return status;
}

unsigned int tcp_verify_checksum(unsigned char segment[], unsigned char psuedo[],
                                 unsigned int size) {
	unsigned int actual_size, header_16bit_words[740], psuedo_header_16bit_words[6],
                count, index, result;
	long sum = 0, temp = 0;

        // padding end with 0 if TCP segment has an odd amount of bytes which is
	if (size % 2 != 0) {
                // necessary to form an even amount of 16-bit words for checksum purposes
		segment[size] = 0;	
		actual_size = size + 1;
	}
	else {
		actual_size = size;
	}
	
	for (count = 0, index = 0; index < 12; ++count, index += 2) {
		psuedo_header_16bit_words[count] = psuedo[index];
		psuedo_header_16bit_words[count] =
                        (psuedo_header_16bit_words[count] << 8);
		psuedo_header_16bit_words[count] |= psuedo[index + 1];
	}
	
	for (count = 0, index = 0; index < actual_size; ++count, index += 2) {
		header_16bit_words[count] = segment[index];
		header_16bit_words[count] = (header_16bit_words[count] << 8);
		header_16bit_words[count] |= segment[index + 1];
	}
	
	for (count = 0; count < 6; ++count) {
		sum += psuedo_header_16bit_words[count];
	}
	
	for (count = 0; count < (actual_size / 2); ++count) {
		sum += header_16bit_words[count];
	}
	
	temp = (sum >> 16);
	sum &= 0xFFFF;
	result = sum + temp;
	result = ~result;
	
	return result;
}

unsigned char tcp_check_connection_with_ip(unsigned char list_of_connections[],
                                           unsigned char target_ip[],
                                           unsigned char size_of_list,
                                           unsigned char *location) {
	enum {FOUND, NOT_FOUND} ip_connection;
	unsigned char count1, count2, index = 0, boundary = 4, match_certainty;
	
	ip_connection = NOT_FOUND;
	
	for (count1 = 0; count1 < size_of_list; ++count1) {
		match_certainty = 0;
		for (index = index, count2 = 0; index < boundary; ++index, ++count2){
			if (target_ip[count2] == list_of_connections[index]) {
				++match_certainty;
			}
		}
		if (match_certainty > 4) {
			ip_connection = FOUND;
			*location = count1;
		}
	}
	
	return ip_connection;
}






