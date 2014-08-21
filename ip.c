// File: ip.c
// Created: 01, June 2013

/* Copyright (C) 2013, Jarielle Catbagan
 *
 * BSD License
 *
 * Please refer to LICENSE.txt for license details
 *
 */

#include "ip.h"

unsigned char ip_verify_header_validity(unsigned char packet[],
                                        unsigned char source_ip[],
                                        unsigned char target_ip[]) {
	enum {NO_ERROR, ERROR} status;
	unsigned char version, target_ip_in_header[4], header_byte_length, ip_header[60];
	unsigned int count;
		
	status = NO_ERROR;
	
	version = packet[14];
	version = (version >> 4);
	version &= 0x0F;
	
	for (count = 0; count < 4; ++count) {
                //Saving source IP in incoming header in destination variable
		target_ip[count] = packet[count + 26];		
		target_ip_in_header[count] = packet[count + 30];
	}
	
	
	header_byte_length = packet[14];
	header_byte_length &= 0x0F;
	header_byte_length *= 4;
	
	for (count = 0; count < header_byte_length; ++count) {
		ip_header[count] = packet[count + 14];
	}
	
	if (version != 4) {
		status = ERROR;
	}
	for (count = 0; count < 4; ++count) {
		if (target_ip_in_header[count] != source_ip[count]) {
			status = ERROR;
		}
	}
	if (ip_verify_checksum(ip_header, header_byte_length) != 0) {
		status = ERROR;
	}
	return status;
}

unsigned char ip_verify_checksum(unsigned char header[],
                                 unsigned int header_size_in_bytes) {
	unsigned char number_of_16bit_words, CORRECT = 0, INCORRECT = 1;
	unsigned int count, index, header_16bit_words[30], result;
	long sum = 0, temp = 0;
	
	
	number_of_16bit_words = (header_size_in_bytes / 2);
	
	for (count = 0, index = 0; count < number_of_16bit_words; ++count, index += 2) {
		header_16bit_words[count] = header[index];
		header_16bit_words[count] = (header_16bit_words[count] << 8);
		header_16bit_words[count] |= header[index + 1];
	}
	
	for (count = 0; count < number_of_16bit_words; ++count) {
		sum += header_16bit_words[count];
	}
	
	temp = (sum >> 16);
	sum &= 0xFFFF;
	result = (sum + temp);
	result = ~result;
	
	if (result == 0) {
		return CORRECT;
	}
	else {
		return INCORRECT;
	}
}

unsigned char ip_transport_layer_protocol(unsigned char packet[]) {
	char protocol;
	enum {TCP, UDP} transport;
	
	protocol = packet[23];
	
	if (protocol == 0x06) {
		transport = TCP;
	}
	else if (protocol == 0x11) {
		transport = UDP;
	}
	else {
		return 0;
	}
	return transport;
}

void ip_calculate_checksum(unsigned char header[]) {
	int result, temp = 0, count, index;
	int h[10];
	long sum = 0;
	
	header[10] = 0;
	header[11] = 0;
	
	for (count = 0, index = 0; count < 10; ++count, index += 2) {
		h[count] = header[index];
		h[count] = (h[count] << 8);
		h[count] |= header[index + 1];
	}
	for (count = 0; count < 10; ++count) {
		sum += h[count];
	}
	temp = (sum >> 16);
	sum &= 0xFFFF;
	result = sum;
	result += temp;
	result = ~result;
	
	header[10] = (result >> 8);
	header[11] = (result & 0x00FF);
}

