// File: ip.h
// Created: 27, May 2013

/* Copyright (C) 2013, Jarielle Catbagan
 *
 * BSD License
 *
 * Please refer to LICENSE.txt for license details
 *
 */

#ifndef IP_H_
#define IP_H_

/* The ip_verify_header_validity() function verifies the contents of the IP header only.
 * Although the function's purpose needs no explanation because of its name, the
 * parameters it takes can be ambiguous. The first parameter simply takes a packet of
 * type array that contains the IP header. This will be used to verify the headers
 * validity. The second parameter requires that a source IP of type array is supplied
 * so that it can be compared with the destination IP field in the IP header. For the
 * last parameter, a destination IP of type array, which must be empty, must be supplied
 * so that the source IP field in the IP header can be saved in the array. This will be
 * used as the destination IP when constructing an outgoing packet. A function called
 * ip_verify_checksum() resides within this function. This function is used to check the
 * checksum in the IP header as part of verifying the header's validity. More information
 * on the ip_verify_checksum() function is provided below. The function requires that
 * any array supplied to the second and third parameters must only be 4 elements long
 * and that any other lengths are prohibited since it will cause unpredictable results
 * or loss of data to occur.
 */

unsigned char ip_verify_header_validity(unsigned char packet[],
                                        unsigned char source_ip[],
                                        unsigned char destination_ip[]);


/* The ip_verify_checksum() function's purpose, as its name states, is to verify the
 * checksum. To do so, the 16-bit one's complement of the one's complement sum of all
 * the 16-bit words in the IP header is performed. The checksum excludes the data. If
 * the checksum equals zero then there is no error, otherwise an error has occurred
 * during the transmission process. The first parameter requires that an IP header
 * (excluding the data) of type array is provided in order to verify the checksum. The
 * last parameter is is used to give the length of the header in bytes. The last
 * parameter is important since IP header lengths can vary from 20 to 60 bytes. The
 * function requires that any array supplied to first parameter must not exceed 60 bytes
 * (max IP header length), otherwise unpredictable results or loss of data may occur.
 */

unsigned char ip_verify_checksum(unsigned char header[],
                                 unsigned int header_size_in_bytes);


/* The ip_transport_layer_protocol() function is used to determine what the transport
 * protocol is in order to determine where to pass the packet to.  For this, a packet
 * of type array must be supplied.  Note: As of right now, the function can only
 * determine if the transport protocol is either TCP or UDP.
 */

unsigned char ip_transport_layer_protocol(unsigned char packet[]);

void ip_calculate_checksum(unsigned char header[]);

#endif /* IP_H_ */
