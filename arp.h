// File: arp.h
// Created: 15, June 2013

/* Copyright (C) 2013, Jarielle Catbagan
 *
 * BSD License
 *
 * Please refer to LICENSE.txt for license details
 *
 */

#ifndef ARP_H_
#define ARP_H_

/* The arp_verify_request() function's purpose, as its name already states, is to
 * determine whether the ARP datagram does not contain any errors. The first parameter
 * is an array that must be supplied that contains the ARP request. The second and
 * third parameters are used to save the source addresses in the ARP request. These
 * addresses will be used for the ARP reply. For the second and third parameters, an
 * array of 6 elements and an array of 4 elements must be supplied respectively. Any
 * other array lengths are not permitted since it may cause unpredicatable results of
 * loss of data to occur. The last parameter compares the destination IP field in the
 * ARP request to the source IP provided to the parameter.
 */

char arp_verify_request(unsigned char packet[], unsigned char destination_mac[],
                        unsigned char destination_ip[], unsigned char source_ip[]);


/* The arp_construct_reply() function constructs an ARP reply after having analyzed the
 * ARP request. The first parameter is an array that will hold the ARP reply. The second
 * third, fourth, and fifth parameters require arrays to be supplied that are 6, 4, 6,
 * and 4 elements in length respectively. These arrays are placed in the ARP reply. The
 * arrays supplied to the second, third, fourth, and fifth parameters must be the lengths
 * provided. Other lengths are not permitted since it will cause unpredicatable results
 * or loss of data to occur.
 */

void arp_construct_reply(unsigned char packet[], unsigned char destination_mac[],
                         unsigned char destination_ip[], unsigned char source_mac[],
                         unsigned char source_ip[], int *update_size);

#endif /* ARP_H_ */
