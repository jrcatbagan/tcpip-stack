// File: tcp.h
// Created: 27, May 2013

#ifndef TCP_H_
#define TCP_H_

/* The tcp_verify_header_validity() function verifies that no errors exist in the TCP
 * header. If no errors are present the function will return a no error value, otherwise
 * it will return an error value. A packet of type array that contains the TCP segment
 * and within it the TCP header, must be supplied to the first parameter. The second
 * parameter is used to compare the destination port in the incoming TCP header to the
 * source port provided. The third parameter is a pointer to a variable where the source
 * port in the incoming TCP segment will be saved and used as the destination port when
 * constructing an outgoing TCP segment. A pointer must be used to actually save the
 * variable that is located outside of the scope of this function. The size of the
 * packet must be known in order to determine the length of the TCP segment. This is
 * crucial since the whole segment must be included for checksum purposes. Therefore
 * the size of the packet provided must be supplied to the last parameter. A function
 * called tcp_verify_checksum() resides within this function this function is used to
 * check the checksum and is part of verifying the header's validity. More information
 * on the tcp_verify_checksum() function is provided below.
 */

unsigned char tcp_verify_header_validity(unsigned char packet[], unsigned int s_port,
                                         unsigned int *d_port, unsigned int size);


/* The tcp_verify_checksum() function verifies the checksum field in the TCP header. The
 * first parameter requires that an array containing the TCP segment must be supplied.
 * The second parameter is an array that contains a pseudo header that mimics the IP
 * header, where this pseudo header will be included for the TCP checksum. The last
 * parameter is the length of the TCP segment. The TCP checksum is performed by doing
 * the 16-bit one's complement of the one's complement sum of all the 16-bit words in
 * pseudo header, TCP header, and the data combined. If the checksum calculated equals
 * the checksum provided in the incoming TCP segment, then there is no error. Otherwise
 * an error has occurred during the transmission process. The function requires that
 * any array supplied to the second and third parameters must only be 12 elements long
 * and that any other lengths are prohibited since it will cause unpredictable results
 * or loss of data to occur.
 */

unsigned int tcp_verify_checksum(unsigned char segment[], unsigned char pseudo[],
                                 unsigned int size);


/* The tcp_check_connection_with_ip() function determines what the connection state
 * between the local TCP and the foreign TCP are currently in. The destination IP, is
 * used to determine the connection state. This must be of type array and supplied to
 * the second parameter. The first parameter, is a list of all the IP addresses
 * currently in a connection state other than "not established". The third parameter
 * states what the length is of the array supplied in the first parameter. For the last
 * parameter, if the IP address is found, a value of "found" is returned and the
 * variable pointed to by the parameter is updated with the location of the IP in the
 * list.  If no IP address is found, a value of "not found" is returned.
 */

unsigned char tcp_check_connection_with_ip(unsigned char list_of_connections[], unsigned char target_ip[], unsigned char size_of_list, unsigned char *location);

#endif /* TCP_H_ */
