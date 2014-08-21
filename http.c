// File: http.c
// Created: 01, June 2013

/* Copyright (C) 2013, Jarielle Catbagan
 *
 * BSD License
 *
 * Please refer to LICENSE.txt for license details
 *
 */

#include "http.h"

void http_extract_data() {
	int count;
	
	for (count = 55; count < 1515; ++count) {
		application_data[count - 55] = ethernet_frame[count];
	}
}
