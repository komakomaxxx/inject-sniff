/*
 * hexinject.h
 *
 *  Created on: 08/mag/2010
 *      Author: Acri Emanuele
 */

#ifndef HEXINJECTION_H_
#define HEXINJECTION_H_

#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <getopt.h>
#include <assert.h>
#include <arpa/inet.h>

#define BUFFER_SIZE 8192

// for disassembling and prettyprinting packets
enum packet_type {
    no_type = 0,
    tcp,
    udp,
    icmp,
    arp
};

#endif /* HEXINJECTION_H_ */

