//
//  WrapperFunctions.hpp
//  swiftyPcaplib
//
//  Created by Kevin Vallejo on 10/28/18.
//  Copyright © 2018 Vallejo. All rights reserved.
//

#ifndef WrapperFunctions_hpp
#define WrapperFunctions_hpp
#include "pcap.h"
#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <string.h>
#include <time.h>
#include <pcap.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <sys/stat.h>
#include <stdio.h>
#include "time.h"

/****************************************************************************************************************
 Wrapper function that extracts the ipHeader content in C since I couldnt figure out how to do this effciently in swift :)
 *****************************************************************************************************************/

struct ip* get_ipHeader(const u_char * packet) {
    
    struct ip* iph;
    
    iph = (struct ip*)(packet + sizeof(struct ether_header));
    
    return iph;
}


struct tcphdr* get_tcpHeader(const u_char * packet) {
    
   struct tcphdr* tcpHeader = (struct tcphdr*)(packet + sizeof(struct ip));
   // sizeof(struct ether_header)+sizeof(struct ip));
    return tcpHeader;

}

struct udphdr* get_udpHeader(const u_char * packet) {
    
    struct udphdr* udpHeader = (struct udphdr*)(packet + sizeof(struct ip));
    
    return udpHeader;
}



#endif /* WrapperFunctions_hpp */
