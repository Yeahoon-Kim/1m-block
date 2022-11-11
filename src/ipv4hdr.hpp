#pragma once

#include <cstdint>
#include <arpa/inet.h>
#include "ip.hpp"

struct IPv4Hdr final {
    uint8_t ip_hl:4,        /* header length */
            ip_v:4;         /* version */
    uint8_t ip_tos;         /* type of service */

    uint16_t ip_len;        /* total length */
    uint16_t ip_id;         /* identification */
    uint16_t ip_off;

    uint8_t ip_ttl;         /* time to live */

    enum IP_PROTOCOL: uint8_t {
        HOPORT   = 0x00,    /* IPv6 Hop-by-Hop Option */
        ICMP     = 0x01,    /* Internet Control Message Protocol */
        IGMP     = 0x02,    /* Internet Group Management Protocol */
        GGP      = 0x03,    /* Gateway-to-Gateway Protocol */
        IP_in_IP = 0x04,    /* IP in IP (encapsulation) */
        ST       = 0x05,    /* Internet Stream Protocol */
        TCP      = 0x06,    /* Transmission Control Protocol */
        CBT      = 0x07,    /* Core-based trees */
        EGP      = 0x08,    /* Exterior Gateway Protocol */
        IGP      = 0x09,    /* Interior Gateway Protocol */
        UDP      = 0x11,    /* User Datagram Protocol */
        RDP      = 0x1b,    /* Reliable Data Protocol */
        IPv6     = 0x29     /* IPv6 Encapsulation (6to4 and 6in4) */
    } ip_p;                 /* protocol */
    
    uint16_t ip_sum;        /* checksum */

    IPv4 ip_src, ip_dst;    /* source and dest address */

    uint32_t sip() { return ntohl(ip_src); }
    uint32_t dip() { return ntohl(ip_dst); }
    uint16_t totalLength() { return ntohs(ip_len); }
};
