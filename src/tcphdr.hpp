#pragma once

#include <cstdint>
#include <arpa/inet.h>

/*
 *  TCP header
 *  Transmission Control Protocol
 *  Static header size: 20 bytes
 */
#pragma pack(push, 1)
struct TcpHdr final {
    uint16_t th_sport;          /* source port */
    uint16_t th_dport;          /* destination port */
    uint32_t th_seq;            /* sequence number */
    uint32_t th_ack;            /* acknowledgement number */

    uint8_t th_x2: 4,           /* (unused) */
           th_off: 4;           /* data offset */

    /* control flags */
    enum TCP_FLAGS: uint8_t {
        FIN = 0x01,  /* finished send data */
        SYN = 0x02,  /* synchronize sequence numbers */
        RST = 0x04,  /* reset the connection */
        PUSH = 0x08, /* push data to the app layer */
        ACK = 0x10,  /* acknowledge */
        URG = 0x20,  /* urgent! */
        ECE = 0x40,  
        CWR = 0x80   
    } th_flags;

    uint16_t th_win;    /* window */
    uint16_t th_sum;    /* checksum */
    uint16_t th_urp;    /* urgent pointer */

    uint16_t sport() { return ntohs(this->th_sport); }
    uint16_t dport() { return ntohs(this->th_dport); }
};
#pragma pack(pop)
