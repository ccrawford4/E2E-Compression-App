#include "main.h"

unsigned short csum(unsigned short *buf, int nwords);

// IP Header
struct ipheader {
 unsigned char       ip_ihl:5, ip_v:4;
 unsigned char       ip_tos;
 unsigned short int  ip_len;
 unsigned short int  ip_ident;
 unsigned char       ip_flag;
 unsigned short int  ip_offset;
 unsigned char       ip_ttl;
 unsigned char       ip_protocol;
 unsigned short int  ip_chksum;
 unsigned int        ip_sourceip;
 unsigned int        ip_dst;
};

struct tcpheader {
    unsigned short int th_sport;
    unsigned short int th_dport;
    unsigned int th_seq;
    unsigned int th_ack;
    unsigned char th_x2:4, th_off:4;
    unsigned char th_flags; // Should have SYN flags
    unsigned short int th_win;
    unsigned short int th_sum;
    unsigned short int th_urp;
};


// UDP Header
struct udpheader {
 unsigned short int  udph_srcport;
 unsigned short int  udph_destport;
 unsigned short int  udph_len;
 unsigned short int  udph_chksum;
};

