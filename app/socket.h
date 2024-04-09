#include "main.h"

unsigned short csum(unsigned short *buf, int nwords);

// IP Header
struct ipheader {
 unsigned char       iph_ihl:5, iph_ver:4;
 unsigned char       iph_tos;
 unsigned short int  iph_len;
 unsigned short int  iph_ident;
 unsigned char       iph_flag;
 unsigned short int  iph_offset;
 unsigned char       iph_ttl;
 unsigned char       iph_protocol;
 unsigned short int  iph_chksum;
 unsigned int        iph_sourceip;
 unsigned int        iph_destip;
};

struct tcpheader {
    }


// UDP Header
struct udpheader {
 unsigned short int  udph_srcport;
 unsigned short int  udph_destport;
 unsigned short int  udph_len;
 unsigned short int  udph_chksum;
};

