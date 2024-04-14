#include <sys/types.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

// IP Header
struct ipheader {
 unsigned char       iph_ihl:5, iph_v:4;
 unsigned char       iph_tos;
 unsigned short int  iph_len;
 unsigned short int  iph_ident;
 unsigned char       iph_flag;
 unsigned short int  iph_offset;
 unsigned char       iph_ttl;
 unsigned char       iph_protocol;
 unsigned short int  iph_chksum;
 unsigned int        iph_sourceip;
 unsigned int        iph_dstip;
};

// TCP Header
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

unsigned short csum(unsigned short *buf, int nwords);
int init_socket(int type);
void send_packets(int sockfd, char *buffer, struct ipheader *iph);
void recv_packets(int sockfd);
void fill_ip_header(struct ipheader *ip, size_t struct_size, unsigned int ttl, unsigned int proto,
                    unsigned long dst_addr, unsigned long host_addr, char* buffer);
void fill_udp_header(char *buffer, struct ipheader *ip, struct udpheader *udp,
                    struct sockaddr_in *sin, struct sockaddr_in *din, int sockfd,
                    unsigned int udp_dst_port, unsigned int udp_src_port, const char *server_ip, unsigned int ttl);
