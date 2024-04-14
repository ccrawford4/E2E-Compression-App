#include "main.h"
#include "socket.h"

#define PCKT_LEN 8192
#define BUF_SIZE 8193

int init_socket(int type) {
    int sockfd;
    if ((sockfd = socket(AF_INET, SOCK_RAW, type)) < 0) {
        perror("socket()");
    }
    int one = 1;
    const int *val = &one;
    if ((setsockopt(sockfd, IPPROTO_IP, IPHDRINCL, val, sizeof(one))) < 0) {
        handle_error(sockfd, "setsockopt()");
    }
    return sockfd;
}

// Function for checksum calculation
unsigned short csum(unsigned short *buf, int nwords) {
    unsigned long sum;
    for (sum = 0; nword > 0; nwords--) {
         sum += *buf++;
    }
     sum = (sum >> 16) + (sum &0xffff);
     sum += (sum >> 16);
     return (unsigned short) (~sum);
}

void send_packets(int sockfd, char *buffer, struct ipheader *iph) {
    // do sin stuff
    struct sockaddr_in sin;
    sendto(sockfd, buffer, iph->ip_len, 0, (struct sockaddr *) sin, sizeof(sin));
}

void recv_packets(int sockfd) {
    char* buf = (char*)malloc(BUF_SIZE);
    if (buf == NULL) {
        handle_error(sockfd, "Memory Allocation Error");
    }
    // for (;;) {
    ssize_t psize = recvfrom(sockfd, buf, BUF_SIZE, 0, NULL, NULL);
    // ...
    if (psize < 0) {
        handle_error(sockfd, "recvfrom()");
    }
    // ...
    struct ipheader *ip_head = (struct ipheader*)buf;
    // exxtract ip_head_len using ip_head->ihl

    struct tcpheader *tcp_head = (struct tcpheader*) (buf + ip_head_len);
    // set pointer to beginning of data
    // ...
    
}

void fill_tcp_header(struct tcpheader *tcph, unsigned int port, int type) {
    tcph->th_sport = htons(port);
    tcph->th_flags = type;
}

void fill_header(struct ipheader *iph, unsigned int port, struct int type, char* buffer) {
    // iph->ip_v -> done automatically
    iph->ip_tos = 0;
    iph->ip_dst.s_addr = sin.sin_addr.s_addr;
    
    // create tcp header
    fill_tcp_header(tcph, port, type);

    // fill buffer with payload
    
    // ...
    /* if no payload */
    iph->ip_len = sizeof (struct ipheader) + sizeof(tcpheader);

}
