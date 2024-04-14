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

void get_hostip(char* host) {
    struct ifaddrs *ifaddr, *ifa;
    int family;
    if (getifaddrs(&ifaddr) < 0) {
        perror("getifaddrs()");
        exit(EXIT_FAILURE);
    }
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) {
             continue;
        }
        family = ifa->ifa_addr->sa_family;
        if (family == AF_INET) {
            int s = getnameinfo(ifa->ifa_addr,
                sizeof(struct sockaddr_in),
                *host, NI_MAXHOST,
                NULL, 0, NI_NUMERICHOST);
            if (s != 0) {
                printf("getnameinfo()");
                exit(EXIT_FAILURE);
            }
        }
    }
}

void fill_udp_header(char *buffer, struct ipheader *ip, struct udpheader *udp, struct sockaddr_in *sin, struct sockaddr_in *din, int sockfd, unsigned int udp_dst_port, unsigned int udp_src_port, const char* server_ip, unsigned int ttl) {

    struct sockaddr_in sin, din;

    sin.sin_family = AF_INET;
    din.sin_family = AF_INET;

    sin.sin_port = htons(udp_dst_port);
    din.sin_port = htons(udp_src_port);

    char host[NI_MAXHOST];
    get_hostip(&host);

    unsigned long dst_addr = inet_addr(server_ip);
    if (dst_addr == INADDR_NONE) {
        fprintf(stderr, "Invalid address\n");
        exit(EXIT_FAILURE);
    }
    unsigned long host_addr = inet_addr(host);
    if (host_addr == INADDR_NONE) {
        fprintf(stderr, "Invalid address\n");
        exit(EXIT_FAILURE);
    }

    sin.sin_addr.s_addr = dst_addr;
    din.sin_addr.s_addr = host_addr;

    ip->iph_ihl = 5;
    ip->iph_tos = 16;
    ip->iph_len = sizeof(struct ipheader) + sizeof(struct udpheader);
    ip->iph_ident = htons(54321);
    ip->iph_ttl = ttl;
    ip->iph_protocol = 17; // UDP
    ip->iph_sourceip = host_addr;
    ip->iph_destip = dst_addr;

    udp->udph_srcport = htons(udp_src_port);
    udp->udph_len = htons(sizeof(struct udpheader));

    // calculate the checksum for integrity
    ip->iph_chksum = csum((unsigned short *)buffer,
    sizeof(struct ipheader + sizeof(struct udpheader));
        
}
