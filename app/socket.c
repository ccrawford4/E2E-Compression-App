#include "headers/main.h"
#include "headers/socket.h"
#include "headers/shared.h"

#define PCKT_LEN 8192
#define BUF_SIZE 8193
#define UDP_PROTO 17
#define RANDOM_FILE "random_file"

#define DEBUG 1

void send_tcp_pckt(char *buffer, size_t buffer_len, int sockfd, struct iphdr *ip,
                 struct sockaddr_in *sin) {
    int num_packets = sendto(sockfd, buffer, buffer_len, 0, (struct sockaddr *)sin,
                            sizeof(struct sockaddr_in));
    if (num_packets < 0) {
        handle_error(sockfd, "sendto()");
    }
    #ifdef DEBUG
     printf("Sent SYN packet!\n");
    #endif
}

void send_udp_pckts(char *buffer, int sockfd, struct iphdr *ip,
             struct sockaddr_in sin, int n_pckts, int pckt_len, bool high_entropy) 
{
    FILE *fp = fopen(RANDOM_FILE, "rb");
    if (fp == NULL) {
        handle_error(sockfd, "Error opening file");
     }

     for (int i = 0; i < n_pckts; i++) {
        if (high_entropy) {
            fseek(fp, 0, SEEK_SET);
            size_t bytes_read = fread(buffer, 1, pckt_len, fp);
            if (bytes_read < pckt_len) {
                handle_error(sockfd, "Failed to read bytes from file");
            }

        }
        // Set the packet ID
        buffer[0] = i & 0xFF;
        buffer[1] = (i >> 8) & 0xFF;

        ssize_t bytes_sent = sendto(sockfd, buffer, pckt_len, 0,
                                   (struct sockaddr *)&sin, sizeof(sin));
        if (bytes_sent < 0) {
            handle_error(sockfd, "sendto()");
        }
   }
}

int init_socket(int type) {
    int sockfd;
    if ((sockfd = socket(AF_INET, SOCK_RAW, type)) < 0) {
        perror("socket()");
    }
    int one = 1;
    const int *val = &one;
    if ((setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one))) < 0) {
        handle_error(sockfd, "setsockopt()");
    }
    return sockfd;
}

// Function for checksum calculation
unsigned short csum(unsigned short *buf, int nwords) {
    unsigned long sum;
    for (sum = 0; nwords > 0; nwords--) {
         sum += *buf++;
     }
     sum = (sum >> 16) + (sum &0xffff);
     sum += (sum >> 16);
    return (unsigned short) (~sum);
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
    struct iphdr *ip_head = (struct iphdr*)buf;
    // exxtract ip_head_len using ip_head->ihl
    
    //TODO: Fix to use real header size instead of 56
    struct tcphdr *tcp_head = (struct tcphdr*) (buf + 56);
    // set pointer to beginning of data
    // ...
    
}

void get_hostip(char *host) {
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
                host, NI_MAXHOST,
                NULL, 0, NI_NUMERICHOST);
            if (s != 0) {
                printf("getnameinfo()");
                exit(EXIT_FAILURE);
            }
        }
    }
}

void fill_ip_header(struct iphdr *ip, size_t struct_size, unsigned int ttl, unsigned int proto,
                    unsigned long dst_addr, unsigned long host_addr) {

    ip->version = 4; // IPv4
    ip->ihl = 5;     // length of IP header in 32-bit words
    ip->tos = 16; // could be 0
    ip->tot_len = sizeof(struct iphdr) + struct_size;
    ip->ttl = ttl;
    ip->frag_off = 0;
    ip->protocol = proto;
    ip->check = 0;
    ip->saddr = host_addr;
    ip->daddr = dst_addr;
}

//void fill_header(char *buffer, struct iphdr *ip, struct udphdr

void fill_tcp_header(struct tcphdr *tcp, unsigned int src_port, unsigned int dst_port, int type) 
{
    tcp->th_sport = htons(src_port);
    tcp->th_dport = htons(dst_port);
    tcp->th_seq = htonl(1);
    tcp->th_ack = 0;
    tcp->th_flags = type; // change to type
    tcp->th_win = htons(32767);
    tcp->th_sum = 0;
    tcp->th_urp = 0;
    tcp->check = 0;
    tcp->th_off = 5;     // Header length in 32-bit words
}

void fill_udp_header(char *buffer, struct iphdr *ip, struct udphdr *udp, struct sockaddr_in *sin, struct sockaddr_in *din, int sockfd, unsigned int udp_dst_port, unsigned int udp_src_port, const char* server_ip, unsigned int ttl) {  

    sin->sin_family = AF_INET;
    din->sin_family = AF_INET;

    sin->sin_port = htons(udp_dst_port);
    din->sin_port = htons(udp_src_port);
    
    char *host = (char*)malloc(NI_MAXHOST);
    get_hostip(host);

    unsigned long dst_addr = inet_addr(server_ip);
    if (dst_addr == INADDR_NONE) {
        fprintf(stderr, "Invalid address\n");
        exit(EXIT_FAILURE);
    }
    unsigned long host_addr = inet_addr(host);
    free(host);

    if (host_addr == INADDR_NONE) {
        fprintf(stderr, "Invalid address\n");
        exit(EXIT_FAILURE);
    }

    sin->sin_addr.s_addr = dst_addr;
    din->sin_addr.s_addr = host_addr;
    
    fill_ip_header(ip, sizeof(struct udphdr), ttl, UDP_PROTO, dst_addr, host_addr);

    udp->uh_sport = htons(udp_src_port);
    udp->uh_dport = htons(udp_dst_port);
    udp->uh_ulen = htons(sizeof(struct udphdr));
    udp->uh_sum = csum((unsigned short *)buffer, sizeof(struct iphdr) + sizeof(struct udphdr));
        
}
