#include "headers/main.h"
#include "headers/socket.h"
#include "headers/shared.h"

#define PCKT_LEN 8192
#define BUF_SIZE 8193
#define UDP_PROTO 17
#define RANDOM_FILE "random_file"
#define DEBUG 1

// Pseudo header needed for TCP checksum calculation
struct pseudo_header {
    unsigned long src_addr;
    unsigned long dst_addr;
    unsigned char placeholder;
    unsigned char protocol;
    unsigned short tcp_length;
};

unsigned short calculate_checksum(unsigned short *ptr, int nbytes) {
    long sum;
    unsigned short oddbyte;
    short answer;

    sum = 0;
    while (nbytes > 1) {
        sum += *ptr++;
        nbytes -= 2;
    }
    if (nbytes == 1) {
        oddbyte = 0;
        *((unsigned char *)&oddbyte) = *(unsigned char *)ptr;
        sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = (short)~sum;

    return answer;
}

void calculate_tcp_checksum(struct iphdr *ip, struct tcphdr *tcp) {
    struct pseudo_header psh;
    char *pseudogram;
    int psize = sizeof(struct pseudo_header) + ntohs(ip->tot_len) - ip->ihl * 4;

    psh.src_addr = ip->saddr;
    psh.dst_addr = ip->daddr;
    psh.placeholder = 0;
    psh.protocol = IPPROTO_TCP;
    psh.tcp_length = htons(sizeof(struct tcphdr));  // tcp length (not including data)

    int total_len = psize;
    pseudogram = malloc(total_len);

    memcpy(pseudogram, (char *)&psh, sizeof(struct pseudo_header));
    memcpy(pseudogram + sizeof(struct pseudo_header), tcp, tcp->doff * 4);

    tcp->check = calculate_checksum((unsigned short *)pseudogram, total_len);

    free(pseudogram);
}

void send_tcp_pckt(char *buffer, size_t buffer_len, int sockfd, struct sockaddr_in *sin) {
    int num_packets = sendto(sockfd, buffer, buffer_len, 0, (struct sockaddr *)sin,
                            sizeof(struct sockaddr_in));
    if (num_packets < 0) {
        handle_error(sockfd, "sendto()");
    }
    #ifdef DEBUG
     printf("Sent SYN packet!\n");
    #endif
}

void send_udp_pckts(char *buffer, size_t buffer_len, int sockfd, struct sockaddr_in *sin, 
                    int n_pckts, bool h_entropy) 
{
    FILE *fp = fopen(RANDOM_FILE, "rb");
    if (fp == NULL) {
        handle_error(sockfd, "Error opening file");
     }

     size_t offset = sizeof(struct iphdr) + sizeof(struct udphdr);

     for (int i = 0; i < n_pckts; i++) {
        if (h_entropy) {
            fseek(fp, 0, SEEK_SET);
            size_t bytes_read = fread(buffer + offset, 1, buffer_len - offset, fp);
            if (bytes_read < buffer_len - offset) {
                handle_error(sockfd, "Failed to read bytes from file");
            }

        }
        // Set the packet ID
        *(buffer + offset) = i & 0xFF;
        *(buffer + offset + 1) = (i >> 8) & 0xFF;

        ssize_t bytes_sent = sendto(sockfd, buffer, buffer_len, 0,
                                   (struct sockaddr *)sin, sizeof(struct sockaddr_in));
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

void fill_ip_header(struct iphdr *ip, size_t size, unsigned int ttl, unsigned int proto,
                    unsigned long host_addr, unsigned long dst_addr) {

    ip->version = 4; // IPv4
    ip->ihl = 5;     // length of IP header in 32-bit words
    ip->tos = 0;     // Type of service
    ip->tot_len = size; // Total length
    ip->id = htonl(rand()); // ID of the current packet
    ip->ttl = ttl;      // Time to live
    ip->frag_off = 0;   // No fragment
    ip->protocol = proto;   // Protocol
    ip->check = 0;          // Checksum (temporary)  
    ip->saddr = host_addr;  // Source IP Address
    ip->daddr = dst_addr;   // Destination IP address
}


void fill_tcp_header(struct tcphdr *tcp, unsigned int src_port, unsigned int dst_port, int type) 
{
    tcp->th_sport = htons(src_port);
    tcp->th_dport = htons(dst_port);
    tcp->th_seq = htonl(rand());      // Initial sequence num
    tcp->th_ack = 0;                 // No acknowledgment
    tcp->th_flags = type;            // change to type
    tcp->th_win = htons(5840);      // Maximum allowed window size
    tcp->th_sum = 0;
    tcp->th_urp = 0;
    tcp->check = 0;
    tcp->th_off = 5;     // Header length in 32-bit words
}

void fill_udp_header(struct udphdr *udp, int pckt_len, unsigned int src_port, 
                    unsigned int dst_port) {  
    udp->uh_sport = htons(src_port);
    udp->uh_dport = htons(dst_port);
    udp->uh_ulen = htons(sizeof(struct udphdr) + pckt_len);
    udp->uh_sum = 0;        
}
