#include "headers/main.h"
#include "headers/socket.h"
#include "headers/shared.h"

#define PCKT_LEN 8192
#define BUF_SIZE 8193
#define UDP_PROTO 17
#define RANDOM_FILE "random_file"

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

// Sends UDP packets
//TODO fix
void send_udp_packets(int sockfd, struct sockaddr_in server_addr,
                      int server_port, int packet_size, int num_packets,
                      bool low_entropy) {
  char *payload = (char *)malloc(packet_size);
  if (payload == NULL) {
    perror("Memory allocation failed\n");
    abort();
  }
  memset(payload, 0, packet_size);

  FILE *fp = fopen(RANDOM_FILE, "rb");
  if (fp == NULL) {
    free(payload);
    printf("Error Opening File %s\n", RANDOM_FILE);
    exit(EXIT_FAILURE);
  }

  // Send the packets
  for (int i = 0; i < num_packets; i++) {
    if (!low_entropy) {
      fseek(fp, 0, SEEK_SET);
      size_t bytes_read = fread(payload, 1, packet_size, fp);
      if (bytes_read < packet_size) {
        fprintf(stderr,
                "Failed to read %d bytes from the file for packet %d.\n",
                packet_size, i);
        break;
      }
    }

    // Set the payload ID
    payload[0] = i & 0xFF;
    payload[1] = (i >> 8) & 0xFF;

    ssize_t bytes_sent =
        sendto(sockfd, payload, packet_size, 0,
               (const struct sockaddr *)&server_addr, sizeof(server_addr));
    if (bytes_sent < 0) {
      perror("sendto()");
      exit(EXIT_FAILURE);
    }
  }

  fclose(fp);
  free(payload);
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
    
    //TODO: Fix to use real header size instead of 56
    struct tcpheader *tcp_head = (struct tcpheader*) (buf + 56);
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
                host, NI_MAXHOST,
                NULL, 0, NI_NUMERICHOST);
            if (s != 0) {
                printf("getnameinfo()");
                exit(EXIT_FAILURE);
            }
        }
    }
}

void fill_ip_header(struct ipheader *ip, size_t struct_size, unsigned int ttl, unsigned int proto,
                    unsigned long dst_addr, unsigned long host_addr, char* buffer) {
    ip->iph_tos = 16;
    ip->iph_len = sizeof(struct ipheader) + struct_size;
    ip->iph_ttl = ttl;
    ip->iph_protocol = proto;
    ip->iph_sourceip = host_addr;
    ip->iph_dstip = dst_addr;

    ip->iph_chksum = csum((unsigned short *)buffer, sizeof(struct ipheader) + struct_size);

}

void fill_udp_header(char *buffer, struct ipheader *ip, struct udpheader *udp, struct sockaddr_in *sin, struct sockaddr_in *din, int sockfd, unsigned int udp_dst_port, unsigned int udp_src_port, const char* server_ip, unsigned int ttl) {  

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
    
    fill_ip_header(ip, sizeof(struct udpheader), ttl, UDP_PROTO, dst_addr, host_addr, buffer);

    udp->udph_srcport = htons(udp_src_port);
    udp->udph_destport = htons(udp_dst_port);
    udp->udph_len = htons(sizeof(struct udpheader));
    udp->udph_chksum = csum((unsigned short *)buffer, sizeof(struct ipheader) + sizeof(struct udpheader));
        
}
