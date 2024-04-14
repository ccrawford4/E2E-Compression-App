#include "main.h"
#define PCKT_LEN 8192
#define ERROR "ERROR"

int main(int argc, char **argv) {
    // 1. Send a single head SYN packet (port x)
    // 2. Send n UDP packets
    // 3. Send a single tail SYN packet (port y)
    // SYN should trigger RST packets

    // Listen for RST packets

    // RST1 - RST2 -> will determine comperssion

    // If the RST packet is loss (use a timer) -> 
    // output: "Failed to detect due to insufficent information"
    
    // compdetect myconfig.json

    if (argc != 2) {
        printf("usage: \n");
        printf("./compdetect <file_name>.json>\n");
        return EXIT_FAILURE;
    }

    char* config_file = argv[1];
    
    const char* server_addr = get_value(config_file, "server_ip");
    if (!stcmp(server_addr, "ERROR")) {
        printf("ERROR! You must enter a server IP address in the %s file", argv[1]);
        return EXIT_FAILURE;
    }

    unsigned int hsyn_port = (unsigned int)atoi(get_value(config_file, "TCP_HEADSYN_dest_port_number"));
    if (hsyn_port == 0) {
        handle_key_error(hsyn_port, "TCP_HEADSYN_dest_port_number", config_file);
    }
    unsigned int udp_dst_port = (unsigned int)atoi(get_value(config_file, "UDP_dest_port_number"));
    if (udp_dst_port == 0) {
        handle_key_error(udp_dst_port, "UDP_dest_port_number", config_file);
    }
    unsigned int udp_src_port = (unsigned int)atoi(get_value(config_file, "UDP_src_port_number"));
    if (udp_src_port == 0) {
        handle_key_error(udp_src_port, "UDP_src_port_number", config_file);
    }
    const char *server_ip = get_value(config_file, "server_ip");
    if (!strcmp(server_ip, ERROR)) {
        printf("INVALID server_ip in file %s\n", config_file);
        return EXIT_FAILURE;
    }
    const char* ttl_str = get_value(config_file, "UDP_packet_TTL");
    unsigned int ttl = (unsigned int) atoi(ttl_str);
    if (ttl == 0 && strcmp(ttl_str, "0")) {
        handle_key_error(ttl, "UDP_packet_TTL", config_file);
    }

// UDP PACKET SENDING PROCESS
    int sockfd;

    char buffer[PCKT_LEN];

    struct ipheader *ip = (struct ipheader *) buffer;
    struct udpheader *udp = (struct udpheader *) (buffer + sizeof(struct ipheader));

    // Source and destination
    struct sockaddr_in sin, din;
    int one = 1;
    const int *val = &one;
    memset(buffer, 0, PCKT_LEN);

    sockfd = socket(PF_INET, SOCK_RAW, IPPROTO_UDP);
    if (sd < 0) {
        perror("socket()");
        exit(EXIT_FAILURE);
    }

    sin.sin_family = AF_INET;
    din.sin_family = AF_INET;

    // Set IP address ports
    sin.sin_port = htons(udp_dst_port);
    din.sin_port = htons(udp_src_port);
    

    // Get the hosts IP address
    struct ifaddrs *ifaddr, *ifa;
    int family;
    char host[NI_MAXHOST];
    if (getifaddrs(&ifaddr) < 0) {
        handle_error(sockfd, "getifaddrs()");
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
                printf("getnameinfo() failed: %s\n", gai_strerror(s));
                return EXIT_FAILURE;
            }
            printf("Interface: %s\tAddress: %s\n", ifa->ifa_name, host);
        }
    }

    // Set IP
    unsigned long dst_addr = inet_addr(server_ip);
    unsigned long host_addr = inet_addr(host);

    sin.sin_addr.s_addr = dst_addr;
    din.sin_addr.s_addr = host_addr;

    ip->iph_ihl = 5;
    // ver is set
    ip->iph_tos = 16;
    ip->iph_len = sizeof(struct ipheader) + sizeof(struct udpheader);
    ip->iph_ident = htons(54321);
    ip->iph_ttl = ttl;
    ip->iph_protocol = 17; // UDP
    // set ip, could use spoofing here
    ip->iph_sourceip = host_addr;
    ip->iph_destip = dst_addr;

    udp->udph_srcport = htons(udp_src_port);
    udp->udph_len = htons(sizeof(struct udpheader));

    // calculate checksum for integrity
    ip->iph_chksum = csum((unsigned short *)buffer,
    sizeof(struct ipheader) + sizeof(struct updheader));

    if (setsockopt(sockfd, IPPROTO, IP_HDRINCL, val, sizeof(one)) < 0) {
        perror("setsockopt() error");
        close(sockfd);
        return EXIT_FAILURE;
    }
    // send

}
