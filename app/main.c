#include "headers/main.h"
#include "headers/socket.h"
#include "headers/shared.h"
#include "headers/json.h"

#define PCKT_LEN 8192
#define ERROR "ERROR"

void create_tcp_packet(unsigned int src_port, unsigned int dst_port, const char* server_ip,
                     unsigned int ttl) {
    // type will equal SYN or 
    int sockfd = init_socket(IPPROTO_TCP);
    struct sockaddr_in sin, din;
    sin.sin_family = AF_INET;
    sin.sin_family = AF_INET;

    sin.sin_port = htons(dst_port);
    din.sin_port = htons(src_port);

    char *host = (char*)malloc(NI_MAXHOST);
    if (host == NULL) {
        handle_error(sockfd, "Memory allocation error");
    }
    get_hostip(host);
    unsigned long host_addr = inet_addr(host);
    free(host);

    if (host_addr == INADDR_NONE) {
        handle_error(sockfd, "Invalid address");
    }
    unsigned long dst_addr = inet_addr(server_ip);
    if (dst_addr == INADDR_NONE) {
        handle_error(sockfd, "Invalid address");
    }
    sin.sin_addr.s_addr = dst_addr;
    din.sin_addr.s_addr = host_addr;

    struct iphdr *ip = (struct iphdr *)malloc(sizeof(struct iphdr));
    if (ip == NULL) {
        handle_error(sockfd, "Memory allocation error");
    }
    struct tcphdr *tcp = (struct tcphdr *)malloc(sizeof(struct tcphdr));
    if (tcp == NULL) {
        handle_error(sockfd, "Memory allocation error");
    }
    char *buffer = (char*)malloc(NI_MAXHOST);
    if (buffer == NULL) {
        handle_error(sockfd, "Memory allocation error");
    }
    fill_ip_header(ip, sizeof(struct tcphdr), ttl, IPPROTO_TCP, dst_addr, host_addr,
                   buffer);
    fill_tcp_header(tcp, src_port, dst_port, TH_SYN);

}


void udp_phase(unsigned int udp_dst_port, unsigned int udp_src_port,
               const char* server_ip, unsigned int ttl) {
   int sockfd = init_socket(IPPROTO_UDP);

    char* buffer = (char*)malloc(PCKT_LEN);

    struct iphdr *ip = (struct iphdr *) buffer;
    struct udphdr *udp = (struct udphdr *) (buffer + sizeof(struct iphdr));
    struct sockaddr_in sin, din;

    fill_udp_header(buffer, ip, udp, &sin, &din, sockfd, udp_dst_port,
                    udp_src_port, server_ip, ttl);
    // SEND PACKETS 
    // close fd
}


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
    if (!strcmp(server_addr, ERROR)) {
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

    struct iphdr *ip;
    // TODO
    


}
