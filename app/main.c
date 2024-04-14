#include "main.h"

#define PCKT_LEN 8192
#define ERROR "ERROR"

void udp_phase(unsigned int udp_dst_port, unsigned int udp_src_port,
               const char* server_ip, unsigned int ttl) {
   int sockfd = init_socket(IPPROTO_UDP);

    char buffer[PCKT_LEN];

    struct ipheader *ip = (struct ipheader *) buffer;
    struct udpheader *udp = (struct udpheader *) (buffer + sizeof(struct ipheader));
    struct sockaddr_in sin, din;

    fill_udp_header(&buffer, ip, udp, &sin, &din, sockfd, udp_dst_port,
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

}
