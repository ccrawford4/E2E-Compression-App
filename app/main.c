#include "headers/main.h"
#include "headers/socket.h"
#include "headers/shared.h"
#include "headers/json.h"

#define ERROR "ERROR"
#define RANDOM_FILE "random_file"

void tcp_phase(unsigned int port, const char *server_ip, unsigned int ttl) 
{

    int sockfd = init_socket(IPPROTO_TCP);
    struct hostent *host = gethostbyname(server_ip);
    if (host == NULL) {
        handle_error(sockfd, "gethostbyname()");
    }

    in_addr_t server_addr = *(in_addr_t *)host->h_addr_list[0];

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = server_addr;
    sin.sin_port = htons(port);
    

    char buffer[sizeof(struct iphdr) + sizeof(struct tcphdr)];

    struct iphdr *ip = (struct iphdr *) buffer;
    struct tcphdr *tcp = (struct tcphdr *) (buffer + sizeof(struct iphdr));

    fill_ip_header(ip, sizeof(struct tcphdr), ttl, IPPROTO_TCP, dst_addr, host_addr);
    fill_tcp_header(tcp, src_port, dst_port, type);

    ip->check = csum((unsigned short *)buffer, sizeof(struct iphdr) + 
                     sizeof(struct tcphdr));
    tcp->check = csum((unsigned short *)buffer, sizeof(struct iphdr) + 
                     sizeof(struct tcphdr));
    
    struct sockaddr_in sin;

    send_tcp_pckt(buffer, ip->tot_len, sockfd, ip, sin);

}


void udp_phase(unsigned int udp_dst_port, unsigned int udp_src_port,
               const char* server_ip, unsigned int ttl, int n_pckts,
               int pckt_len, bool high_entropy) 
{
    int sockfd = init_socket(IPPROTO_UDP);
    char* buffer = (char*)malloc(pckt_len);
    if (buffer == NULL) {
        handle_error(sockfd, "Memory Allocation Error");
    }
    memset(buffer, 0, pckt_len);

    struct iphdr *ip = (struct iphdr *) buffer;
    struct udphdr *udp = (struct udphdr *) (buffer + sizeof(struct iphdr));
    struct sockaddr_in sin, din;

    fill_udp_header(buffer, ip, udp, &sin, &din, sockfd, udp_dst_port,
                    udp_src_port, server_ip, ttl);

    send_udp_pckts(buffer, sockfd, ip, sin, n_pckts, pckt_len, high_entropy);
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
    
    if (argc != 2) {
        printf("usage: \n");
        printf("./compdetect <file_name>.json>\n");
        return EXIT_FAILURE;
    }

    char* config_file = argv[1];
    
    const char* server_ip = get_value(config_file, "server_ip");
    if (!strcmp(server_ip, ERROR)) {
        printf("ERROR! You must enter a server IP address in the %s file", argv[1]);
        return EXIT_FAILURE;
    }

    unsigned int hsyn_port = (unsigned int)atoi(get_value(config_file, "TCP_HEADSYN_dest_port_number"));
    unsigned int tsyn_port = (unsigned int)atoi(get_value(config_file, "TCP_TAILSYN_dest_port_number"));
    unsigned int udp_src_port = (unsigned int)atoi(get_value(config_file, "UDP_src_port_number"));
    unsigned int udp_dst_port = (unsigned int)atoi(get_value(config_file, "UDP_dest_port_number"));
    unsigned int ttl = (unsigned int)atoi(get_value(config_file, "UDP_packet_TTL"));
    unsigned int m_time = (unsigned int)atoi(get_value(config_file, "measurement_time"));

    if (hsyn_port == 0) 
        handle_key_error(hsyn_port, "TCP_HEADSYN_dest_port_number", config_file);
    if (tsyn_port == 0)
        handle_key_error(tsyn_port, "TCP_TAILSYN_dest_port_number", config_file);
    if (udp_src_port == 0) 
        handle_key_error(udp_dst_port, "UDP_src_port_number", config_file);
    if (udp_dst_port == 0) 
        handle_key_error(udp_src_port, "UDP_dest_port_number", config_file);    
    if (ttl == 0) 
        handle_key_error(ttl, "UDP_packet_TTL", config_file);
    if (m_time == 0)
        handle_key_error(m_time, "measurement_time", config_file);

    tcp_phase(src_port, dst_port, server_ip, ttl);
        
    return EXIT_SUCCESS;
}
