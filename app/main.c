#include "headers/main.h"
#include "headers/socket.h"
#include "headers/shared.h"
#include "headers/json.h"

#define ERROR "ERROR"
#define RANDOM_FILE "random_file"
#define DATAGRAM_LEN 4096
#define DEBUG 1

struct recv_args {
    int sockfd;
    char *recvbuf;
    size_t sizeof_recvbuf;
    struct sockaddr_in *saddr;
};

int run(void *arg) {
    struct recv_args *args = (struct recv_args *)arg;

    int sockfd = args->sockfd;
    char *recvbuf = args->recvbuf;
    size_t size = args->sizeof_recvbuf;
    struct sockaddr_in *saddr = args->saddr;

    int bytes_recv = receive_from(sockfd, recvbuf, size, saddr);
    
    return bytes_recv;
}

void tcp_phase(unsigned int src_port, unsigned int dst_port, const char *host_ip,
               const char *server_ip, unsigned int ttl) 
{

    int sockfd = init_socket(SOCK_RAW);

   // Destination IP address configuration
   struct sockaddr_in daddr;
   daddr.sin_family = AF_INET;
   daddr.sin_port = htons(dst_port); // Destination port

   if (inet_pton(AF_INET, server_ip, &daddr.sin_addr) != 1)
   {
        handle_error(sockfd, "inet_pton() - dest ip");
   }

   // Source IP address configuration
   struct sockaddr_in saddr;
   saddr.sin_family = AF_INET;
   saddr.sin_port = htons(src_port);    // TCP Source Port

   if (inet_pton(AF_INET, host_ip, &saddr.sin_addr) != 1)
        handle_error(sockfd, "inet_pton() - host ip");

   int one = 1;
   const int *val = &one;
   // Tell Kernel not to fill in header fields
   if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) == -1)
       handle_error(sockfd, "setsockopt()");


    char recvbuf[DATAGRAM_LEN];

    thrd_t t; // t will hold the thread id
    
    // Create argument struct for the thread
    struct recv_args *args = malloc(sizeof(struct recv_args));
    if (args == NULL)
        handle_error(sockfd, "memory allocation error");
    
    // Populate the args struct with the necessary parameters
    args->sockfd = sockfd;
    args->recvbuf = recvbuf;
    args->sizeof_recvbuf = sizeof(recvbuf);
    args->saddr = &saddr;
    
    // Create a thread to listen for RST packets
    thrd_create(&t, run, args);

    // Send SYN (confine to another function later
    char *packet;
    int pckt_len;
    create_syn_packet(&saddr, &daddr, &packet, &pckt_len);
   
    int sent;
    if ((sent = sendto(sockfd, packet, pckt_len, 0, (struct sockaddr*)&daddr, sizeof(struct sockaddr)) == -1))
        handle_error(sockfd, "sendto()");

    #ifdef DEBUG
        printf("SYN Sent\n");
    #endif
    
    int recv_bytes;
    thrd_join(t, &recv_bytes);

    if (recv_bytes <= 0)
        handle_error(sockfd, "recv()");
    #ifdef DEBUG
        printf("Succcessfully received %d bytes from RST: \n", recv_bytes);
    #endif

    // Close the socket
    close(sockfd);
}


void udp_phase(const char *dst_ip, int port, int n_pckts, int pckt_len, bool h_entropy)
 {

    // CONSOLIDATE to another function (also clean up paramaters
    int sockfd;
     struct sockaddr_in addr;
     if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
      perror("socket()");
      exit(EXIT_FAILURE);
     }
     // DESTINATION ADDR
      memset(&addr, 0, sizeof(addr));
      addr.sin_family = AF_INET;
      addr.sin_port = htons(port);

      if (inet_pton(AF_INET, dst_ip, &addr.sin_addr) != 1)
          handle_error(sockfd, "inet_pton()");
 
      int optval = 1;
      if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) <
          0) {
          handle_error(sockfd, "setsockopt()");
      }

     // TODO: Fix it so it includes the TTL
     send_udp_packets(sockfd, &addr, port, pckt_len, n_pckts, h_entropy);
     close(sockfd);

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
    unsigned tcp_src_port = (unsigned int)atoi(get_value(config_file, "TCP_PREPROB_port_number"));
    unsigned int udp_src_port = (unsigned int)atoi(get_value(config_file, "UDP_src_port_number"));
    unsigned int udp_dst_port = (unsigned int)atoi(get_value(config_file, "UDP_dest_port_number"));
    unsigned int ttl = (unsigned int)atoi(get_value(config_file, "UDP_packet_TTL"));
    unsigned int m_time = (unsigned int)atoi(get_value(config_file, "measurement_time"));
    unsigned int n_pckts = (unsigned int)atoi(get_value(config_file, "UDP_packet_train_size"));
    char *payload_str = (char*)get_value(config_file, "UDP_payload_size");
    int idx = strlen(payload_str) - 1;
    *(payload_str + idx) = '\0';        // Remove the 'B' from the Payload String
    unsigned int pckt_len = (unsigned int)atoi(payload_str);

    if (hsyn_port == 0) 
        handle_key_error(hsyn_port, "TCP_HEADSYN_dest_port_number", config_file);
    if (tsyn_port == 0)
        handle_key_error(tsyn_port, "TCP_TAILSYN_dest_port_number", config_file);
    if (tcp_src_port == 0)
        handle_key_error(tcp_src_port, "TCP_PREPROB_port_number", config_file);
    if (udp_src_port == 0) 
        handle_key_error(udp_dst_port, "UDP_src_port_number", config_file);
    if (udp_dst_port == 0) 
        handle_key_error(udp_src_port, "UDP_dest_port_number", config_file);    
    if (ttl == 0) 
        handle_key_error(ttl, "UDP_packet_TTL", config_file);
    if (m_time == 0)
        handle_key_error(m_time, "measurement_time", config_file);
    if (n_pckts == 0)
        handle_key_error(n_pckts, "UDP_packet_train_size", config_file);
    if (pckt_len == 0)
        handle_key_error(pckt_len, "UDP_payload_size", config_file);


    char *hostip = (char*)malloc(NI_MAXHOST);
    if (hostip == NULL) {
        printf("Memory allocation error\n");
        return EXIT_FAILURE;
    }

    get_hostip(hostip);

    tcp_phase(tcp_src_port, hsyn_port, hostip, server_ip, ttl);     // Head SYN
    udp_phase(server_ip, udp_dst_port, n_pckts, pckt_len, false);   // Low entropy
    tcp_phase(tcp_src_port, tsyn_port, hostip, server_ip, ttl);     // Tail SYN

    wait(15);

    tcp_phase(tcp_src_port, hsyn_port, hostip, server_ip, ttl);       // Head SYN
    udp_phase(server_ip, udp_dst_port, n_pckts, pckt_len, true);    // High entropy
    tcp_phase(tcp_src_port, tsyn_port, hostip, server_ip, ttl);     // Tail SYN
        
    return EXIT_SUCCESS;
}
