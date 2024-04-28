#include "headers/main.h"
#include "headers/socket.h"
#include "headers/shared.h"
#include "headers/json.h"

#define ERROR "ERROR"
#define RANDOM_FILE "random_file"
#define DATAGRAM_LEN 4096
#define DEBUG 1

struct recv_args {
    int sockfd;                   // Socket file descriptor
    struct sockaddr_in *saddr;    // Sender IP address configuration
    unsigned int m_time;         // Measurement time
};

int run(void *arg) {
    struct recv_args *args = (struct recv_args *)arg;

    int sockfd = args->sockfd;
    struct sockaddr_in *saddr = args->saddr;
    unsigned int m_time = args->m_time;

    double *stream_time = malloc(sizeof(double));
    if (stream_time == NULL)
        handle_error(sockfd, "Memory allocation");

    
    *stream_time = calc_stream_time(sockfd, saddr, m_time);    

    return (intptr_t)stream_time;
}

void send_syn(int sockfd, struct sockaddr_in *saddr, struct sockaddr_in *daddr) {
   char *packet;
   int pckt_len;
   create_syn_packet(saddr, daddr, &packet, &pckt_len);

   int sent;
   if ((sent = sendto(sockfd, packet, pckt_len, 0, (struct sockaddr*)daddr,
                     sizeof(struct sockaddr)) == -1))
       handle_error(sockfd, "sendto()");

    #ifdef DEBUG
        printf("SYN Sent\n");
    #endif
}


void udp_phase(const char *dst_ip, int port, int n_pckts, int pckt_len, bool h_entropy)
 {

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


double probe_server(unsigned int tcp_src_port, unsigned int hsyn_port, unsigned int tsyn_port,
                 char *hostip, const char *server_ip, int ttl, unsigned int udp_dst_port, 
                 int n_pckts, int pckt_len, bool h_entropy) 
{
    // Create the RAW socket
    int sockfd;
    if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
        handle_error(sockfd, "socket()");

    // Source IP address configurations
    struct sockaddr_in saddr;
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(tcp_src_port);

    if (inet_pton(AF_INET, hostip, &saddr.sin_addr) != 1)
        handle_error(sockfd, "inet_pton()");
    
    // Destination IP address configurations for head SYN
    struct sockaddr_in h_daddr;
    h_daddr.sin_family = AF_INET;
    h_daddr.sin_port = htons(hsyn_port);

    if (inet_pton(AF_INET, server_ip, &h_daddr.sin_addr) != 1)
        handle_error(sockfd, "inet_pton()");

    // Destination IP address configurations for tail SYN
    struct sockaddr_in t_daddr;
    t_daddr.sin_family = AF_INET;
    t_daddr.sin_port = htons(tsyn_port);

    if (inet_pton(AF_INET, server_ip, &t_daddr.sin_addr) != 1)
        handle_error(sockfd, "inet_pton()");

    int one = 1;
    const int *val = &one;
    
    // Tell Kernel not to fill in header fields
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) == -1)
        handle_error(sockfd, "setsockopt()");

   
    char recvbuf[DATAGRAM_LEN];
    thrd_t t; //t will hold the thread id

    // Create argument struct for the thread
    struct recv_args *args = malloc(sizeof(struct recv_args));
    if (args == NULL)
        handle_error(sockfd, "memory allocation error");

    // Populate the args struct with necessary parameters
    args->sockfd = sockfd;
    args->saddr = &saddr;
    args->m_time = 15;      // TODO: change to measurement time

    // Create and start the thread to listen for RST packets
    if (thrd_create(&t, run, args) != thrd_success) {
        fprintf(stderr, "Failed to created thread\n");
        return EXIT_FAILURE;
    }


    send_syn(sockfd, &saddr, &h_daddr);                                 // Send Head SYN
    udp_phase(server_ip, udp_dst_port, n_pckts, pckt_len, h_entropy);   // UDP Phase
    send_syn(sockfd, &saddr, &t_daddr);                                 // Send Tail SYN

    // Join thread and return the results
    intptr_t result;
    if (thrd_join(t, (int*)&result) != thrd_success) {
        fprintf(stderr, "Failed to join thread\n");
        return EXIT_FAILURE;
    }

    double stream_time = *(double *)(intptr_t)result;

    #ifdef DEBUG
        printf("Stream Time: %f\n", stream_time);
    #endif

    close(sockfd);

    return stream_time;
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

    // Probe server with Low Entropy
    double time1 = probe_server(tcp_src_port, hsyn_port, tsyn_port, hostip, server_ip, ttl,
                udp_dst_port, n_pckts, pckt_len, false);

    wait(15); // replace with server wait time

     // Probe server with High Entropy
    double time2 = probe_server(tcp_src_port, hsyn_port, tsyn_port, hostip, server_ip, ttl,
                udp_dst_port, n_pckts, pckt_len, true);

     bool detect_compression = found_compression(time1, time2);
     if (detect_compression) {
        printf("Compression Detected!\n");
     } else {
        printf("No Compression Detected!\n");
     }
        
    return EXIT_SUCCESS;
}
