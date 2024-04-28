#include "headers/main.h"
#include "headers/socket.h"
#include "headers/shared.h"
#include "headers/json.h"
#include <time.h>

#define ERROR "ERROR"
#define RANDOM_FILE "random_file"
#define DATAGRAM_LEN 4096
#define DEBUG 0

struct recv_args {
    int sockfd;                   // Socket file descriptor
    struct sockaddr_in *h_saddr;    // Head SYN IP address configuration
    struct sockaddr_in *t_saddr;    // Tail SYN IP address configuration
    unsigned int m_time;         // Measurement time
};

struct send_args {
    int sockfd;                   // Socket file descriptor
    struct sockaddr_in *saddr;    // Sender IP address configuration
    struct sockaddr_in *h_daddr;  // Head SYN destination address
    struct sockaddr_in *t_daddr;  // Tail SYN destination address
    const char *server_ip;       // Server_IP for UDP
    unsigned int udp_dst_port;    // Dest port for UDP
    int n_pckts;                  // Number of packets in stream
    int pckt_len;                 // Size of payload
    bool h_entropy;               // High entropy or not
};


void send_syn(int sockfd, struct sockaddr_in *saddr, struct sockaddr_in *daddr) {
   char *packet;
   int pckt_len;
   create_syn_packet(saddr, daddr, &packet, &pckt_len);

   int sent;
   if ((sent = sendto(sockfd, packet, pckt_len, 0, (struct sockaddr*)daddr,
                     sizeof(struct sockaddr)) == -1))
       handle_error(sockfd, "sendto()");
        
        printf("SYN Bytes sent: %d\n", sent);
    #ifdef DEBUG
       // printf("SYN Sent\n");
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

     // TODO: Fix it so it includes the TTL
     send_udp_packets(sockfd, &addr, port, pckt_len, n_pckts, h_entropy);
}

int send_packets(void *arg) {
    struct send_args *args = (struct send_args *)arg;
    int sockfd = args->sockfd;
    struct sockaddr_in *saddr = args->saddr;
    struct sockaddr_in *h_daddr = args->h_daddr;
    struct sockaddr_in *t_daddr = args->t_daddr;
    const char *server_ip = args->server_ip;
    unsigned int udp_dst_port = args->udp_dst_port;
    int n_pckts = args->n_pckts;
    int pckt_len = args->pckt_len;
    bool h_entropy = args->h_entropy;

    struct timespec curr_time;
    clock_gettime(CLOCK_MONOTONIC, &curr_time);
    printf("Time when sending packets\n");
    print_time(curr_time);
    
    send_syn(sockfd, saddr, h_daddr);
    udp_phase(server_ip, udp_dst_port, n_pckts, pckt_len, h_entropy);
    send_syn(sockfd, saddr, t_daddr);
    printf("Sent all syn\n");

    return 1; // indicate success
}

int recv_rst(void *arg) {
    struct recv_args *args = (struct recv_args *)arg;

    int sockfd = args->sockfd;
    struct sockaddr_in *h_saddr = args->h_saddr;
    struct sockaddr_in *t_saddr = args->t_saddr;
    unsigned int m_time = args->m_time;

    double *stream_time = malloc(sizeof(double));
    if (stream_time == NULL)
        handle_error(sockfd, "Memory allocation");
    
  //  printf("IN stream...\n");
    
    *stream_time = calc_stream_time(sockfd, h_saddr, t_saddr, m_time);   

    printf("Calculated stream time: %f\n", *stream_time);

    return (intptr_t)stream_time;
}


double probe_server(unsigned int tcp_src_port, unsigned int hsyn_port, unsigned int tsyn_port,
                 char *hostip, const char *server_ip, int ttl, unsigned int udp_dst_port, 
                 int n_pckts, int pckt_len, bool h_entropy) 
{
    // Create the RAW socket
    int sockfd;
    if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0)
        handle_error(sockfd, "socket()");

    printf("Head SYN port before setting: %d\n", hsyn_port);
    printf("Tail SYN port after setting: %d\n", tsyn_port);

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

    printf("Head SYN port after setting: %d\n", ntohs(h_daddr.sin_port));
    printf("Tail SYN port after setting: %d\n", ntohs(t_daddr.sin_port));

    int one = 1;
    const int *val = &one;
    
    // Tell Kernel not to fill in header fields
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) == -1)
        handle_error(sockfd, "setsockopt()");
   
    char recvbuf[DATAGRAM_LEN];
    thrd_t t0; //t will hold the thread id

    // Create argument struct for the thread
    struct recv_args *args = malloc(sizeof(struct recv_args));
    if (args == NULL)
        handle_error(sockfd, "memory allocation error");

    // Populate the args struct with necessary parameters
    args->sockfd = sockfd;
    args->h_saddr = &h_daddr;
    args->t_saddr = &t_daddr;
    args->m_time = 10;      // TODO: change to measurement time

    // Create and start the thread to listen for RST packets
    printf("Starting recv thread\n");
    if (thrd_create(&t0, recv_rst, args) != thrd_success) {
        fprintf(stderr, "Failed to created thread\n");
        return EXIT_FAILURE;
    }
    printf("Created recv thread\n");
    
    struct send_args *s_args = malloc(sizeof(struct send_args));
    if (s_args == NULL)
        handle_error(sockfd, "memory allocation error");

    s_args->sockfd = sockfd;
    s_args->saddr = &saddr;
    s_args->h_daddr = &h_daddr;
    s_args->t_daddr = &t_daddr;
    s_args->server_ip = server_ip;
    s_args->udp_dst_port = udp_dst_port;
    s_args->n_pckts = n_pckts;
    s_args->pckt_len = pckt_len;
    s_args->h_entropy = h_entropy;

    printf("Starting send thread\n");
    thrd_t t1;
   // wait(1);
    if (thrd_create(&t1, send_packets, s_args) != thrd_success) {
        fprintf(stderr, "Failed to create thread\n");
        return EXIT_FAILURE;
    }
    printf("Created send thread\n");

    // Join thread and return the results
    intptr_t result;
    if (thrd_join(t0, (int*)&result) != thrd_success) {
        fprintf(stderr, "Failed to join thread\n");
        return EXIT_FAILURE;
    }

    int sres;
    if (thrd_join(t1, (int*)&sres) != thrd_success) {
        fprintf(stderr, "Failed to join thread\n");
        return EXIT_FAILURE;
    }

    printf("Joining all threads\n");

    double stream_time = *(double *)(intptr_t)result;

    #ifdef DEBUG
       // printf("Stream Time: %f\n", stream_time);
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
