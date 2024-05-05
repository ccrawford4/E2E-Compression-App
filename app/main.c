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
    int sockfd;                    // Socket file descriptor
    struct sockaddr_in *h_saddr;   // Head SYN IP address configuration
    struct sockaddr_in *t_saddr;   // Tail SYN IP address configuration
    unsigned int m_time;           // Measurement time
    double stream_time;            // Stream time (where the result will be stored)
};

struct send_args {
    int sockfd;                    // Socket file descriptor
    struct sockaddr_in *saddr;     // Sender IP address configuration
    struct sockaddr_in *daddr;     // SYN destination address (includes Head SYN port)
    unsigned int tsyn_port;        // Tail SYN port
    const char *server_ip;         // Server_IP for UDP
    unsigned int udp_dst_port;     // Dest port for UDP
    int n_pckts;                   // Number of packets in stream
    int pckt_len;                  // Size of payload
    bool h_entropy;                // High entropy or not
    int ttl;                       // TTL
};

// Fill the IP config struct assuming we are using IPv4
void fill_ipstruct(struct sockaddr_in *addr, int port, char *ip_address) {
  memset(&addr, 0, sizeof(addr));              // Clear out the struct
  addr->sin_family = AF_INET;                  // Using IPv4
  addr->sin_port = htons(port);                // Set the port

  // Convert the IP address to binary
  if (inet_pton(AF_INET, ip_address, &(addr->sin_addr)) != 1)
     printf("ERROR! Failed to set IP_address\n");
     exit(EXIT_FAILURE);
}

// Sends a TCP SYN packet given a socket, and source/destination IP configs
void send_syn(int sockfd, struct sockaddr_in *saddr, struct sockaddr_in *daddr) {
   char *packet;
   int pckt_len;

   // Fill the IP/TCP headers and create the SYN packet
   create_syn_packet(saddr, daddr, &packet, &pckt_len);

   // Send the SYN packet
   int sent;
   if ((sent = sendto(sockfd, packet, pckt_len, 0, (struct sockaddr*)daddr,
                     sizeof(struct sockaddr)) == -1))
       handle_error(sockfd, "sendto()");
}

// Handles the UDP phase by creating the socket and sending the datagram
void udp_phase(const char *dst_ip, int port, int n_pckts, int pckt_len, bool h_entropy, int ttl)
 {

     // Create a UDP socket
     int sockfd;
     if ((sockfd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
      perror("socket()");
      exit(EXIT_FAILURE);
     }

     // Set the TTL value for the UDP packets - should be provided by the config file
     if (setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) < 0) {
        handle_error(sockfd, "setsockopt()");
     }

     // Create and fill the Destination IP address configuration
     struct sockaddr_in addr;
     fill_ipstruct(&addr, port, dst_ip);

     // Sends the UDP packet stream
     send_udp_packets(sockfd, &addr, port, pckt_len, n_pckts, h_entropy);

     // Close the socket after use
     close(sockfd);
}

// Threaded function called to send the TCP/UDP packets while another thread is listening for RST
int send_packets(void *arg) {
    struct send_args *args = (struct send_args *)arg;   
    int sockfd = args->sockfd;
    struct sockaddr_in *saddr = args->saddr;
    struct sockaddr_in *daddr = args->daddr;
    unsigned int tsyn_port = args->tsyn_port;
    const char *server_ip = args->server_ip;
    unsigned int udp_dst_port = args->udp_dst_port;
    int n_pckts = args->n_pckts;
    int pckt_len = args->pckt_len;
    bool h_entropy = args->h_entropy;
    int ttl = args->ttl;

    struct timespec curr_time;
    clock_gettime(CLOCK_MONOTONIC, &curr_time);
    
    send_syn(sockfd, saddr, daddr);
    udp_phase(server_ip, udp_dst_port, n_pckts, pckt_len, h_entropy, ttl);
    daddr->sin_port = htons(tsyn_port);
    send_syn(sockfd, saddr, daddr);

    return 1; // indicate success
}

// Thread function responsible for receiving the TCP RST packets
int recv_rst(void *arg) {
    struct recv_args *args = (struct recv_args *)arg;

    int sockfd = args->sockfd;
    struct sockaddr_in *h_saddr = args->h_saddr;
    struct sockaddr_in *t_saddr = args->t_saddr;
    unsigned int m_time = args->m_time;
        
    args->stream_time = calc_stream_time(sockfd, h_saddr, t_saddr, m_time);   

    return 1; // Indicate success
}


double probe_server(unsigned int tcp_src_port, unsigned int hsyn_port, unsigned int tsyn_port,
                 char *hostip, const char *server_ip, int ttl, unsigned int udp_dst_port, 
                 int n_pckts, int pckt_len, bool h_entropy, unsigned short timeout) 
{
    int sockfd;
    if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0)
        handle_error(sockfd, "socket()");

    // Source IP address configurations
    struct sockaddr_in saddr;
    fill_ipstruct(&saddr, tcp_src_port, hostip);
    
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
    thrd_t t0; //t will hold the thread id

    // Create argument struct for the thread
    struct recv_args *args = malloc(sizeof(struct recv_args));
    if (args == NULL)
        handle_error(sockfd, "memory allocation error");

    // Populate the args struct with necessary parameters
    args->sockfd = sockfd;
    args->h_saddr = &h_daddr;
    args->t_saddr = &t_daddr;
    args->m_time = timeout;

    if (thrd_create(&t0, recv_rst, args) != thrd_success) {
        fprintf(stderr, "Failed to created thread\n");
        return EXIT_FAILURE;
    }
    
    struct send_args *s_args = malloc(sizeof(struct send_args));
    if (s_args == NULL)
        handle_error(sockfd, "memory allocation error");

    s_args->sockfd = sockfd;
    s_args->saddr = &saddr;
    s_args->daddr = &h_daddr;
    s_args->tsyn_port = tsyn_port;
    s_args->server_ip = server_ip;
    s_args->udp_dst_port = udp_dst_port;
    s_args->n_pckts = n_pckts;
    s_args->pckt_len = pckt_len;
    s_args->h_entropy = h_entropy;
    s_args->ttl = ttl;

    thrd_t t1;

   if (thrd_create(&t1, send_packets, s_args) != thrd_success) {
        fprintf(stderr, "Failed to create thread\n");
        return EXIT_FAILURE;
    }

    int res;
    intptr_t return_value;
    if (thrd_join(t0, &res) != thrd_success) {
        fprintf(stderr, "Failed to join thread\n");
        return EXIT_FAILURE;
    }

    int sres;
    if (thrd_join(t1, &sres) != thrd_success) {
        fprintf(stderr, "Failed to join thread\n");
        return EXIT_FAILURE;
    }
     
    double ret_val = args->stream_time;
    close(sockfd);

    return ret_val;
}


int main(int argc, char **argv) {    
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

    unsigned short timeout = (unsigned short)atoi(get_value(config_file, "RST_timeout"));
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
        handle_key_error("TCP_HEADSYN_dest_port_number", config_file);
    if (tsyn_port == 0)
        handle_key_error("TCP_TAILSYN_dest_port_number", config_file);
    if (tcp_src_port == 0)
        handle_key_error("TCP_PREPROB_port_number", config_file);
    if (udp_src_port == 0) 
        handle_key_error("UDP_src_port_number", config_file);
    if (udp_dst_port == 0) 
        handle_key_error("UDP_dest_port_number", config_file);    
    if (ttl == 0) 
        handle_key_error("UDP_packet_TTL", config_file);
    if (m_time == 0)
        handle_key_error("measurement_time", config_file);
    if (n_pckts == 0)
        handle_key_error("UDP_packet_train_size", config_file);
    if (pckt_len == 0)
        handle_key_error("UDP_payload_size", config_file);


    char *hostip = (char*)malloc(NI_MAXHOST);
    if (hostip == NULL) {
        printf("Memory allocation error\n");
        return EXIT_FAILURE;
    }

    get_hostip(hostip);

    // Probe server with Low Entropy
    double time1 = probe_server(tcp_src_port, hsyn_port, tsyn_port, hostip, server_ip, ttl,
                udp_dst_port, n_pckts, pckt_len, false, timeout);

    wait(m_time);

     // Probe server with High Entropy
    double time2 = probe_server(tcp_src_port, hsyn_port, tsyn_port, hostip, server_ip, ttl,
                udp_dst_port, n_pckts, pckt_len, true, timeout);

    if (time1 == -1 || time2 == -1) {
        printf("Failed to detect due to insufficent information\n");
        return EXIT_FAILURE;
    }   

     bool detect_compression = found_compression(time1, time2);
     if (detect_compression) {
        printf("Compression Detected!\n");
     } else {
        printf("No Compression Detected!\n");
     }
        
    return EXIT_SUCCESS;
}
