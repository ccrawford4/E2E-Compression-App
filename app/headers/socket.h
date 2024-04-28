#include <sys/types.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>

void get_hostip(char *host);
void create_syn_packet(struct sockaddr_in *src, struct sockaddr_in *dst, char **out_packet,
                       int *out_packet_len);

int receive_from(int sock, char *buffer, size_t buffer_len, struct sockaddr_in *dst);
void send_udp_packets(int sockfd, struct sockaddr_in *server_addr, int server_port, int pckt_size,
                     int n_pckts, bool h_entropy);
int init_socket(int type);
