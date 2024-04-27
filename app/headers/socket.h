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

void send_tcp_pckt(char *buffer, size_t buffer_len, int sockfd, struct sockaddr_in *sin);
void fill_tcp_header(struct tcphdr *tcp, unsigned int src_port,
                    unsigned int dst_port, int type);
void get_hostip(char *host);
unsigned short csum(unsigned short *buf, int nwords);
int init_socket(int type);
void recv_packets(int sockfd);
void fill_ip_header(struct iphdr *ip, size_t struct_size, unsigned int ttl, unsigned int proto,
                    unsigned long dst_addr, unsigned long host_addr);
void fill_udp_header(struct udphdr *udp, int pckt_len, unsigned int src_port, unsigned int dst_port);

void send_udp_pckts(char *buffer, size_t buffer_len, int sockfd, 
                    struct sockaddr_in *sin, int n_pckts, bool h_entropy);
