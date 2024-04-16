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

void fill_tcp_header(struct tcphdr *tcp, unsigned int src_port,
                    unsigned int dst_port, int type);
void get_hostip(char *host);
unsigned short csum(unsigned short *buf, int nwords);
int init_socket(int type);
void send_packets(int sockfd, char *buffer, struct iphdr *iph);
void recv_packets(int sockfd);
void fill_ip_header(struct iphdr *ip, size_t struct_size, unsigned int ttl, unsigned int proto,
                    unsigned long dst_addr, unsigned long host_addr, char* buffer);
void fill_udp_header(char *buffer, struct iphdr *ip, struct udphdr *udp,
                    struct sockaddr_in *sin, struct sockaddr_in *din, int sockfd,
                    unsigned int udp_dst_port, unsigned int udp_src_port, const char *server_ip, unsigned int ttl);
