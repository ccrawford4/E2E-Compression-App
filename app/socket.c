#include "headers/main.h"
#include "headers/socket.h"
#include "headers/shared.h"

#define PCKT_LEN 8192
#define BUF_SIZE 8193
#define UDP_PROTO 17
#define RANDOM_FILE "random_file"
#define DEBUG 1


// pseudo header needed for tcp header checksum calculation
struct pseudo_header
{
	u_int32_t source_address;
	u_int32_t dest_address;
	u_int8_t placeholder;
	u_int8_t protocol;
	u_int16_t tcp_length;
};

#define DATAGRAM_LEN 4096
#define OPT_SIZE 20

unsigned short checksum(const char *buf, unsigned size)
{
	unsigned sum = 0, i;

	/* Accumulate checksum */
	for (i = 0; i < size - 1; i += 2)
	{
		unsigned short word16 = *(unsigned short *) &buf[i];
		sum += word16;
	}

	/* Handle odd-sized case */
	if (size & 1)
	{
		unsigned short word16 = (unsigned char) buf[i];
		sum += word16;
	}

	/* Fold to get the ones-complement result */
	while (sum >> 16) sum = (sum & 0xFFFF)+(sum >> 16);

	/* Invert to get the negative in ones-complement arithmetic */
	return ~sum;
}

void create_syn_packet(struct sockaddr_in* src, struct sockaddr_in* dst, char** out_packet, int* out_packet_len)
{
	// datagram to represent the packet
	char *datagram = calloc(DATAGRAM_LEN, sizeof(char));

	// required structs for IP and TCP header
	struct iphdr *iph = (struct iphdr*)datagram;
	struct tcphdr *tcph = (struct tcphdr*)(datagram + sizeof(struct iphdr));
	struct pseudo_header psh;

	// IP header configuration
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + OPT_SIZE;
	iph->id = htonl(rand() % 65535); // id of this packet
	iph->frag_off = 0;
	iph->ttl = 64;
	iph->protocol = IPPROTO_TCP;
	iph->check = 0; // correct calculation follows later
	iph->saddr = src->sin_addr.s_addr;
	iph->daddr = dst->sin_addr.s_addr;

	// TCP header configuration
	tcph->source = src->sin_port;
	tcph->dest = dst->sin_port;
	tcph->seq = htonl(rand() % 4294967295);
	tcph->ack_seq = htonl(0);
	tcph->doff = 10; // tcp header size
	tcph->fin = 0;
	tcph->syn = 1;
	tcph->rst = 0;
	tcph->psh = 0;
	tcph->ack = 0;
	tcph->urg = 0;
	tcph->check = 0; // correct calculation follows later
	tcph->window = htons(5840); // window size
	tcph->urg_ptr = 0;

	// TCP pseudo header for checksum calculation
	psh.source_address = src->sin_addr.s_addr;
	psh.dest_address = dst->sin_addr.s_addr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_TCP;
	psh.tcp_length = htons(sizeof(struct tcphdr) + OPT_SIZE);
	int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + OPT_SIZE;
	// fill pseudo packet
	char* pseudogram = malloc(psize);
	memcpy(pseudogram, (char*)&psh, sizeof(struct pseudo_header));
	memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr) + OPT_SIZE);

	// TCP options are only set in the SYN packet
	// ---- set mss ----
	datagram[40] = 0x02;
	datagram[41] = 0x04;
	int16_t mss = htons(48); // mss value
	memcpy(datagram + 42, &mss, sizeof(int16_t));
	// ---- enable SACK ----
	datagram[44] = 0x04;
	datagram[45] = 0x02;
	// do the same for the pseudo header
	pseudogram[32] = 0x02;
	pseudogram[33] = 0x04;
	memcpy(pseudogram + 34, &mss, sizeof(int16_t));
	pseudogram[36] = 0x04;
	pseudogram[37] = 0x02;

	tcph->check = checksum((const char*)pseudogram, psize);
	iph->check = checksum((const char*)datagram, iph->tot_len);

	*out_packet = datagram;
	*out_packet_len = iph->tot_len;
	free(pseudogram);
}

int receive_from(int sock, char* buffer, size_t buffer_length, struct sockaddr_in *dst)
{
	unsigned short dst_port;
	int received;
	do
	{
		received = recvfrom(sock, buffer, buffer_length, 0, NULL, NULL);
		if (received < 0)
			break;
		memcpy(&dst_port, buffer + 22, sizeof(dst_port));
	}
	while (dst_port != dst->sin_port);
	printf("received bytes: %d\n", received);
	printf("destination port: %d\n", ntohs(dst->sin_port));
	return received;
}

void get_hostip(char *host) {
    struct ifaddrs *ifaddr, *ifa;
    int family;
    if (getifaddrs(&ifaddr) < 0) {
        perror("getifaddrs()");
        exit(EXIT_FAILURE);
    }
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) {
             continue;
        }
        family = ifa->ifa_addr->sa_family;
        if (family == AF_INET) {
            int s = getnameinfo(ifa->ifa_addr,
                sizeof(struct sockaddr_in),
                host, NI_MAXHOST,
                NULL, 0, NI_NUMERICHOST);
            if (s != 0) {
                printf("getnameinfo()");
                exit(EXIT_FAILURE);
            }
        }
    }
}

// Sends UDP packets
void send_udp_packets(int sockfd, struct sockaddr_in *server_addr,
                      int server_port, int packet_size, int num_packets,
                      bool h_entropy) {
  char *payload = (char *)malloc(packet_size);
  if (payload == NULL) {
    perror("Memory allocation failed\n");
    abort();
  }
  memset(payload, 0, packet_size);

  FILE *fp = fopen(RANDOM_FILE, "rb");
  if (fp == NULL) {
    free(payload);
    printf("Error Opening File %s\n", RANDOM_FILE);
    exit(EXIT_FAILURE);
  }

  // Send the packets
  for (int i = 0; i < num_packets; i++) {
    if (h_entropy) {
      fseek(fp, 0, SEEK_SET);
      size_t bytes_read = fread(payload, 1, packet_size, fp);
      if (bytes_read < packet_size) {
        fprintf(stderr,
                "Failed to read %d bytes from the file for packet %d.\n",
                packet_size, i);
        break;
      }
    }

    // Set the payload ID
    payload[0] = i & 0xFF;
    payload[1] = (i >> 8) & 0xFF;

    ssize_t bytes_sent =
        sendto(sockfd, payload, packet_size, 0,
               (struct sockaddr *)server_addr, sizeof(struct sockaddr_in));
    if (bytes_sent < 0) {
      perror("sendto()");
      exit(EXIT_FAILURE);
    }
  }

  fclose(fp);
  free(payload);
}
