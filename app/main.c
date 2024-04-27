#include "headers/main.h"
#include "headers/socket.h"
#include "headers/shared.h"
#include "headers/json.h"

#define ERROR "ERROR"
#define RANDOM_FILE "random_file"

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

void create_data_packet(struct sockaddr_in* src, struct sockaddr_in* dst, int32_t seq, int32_t ack_seq, char* data, int data_len, char** out_packet, int* out_packet_len)
{
	// datagram to represent the packet
	char *datagram = calloc(DATAGRAM_LEN, sizeof(char));

	// required structs for IP and TCP header
	struct iphdr *iph = (struct iphdr*)datagram;
	struct tcphdr *tcph = (struct tcphdr*)(datagram + sizeof(struct iphdr));
	struct pseudo_header psh;

	// set payload
	char* payload = datagram + sizeof(struct iphdr) + sizeof(struct tcphdr) + OPT_SIZE;
	memcpy(payload, data, data_len);

	// IP header configuration
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + OPT_SIZE + data_len;
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
	tcph->seq = htonl(seq);
	tcph->ack_seq = htonl(ack_seq);
	tcph->doff = 10; // tcp header size
	tcph->fin = 0;
	tcph->syn = 0;
	tcph->rst = 0;
	tcph->psh = 1;
	tcph->ack = 1;
	tcph->urg = 0;
	tcph->check = 0; // correct calculation follows later
	tcph->window = htons(5840); // window size
	tcph->urg_ptr = 0;

	// TCP pseudo header for checksum calculation
	psh.source_address = src->sin_addr.s_addr;
	psh.dest_address = dst->sin_addr.s_addr;
	psh.placeholder = 0;
	psh.protocol = IPPROTO_TCP;
	psh.tcp_length = htons(sizeof(struct tcphdr) + OPT_SIZE + data_len);
	int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr) + OPT_SIZE + data_len;
	// fill pseudo packet
	char* pseudogram = malloc(psize);
	memcpy(pseudogram, (char*)&psh, sizeof(struct pseudo_header));
	memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr) + OPT_SIZE + data_len);

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

void tcp_phase(unsigned int src_port, unsigned int dst_port, unsigned long host_addr,
               unsigned int dst_addr, unsigned int ttl) 
{

    int sockfd = init_socket(IPPROTO_TCP);
    
    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(dst_port);
    sin.sin_addr.s_addr = dst_addr;

    char buffer[sizeof(struct iphdr) + sizeof(struct tcphdr)];
    memset(&buffer, 0, sizeof(buffer));

    struct iphdr *ip = (struct iphdr *) buffer;
    struct tcphdr *tcp = (struct tcphdr *) (buffer + sizeof(struct iphdr));

    size_t tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);

    fill_ip_header(ip, tot_len, ttl,IPPROTO_TCP, host_addr, dst_addr);
    fill_tcp_header(tcp, src_port, dst_port, TH_SYN);

    calculate_tcp_checksum(ip, tcp);

    send_tcp_pckt(buffer, ip->tot_len, sockfd, &sin);
    close(sockfd);

}


void udp_phase(unsigned int src_port, unsigned int dst_port,
               unsigned long host_addr, unsigned long dst_addr, unsigned int ttl,
               int n_pckts, int pckt_len, bool h_entropy) 
{
    int sockfd = init_socket(IPPROTO_UDP);

    struct sockaddr_in sin;
    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = htons(dst_port);
    sin.sin_addr.s_addr = dst_addr;

    char buffer[sizeof(struct iphdr) + sizeof(struct udphdr) + pckt_len];
    memset(&buffer, 0, sizeof(buffer));

    struct iphdr *ip = (struct iphdr *) buffer;
    struct udphdr *udp = (struct udphdr *) (buffer + sizeof(struct iphdr));


    fill_udp_header(udp, pckt_len, src_port, dst_port);
    fill_ip_header(ip, sizeof(buffer), ttl, IPPROTO_UDP, host_addr, dst_addr);

    ip->check = csum((unsigned short *)buffer, sizeof(struct iphdr) + sizeof(struct udphdr));
    udp->check = csum((unsigned short *)buffer, sizeof(struct iphdr) + sizeof(struct udphdr));

    send_udp_pckts(buffer, ip->tot_len, sockfd, &sin, n_pckts, h_entropy);
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

    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (sock == -1)
	{
		printf("socket creation failed\n");
		return 1;
	}

	// destination IP address configuration
	struct sockaddr_in daddr;
	daddr.sin_family = AF_INET;
	daddr.sin_port = htons(hsyn_port);
	if (inet_pton(AF_INET, server_ip, &daddr.sin_addr) != 1)
	{
		printf("destination IP configuration failed\n");
		return 1;
	}

	// source IP address configuration
    char *host = "192.168.80.2";
	struct sockaddr_in saddr;
	saddr.sin_family = AF_INET;
	saddr.sin_port = htons(tcp_src_port); // random client port
	if (inet_pton(AF_INET, host, &saddr.sin_addr) != 1)
	{
		printf("source IP configuration failed\n");
		return 1;
	}

	printf("selected source port number: %d\n", ntohs(saddr.sin_port));

	// tell the kernel that headers are included in the packet
	int one = 1;
	const int *val = &one;
	if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, val, sizeof(one)) == -1)
	{
		printf("setsockopt(IP_HDRINCL, 1) failed\n");
		return 1;
	}

	// send SYN
	char* packet;
	int packet_len;
	create_syn_packet(&saddr, &daddr, &packet, &packet_len);

	int sent;
	if ((sent = sendto(sock, packet, packet_len, 0, (struct sockaddr*)&daddr, sizeof(struct sockaddr))) == -1)
	{
		printf("sendto() failed\n");
	}
	else
	{
		printf("successfully sent %d bytes SYN!\n", sent);
	}


    // receive SYN-ACK
	char recvbuf[DATAGRAM_LEN];
	int received = receive_from(sock, recvbuf, sizeof(recvbuf), &saddr);
	if (received <= 0)
	{
		printf("receive_from() failed\n");
	}
	else
	{
		printf("successfully received %d bytes SYN-ACK!\n", received);
	}



   /* char *host = (char*)malloc(NI_MAXHOST);
    if (host == NULL) {
        printf("Memory allocation error\n");
        return EXIT_FAILURE;
    }

    get_hostip(host);
    unsigned long host_addr = inet_addr(host);
    free(host);

    if (host_addr == INADDR_NONE) {
        printf("Invalid IP Address: %lu\n", host_addr);
        return EXIT_FAILURE;
    }

    unsigned long dst_addr = inet_addr(server_ip);

    if (host_addr == INADDR_NONE) {
        printf("Invalid IP Address: %lu\n", dst_addr);
        return EXIT_FAILURE;
     }

    tcp_phase(tcp_src_port, hsyn_port, host_addr, dst_addr, ttl);
    wait(5);
    udp_phase(udp_src_port, udp_dst_port, host_addr, dst_addr, ttl, n_pckts, pckt_len, false);
    tcp_phase(tcp_src_port, tsyn_port, host_addr, dst_addr, ttl);
    wait(5);
        
    return EXIT_SUCCESS;*/
}
