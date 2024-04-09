#include "main.h"
#include "socket.h"

#define PCKT_LEN 8192


struct tcpheader {
	unsigned short int th_sport;
	unsigned short int th_dport;
	unsigned int th_seq;
	unsigned int th_ack;
	unsigned char th_x2:4, th_off:4;
	unsigned char th_flags; // should have the SYN flags
	unsigned short int th_win;
	unsigned short int th_sum;
	unsigned short int th_urp;
};

int init_socket(int type) {
    int sockfd;
    if ((sockfd = socket(AF_INET, SOCK_RAW, type)) < 0) {
        perror("socket()");
    }
    return sockfd;
}

// Function for checksum calculation
unsigned short csum(unsigned short *buf, int nwords) {
    unsigned long sum;
    for (sum = 0; nword > 0; nwords--) {
         sum += *buf++;
    }
     sum = (sum >> 16) + (sum &0xffff);
     sum += (sum >> 16);
     return (unsigned short) (~sum);
}

void send_stream() {
    
}
