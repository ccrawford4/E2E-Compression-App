#include "headers/shared.h"
#include "headers/socket.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

#define R 0.100
#define MAX_BUFFER_LEN 1000
#define DEBUG 1
#define DATAGRAM_LEN 4096

bool found_compression(double time_one, double time_two) {
    double diff = abs(time_one - time_two);
    if (diff > R)
        return true;
    return false;
}

void print_time(struct timespec current_time) {
    struct tm *time_info;
    char buffer[80];

    clock_gettime(CLOCK_REALTIME, &current_time);
    time_info = localtime(&current_time.tv_sec);

    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", time_info);

    printf(": %s.%09ld\n", buffer, current_time.tv_nsec);
}

double calc_stream_time(int sockfd, struct sockaddr_in *h_saddr, struct sockaddr_in *t_saddr, unsigned int m_time) 
{
    char buffer[DATAGRAM_LEN];
    size_t buffer_len = sizeof(buffer);

    struct timeval timeout;
    timeout.tv_sec = m_time; // measurement time
    timeout.tv_usec = 0;     // No microseconds
    
    struct timespec timer_start, start_time, curr_time, end_time;

    bool found_rst = false;
    int n;

    int flags = fcntl(sockfd, F_GETFL, 0);
    if (flags == -1)
        handle_error(sockfd, "fcntl get");

    flags = (flags | O_NONBLOCK);
    if (fcntl(sockfd, F_SETFL, flags) == -1)
        handle_error(sockfd, "fcntl set");

    clock_gettime(CLOCK_MONOTONIC, &timer_start);

    socklen_t saddr_len = sizeof(struct sockaddr_in);
    printf("Time starting to receive packets: \n");
    print_time(timer_start);
    while (true) {
        clock_gettime(CLOCK_MONOTONIC, &curr_time);
        double elapsed = (curr_time.tv_sec - timer_start.tv_sec) + 
                        (curr_time.tv_nsec - timer_start.tv_nsec) / 1000000000.0;
        if (found_rst) {
            n = recvfrom(sockfd, buffer, buffer_len, 0, (struct sockaddr*)t_saddr, &saddr_len);
        } else {
            n = recvfrom(sockfd, buffer, buffer_len, 0, (struct sockaddr*)h_saddr, &saddr_len);
        }

        
        #ifdef DEBUG
          //  print_time(curr_time);
          //  printf("Bytes received: %d\n", n);
        #endif
        if (n > 0) {
            struct iphdr *iph = (struct iphdr *)buffer;
            struct tcphdr *tcph = (struct tcphdr *)(buffer + iph->ihl * 4);

            char src_ip[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &(iph->saddr), src_ip, INET_ADDRSTRLEN);

            char expected_ip[] = "192.168.80.4";

            if (strcmp(src_ip, expected_ip) == 0) {
                 printf("   From: %s\n", inet_ntoa(*(struct in_addr *)&iph->saddr));
                 printf("   To: %s\n", inet_ntoa(*(struct in_addr *)&iph->daddr));
                 printf("   Source Port: %u\n", ntohs(tcph->source));
                 printf("   Destination Port: %u\n", ntohs(tcph->dest));
            }

            // Check for TCP RST flag
            if (tcph->rst) {
                // If its the first RST packet
                if (!found_rst) {
                    clock_gettime(CLOCK_MONOTONIC, &start_time);
                    found_rst = true;
                } else {
                    clock_gettime(CLOCK_MONOTONIC, &end_time);
                  //  break;
                }
            }
        } else if (errno == EAGAIN || errno == EWOULDBLOCK) {
          //  printf("No data available yet\n");
        } else if (n < 0) {
            perror("recvfrom()");
        }
        // reset the buffer
        memset(buffer, 0, sizeof(buffer));

        if (elapsed >= m_time) {
            return -1;
        }
     }
        
    double total_elapsed = ((end_time.tv_sec - start_time.tv_sec) + 
                            (end_time.tv_nsec - start_time.tv_nsec)) / 1000000000.0;

    return total_elapsed;
}
