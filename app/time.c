#include "headers/shared.h"
#include "headers/socket.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

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

    printf("Current Time: %s.%09ld\n", buffer, current_time.tv_nsec);
}

double calc_stream_time(int sockfd, struct sockaddr_in *cliaddr, unsigned int m_time) 
{
    char buffer[DATAGRAM_LEN];
    size_t buffer_len = sizeof(buffer);

    struct timeval timeout;
    timeout.tv_sec = m_time; // measurement time
    timeout.tv_usec = 0;     // No microseconds

   /* if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0)
        handle_error(sockfd, "setsockopt()");*/
    
    struct timespec start_time, curr_time, end_time;

    bool found_rst = false;
    int n;
      
   // while (true) {
        clock_gettime(CLOCK_MONOTONIC, &curr_time);
        double elapsed = (curr_time.tv_sec - start_time.tv_sec) + 
                         (curr_time.tv_nsec - start_time.tv_nsec) / 1000000000.0;
        printf("recvfrom()");
        n = recvfrom(sockfd, buffer, buffer_len, 0, NULL, NULL);
        printf("after recvfrom()");
        
        #ifdef DEBUG
            print_time(curr_time);
            printf("Bytes received: %d\n", n);
        #endif
        if (n > 0) {
            struct iphdr *iph = (struct iphdr *)buffer;
            struct tcphdr *tcph = (struct tcphdr *)(buffer + iph->ihl * 4);

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
            printf("No data available yet\n");
        } else if (n < 0) {
            perror("recvfrom()");
        }

        if (elapsed >= m_time) {
            return -1;
        }
   //  }
        
    double total_elapsed = ((end_time.tv_sec - start_time.tv_sec) + 
                            (end_time.tv_nsec - start_time.tv_nsec)) / 1000000000.0;

    return total_elapsed;
}
