#include "headers/shared.h"
#include "headers/socket.h"
#include <stdlib.h>

#define R 0.100
#define MAX_BUFFER_LEN 1000

bool found_compression(double time_one, double time_two) {
    double diff = abs(time_one - time_two);
    if (diff > R)
        return true;
    return false;
}


double calc_stream_time(int sockfd, struct sockaddr_in *cliaddr, unsigned int m_time) 
{
    char *buffer = (char*)malloc(MAX_BUFFER_LEN);
    if (buffer == NULL)
        handle_error(sockfd, "Memory allocation failure");

    struct timeval timeout;
    timeout.tv_sec = m_time; // measurement time
    timeout.tv_usec = 0;     // No microseconds

    if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0)
        handle_error(sockfd, "setsockopt()");
    
    struct timespec start_time, curr_time, end_time;

    bool found_rst = false;
    int n;
    socklen_t len = sizeof(struct sockaddr_in);
  
    while (true) {
        clock_gettime(CLOCK_MONOTONIC, &curr_time);
        double elapsed = (curr_time.tv_sec - start_time.tv_sec) + 
                         (curr_time.tv_nsec - start_time.tv_nsec) / 1000000000.0;
        n = recvfrom(sockfd, buffer, MAX_BUFFER_LEN - 1, 0, (struct sockaddr *)cliaddr,
                     &len);

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
                    break;
                }
            }
        } else if (n < 0) {
            handle_error(sockfd, "recvfrom()");
        } else if (elapsed >= m_time) {
            return -1;      // TIMEOUT Exceeded! The second RST was not found
        }

     }
        

    double total_elapsed = ((end_time.tv_sec - start_time.tv_sec) + 
                            (end_time.tv_nsec - start_time.tv_nsec)) / 1000000000.0;

     free(buffer);

     return total_elapsed;
}
