#include "headers/shared.h"
#include "headers/socket.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>

#define R 0.100
#define DATAGRAM_LEN 4096

// Determines if compression has occured
bool found_compression(double time_one, double time_two) {
    double diff = abs(time_one - time_two);
    if (diff > R)
        return true;
    return false;
}

// Prints out the current time given a struct timespec (helpful for debugging)
void print_time(struct timespec current_time) {
    struct tm *time_info;
    char buffer[80];

    clock_gettime(CLOCK_REALTIME, &current_time);
    time_info = localtime(&current_time.tv_sec);

    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", time_info);

    printf(": %s.%09ld\n", buffer, current_time.tv_nsec);
}

// Listens for RST packets and calculates the streamtime
double calc_stream_time(int sockfd, struct sockaddr_in *h_saddr, struct sockaddr_in *t_saddr, unsigned int m_time) 
{
    // Buffer to receive the RST
    char buffer[DATAGRAM_LEN];
    size_t buffer_len = sizeof(buffer);

    struct timeval timeout;
    timeout.tv_sec = m_time; // measurement time
    timeout.tv_usec = 0;     // No microseconds
   
    // Timespec structs for stream time calculations and timeout feature
    struct timespec timer_start, start_time, curr_time, end_time;

    // Found RST will be false to start
    bool found_rst = false;
    int n;                                               // Number of bytes to receive
    socklen_t saddr_len = sizeof(struct sockaddr_in);    // IP config struct length

    // Set socket configurations so that if no data is received the socket doesnt sit and wait
    int flags = fcntl(sockfd, F_GETFL, 0);
    if (flags == -1)
        handle_error(sockfd, "fcntl get");
    flags = (flags | O_NONBLOCK);
    if (fcntl(sockfd, F_SETFL, flags) == -1)
        handle_error(sockfd, "fcntl set");

     // Start the timer
     clock_gettime(CLOCK_MONOTONIC, &timer_start);

     // Continue until we recieve both RSTs or we reach the timeout time (RST_timeout in the config file)
     while (true) {
        // Get the current time
        clock_gettime(CLOCK_MONOTONIC, &curr_time);

        // Calculate how many seconds have elapsed
        double elapsed = (curr_time.tv_sec - timer_start.tv_sec) + 
                        (curr_time.tv_nsec - timer_start.tv_nsec) / 1000000000.0;

        // Depending on if you found the RST or not should be listening to the corresponding port
        if (found_rst) {
            n = recvfrom(sockfd, buffer, buffer_len, 0, (struct sockaddr*)t_saddr, &saddr_len);
        } else {
            n = recvfrom(sockfd, buffer, buffer_len, 0, (struct sockaddr*)h_saddr, &saddr_len);
        }
        
        // If we receive data then check the packet to see if its an RST
        if (n > 0) {
            // Extract the IP and TCP headers
            struct iphdr *iph = (struct iphdr *)buffer;
            struct tcphdr *tcph = (struct tcphdr *)(buffer + iph->ihl * 4);

            // Check for TCP RST flag
            if (tcph->rst) {
                if (!found_rst) {
                    // If this is the first RST packet then start the timer
                    clock_gettime(CLOCK_MONOTONIC, &start_time);
                    found_rst = true;
                } else {                  
                    // If this is the second RST then set the end time and then end the loop
                    clock_gettime(CLOCK_MONOTONIC, &end_time);
                    break;
                }
           }

        } else {
            // If the error returned is a blocking error then ignore and keep going
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                continue;
            
            // Otherwise recvfrom() failed
            perror("recvfrom()");
        }

        // reset the buffer
        memset(buffer, 0, sizeof(buffer));

        // Account for if the number of seconds elapsed is more than or equal to the timeout
        if (elapsed >= m_time) {

            // Return -1 to indicate that we did not find both RSTs in enough time
            return -1;
        }
     }
        
    // Calculate the total stream time
    double total_elapsed = ((end_time.tv_sec - start_time.tv_sec) + 
                            (end_time.tv_nsec - start_time.tv_nsec)) / 1000000000.0;

    // Return the stream time
    return total_elapsed;
}
