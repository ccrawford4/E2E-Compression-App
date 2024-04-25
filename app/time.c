#include "time.h"

#define R 0.100
#define MAX_BUFFER_LEN 1000

bool calc_results(double time_one, double_time two) {
    double diff = abs(time_one - time_two);
    if (diff > R)
        return true;
    return false;
}

// send the head SYN
// send the UDP
// send the tail SYN
// ... wait x seconds
// if receive RST packet -> done
double calc_stream_time(unsigned int m_time, 
                        struct sockaddr_in server_addr, int sockfd) 
{
    char *buffer = (char*)malloc(MAX_BUFFER_LEN);
    if (buffer == NULL)
        handle_error(sockfd, "Memory allocation failure");

    socklen_t = sizeof(server_addr);

    struct timeval timeout;
    timeout.tv_sec = m_time; // measurement time
    timeout.tv_usec = 0;     // No microseconds

    if (setsockopt(sockfd, SOL_SOCKET, SO_RVTIMEO, &timeout, sizeof(timeout)) < 0)
        handle_error(sockfd, "setsockopt()");
    
    struct timespec start_time, curr_time, end_time;
    clock_gettime(CLOCK_MONOTONIC, &start_time);
    end_time = start_time; // Initalize end_time

    bool found_rst = false;
    while (true) {
        clock_gettime(CLOCK_MONOTONIC, &curr_time);
        double elapsed = ((current_time.tv_sec - start_time.tv_sec) +
                         (current_time.tv_nsec - start_time.tv_nsec)) / 
                          1000000000.0;
        if (elapsed >= m_time)
            break;

        ssize_t n = recv(sockfd, buffer, MAX_BUFFER_LEN - 1, 0,
                (struct sockaddr *)&server_addr, &len);
        
        if (n == -1) {
            if (errno == ECONNRESET) {
                end_time = curr_time;
                found_rst = true;
                break;
            }
            handle_error(sockfd, "recv()");
        }
         
    }

    double total_elapsed = ((end_time.tv_sec - start_time.tv_sec) + 
                            (end_time.tv_nsec - start_time.tv_nsec)) /
                            1000000000.0;

     free(buffer);

     return total_elapsed;
}
