#include <time.h>
#include <stdbool.h>
#include "socket.h"

#define MAX_KEY_LEN 100

void print_time(struct timespec current_time);
void handle_error(int sockfd, char* error_msg);
void write_contents_to_file(char* file_name, char* buffer, int len);
void wait(unsigned int seconds);
char* read_file(char* file_path);
double calc_stream_time(int sockfd, struct sockaddr_in *h_saddr, 
                        struct sockaddr_in *t_saddr, unsigned int m_time);
bool found_compression(double time1, double time2);
