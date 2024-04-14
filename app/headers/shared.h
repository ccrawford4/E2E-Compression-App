#define MAX_KEY_LEN 100

void print_time(struct timespec current_time);
void handle_error(int sockfd, char* error_msg);
void write_contents_to_file(char* file_name, char* buffer, int len);
void wait(unsigned int seconds);
char* read_file(char* file_path);
