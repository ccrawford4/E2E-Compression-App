#include "headers/main.h"
#include "headers/socket.h"

#define MAX_KEY_LEN 100

void handle_error(int sockfd, char* error_msg) {
    perror(error_msg);
    close(sockfd);
    exit(EXIT_FAILURE);
}

void write_contents_to_file(char* file_name, char* buffer, int len) {
    FILE* fp = fopen(file_name, "w");
    if (fp == NULL) {
        perror("Failed to open file");
        exit(EXIT_FAILURE);
    }
    
    size_t bytes_written = fwrite(buffer, 1, len, fp);
    if (bytes_written < len) {
        perror("Failed to write full buffer to file");
        exit(EXIT_FAILURE);
    }
    fclose(fp);
}

// Given a time (in seconds) it pauses the program
void wait(unsigned int seconds) {
    usleep(seconds * 1000000);
}

char* read_file(char* file_path) {
    FILE* file = fopen(file_path, "rb");
    if (file == NULL) {
        perror("Unable to open file");
        exit(EXIT_FAILURE);
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    char* buffer = (char*)malloc(file_size + 1);
    if (buffer == NULL) {
        perror("Memory allocation failed");
        fclose(file);
        exit(EXIT_FAILURE);
    }

    fread(buffer, 1, file_size, file);
    buffer[file_size] = '\0';

    fclose(file);

    return buffer;
}
