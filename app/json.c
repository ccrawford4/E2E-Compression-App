#include "main.h"

#define NUM_ITEMS 11
#define ERROR "ERROR"

typedef struct {
    char* key;
    const char* value;
} item;

item default_items[NUM_ITEMS] = {
    {"UDP_src_port_number", "9876"},
    {"UDP_dest_port_number", "8765"},
    {"TCP_HEADSYN_dest_port_number", "9999"},
    {"TCP_TAILSYN_dest_port_number", "8888"},
    {"TCP_PREPROB_port_number", "7777"},
    {"TCP_POSTPROB_port_number", "6666"},
    {"UDP_payload_size", "1000B"},
    {"measurement_time", "15"},
    {"UDP_packet_train_size", "6000"},
    {"UDP_packet_TTL", "225"},
    {"server_wait_time", "5"}
};

void handle_key_error(int ret_val, char* key, char* file_name) {
    if (key == 0) {
        printf("ERROR! Invalid Value For Said Key: %s\n", key);
        printf("See file %s\n", file_name);
        exit(EXIT_FAILURE);
    }
}


// Return the default value if the value doesn't in the JSON
const char* get_default(char* key) {
    for (int i = 0; i < NUM_ITEMS; i++) {
        if (!strcmp(default_items->key, key)) {
            return default_items->value;
        }
    }
    return ERROR;
}

// Gets the JSON's corresponding value given a key
const char* get_value(char* file_path, char* key) {
    json_t *root;
    json_error_t error;

    const char* text = read_file(file_path);
    root = json_loads(text, 0, &error);

    if (!root) {
        fprintf(stderr, "error on line %d: %s\n", error.line, error.text);
        exit(EXIT_FAILURE);
    }

    if (!json_is_object(root)) {
         fprintf(stderr, "error on line %d: %s\n", error.line, error.text);
         exit(EXIT_FAILURE);
    }

    json_t *data = json_object_get(root, key);
    const char* value;
    
    if (!json_is_string(data)) { // If key, value pair is empty then try to get the default first
        value = get_default(key);
        if (!strcmp(value, ERROR)) {
            fprintf(stderr, "error parsing key %s\n", key);
            exit(EXIT_FAILURE);
        }
        return value;
    }

    value = json_string_value(data);

    return value;
}

