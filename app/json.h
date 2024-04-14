#define NUM_ITEMS 11

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

void handle_key_error(int ret_val, char* key, char* file_name);
const char* get_default(char* key);
const char* get_value(char* file_path, char* key);
