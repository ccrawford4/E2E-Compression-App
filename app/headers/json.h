#include <jansson.h>
#define NUM_ITEMS 11

void handle_key_error(char* key, char* file_name);
const char* get_default(char* key);
const char* get_value(char* file_path, char* key);
