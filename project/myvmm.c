#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdarg.h>
#include <regex.h>
#include <stdint.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <signal.h>
#include <time.h>
#include <sys/time.h>
#include <fcntl.h>

#define MAX_LINE_LEN 4096
#define MAX_ARG_LEN 4096
#define HASH_STR_LEN 9
#define MAX_PAYLOAD_SIZE (50 * 1024 * 1024)
#define COLOR_YELLOW "\033[0;33m"
#define COLOR_RESET "\033[0m"

static const char received_file_prefix[] = "/tmp/myvmm_received_";
static const size_t received_file_prefix_length = sizeof(received_file_prefix) - 1;

static bool debug_enabled = false;
static volatile sig_atomic_t keep_running = 1;

static void handle_signal(int sig)
{
    (void)sig;
    keep_running = 0;
}

/* Flawfinder: ignore - gcc format attribute */
__attribute__((unused, format(printf, 1, 2)))
static void debug(const char* format, ...)
{
    if (!debug_enabled)
        return;

    va_list args;
    va_start(args, format);
    fprintf(stderr, "%sDebug: ", COLOR_YELLOW);
    /* Flawfinder: ignore - format string supplied internally */
    vfprintf(stderr, format, args);
    fprintf(stderr, "%s", COLOR_RESET);
    va_end(args);
}

typedef struct Pattern
{
    regex_t pattern;
    int8_t groups;
    bool is_initialized;
} Pattern;

typedef struct Patterns
{
    Pattern vm_binary;
    Pattern vm_exec_slice_in_instructions;
    Pattern dump_processor_state;
    Pattern dump_register_state;
    Pattern li;
    Pattern add;
    Pattern sub;
    Pattern addi;
    Pattern addu;
    Pattern subu;
    Pattern addiu;
    Pattern mul;
    Pattern mult;
    Pattern div;
    Pattern and;
    Pattern or;
    Pattern andi;
    Pattern ori;
    Pattern sll;
    Pattern srl;
    Pattern xor;
    Pattern snapshot;
    Pattern validate_instructions;
    Pattern skip_instructions;
    Pattern migrate;
} Patterns;

typedef struct Match
{
    bool is_match;
    bool has_error;
    const char* original;
    char** capture_groups;
} Match;

static void teardown_match(Match* match)
{
    if (match == NULL)
        return;

    if (match->capture_groups != NULL)
    {
        for (size_t i = 0; match->capture_groups[i] != NULL; i++)
        {
            free(match->capture_groups[i]);
            match->capture_groups[i] = NULL;
        }
        free(match->capture_groups);
        match->capture_groups = NULL;
    }

    memset(match, 0, sizeof(Match));
    free(match);
}

static bool match_pattern(const char* string, const Pattern* pattern, Match* match)
{
    if (string == NULL || pattern == NULL || match == NULL || match->has_error)
        return false;

    regmatch_t matched_groups[pattern->groups + 1];

    if (regexec(&pattern->pattern, string, pattern->groups + 1, matched_groups, 0) != 0)
        return false;

    match->is_match = true;
    match->original = string;

    if (pattern->groups > 0)
    {
        match->capture_groups = calloc(pattern->groups + 1, sizeof(char*));

        if (match->capture_groups == NULL)
        {
            fprintf(stderr, "Error: Match->capture_groups memory allocation failed.\n");
            match->has_error = true;
            return false;
        }

        for (size_t i = 0; i < pattern->groups; i++)
        {
            size_t group_idx = i + 1;

            if (matched_groups[group_idx].rm_so == -1 || matched_groups[group_idx].rm_eo == -1)
            {
                match->capture_groups[i] = NULL;
                break;
            }

            const size_t match_len = matched_groups[group_idx].rm_eo - matched_groups[group_idx].rm_so;
            match->capture_groups[i] = strndup(string + matched_groups[group_idx].rm_so, match_len);
        }
    }

    return true;
}

static bool initialize_match(Match** match)
{
    if (match == NULL)
        return false;

    if (*match == NULL)
    {
        *match = calloc(1, sizeof(Match));
        if (*match == NULL)
        {
            fprintf(stderr, "Error: Match memory allocation failed.\n");
            return false;
        }
        (*match)->has_error = false;
        return true;
    }

    if ((*match)->has_error)
        return false;

    (*match)->is_match = false;
    (*match)->original = NULL;

    if ((*match)->capture_groups != NULL)
    {
        for (size_t i = 0; (*match)->capture_groups[i] != NULL; i++)
        {
            free((*match)->capture_groups[i]);
            (*match)->capture_groups[i] = NULL;
        }
        free((*match)->capture_groups);
        (*match)->capture_groups = NULL;
    }

    return true;
}

typedef struct NodeConfig
{
    char* assembly_file_name;
    char* vm_binary;
    char* snapshot_file;
    int exec_slice;
} NodeConfig;

typedef struct NodeSocket
{
    FILE* file;
    bool has_pending_instructions;
} NodeSocket;

typedef struct NodeProcessor
{
    /*
     * registers[32] == $hi
     * registers[33] == $low
     */
    int32_t registers[34];
    int32_t executed_instructions;
} NodeProcessor;

typedef struct Node
{
    NodeConfig config;
    NodeSocket socket;
    NodeProcessor processor;
    struct Node* next;
} Node;

typedef struct Hypervisor
{
    Node* head_node;
    Node* current_node;
    Node* pending_head;
    Patterns patterns;
    unsigned int node_count;
    int instruction_slice;
    int server_port;
    int server_socket_file_descriptor;
    int server_timeout_seconds;
} Hypervisor;

static bool get_register_key(const char* raw_key, int8_t* key)
{
    if (raw_key == NULL)
        return false;

    if (strcmp(raw_key, "hi") == 0)
    {
        *key = 32;
        return true;
    }

    if (strcmp(raw_key, "low") == 0)
    {
        *key = 33;
        return true;
    }

    char* endptr = NULL;
    const long converted_key = strtol(raw_key, &endptr, 10);

    if (endptr == raw_key || *endptr != '\0' || converted_key < 0 || converted_key > 31)
    {
        fprintf(stderr, "Exception: Invalid register \"$%s\"\n", raw_key);

        return false;
    }

    *key = (int8_t)converted_key;

    return true;
}

static bool get_register(const NodeProcessor* processor, const char* raw_key, int32_t* value)
{
    int8_t key;

    if (!get_register_key(raw_key, &key))
        return false;

    *value = processor->registers[key];
    return true;
}

static void set_register(NodeProcessor* processor, const char* raw_key, int32_t value)
{
    int8_t key;

    if (!get_register_key(raw_key, &key))
    {
        return;
    }

    if (key == 0)
    {
        return;
    }

    processor->registers[key] = value;
    debug("NodeProcessor->registers[%d] = %d\n", key, processor->registers[key]);
}

static void dump_processor_state(const NodeProcessor* processor)
{
    for (int i = 0; i < 32; i++)
    {
        fprintf(stdout, "R%d=%d\n", i, processor->registers[i]);
    }

    fprintf(stdout, "Rhi=%d\n", processor->registers[32]);
    fprintf(stdout, "Rlow=%d\n", processor->registers[33]);
}

static void dump_register_state(const NodeProcessor* processor, const Match* match)
{
    int32_t value;

    if (get_register(processor, match->capture_groups[0], &value))
    {
        fprintf(stdout, "R%s=%d\n", match->capture_groups[0], value);
    }
}

static void load_immediate(Node* node, const Match* match)
{
    set_register(&node->processor, match->capture_groups[0], (int32_t)strtol(match->capture_groups[1], NULL, 10));
}

static void add(NodeProcessor* processor, const Match* match)
{
    int32_t value_1;
    int32_t value_2;

    if (!get_register(processor, match->capture_groups[1], &value_1) || !get_register(
        processor, match->capture_groups[2], &value_2))
    {
        return;
    }

    const int64_t sum = (int64_t)value_1 + (int64_t)value_2;

    if (sum < INT32_MIN || sum > INT32_MAX)
    {
        fprintf(stderr, "Exception: Integer overflow in \"%s\"\n", match->original);
        return;
    }

    set_register(processor, match->capture_groups[0], (int32_t)sum);
}

static void subtract(NodeProcessor* processor, const Match* match)
{
    int32_t value_1;
    int32_t value_2;

    if (!get_register(processor, match->capture_groups[1], &value_1) || !get_register(
        processor, match->capture_groups[2], &value_2))
    {
        return;
    }

    const int64_t difference = (int64_t)value_1 - (int64_t)value_2;

    if (difference < INT32_MIN || difference > INT32_MAX)
    {
        fprintf(stderr, "Exception: Integer overflow in \"%s\"\n", match->original);
        return;
    }

    set_register(processor, match->capture_groups[0], (int32_t)difference);
}

static void add_immediate(NodeProcessor* processor, const Match* match)
{
    int32_t value_1;

    if (!get_register(processor, match->capture_groups[1], &value_1))
    {
        return;
    }

    const int64_t sum = (int64_t)value_1 + (int64_t)strtol(match->capture_groups[2], NULL, 10);

    if (sum < INT32_MIN || sum > INT32_MAX)
    {
        fprintf(stderr, "Exception: Integer overflow in \"%s\"\n", match->original);
        return;
    }

    set_register(processor, match->capture_groups[0], (int32_t)sum);
}

static void add_unsigned(NodeProcessor* processor, const Match* match)
{
    int32_t value_1;
    int32_t value_2;

    if (!get_register(processor, match->capture_groups[1], &value_1) || !get_register(
        processor, match->capture_groups[2], &value_2))
    {
        return;
    }

    set_register(processor, match->capture_groups[0], (int32_t)((uint32_t)value_1 + (uint32_t)value_2));
}

static void subtract_unsigned(NodeProcessor* processor, const Match* match)
{
    int32_t value_1;
    int32_t value_2;

    if (!get_register(processor, match->capture_groups[1], &value_1) || !get_register(
        processor, match->capture_groups[2], &value_2))
    {
        return;
    }

    set_register(processor, match->capture_groups[0], (int32_t)((uint32_t)value_1 - (uint32_t)value_2));
}

static void add_immediate_unsigned(NodeProcessor* processor, const Match* match)
{
    int32_t value_1;

    if (!get_register(processor, match->capture_groups[1], &value_1))
    {
        return;
    }

    const int32_t value_2 = (int32_t)strtol(match->capture_groups[2], NULL, 10);
    set_register(processor, match->capture_groups[0], (int32_t)((uint32_t)value_1 + (uint32_t)value_2));
}

static void multiply_without_overflow(NodeProcessor* processor, const Match* match)
{
    int32_t value_1;
    int32_t value_2;

    if (!get_register(processor, match->capture_groups[1], &value_1) || !get_register(
        processor, match->capture_groups[2], &value_2))
    {
        return;
    }

    set_register(processor, match->capture_groups[0], (int32_t)((uint32_t)value_1 * (uint32_t)value_2));
}

static void multiply(NodeProcessor* processor, const Match* match)
{
    int32_t value_1;
    int32_t value_2;

    if (!get_register(processor, match->capture_groups[0], &value_1) || !get_register(
        processor, match->capture_groups[1], &value_2))
    {
        return;
    }

    const int64_t product = (int64_t)value_1 * (int64_t)value_2;
    const uint64_t unsigned_product = (uint64_t)product;

    set_register(processor, "hi", (int32_t)(unsigned_product >> 32));
    set_register(processor, "low", (int32_t)(unsigned_product & 0xFFFFFFFF));
}

static void divide(NodeProcessor* processor, const Match* match)
{
    int32_t value_1;
    int32_t value_2;

    if (!get_register(processor, match->capture_groups[0], &value_1) || !get_register(
        processor, match->capture_groups[1], &value_2))
    {
        return;
    }

    if (value_2 == 0)
    {
        fprintf(stderr, "Exception: Division by zero in \"%s\"\n", match->original);
        return;
    }

    if (value_1 == INT32_MIN && value_2 == -1)
    {
        set_register(processor, "hi", 0);
        set_register(processor, "low", INT32_MIN);
        return;
    }

    set_register(processor, "hi", value_1 % value_2);
    set_register(processor, "low", value_1 / value_2);
}

static void and(NodeProcessor* processor, const Match* match)
{
    int32_t value_1;
    int32_t value_2;

    if (!get_register(processor, match->capture_groups[1], &value_1) || !get_register(
        processor, match->capture_groups[2], &value_2))
    {
        return;
    }

    set_register(processor, match->capture_groups[0], value_1 & value_2);
}

static void or(NodeProcessor* processor, const Match* match)
{
    int32_t value_1;
    int32_t value_2;

    if (!get_register(processor, match->capture_groups[1], &value_1) || !get_register(
        processor, match->capture_groups[2], &value_2))
    {
        return;
    }

    set_register(processor, match->capture_groups[0], value_1 | value_2);
}

static void xor(NodeProcessor* processor, const Match* match)
{
    int32_t value_1;
    int32_t value_2;

    if (!get_register(processor, match->capture_groups[1], &value_1) || !get_register(
        processor, match->capture_groups[2], &value_2))
    {
        return;
    }

    set_register(processor, match->capture_groups[0], value_1 ^ value_2);
}

static void and_immediate(NodeProcessor* processor, const Match* match)
{
    int32_t value_1;

    if (!get_register(processor, match->capture_groups[1], &value_1))
    {
        return;
    }

    const int32_t value_2 = (int32_t)strtol(match->capture_groups[2], NULL, 10);
    set_register(processor, match->capture_groups[0], value_1 & value_2);
}

static void or_immediate(NodeProcessor* processor, const Match* match)
{
    int32_t value_1;

    if (!get_register(processor, match->capture_groups[1], &value_1))
    {
        return;
    }

    const int32_t value_2 = (int32_t)strtol(match->capture_groups[2], NULL, 10);
    set_register(processor, match->capture_groups[0], value_1 | value_2);
}

static void shift_left_logical(NodeProcessor* processor, const Match* match)
{
    int32_t value_1;

    if (!get_register(processor, match->capture_groups[1], &value_1))
    {
        return;
    }

    const int32_t value_2 = (int32_t)strtol(match->capture_groups[2], NULL, 10);
    set_register(processor, match->capture_groups[0], (int32_t)((uint32_t)value_1 << (value_2 & 0x1F)));
}

static void shift_right_logical(NodeProcessor* processor, const Match* match)
{
    int32_t value_1;

    if (!get_register(processor, match->capture_groups[1], &value_1))
    {
        return;
    }

    const int32_t value_2 = (int32_t)strtol(match->capture_groups[2], NULL, 10);
    set_register(processor, match->capture_groups[0], (int32_t)((uint32_t)value_1 >> (value_2 & 0x1F)));
}

// Checks whether a line is empty after stripping line breaks to allow skipping blank lines.
static bool is_blank_line(const char* line)
{
    return line == NULL || line[0] == '\0';
}

// See https://gist.github.com/sgsfak/9ba382a0049f6ee885f68621ae86079b#file-hashes-c-L37-L58.
static bool hash_file(const char* file_path, char* output_hash)
{
    if (file_path == NULL || output_hash == NULL)
        return false;

    /* Flawfinder: ignore - file name validated/supplied internally */
    FILE* file = fopen(file_path, "rb");

    if (file == NULL)
        return false;

    uint32_t hash = 0x811c9dc5;
    uint8_t buffer[4096];
    size_t bytes_read;

    while ((bytes_read = fread(buffer, 1, sizeof(buffer), file)) > 0)
    {
        for (size_t i = 0; i < bytes_read; i++)
        {
            const uint32_t fnv_32_prime = 0x01000193;
            hash ^= (uint32_t)buffer[i];
            hash *= fnv_32_prime;
        }
    }

    fclose(file);
    snprintf(output_hash, HASH_STR_LEN, "%08x", hash);
    return true;
}

static void take_snapshot(const Node* node, const char* snapshot_path)
{
    if (node == NULL || snapshot_path == NULL)
        return;

    debug("Taking snapshot \"%s\"\n", snapshot_path);

    /* Flawfinder: ignore - snapshot path supplied by instruction */
    FILE* file = fopen(snapshot_path, "w");

    if (file == NULL)
    {
        fprintf(stderr, "Exception: Failed to create snapshot \"%s\"\n", snapshot_path);
        return;
    }

    /* Flawfinder: ignore - fixed size FNV-1 32-bit hex hash string */
    char hash[HASH_STR_LEN] = {0};

    if (!hash_file(node->config.vm_binary, hash))
    {
        fclose(file);
        fprintf(stderr, "Exception: Failed to create snapshot \"%s\"\n", snapshot_path);
        return;
    }

    fprintf(file, "VALIDATE_INSTRUCTIONS=%s\n", hash);
    fprintf(file, "SKIP_INSTRUCTIONS=%d\n", node->processor.executed_instructions + 1);

    for (int i = 0; i < 32; i++)
    {
        if (node->processor.registers[i] != 0)
            fprintf(file, "li $%d,%d\n", i, node->processor.registers[i]);
    }

    if (node->processor.registers[32] != 0)
        fprintf(file, "li $hi,%d\n", node->processor.registers[32]);

    if (node->processor.registers[33] != 0)
        fprintf(file, "li $low,%d\n", node->processor.registers[33]);

    fclose(file);
}

static bool send_all(int file_descriptor, const void* buffer, size_t length)
{
    const uint8_t* ptr = buffer;
    size_t remaining = length;

    while (remaining > 0)
    {
        ssize_t sent = write(file_descriptor, ptr, remaining);

        if (sent <= 0)
            return false;

        ptr += sent;
        remaining -= (size_t)sent;
    }

    return true;
}

static bool read_all(int file_descriptor, void* buffer, size_t length)
{
    uint8_t* ptr = (uint8_t*)buffer;
    size_t remaining = length;

    while (remaining > 0)
    {
        /* Flawfinder: ignore - buffer boundary strictly constrained by remaining bytes */
        ssize_t received = read(file_descriptor, ptr, remaining);

        if (received <= 0)
            return false;

        ptr += received;
        remaining -= (size_t)received;
    }

    return true;
}

static bool send_file_payload(int socket_file_descriptor, const char* file_path)
{
    if (socket_file_descriptor < 0 || file_path == NULL)
        return false;

    /* Flawfinder: ignore - internal configuration or snapshot path */
    FILE* file = fopen(file_path, "rb");

    if (file == NULL)
    {
        fprintf(stderr, "Error: Failed to open file \"%s\" for migration transfer.\n", file_path);
        return false;
    }

    if (fseek(file, 0, SEEK_END) != 0)
    {
        fclose(file);
        return false;
    }

    long file_size = ftell(file);

    if (file_size < 0)
    {
        fclose(file);
        return false;
    }

    rewind(file);

    uint32_t net_len = htonl((uint32_t)file_size);

    if (!send_all(socket_file_descriptor, &net_len, sizeof(net_len)))
    {
        fclose(file);
        return false;
    }

    uint8_t buffer[4096];
    size_t remaining = (size_t)file_size;

    while (remaining > 0)
    {
        size_t to_read = remaining < sizeof(buffer) ? remaining : sizeof(buffer);
        size_t bytes_read = fread(buffer, 1, to_read, file);

        if (bytes_read != to_read)
        {
            fclose(file);
            return false;
        }

        if (!send_all(socket_file_descriptor, buffer, to_read))
        {
            fclose(file);
            return false;
        }

        remaining -= to_read;
    }

    fclose(file);
    return true;
}

static bool receive_file_payload(int socket_file_descriptor, const char* output_path)
{
    if (socket_file_descriptor < 0 || output_path == NULL)
        return false;

    uint32_t net_len = 0;

    if (!read_all(socket_file_descriptor, &net_len, sizeof(net_len)))
        return false;

    uint32_t len = ntohl(net_len);

    if (len > MAX_PAYLOAD_SIZE)
    {
        fprintf(stderr, "Error: Payload size %u exceeds maximum allowed limit (%u bytes).\n", len, MAX_PAYLOAD_SIZE);
        return false;
    }

    unlink(output_path);
    /* Flawfinder: ignore - temporary file destination with exclusive creation */
    int fd = open(output_path, O_CREAT | O_EXCL | O_WRONLY, 0600);

    if (fd < 0)
    {
        fprintf(stderr, "Error: Failed to open output file \"%s\" for received migration.\n", output_path);
        return false;
    }

    FILE* file = fdopen(fd, "wb");

    if (file == NULL)
    {
        close(fd);
        unlink(output_path);
        return false;
    }

    uint8_t buffer[4096];
    size_t remaining = len;

    while (remaining > 0)
    {
        size_t to_read = remaining < sizeof(buffer) ? remaining : sizeof(buffer);

        if (!read_all(socket_file_descriptor, buffer, to_read))
        {
            fclose(file);
            return false;
        }

        if (fwrite(buffer, 1, to_read, file) != to_read)
        {
            fclose(file);
            return false;
        }

        remaining -= to_read;
    }

    fclose(file);
    return true;
}

static void migrate_node(const Hypervisor* hypervisor, const Match* match)
{
    if (hypervisor == NULL || hypervisor->current_node == NULL || match == NULL)
        return;

    static unsigned int tx_counter = 0;
    const char* host = match->capture_groups[0];
    const char* port_str = match->capture_groups[1];
    char* endptr = NULL;
    const long port = strtol(port_str, &endptr, 10);

    if (endptr == port_str || *endptr != '\0' || port < 1024 || port > 65535)
    {
        fprintf(stderr,
                "Error: Invalid migration port \"%s\". Only unprivileged ports (1024-65535) are supported.\n",
                port_str);
        return;
    }

    /* Flawfinder: ignore - fixed buffer size for snapshot path */
    char snap_path[MAX_LINE_LEN];

    snprintf(snap_path, sizeof(snap_path), "/tmp/myvmm_snap_%ld_%u", port, tx_counter++);
    take_snapshot(hypervisor->current_node, snap_path);

    struct addrinfo hints;
    struct addrinfo* res = NULL;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, port_str, &hints, &res) != 0 || res == NULL)
    {
        fprintf(stderr,
                "Error: Failed to resolve migration target \"%s:%s\". Aborting migration and resuming local execution.\n",
                host, port_str);
        unlink(snap_path);
        return;
    }

    int client_file_descriptor = -1;
    struct timespec retry_delay = {0, 25000000L};

    // Retry with backoff (25ms, 50ms, 100ms, 200ms, and 400ms).
    for (int attempt = 0; attempt < 6; attempt++)
    {
        for (struct addrinfo* rp = res; rp != NULL; rp = rp->ai_next)
        {
            client_file_descriptor = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);

            if (client_file_descriptor < 0)
                continue;

            struct timeval connect_timeout;

            connect_timeout.tv_sec = 1;
            connect_timeout.tv_usec = 0;
            setsockopt(client_file_descriptor, SOL_SOCKET, SO_SNDTIMEO, &connect_timeout, sizeof(connect_timeout));

            if (connect(client_file_descriptor, rp->ai_addr, rp->ai_addrlen) == 0)
                break;

            close(client_file_descriptor);
            client_file_descriptor = -1;
        }

        if (client_file_descriptor >= 0)
            break;

        if (attempt < 5)
        {
            debug("Connection attempt %d to %s:%s timed out or failed, retrying in %ld ms...\n",
                  attempt + 1,
                  host,
                  port_str,
                  retry_delay.tv_nsec / 1000000L);

            nanosleep(&retry_delay, NULL);
            retry_delay.tv_nsec *= 2;
        }
    }

    freeaddrinfo(res);

    if (client_file_descriptor < 0)
    {
        fprintf(stderr,
                "Error: Failed to connect to migration target \"%s:%s\". Aborting migration and resuming local execution.\n",
                host, port_str);
        unlink(snap_path);
        return;
    }

    debug("Migrating node \"%s\" to %s:%s\n", hypervisor->current_node->config.vm_binary, host, port_str);

    if (!send_file_payload(client_file_descriptor, hypervisor->current_node->config.assembly_file_name) ||
        !send_file_payload(client_file_descriptor, hypervisor->current_node->config.vm_binary) ||
        !send_file_payload(client_file_descriptor, snap_path))
    {
        fprintf(stderr, "Error: Failed to transmit migration payload to %s:%s.\n", host, port_str);
    }

    close(client_file_descriptor);
    unlink(snap_path);
    hypervisor->current_node->socket.has_pending_instructions = false;
}

static void skip_instructions(Node* node, const Match* match)
{
    const long skip_count = strtol(match->capture_groups[0], NULL, 10);
    char* skip_line = NULL;
    size_t skip_len = 0;
    long skipped = 0;

    debug("Skipping %ld instructions\n", skip_count);

    while (skipped < skip_count)
    {
        if (getline(&skip_line, &skip_len, node->socket.file) == -1)
            break;

        skip_line[strcspn(skip_line, "\r\n")] = '\0';

        if (is_blank_line(skip_line))
            continue;

        skipped++;
    }

    if (skip_line != NULL)
        free(skip_line);

    node->processor.executed_instructions = (int32_t)skip_count;
}

static bool run_node(const Hypervisor* hypervisor)
{
    ssize_t chars_read = 0;
    char* line = NULL;
    size_t len = 0;
    Match* match = NULL;
    bool has_error = false;
    int slice = -1;
    int instructions_run = 0;

    if (hypervisor->instruction_slice > 0)
        slice = hypervisor->instruction_slice;
    else if (hypervisor->current_node->config.exec_slice > 0)
        slice = hypervisor->current_node->config.exec_slice;

    while (
        keep_running &&
        hypervisor->current_node->socket.has_pending_instructions &&
        (slice <= 0 || instructions_run < slice) &&
        (chars_read = getline(&line, &len, hypervisor->current_node->socket.file)) != -1)
    {
        line[strcspn(line, "\r\n")] = '\0'; // Remove line breaks.

        if (is_blank_line(line))
            continue;

        debug("Running instruction \"%s\"\n", line);

        if (!initialize_match(&match))
        {
            has_error = true;
            break;
        }

        if (match_pattern(line, &hypervisor->patterns.dump_processor_state, match))
            dump_processor_state(&hypervisor->current_node->processor);
        else if (match_pattern(line, &hypervisor->patterns.dump_register_state, match))
            dump_register_state(&hypervisor->current_node->processor, match);
        else if (match_pattern(line, &hypervisor->patterns.li, match))
            load_immediate(hypervisor->current_node, match);
        else if (match_pattern(line, &hypervisor->patterns.add, match))
            add(&hypervisor->current_node->processor, match);
        else if (match_pattern(line, &hypervisor->patterns.sub, match))
            subtract(&hypervisor->current_node->processor, match);
        else if (match_pattern(line, &hypervisor->patterns.addi, match))
            add_immediate(&hypervisor->current_node->processor, match);
        else if (match_pattern(line, &hypervisor->patterns.addu, match))
            add_unsigned(&hypervisor->current_node->processor, match);
        else if (match_pattern(line, &hypervisor->patterns.subu, match))
            subtract_unsigned(&hypervisor->current_node->processor, match);
        else if (match_pattern(line, &hypervisor->patterns.addiu, match))
            add_immediate_unsigned(&hypervisor->current_node->processor, match);
        else if (match_pattern(line, &hypervisor->patterns.mul, match))
            multiply_without_overflow(&hypervisor->current_node->processor, match);
        else if (match_pattern(line, &hypervisor->patterns.mult, match))
            multiply(&hypervisor->current_node->processor, match);
        else if (match_pattern(line, &hypervisor->patterns.div, match))
            divide(&hypervisor->current_node->processor, match);
        else if (match_pattern(line, &hypervisor->patterns.and, match))
            and(&hypervisor->current_node->processor, match);
        else if (match_pattern(line, &hypervisor->patterns.or, match))
            or(&hypervisor->current_node->processor, match);
        else if (match_pattern(line, &hypervisor->patterns.andi, match))
            and_immediate(&hypervisor->current_node->processor, match);
        else if (match_pattern(line, &hypervisor->patterns.ori, match))
            or_immediate(&hypervisor->current_node->processor, match);
        else if (match_pattern(line, &hypervisor->patterns.sll, match))
            shift_left_logical(&hypervisor->current_node->processor, match);
        else if (match_pattern(line, &hypervisor->patterns.srl, match))
            shift_right_logical(&hypervisor->current_node->processor, match);
        else if (match_pattern(line, &hypervisor->patterns.xor, match))
            xor(&hypervisor->current_node->processor, match);
        else if (match_pattern(line, &hypervisor->patterns.snapshot, match))
            take_snapshot(hypervisor->current_node, match->capture_groups[0]);
        else if (match_pattern(line, &hypervisor->patterns.migrate, match))
            migrate_node(hypervisor, match);
        else
            fprintf(stderr, "Exception: Unknown instruction \"%s\"\n", line);

        hypervisor->current_node->processor.executed_instructions += 1;
        instructions_run += 1;
    }

    if (chars_read == -1)
        hypervisor->current_node->socket.has_pending_instructions = false;

    teardown_match(match);

    if (line != NULL)
        free(line);

    return !has_error;
}

static void reset_node_processor(NodeProcessor* processor)
{
    if (processor == NULL)
        return;

    for (int i = 0; i < 34; i++)
    {
        processor->registers[i] = 0;
    }

    processor->executed_instructions = 0;
}

static void teardown_node_socket(NodeSocket* socket)
{
    if (socket == NULL)
        return;

    if (socket->file != NULL)
    {
        fclose(socket->file);
        socket->file = NULL;
    }

    socket->has_pending_instructions = false;
}

static bool setup_node_socket(char* vm_binary, NodeSocket* socket)
{
    memset(socket, 0, sizeof(NodeSocket));

    if (vm_binary == NULL)
    {
        fprintf(stderr, "Error: vm_binary was not configured.\n");
        return false;
    }

    /* Flawfinder: ignore - file name supplied by user. */
    socket->file = fopen(vm_binary, "r");

    if (socket->file == NULL)
    {
        fprintf(stderr, "Error: vm_binary \"%s\" cannot be opened.\n", vm_binary);
        return false;
    }

    socket->has_pending_instructions = true;

    return true;
}

static void teardown_node_config(NodeConfig* config)
{
    if (config == NULL)
        return;

    if (config->assembly_file_name != NULL)
    {
        if (strncmp(config->assembly_file_name, received_file_prefix, received_file_prefix_length) == 0)
            unlink(config->assembly_file_name);

        memset(config->assembly_file_name, 0, strnlen(config->assembly_file_name, MAX_ARG_LEN));
        free(config->assembly_file_name);
        config->assembly_file_name = NULL;
    }

    if (config->vm_binary != NULL)
    {
        if (strncmp(config->vm_binary, received_file_prefix, received_file_prefix_length) == 0)
            unlink(config->vm_binary);

        memset(config->vm_binary, 0, strnlen(config->vm_binary, MAX_LINE_LEN));
        free(config->vm_binary);
        config->vm_binary = NULL;
    }

    if (config->snapshot_file != NULL)
    {
        if (strncmp(config->snapshot_file, received_file_prefix, received_file_prefix_length) == 0)
            unlink(config->snapshot_file);

        memset(config->snapshot_file, 0, strnlen(config->snapshot_file, MAX_LINE_LEN));
        free(config->snapshot_file);
        config->snapshot_file = NULL;
    }

    memset(config, 0, sizeof(NodeConfig));
}

static bool setup_node_config(char* assembly_file_name, NodeConfig* config, const Patterns* patterns)
{
    memset(config, 0, sizeof(NodeConfig));
    config->exec_slice = -1;
    config->assembly_file_name = strndup(assembly_file_name, MAX_LINE_LEN);
    debug("NodeConfig->assembly_file_name = \"%s\"\n", config->assembly_file_name);

    if (config->assembly_file_name == NULL)
    {
        fprintf(stderr, "Error: NodeConfig.assembly_file_name memory allocation failed.\n");
        return false;
    }

    /* Flawfinder: ignore - file name supplied by user. */
    FILE* assembly_file = fopen(assembly_file_name, "r");

    if (assembly_file == NULL)
    {
        fprintf(stderr, "Error: configuration \"%s\" cannot be opened.\n", assembly_file_name);
        teardown_node_config(config);
        return false;
    }

    char* line = NULL;
    size_t len = 0;
    bool has_error = false;
    Match* match = NULL;

    while (getline(&line, &len, assembly_file) != -1)
    {
        if (!initialize_match(&match))
        {
            has_error = true;
            break;
        }

        if (match_pattern(line, &patterns->vm_binary, match))
        {
            if (config->vm_binary != NULL)
                free(config->vm_binary);

            config->vm_binary = strndup(match->capture_groups[0], MAX_LINE_LEN);
            debug("NodeConfig->vm_binary = \"%s\"\n", config->vm_binary);

            if (config->vm_binary == NULL)
            {
                fprintf(stderr, "Error: NodeConfig.vm_binary memory allocation failed.\n");
                has_error = true;
            }
        }
        else if (match_pattern(line, &patterns->vm_exec_slice_in_instructions, match))
        {
            char* endptr = NULL;
            const long slice = strtol(match->capture_groups[0], &endptr, 10);

            if (endptr != match->capture_groups[0] && *endptr == '\0' && slice > 0)
            {
                config->exec_slice = (int)slice;
                debug("NodeConfig->exec_slice = %d\n", config->exec_slice);
            }
        }

        if (has_error)
            break;
    }

    fclose(assembly_file);
    teardown_match(match);

    if (line != NULL)
        free(line);

    if (has_error)
    {
        teardown_node_config(config);
        return false;
    }

    return true;
}

static void teardown_node(Node* node)
{
    if (node == NULL)
        return;

    teardown_node_config(&node->config);
    teardown_node_socket(&node->socket);
    reset_node_processor(&node->processor);

    memset(node, 0, sizeof(Node));
    free(node);
}

static bool unlink_node(Node** head_ref, Node* target_node)
{
    if (head_ref == NULL || *head_ref == NULL || target_node == NULL)
        return false;

    Node* prev = NULL;
    Node* current = *head_ref;

    while (current != NULL && current != target_node)
    {
        prev = current;
        current = current->next;
    }

    if (current == target_node)
    {
        if (prev == NULL)
            *head_ref = target_node->next;
        else
            prev->next = target_node->next;

        target_node->next = NULL;
        return true;
    }

    return false;
}

static void drop_node(Hypervisor* hypervisor, Node* target_node)
{
    if (hypervisor == NULL || target_node == NULL)
        return;

    bool was_unlinked = unlink_node(&hypervisor->head_node, target_node);

    if (!was_unlinked)
        was_unlinked = unlink_node(&hypervisor->pending_head, target_node);

    if (was_unlinked)
    {
        debug("Dropping node \"%s\"\n", target_node->config.vm_binary);
        hypervisor->node_count -= 1;
        teardown_node(target_node);
    }

    if (hypervisor->head_node == NULL || hypervisor->current_node == target_node)
        hypervisor->current_node = NULL;
}

static void enqueue_pending_node(Hypervisor* hypervisor, Node* node)
{
    if (hypervisor == NULL || node == NULL)
        return;

    debug("Enqueuing pending node \"%s\"\n",
          (node->config.vm_binary != NULL) ? node->config.vm_binary : "unknown");

    hypervisor->node_count += 1;
    node->next = NULL;

    if (hypervisor->pending_head == NULL)
    {
        hypervisor->pending_head = node;
        return;
    }

    Node* current = hypervisor->pending_head;

    while (current->next != NULL)
        current = current->next;

    current->next = node;
}

static void transfer_pending_to_running(Hypervisor* hypervisor)
{
    if (hypervisor == NULL || hypervisor->pending_head == NULL)
        return;

    Node* current = hypervisor->pending_head;

    while (current != NULL)
    {
        debug("Transferring pending node \"%s\" to running list\n",
              (current->config.vm_binary != NULL) ? current->config.vm_binary : "unknown");
        current = current->next;
    }

    if (hypervisor->head_node == NULL)
        hypervisor->head_node = hypervisor->pending_head;
    else
    {
        Node* tail = hypervisor->head_node;

        while (tail->next != NULL)
            tail = tail->next;

        tail->next = hypervisor->pending_head;
    }

    hypervisor->pending_head = NULL;
}

static void debug_node(const Hypervisor* hypervisor)
{
    debug("Hypervisor->current_node = \"%s\"\n", hypervisor->current_node->config.vm_binary);
}

static void switch_node(Hypervisor* hypervisor)
{
    hypervisor->current_node = (hypervisor->current_node->next != NULL)
                                   ? hypervisor->current_node->next
                                   : hypervisor->head_node;

    debug_node(hypervisor);
}


static bool validate_snapshot(FILE* snapshot_file, const Node* node, const Patterns* patterns)
{
    if (snapshot_file == NULL || node == NULL || patterns == NULL)
        return false;

    debug("Validating snapshot \"%s\"\n", node->config.snapshot_file);

    /* Flawfinder: ignore - fixed size FNV-1 32-bit hex hash string */
    char expected_hash[HASH_STR_LEN] = {0};

    if (!hash_file(node->config.vm_binary, expected_hash))
    {
        fprintf(stderr, "Error: Failed to hash instruction file \"%s\".\n", node->config.vm_binary);
        return false;
    }

    char* line = NULL;
    size_t len = 0;
    Match* match = NULL;
    bool has_validate_instruction = false;
    bool is_hash_matched = false;
    bool is_skip_validated = false;

    while (getline(&line, &len, snapshot_file) != -1)
    {
        line[strcspn(line, "\r\n")] = '\0';

        if (is_blank_line(line))
            continue;

        if (!initialize_match(&match))
            break;

        if (!has_validate_instruction)
        {
            if (match_pattern(line, &patterns->validate_instructions, match))
            {
                has_validate_instruction = true;

                if (strcmp(match->capture_groups[0], expected_hash) == 0)
                {
                    is_hash_matched = true;
                    continue;
                }
            }

            break;
        }

        if (match_pattern(line, &patterns->skip_instructions, match))
            is_skip_validated = true;

        break;
    }

    teardown_match(match);

    if (line != NULL)
        free(line);

    if (!has_validate_instruction)
        fprintf(stderr,
                "Error: Snapshot validation failed for \"%s\". Missing or invalid VALIDATE_INSTRUCTIONS.\n",
                node->config.snapshot_file);
    else if (!is_hash_matched)
        fprintf(stderr,
                "Error: Snapshot validation failed for \"%s\". Instructions from where snapshot was generated does not "
                "match current instructions.\n",
                node->config.snapshot_file);
    else if (!is_skip_validated)
        fprintf(stderr,
                "Error: Snapshot validation failed for \"%s\". Missing or invalid SKIP_INSTRUCTIONS.\n",
                node->config.snapshot_file);

    rewind(snapshot_file);

    return has_validate_instruction && is_hash_matched && is_skip_validated;
}

static bool restore_node(Node* node, const Patterns* patterns)
{
    if (node == NULL || patterns == NULL || node->config.snapshot_file == NULL)
        return false;

    /* Flawfinder: ignore - snapshot file supplied by user */
    FILE* snapshot_file = fopen(node->config.snapshot_file, "r");

    if (snapshot_file == NULL)
    {
        fprintf(stderr, "Error: Snapshot file \"%s\" cannot be opened.\n", node->config.snapshot_file);
        return false;
    }

    debug("Restoring node from \"%s\"\n", node->config.snapshot_file);

    if (!validate_snapshot(snapshot_file, node, patterns))
    {
        fclose(snapshot_file);
        return false;
    }

    char* line = NULL;
    size_t len = 0;
    Match* match = NULL;
    bool has_error = false;

    while (getline(&line, &len, snapshot_file) != -1)
    {
        line[strcspn(line, "\r\n")] = '\0';

        if (is_blank_line(line))
            continue;

        if (!initialize_match(&match))
        {
            has_error = true;
            break;
        }

        if (match_pattern(line, &patterns->validate_instructions, match))
            continue;
        else if (match_pattern(line, &patterns->skip_instructions, match))
            skip_instructions(node, match);
        else if (match_pattern(line, &patterns->li, match))
            load_immediate(node, match);
        else
            fprintf(stderr, "Exception: Unknown snapshot instruction \"%s\"\n", line);
    }

    teardown_match(match);
    fclose(snapshot_file);

    if (line != NULL)
        free(line);

    return !has_error;
}

static bool restore_node_snapshot(Hypervisor* hypervisor, Node* node)
{
    if (hypervisor == NULL || node == NULL)
        return false;

    if (node->config.snapshot_file == NULL)
        return true;

    if (!restore_node(node, &hypervisor->patterns))
    {
        drop_node(hypervisor, node);
        return false;
    }

    return true;
}

static void restore_pending_snapshots(Hypervisor* hypervisor)
{
    if (hypervisor == NULL)
        return;

    Node* current = hypervisor->pending_head;

    while (current != NULL)
    {
        Node* next = current->next;

        restore_node_snapshot(hypervisor, current);
        current = next;
    }

    hypervisor->current_node = NULL;
}

static Node* setup_node(char* assembly_file_name, const Patterns* patterns)
{
    Node* node = calloc(1, sizeof(Node));

    if (node == NULL)
    {
        fprintf(stderr, "Error: Node memory allocation failed.\n");
        return NULL;
    }

    if (!setup_node_config(assembly_file_name, &node->config, patterns))
    {
        teardown_node(node);
        return NULL;
    }

    if (!setup_node_socket(node->config.vm_binary, &node->socket))
    {
        teardown_node(node);
        return NULL;
    }

    reset_node_processor(&node->processor);

    return node;
}

static bool receive_migrated_node(Hypervisor* hypervisor)
{
    if (hypervisor == NULL || hypervisor->server_socket_file_descriptor < 0)
        return false;

    static unsigned int received_counter = 0;
    struct sockaddr_in client_addr;
    socklen_t client_addr_len = sizeof(client_addr);
    int client_file_descriptor =
        accept(hypervisor->server_socket_file_descriptor, (struct sockaddr*)&client_addr, &client_addr_len);

    if (client_file_descriptor < 0)
        return false;

    /* Flawfinder: ignore - fixed buffer size for temporary file path */
    char raw_cfg_path[MAX_LINE_LEN];
    /* Flawfinder: ignore - fixed buffer size for temporary file path */
    char instr_path[MAX_LINE_LEN];
    /* Flawfinder: ignore - fixed buffer size for temporary file path */
    char snap_path[MAX_LINE_LEN];
    /* Flawfinder: ignore - fixed buffer size for temporary file path */
    char cfg_path[MAX_LINE_LEN];

    snprintf(raw_cfg_path, sizeof(raw_cfg_path), "%sraw_%d_%u", received_file_prefix, hypervisor->server_port,
             received_counter);
    snprintf(instr_path, sizeof(instr_path), "%sinstr_%d_%u", received_file_prefix, hypervisor->server_port,
             received_counter);
    snprintf(snap_path, sizeof(snap_path), "%ssnap_%d_%u", received_file_prefix, hypervisor->server_port,
             received_counter);
    snprintf(cfg_path, sizeof(cfg_path), "%scfg_%d_%u", received_file_prefix, hypervisor->server_port,
             received_counter);

    received_counter++;

    if (!receive_file_payload(client_file_descriptor, raw_cfg_path) ||
        !receive_file_payload(client_file_descriptor, instr_path) ||
        !receive_file_payload(client_file_descriptor, snap_path))
    {
        fprintf(stderr, "Error: Failed to receive complete migration payload.\n");
        unlink(raw_cfg_path);
        unlink(instr_path);
        unlink(snap_path);
        close(client_file_descriptor);
        return false;
    }

    close(client_file_descriptor);

    /* Flawfinder: ignore - temporary file */
    FILE* raw_cfg = fopen(raw_cfg_path, "r");

    if (raw_cfg == NULL)
    {
        unlink(raw_cfg_path);
        unlink(instr_path);
        unlink(snap_path);
        return false;
    }

    unlink(cfg_path);
    /* Flawfinder: ignore - temporary file with exclusive creation */
    int out_cfg_fd = open(cfg_path, O_CREAT | O_EXCL | O_WRONLY, 0600);

    if (out_cfg_fd < 0)
    {
        fclose(raw_cfg);
        unlink(raw_cfg_path);
        unlink(instr_path);
        unlink(snap_path);
        return false;
    }

    FILE* out_cfg = fdopen(out_cfg_fd, "w");

    if (out_cfg == NULL)
    {
        close(out_cfg_fd);
        fclose(raw_cfg);
        unlink(raw_cfg_path);
        unlink(instr_path);
        unlink(snap_path);
        unlink(cfg_path);
        return false;
    }

    char* line = NULL;
    size_t line_len = 0;
    Match* match = NULL;

    while (getline(&line, &line_len, raw_cfg) != -1)
    {
        if (initialize_match(&match) && match_pattern(line, &hypervisor->patterns.vm_binary, match))
            fprintf(out_cfg, "vm_binary = %s\n", instr_path);
        else
            fputs(line, out_cfg);

        teardown_match(match);
        match = NULL;
    }

    if (line != NULL)
        free(line);

    fclose(raw_cfg);
    fclose(out_cfg);
    unlink(raw_cfg_path);

    Node* node = setup_node(cfg_path, &hypervisor->patterns);

    if (node == NULL)
    {
        unlink(instr_path);
        unlink(snap_path);
        unlink(cfg_path);
        return false;
    }

    debug("Received node \"%s\"\n", node->config.vm_binary);

    node->config.snapshot_file = strndup(snap_path, sizeof(snap_path));

    if (node->config.snapshot_file == NULL)
    {
        unlink(snap_path);
        teardown_node(node);
        return false;
    }

    enqueue_pending_node(hypervisor, node);

    if (!restore_node_snapshot(hypervisor, node))
        return false;

    debug("Successfully received and restored migrated node \"%s\"\n", node->config.vm_binary);

    return true;
}

static bool check_and_receive_migration(Hypervisor* hypervisor, const int timeout_ms)
{
    if (hypervisor == NULL || hypervisor->server_socket_file_descriptor < 0)
        return false;

    struct pollfd poll_file_descriptor;

    poll_file_descriptor.fd = hypervisor->server_socket_file_descriptor;
    poll_file_descriptor.events = POLLIN;
    poll_file_descriptor.revents = 0;

    int ret = poll(&poll_file_descriptor, 1, timeout_ms);

    if (ret > 0 && (poll_file_descriptor.revents & POLLIN))
    {
        return receive_migrated_node(hypervisor);
    }

    return false;
}

static bool run_hypervisor(Hypervisor* hypervisor)
{
    if (hypervisor == NULL)
        return false;

    int idle_seconds_elapsed = 0;

    while (keep_running)
    {
        // Wait for incoming migrations.
        if (hypervisor->head_node == NULL && hypervisor->pending_head == NULL)
        {
            if (hypervisor->server_socket_file_descriptor < 0)
                return true;

            int poll_timeout_ms = 3000;

            if (hypervisor->server_timeout_seconds > 0)
            {
                const int remaining_ms = (hypervisor->server_timeout_seconds - idle_seconds_elapsed) * 1000;

                if (remaining_ms < poll_timeout_ms)
                    poll_timeout_ms = remaining_ms;
            }

            struct pollfd poll_file_descriptor;

            poll_file_descriptor.fd = hypervisor->server_socket_file_descriptor;
            poll_file_descriptor.events = POLLIN;
            poll_file_descriptor.revents = 0;

            int ret = poll(&poll_file_descriptor, 1, poll_timeout_ms);

            if (!keep_running)
                break;

            if (ret == 0)
            {
                idle_seconds_elapsed += (poll_timeout_ms / 1000);

                fprintf(stdout,
                        "No VM running, waiting for incoming VM migration on port %d...\n",
                        hypervisor->server_port);
                fflush(stdout);

                if (hypervisor->server_timeout_seconds > 0 &&
                    idle_seconds_elapsed >= hypervisor->server_timeout_seconds)
                {
                    fprintf(stdout,
                            "Server timeout reached after %d seconds, closing server.\n",
                            hypervisor->server_timeout_seconds);
                    fflush(stdout);
                    break;
                }

                continue;
            }

            if (ret > 0 && (poll_file_descriptor.revents & POLLIN))
            {
                receive_migrated_node(hypervisor);
                idle_seconds_elapsed = 0;
            }
        }
        else
            idle_seconds_elapsed = 0;

        // Promote pending to running nodes.
        if (hypervisor->pending_head != NULL)
        {
            transfer_pending_to_running(hypervisor);

            if (hypervisor->current_node == NULL)
            {
                hypervisor->current_node = hypervisor->head_node;
                debug_node(hypervisor);
            }
        }

        // End VMM in Standalone Mode.
        if (hypervisor->head_node == NULL)
        {
            if (hypervisor->server_socket_file_descriptor < 0)
                return true;

            continue;
        }

        // Run current VM.
        if (!run_node(hypervisor))
            return false;

        // Context switch to next VM.
        if (!hypervisor->current_node->socket.has_pending_instructions)
        {
            Node* finished_node = hypervisor->current_node;

            switch_node(hypervisor);
            drop_node(hypervisor, finished_node);
        }
        else
            switch_node(hypervisor);

        // Receive migration requests.
        if (hypervisor->server_socket_file_descriptor >= 0)
            check_and_receive_migration(hypervisor, 0);
    }

    return true;
}

static void teardown_hypervisor_patterns(Patterns* patterns)
{
    if (patterns == NULL)
        return;

    if (patterns->vm_binary.is_initialized)
    {
        regfree(&patterns->vm_binary.pattern);
        patterns->vm_binary.groups = 0;
        patterns->vm_binary.is_initialized = false;
    }

    if (patterns->vm_exec_slice_in_instructions.is_initialized)
    {
        regfree(&patterns->vm_exec_slice_in_instructions.pattern);
        patterns->vm_exec_slice_in_instructions.groups = 0;
        patterns->vm_exec_slice_in_instructions.is_initialized = false;
    }

    if (patterns->dump_processor_state.is_initialized)
    {
        regfree(&patterns->dump_processor_state.pattern);
        patterns->dump_processor_state.groups = 0;
        patterns->dump_processor_state.is_initialized = false;
    }

    if (patterns->dump_register_state.is_initialized)
    {
        regfree(&patterns->dump_register_state.pattern);
        patterns->dump_register_state.groups = 0;
        patterns->dump_register_state.is_initialized = false;
    }

    if (patterns->li.is_initialized)
    {
        regfree(&patterns->li.pattern);
        patterns->li.groups = 0;
        patterns->li.is_initialized = false;
    }

    if (patterns->add.is_initialized)
    {
        regfree(&patterns->add.pattern);
        patterns->add.groups = 0;
        patterns->add.is_initialized = false;
    }

    if (patterns->sub.is_initialized)
    {
        regfree(&patterns->sub.pattern);
        patterns->sub.groups = 0;
        patterns->sub.is_initialized = false;
    }

    if (patterns->addi.is_initialized)
    {
        regfree(&patterns->addi.pattern);
        patterns->addi.groups = 0;
        patterns->addi.is_initialized = false;
    }

    if (patterns->addu.is_initialized)
    {
        regfree(&patterns->addu.pattern);
        patterns->addu.groups = 0;
        patterns->addu.is_initialized = false;
    }

    if (patterns->subu.is_initialized)
    {
        regfree(&patterns->subu.pattern);
        patterns->subu.groups = 0;
        patterns->subu.is_initialized = false;
    }

    if (patterns->addiu.is_initialized)
    {
        regfree(&patterns->addiu.pattern);
        patterns->addiu.groups = 0;
        patterns->addiu.is_initialized = false;
    }

    if (patterns->mul.is_initialized)
    {
        regfree(&patterns->mul.pattern);
        patterns->mul.groups = 0;
        patterns->mul.is_initialized = false;
    }

    if (patterns->mult.is_initialized)
    {
        regfree(&patterns->mult.pattern);
        patterns->mult.groups = 0;
        patterns->mult.is_initialized = false;
    }

    if (patterns->div.is_initialized)
    {
        regfree(&patterns->div.pattern);
        patterns->div.groups = 0;
        patterns->div.is_initialized = false;
    }

    if (patterns->and.is_initialized)
    {
        regfree(&patterns->and.pattern);
        patterns->and.groups = 0;
        patterns->and.is_initialized = false;
    }

    if (patterns->or.is_initialized)
    {
        regfree(&patterns->or.pattern);
        patterns->or.groups = 0;
        patterns->or.is_initialized = false;
    }

    if (patterns->andi.is_initialized)
    {
        regfree(&patterns->andi.pattern);
        patterns->andi.groups = 0;
        patterns->andi.is_initialized = false;
    }

    if (patterns->ori.is_initialized)
    {
        regfree(&patterns->ori.pattern);
        patterns->ori.groups = 0;
        patterns->ori.is_initialized = false;
    }

    if (patterns->sll.is_initialized)
    {
        regfree(&patterns->sll.pattern);
        patterns->sll.groups = 0;
        patterns->sll.is_initialized = false;
    }

    if (patterns->srl.is_initialized)
    {
        regfree(&patterns->srl.pattern);
        patterns->srl.groups = 0;
        patterns->srl.is_initialized = false;
    }

    if (patterns->xor.is_initialized)
    {
        regfree(&patterns->xor.pattern);
        patterns->xor.groups = 0;
        patterns->xor.is_initialized = false;
    }

    if (patterns->snapshot.is_initialized)
    {
        regfree(&patterns->snapshot.pattern);
        patterns->snapshot.groups = 0;
        patterns->snapshot.is_initialized = false;
    }

    if (patterns->validate_instructions.is_initialized)
    {
        regfree(&patterns->validate_instructions.pattern);
        patterns->validate_instructions.groups = 0;
        patterns->validate_instructions.is_initialized = false;
    }

    if (patterns->skip_instructions.is_initialized)
    {
        regfree(&patterns->skip_instructions.pattern);
        patterns->skip_instructions.groups = 0;
        patterns->skip_instructions.is_initialized = false;
    }

    if (patterns->migrate.is_initialized)
    {
        regfree(&patterns->migrate.pattern);
        patterns->migrate.groups = 0;
        patterns->migrate.is_initialized = false;
    }
}

static bool fail_setup_hypervisor_pattern(const char* failed_pattern, Patterns* patterns)
{
    fprintf(stderr, "Error: Failed to compile \"%s\" regex pattern.\n", failed_pattern);
    teardown_hypervisor_patterns(patterns);
    return false;
}

static bool setup_hypervisor_patterns(Patterns* patterns)
{
    if (patterns == NULL)
        return false;

    memset(patterns, 0, sizeof(Patterns));

    if (regcomp(&patterns->vm_binary.pattern,
                "^[[:space:]]*vm_binary[[:space:]]*=[[:space:]]*([^[:space:]]+)[[:space:]]*$", REG_EXTENDED) != 0)
        return fail_setup_hypervisor_pattern("vm_binary", patterns);
    patterns->vm_binary.groups = 1;
    patterns->vm_binary.is_initialized = true;

    if (regcomp(&patterns->vm_exec_slice_in_instructions.pattern,
                "^[[:space:]]*vm_exec_slice_in_instructions[[:space:]]*=[[:space:]]*([0-9]+)[[:space:]]*$",
                REG_EXTENDED) != 0)
        return fail_setup_hypervisor_pattern("vm_exec_slice_in_instructions", patterns);
    patterns->vm_exec_slice_in_instructions.groups = 1;
    patterns->vm_exec_slice_in_instructions.is_initialized = true;

    if (regcomp(&patterns->dump_processor_state.pattern, "^[[:space:]]*DUMP_PROCESSOR_STATE[[:space:]]*$",
                REG_EXTENDED) != 0)
        return fail_setup_hypervisor_pattern("dump_processor_state", patterns);
    patterns->dump_processor_state.groups = 0;
    patterns->dump_processor_state.is_initialized = true;

    if (regcomp(&patterns->dump_register_state.pattern,
                "^[[:space:]]*DUMP_REGISTER_STATE[[:space:]]+\\$([0-9]+|hi|low)[[:space:]]*$",
                REG_EXTENDED) != 0)
        return fail_setup_hypervisor_pattern("dump_register_state", patterns);
    patterns->dump_register_state.groups = 1;
    patterns->dump_register_state.is_initialized = true;

    if (regcomp(&patterns->li.pattern,
                "^[[:space:]]*li[[:space:]]+\\$([0-9]+|hi|low)[[:space:]]*,[[:space:]]*([-+]{0,1}[0-9]+)[[:space:]]*$",
                REG_EXTENDED) != 0)
        return fail_setup_hypervisor_pattern("li", patterns);
    patterns->li.groups = 2;
    patterns->li.is_initialized = true;

    if (regcomp(&patterns->add.pattern,
                "^[[:space:]]*add[[:space:]]+\\$([0-9]+|hi|low)[[:space:]]*,[[:space:]]*\\$([0-9]+|hi|low)[[:space:]]*,[[:space:]]*\\$([0-9]+|hi|low)[[:space:]]*$",
                REG_EXTENDED) != 0)
        return fail_setup_hypervisor_pattern("add", patterns);
    patterns->add.groups = 3;
    patterns->add.is_initialized = true;

    if (regcomp(&patterns->sub.pattern,
                "^[[:space:]]*sub[[:space:]]+\\$([0-9]+|hi|low)[[:space:]]*,[[:space:]]*\\$([0-9]+|hi|low)[[:space:]]*,[[:space:]]*\\$([0-9]+|hi|low)[[:space:]]*$",
                REG_EXTENDED) != 0)
        return fail_setup_hypervisor_pattern("sub", patterns);
    patterns->sub.groups = 3;
    patterns->sub.is_initialized = true;

    if (regcomp(&patterns->addi.pattern,
                "^[[:space:]]*addi[[:space:]]+\\$([0-9]+|hi|low)[[:space:]]*,[[:space:]]*\\$([0-9]+|hi|low)[[:space:]]*,[[:space:]]*([-+]{0,1}[0-9]+)[[:space:]]*$",
                REG_EXTENDED) != 0)
        return fail_setup_hypervisor_pattern("addi", patterns);
    patterns->addi.groups = 3;
    patterns->addi.is_initialized = true;

    if (regcomp(&patterns->addu.pattern,
                "^[[:space:]]*addu[[:space:]]+\\$([0-9]+|hi|low)[[:space:]]*,[[:space:]]*\\$([0-9]+|hi|low)[[:space:]]*,[[:space:]]*\\$([0-9]+|hi|low)[[:space:]]*$",
                REG_EXTENDED) != 0)
        return fail_setup_hypervisor_pattern("addu", patterns);
    patterns->addu.groups = 3;
    patterns->addu.is_initialized = true;

    if (regcomp(&patterns->subu.pattern,
                "^[[:space:]]*subu[[:space:]]+\\$([0-9]+|hi|low)[[:space:]]*,[[:space:]]*\\$([0-9]+|hi|low)[[:space:]]*,[[:space:]]*\\$([0-9]+|hi|low)[[:space:]]*$",
                REG_EXTENDED) != 0)
        return fail_setup_hypervisor_pattern("subu", patterns);
    patterns->subu.groups = 3;
    patterns->subu.is_initialized = true;

    if (regcomp(&patterns->addiu.pattern,
                "^[[:space:]]*addiu[[:space:]]+\\$([0-9]+|hi|low)[[:space:]]*,[[:space:]]*\\$([0-9]+|hi|low)[[:space:]]*,[[:space:]]*([-+]{0,1}[0-9]+)[[:space:]]*$",
                REG_EXTENDED) != 0)
        return fail_setup_hypervisor_pattern("addiu", patterns);
    patterns->addiu.groups = 3;
    patterns->addiu.is_initialized = true;

    if (regcomp(&patterns->mul.pattern,
                "^[[:space:]]*mul[[:space:]]+\\$([0-9]+|hi|low)[[:space:]]*,[[:space:]]*\\$([0-9]+|hi|low)[[:space:]]*,[[:space:]]*\\$([0-9]+|hi|low)[[:space:]]*$",
                REG_EXTENDED) != 0)
        return fail_setup_hypervisor_pattern("mul", patterns);
    patterns->mul.groups = 3;
    patterns->mul.is_initialized = true;

    if (regcomp(&patterns->mult.pattern,
                "^[[:space:]]*mult[[:space:]]+\\$([0-9]+|hi|low)[[:space:]]*,[[:space:]]*\\$([0-9]+|hi|low)[[:space:]]*$",
                REG_EXTENDED) != 0)
        return fail_setup_hypervisor_pattern("mult", patterns);
    patterns->mult.groups = 2;
    patterns->mult.is_initialized = true;

    if (regcomp(&patterns->div.pattern,
                "^[[:space:]]*div[[:space:]]+\\$([0-9]+|hi|low)[[:space:]]*,[[:space:]]*\\$([0-9]+|hi|low)[[:space:]]*$",
                REG_EXTENDED) != 0)
        return fail_setup_hypervisor_pattern("div", patterns);
    patterns->div.groups = 2;
    patterns->div.is_initialized = true;

    if (regcomp(&patterns->and.pattern,
                "^[[:space:]]*and[[:space:]]+\\$([0-9]+|hi|low)[[:space:]]*,[[:space:]]*\\$([0-9]+|hi|low)[[:space:]]*,[[:space:]]*\\$([0-9]+|hi|low)[[:space:]]*$",
                REG_EXTENDED) != 0)
        return fail_setup_hypervisor_pattern("and", patterns);
    patterns->and.groups = 3;
    patterns->and.is_initialized = true;

    if (regcomp(&patterns->or.pattern,
                "^[[:space:]]*or[[:space:]]+\\$([0-9]+|hi|low)[[:space:]]*,[[:space:]]*\\$([0-9]+|hi|low)[[:space:]]*,[[:space:]]*\\$([0-9]+|hi|low)[[:space:]]*$",
                REG_EXTENDED) != 0)
        return fail_setup_hypervisor_pattern("or", patterns);
    patterns->or.groups = 3;
    patterns->or.is_initialized = true;

    if (regcomp(&patterns->andi.pattern,
                "^[[:space:]]*andi[[:space:]]+\\$([0-9]+|hi|low)[[:space:]]*,[[:space:]]*\\$([0-9]+|hi|low)[[:space:]]*,[[:space:]]*([-+]{0,1}[0-9]+)[[:space:]]*$",
                REG_EXTENDED) != 0)
        return fail_setup_hypervisor_pattern("andi", patterns);
    patterns->andi.groups = 3;
    patterns->andi.is_initialized = true;

    /* Both "or" and "ori" are supported because the name is "or" in the MIPS Instruction Set document.
     * See https://github.com/ianbunag/mips-virtual-machine-monitor/blob/main/project/doc/MIPS_Instruction_Set.pdf).
     */
    if (regcomp(&patterns->ori.pattern,
                "^[[:space:]]*ori?[[:space:]]+\\$([0-9]+|hi|low)[[:space:]]*,[[:space:]]*\\$([0-9]+|hi|low)[[:space:]]*,[[:space:]]*([-+]{0,1}[0-9]+)[[:space:]]*$",
                REG_EXTENDED) != 0)
        return fail_setup_hypervisor_pattern("ori", patterns);
    patterns->ori.groups = 3;
    patterns->ori.is_initialized = true;

    if (regcomp(&patterns->sll.pattern,
                "^[[:space:]]*sll[[:space:]]+\\$([0-9]+|hi|low)[[:space:]]*,[[:space:]]*\\$([0-9]+|hi|low)[[:space:]]*,[[:space:]]*([0-9]+)[[:space:]]*$",
                REG_EXTENDED) != 0)
        return fail_setup_hypervisor_pattern("sll", patterns);
    patterns->sll.groups = 3;
    patterns->sll.is_initialized = true;

    if (regcomp(&patterns->srl.pattern,
                "^[[:space:]]*srl[[:space:]]+\\$([0-9]+|hi|low)[[:space:]]*,[[:space:]]*\\$([0-9]+|hi|low)[[:space:]]*,[[:space:]]*([0-9]+)[[:space:]]*$",
                REG_EXTENDED) != 0)
        return fail_setup_hypervisor_pattern("srl", patterns);
    patterns->srl.groups = 3;
    patterns->srl.is_initialized = true;

    if (regcomp(&patterns->xor.pattern,
                "^[[:space:]]*xor[[:space:]]+\\$([0-9]+|hi|low)[[:space:]]*,[[:space:]]*\\$([0-9]+|hi|low)[[:space:]]*,[[:space:]]*\\$([0-9]+|hi|low)[[:space:]]*$",
                REG_EXTENDED) != 0)
        return fail_setup_hypervisor_pattern("xor", patterns);
    patterns->xor.groups = 3;
    patterns->xor.is_initialized = true;

    if (regcomp(&patterns->snapshot.pattern,
                "^[[:space:]]*SNAPSHOT[[:space:]]+([^[:space:]]+)[[:space:]]*$",
                REG_EXTENDED) != 0)
        return fail_setup_hypervisor_pattern("snapshot", patterns);
    patterns->snapshot.groups = 1;
    patterns->snapshot.is_initialized = true;

    if (regcomp(&patterns->validate_instructions.pattern,
                "^[[:space:]]*VALIDATE_INSTRUCTIONS[[:space:]]*=[[:space:]]*([a-fA-F0-9]+)[[:space:]]*$",
                REG_EXTENDED) != 0)
        return fail_setup_hypervisor_pattern("validate_instructions", patterns);
    patterns->validate_instructions.groups = 1;
    patterns->validate_instructions.is_initialized = true;

    if (regcomp(&patterns->skip_instructions.pattern,
                "^[[:space:]]*SKIP_INSTRUCTIONS[[:space:]]*=[[:space:]]*([0-9]+)[[:space:]]*$",
                REG_EXTENDED) != 0)
        return fail_setup_hypervisor_pattern("skip_instructions", patterns);
    patterns->skip_instructions.groups = 1;
    patterns->skip_instructions.is_initialized = true;

    if (regcomp(&patterns->migrate.pattern,
                "^[[:space:]]*MIGRATE[[:space:]]+([a-zA-Z0-9\\.-]+):([0-9]+)[[:space:]]*$",
                REG_EXTENDED) != 0)
        return fail_setup_hypervisor_pattern("migrate", patterns);
    patterns->migrate.groups = 2;
    patterns->migrate.is_initialized = true;

    return true;
}

static void teardown_hypervisor(Hypervisor* hypervisor)
{
    if (hypervisor == NULL)
        return;

    teardown_hypervisor_patterns(&hypervisor->patterns);

    Node* current_node = hypervisor->head_node;
    hypervisor->head_node = NULL;
    hypervisor->node_count = 0;

    while (current_node != NULL)
    {
        Node* next = current_node->next;
        teardown_node(current_node);
        current_node = next;
    }

    Node* pending_node = hypervisor->pending_head;

    hypervisor->pending_head = NULL;

    while (pending_node != NULL)
    {
        Node* next = pending_node->next;

        teardown_node(pending_node);
        pending_node = next;
    }

    if (hypervisor->server_socket_file_descriptor >= 0)
    {
        close(hypervisor->server_socket_file_descriptor);
        hypervisor->server_socket_file_descriptor = -1;
    }

    memset(hypervisor, 0, sizeof(Hypervisor));
    free(hypervisor);
}

static bool setup_server_socket(Hypervisor* hypervisor)
{
    if (hypervisor == NULL || hypervisor->server_port <= 0)
        return true;

    int server_file_descriptor = socket(AF_INET, SOCK_STREAM, 0);

    if (server_file_descriptor < 0)
    {
        fprintf(stderr, "Error: Failed to create server socket.\n");
        return false;
    }

    const int reuseaddr_val = true;

    if (setsockopt(server_file_descriptor, SOL_SOCKET, SO_REUSEADDR, &reuseaddr_val, sizeof(reuseaddr_val)) < 0)
    {
        fprintf(stderr, "Error: setsockopt failed on server socket.\n");
        close(server_file_descriptor);
        return false;
    }

    struct sockaddr_in server_addr;

    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons((uint16_t)hypervisor->server_port);

    if (bind(server_file_descriptor, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0)
    {
        fprintf(stderr, "Error: Failed to bind server socket to port %d.\n", hypervisor->server_port);
        close(server_file_descriptor);
        return false;
    }

    if (listen(server_file_descriptor, 10) < 0)
    {
        fprintf(stderr, "Error: Failed to listen on server socket on port %d.\n", hypervisor->server_port);
        close(server_file_descriptor);
        return false;
    }

    hypervisor->server_socket_file_descriptor = server_file_descriptor;
    debug("Server listening on port %d (file_descriptor %d)\n",
          hypervisor->server_port,
          hypervisor->server_socket_file_descriptor);

    return true;
}

static Hypervisor* setup_hypervisor(int argc, char* argv[])
{
    Hypervisor* hypervisor = calloc(1, sizeof(Hypervisor));

    if (hypervisor == NULL)
    {
        fprintf(stderr, "Error: Hypervisor memory allocation failed.\n");
        return NULL;
    }

    if (!setup_hypervisor_patterns(&hypervisor->patterns))
    {
        teardown_hypervisor(hypervisor);
        return NULL;
    }

    hypervisor->current_node = NULL;
    hypervisor->instruction_slice = -1;
    hypervisor->server_port = -1;
    hypervisor->server_socket_file_descriptor = -1;
    hypervisor->server_timeout_seconds = -1;

    int opt = 0;

    /*
     * Options:
     * -v <file>    : Virtual machine configuration file
     * -s <file>    : Snapshot file to restore
     * -p <port>    : Migration server port (unprivileged: 1024-65535)
     * -t <seconds> : Server idle timeout in seconds (optional)
     * -n <slice>   : Instruction execution slice per VM (positive integer)
     * -d           : Enable debug logging
     */
    /* Flawfinder: ignore - args are validated */
    while ((opt = getopt(argc, argv, "v:s:p:t:n:d")) != -1)
    {
        switch (opt)
        {
        case 'n':
            {
                char* endptr = NULL;
                const long slice = strtol(optarg, &endptr, 10);

                if (endptr == optarg || *endptr != '\0' || slice <= 0)
                {
                    fprintf(stderr,
                            "Error: Invalid instruction slice \"%s\". Slice must be a positive integer.\n",
                            optarg);
                    teardown_hypervisor(hypervisor);
                    return NULL;
                }

                hypervisor->instruction_slice = (int)slice;
                debug("Instruction slice = %d\n", hypervisor->instruction_slice);
                break;
            }
        case 'd':
            debug_enabled = true;
            debug("Debug enabled.\n");
            break;
        case 't':
            {
                char* endptr = NULL;
                const long timeout = strtol(optarg, &endptr, 10);

                if (endptr == optarg || *endptr != '\0' || timeout <= 0)
                {
                    fprintf(stderr,
                            "Error: Invalid timeout \"%s\". Timeout must be a positive integer.\n",
                            optarg);
                    teardown_hypervisor(hypervisor);
                    return NULL;
                }

                hypervisor->server_timeout_seconds = (int)timeout;
                debug("Server timeout = %d seconds\n", hypervisor->server_timeout_seconds);
                break;
            }
        case 'p':
            {
                char* endptr = NULL;
                const long port = strtol(optarg, &endptr, 10);

                if (endptr == optarg || *endptr != '\0' || port < 1024 || port > 65535)
                {
                    fprintf(stderr,
                            "Error: Invalid port \"%s\". Only unprivileged ports (1024-65535) are supported.\n",
                            optarg);
                    teardown_hypervisor(hypervisor);
                    return NULL;
                }

                hypervisor->server_port = (int)port;
                debug("Server port = %d\n", hypervisor->server_port);
                break;
            }
        case 's':
            debug("NodeConfig->snapshot_file = \"%s\"\n", optarg);

            if (hypervisor->current_node == NULL)
            {
                fprintf(stderr, "Error: -s flag specified without preceding -v node.\n");
                teardown_hypervisor(hypervisor);
                return NULL;
            }

            if (hypervisor->current_node->config.snapshot_file != NULL)
            {
                free(hypervisor->current_node->config.snapshot_file);
            }

            hypervisor->current_node->config.snapshot_file = strndup(optarg, MAX_LINE_LEN);

            if (hypervisor->current_node->config.snapshot_file == NULL)
            {
                fprintf(stderr, "Error: NodeConfig.snapshot_file memory allocation failed.\n");
                teardown_hypervisor(hypervisor);
                return NULL;
            }
            break;
        case 'v':
            {
                debug("Node = \"%s\"\n", optarg);
                Node* node = setup_node(optarg, &hypervisor->patterns);

                if (node == NULL)
                {
                    teardown_hypervisor(hypervisor);
                    return NULL;
                }

                enqueue_pending_node(hypervisor, node);
                hypervisor->current_node = node;
                break;
            }
        default:
            break;
        }
    }

    restore_pending_snapshots(hypervisor);

    if (hypervisor->server_port > 0)
    {
        if (!setup_server_socket(hypervisor))
        {
            teardown_hypervisor(hypervisor);
            return NULL;
        }
    }

    return hypervisor;
}

static bool validate_args(int argc, char* argv[])
{
    if (argc == 1)
    {
        fprintf(stderr, "Error: No argument provided, exiting.\n");
        return false;
    }

    for (int i = 1; i < argc; i++)
    {
        if (argv[i] != NULL && strnlen(argv[i], MAX_ARG_LEN + 1) > MAX_ARG_LEN)
        {
            fprintf(stderr, "Error: argument exceeds maximum allowed length of %d.\n", MAX_ARG_LEN);
            return false;
        }
    }

    return true;
}

int main(const int argc, char* argv[])
{
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    signal(SIGPIPE, SIG_IGN);

    if (!validate_args(argc, argv))
        return 1;

    Hypervisor* hypervisor = setup_hypervisor(argc, argv);

    if (hypervisor == NULL)
        return 1;

    if (!run_hypervisor(hypervisor))
    {
        teardown_hypervisor(hypervisor);
        return 1;
    }

    teardown_hypervisor(hypervisor);
    return 0;
}
