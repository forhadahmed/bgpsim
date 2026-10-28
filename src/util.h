#ifndef UTIL_H
#define UTIL_H

#include <time.h>
#include <stddef.h>
#include <stdint.h>
#include <netinet/in.h>
#ifdef __APPLE__
// glibc <endian.h> provides these; macOS does not.
#include <libkern/OSByteOrder.h>
#define htobe64(x) OSSwapHostToBigInt64(x)
#define be64toh(x) OSSwapBigToHostInt64(x)
#endif

// Compile-time check with a message, the one spelling used in every C file.
#define STATIC_ASSERT(cond, msg) _Static_assert(cond, msg)

/*
 * Time utilities
 */
void get_timestamp_str(char *buf, size_t bufsize);

/*
 * Format an uptime duration as HH:MM:SS or MM:SS
 */
void format_uptime(time_t uptime, char *buf, size_t bufsize);

/*
 * String utilities
 */
char* str_trim(char *str);

// Maximum complete command size, including its terminating NUL.
#define BGPSIM_COMMAND_SIZE 1024
int command_input_valid(const char *data, size_t length);
int config_name_valid(const char *name, size_t capacity);

// ANSI color sequences for TTY output
#define CLR_RESET  "\x1b[0m"
#define CLR_BOLD   "\x1b[1m"
#define CLR_DIM    "\x1b[2m"
#define CLR_CYAN   "\x1b[36m"
#define CLR_YELLOW "\x1b[33m"
#define CLR_GREEN  "\x1b[32m"
#define CLR_RED    "\x1b[31m"
#define CLR_BLUE   "\x1b[34m"
#define CLR_ORANGE "\x1b[38;5;208m"
int terminal_color_enabled(int requested, int is_terminal);

// Product name and derived file/path constants
#define BGPSIM           "bgpsim"
#define BGPSIM_CONF_FILE BGPSIM ".conf"
#define BGPSIM_LOG_FILE  BGPSIM ".log"
#define BGPSIM_LOG_PATH  "/tmp/" BGPSIM_LOG_FILE
#define BGPSIM_SOCK_FILE BGPSIM ".sock"
#define BGPSIM_SOCK_PATH "/tmp/" BGPSIM_SOCK_FILE

// Shared operator-facing message text
#define BGPSIM_MSG_INTERRUPT_CONFIRM "Press Ctrl+C again to exit."
#define BGPSIM_MSG_FORCE_SHUTDOWN    "Forcing shutdown..."
#define BGPSIM_MSG_TERM_SHUTDOWN     "Termination signal received, shutting down..."

/*
 * IP address utilities
 */
int get_ip_address_family(const char *ip);
int is_ip_address(const char *str);
/*
 * Canonical peer identity, including IPv4-mapped IPv6 -> IPv4. Returns AF_* or -1.
 */
int canonical_ip_address(const char *ip, char *canonical, size_t size);

/*
 * Convert a host-order 32-bit router ID to dotted-decimal string
 */
void router_id_to_str(uint32_t router_id, char *buf, size_t bufsize);

/*
 * Number parsing utilities
 */
int is_uint32(const char *str, uint32_t *value);

/*
 * Add value * 2^shift_bits to an unsigned big-endian number (an address, a
 * MAC, an ESI). Returns -1 when the sum does not fit in byte_count octets;
 * the low octets then hold the wrapped sum. Inline because the ribout
 * generator calls it for every path; a 4-octet number (IPv4) takes one
 * 64-bit add.
 */
static inline int bytes_be_add(uint8_t *bytes, size_t byte_count, uint32_t value, unsigned shift_bits) {
    uint64_t carry;
    size_t   idx;

    if (!bytes || byte_count == 0) {
        return -1;
    }
    if (value == 0) {
        return 0;
    }
    if (shift_bits >= byte_count * 8) {
        return -1;
    }

    if (byte_count == 4) {
        uint64_t sum = (((uint64_t)bytes[0] << 24) | ((uint64_t)bytes[1] << 16) |
                        ((uint64_t)bytes[2] << 8) | bytes[3]) +
                       ((uint64_t)value << shift_bits);

        bytes[0] = (uint8_t)(sum >> 24);
        bytes[1] = (uint8_t)(sum >> 16);
        bytes[2] = (uint8_t)(sum >> 8);
        bytes[3] = (uint8_t)sum;
        return (sum >> 32) ? -1 : 0;
    }

    /*
     * The carry holds the part of the addend not yet added, aligned to the
     * current octet. It never exceeds 2^32 * 2^7 + 2^8, so 64 bits hold it.
     */
    carry = (uint64_t)value << (shift_bits % 8);
    idx = byte_count - shift_bits / 8;
    while (idx > 0 && carry != 0) {
        uint64_t sum;

        idx--;
        sum = bytes[idx] + (carry & 0xFFu);
        bytes[idx] = (uint8_t)sum;
        carry = (carry >> 8) + (sum >> 8);
    }

    return (carry != 0) ? -1 : 0;
}

/*
 * BSD sockets carry structure lengths in the address itself. Linux ignores
 * these fields, so set them only where the platform exposes them.
 */
static inline void sockaddr_set_in_len(struct sockaddr_in *addr) {
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || \
    defined(__OpenBSD__) || defined(__DragonFly__)
    addr->sin_len = (uint8_t)sizeof(*addr);
#else
    (void)addr;
#endif
}

static inline void sockaddr_set_in6_len(struct sockaddr_in6 *addr) {
#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__NetBSD__) || \
    defined(__OpenBSD__) || defined(__DragonFly__)
    addr->sin6_len = (uint8_t)sizeof(*addr);
#else
    (void)addr;
#endif
}

/*
 * Geometrically reserve zero-initialized array slots. Failure leaves data/capacity unchanged.
 */
void *array_reserve(void *data, size_t element_size, int *capacity, int needed);

#endif /* UTIL_H */
