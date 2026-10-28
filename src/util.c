// General utility functions for the BGP simulator

#include <time.h>
#include <ctype.h>
#include <stdio.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include "util.h"

void *array_reserve(void *data, size_t element_size, int *capacity, int needed) {
    if (needed < 0 || !element_size || *capacity < 0) return NULL;
    if (needed <= *capacity) return data;
    int next = *capacity ? *capacity : 8;
    while (next < needed) next = next > INT_MAX / 2 ? needed : next * 2;
    if ((size_t)next > SIZE_MAX / element_size) return NULL;
    void *grown = realloc(data, (size_t)next * element_size);
    if (!grown) return NULL;
    memset((char *)grown + (size_t)*capacity * element_size, 0, (size_t)(next - *capacity) * element_size);
    *capacity = next;
    return grown;
}

// Time Utilities

/*
 * Format an uptime duration as HH:MM:SS or MM:SS.
 * If uptime is 0 or in the future, writes an empty string.
 */
void format_uptime(time_t uptime, char *buf, size_t bufsize) {
    if (uptime == 0) {
        buf[0] = '\0';
        return;
    }

    time_t now = time(NULL);
    int    seconds = (int)difftime(now, uptime);
    int    hours   = seconds / 3600;
    int    minutes = (seconds % 3600) / 60;
    int    secs    = seconds % 60;

    if (hours > 0) {
        snprintf(buf, bufsize, "%02d:%02d:%02d", hours, minutes, secs);
    } else {
        snprintf(buf, bufsize, "%02d:%02d", minutes, secs);
    }
}

/*
 * Format timestamp for event messages
 */
void get_timestamp_str(char *buf, size_t bufsize) {
    struct timeval tv;
    struct tm     *tm_info;

    gettimeofday(&tv, NULL);
    tm_info = localtime(&tv.tv_sec);

    snprintf(buf, bufsize, "%04d-%02d-%02d %02d:%02d:%02d.%03d",
             tm_info->tm_year + 1900,
             tm_info->tm_mon + 1,
             tm_info->tm_mday,
             tm_info->tm_hour,
             tm_info->tm_min,
             tm_info->tm_sec,
             (int)(tv.tv_usec / 1000));
}

// String Utilities

/*
 * Trim leading and trailing whitespace from string (modifies in-place)
 */
char* str_trim(char *str) {
    char *end;

    // Trim leading space
    while (isspace((unsigned char)*str)) str++;

    if (*str == 0)
        return str;

    // Trim trailing space
    end = str + strlen(str) - 1;
    while (end > str && isspace((unsigned char)*end)) end--;

    end[1] = '\0';
    return str;
}

// IP Address Utilities

int command_input_valid(const char *data, size_t length) {
    return length < BGPSIM_COMMAND_SIZE && (!length || (data && !memchr(data, '\0', length)));
}

int config_name_valid(const char *name, size_t capacity) {
    if (!name || !*name || strlen(name) >= capacity) return 0;
    for (const unsigned char *p = (const unsigned char *)name; *p; p++) {
        if (!isalnum(*p) && *p != '-' && *p != '_' && *p != '.') return 0;
    }
    return 1;
}

int terminal_color_enabled(int requested, int is_terminal) {
    const char *term = getenv("TERM");
    return !getenv("NO_COLOR") && !(term && strcmp(term, "dumb") == 0) && (requested || is_terminal);
}

int canonical_ip_address(const char *ip, char *canonical, size_t size) {
    struct in_addr  addr4;
    struct in6_addr addr6;
    if (!ip || !canonical) return -1;
    if (inet_pton(AF_INET, ip, &addr4) == 1) {
        return inet_ntop(AF_INET, &addr4, canonical, size) ? AF_INET : -1;
    }
    if (inet_pton(AF_INET6, ip, &addr6) != 1) return -1;
    if (IN6_IS_ADDR_V4MAPPED(&addr6)) {
        memcpy(&addr4, &addr6.s6_addr[12], sizeof(addr4));
        return inet_ntop(AF_INET, &addr4, canonical, size) ? AF_INET : -1;
    }
    return inet_ntop(AF_INET6, &addr6, canonical, size) ? AF_INET6 : -1;
}

/*
 * Determine address family for an IP address string.
 * Returns AF_INET, AF_INET6, or -1 for invalid.
 */
int get_ip_address_family(const char *ip) {
    struct in_addr  dummy_ipv4;
    struct in6_addr dummy_ipv6;

    if (inet_pton(AF_INET, ip, &dummy_ipv4) == 1) {
        return AF_INET;
    } else if (inet_pton(AF_INET6, ip, &dummy_ipv6) == 1) {
        return AF_INET6;
    }
    return -1;
}

/*
 * Check if string is a valid IP address (IPv4 or IPv6)
 */
int is_ip_address(const char *str) {
    return get_ip_address_family(str) != -1;
}

/*
 * Convert a host-order 32-bit router ID to dotted-decimal string
 */
void router_id_to_str(uint32_t router_id, char *buf, size_t bufsize) {
    struct in_addr addr;
    addr.s_addr = htonl(router_id);
    inet_ntop(AF_INET, &addr, buf, (socklen_t)bufsize);
}

// Number Parsing Utilities

/*
 * Check if string is a valid uint32 and parse it
 * Returns 1 if valid, 0 if invalid
 * If valid, stores result in *value
 */
int is_uint32(const char *str, uint32_t *value) {
    char *endptr;
    unsigned long val = strtoul(str, &endptr, 10);

    if (*endptr != '\0' || endptr == str) {
        return 0;  /* Not a valid number */
    }

    if (val > UINT32_MAX) {
        return 0;  /* Out of range */
    }

    *value = (uint32_t)val;
    return 1;
}
