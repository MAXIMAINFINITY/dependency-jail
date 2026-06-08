/*
 * libjail.c — dependency-jail Network Interceptor
 *
 * Hooks the standard C library's connect() function using LD_PRELOAD.
 * Any outbound TCP/UDP connection to an IP not on the trusted allowlist
 * is blocked with ECONNREFUSED and logged to a FIFO pipe.
 *
 * Compile:
 *   gcc -shared -fPIC -o libjail.so libjail.c -ldl -lpthread
 *
 * Environment Variables (set by the Python runner):
 *   JAIL_ALLOW_IPS  — colon-separated list of allowed CIDR ranges or IPs
 *   JAIL_LOG_FIFO   — path to the named pipe used to send log events back
 *   JAIL_VERBOSE    — if set to "1", also log allowed connections
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <dlfcn.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <time.h>
#include <fcntl.h>
#include <pthread.h>

/* ─── Types ─────────────────────────────────────────────────────────────── */

typedef int (*orig_connect_t)(int, const struct sockaddr *, socklen_t);

typedef struct {
    uint32_t network;   /* host-byte-order network address */
    uint32_t mask;      /* host-byte-order subnet mask     */
} AllowedRange;

typedef struct {
    struct in6_addr network;
    struct in6_addr mask;
} AllowedRange6;

/* ─── Globals ────────────────────────────────────────────────────────────── */

#define MAX_RANGES 256

static orig_connect_t   g_orig_connect  = NULL;
static AllowedRange     g_ranges[MAX_RANGES];
static int              g_range_count   = 0;
static AllowedRange6    g_ranges6[MAX_RANGES];
static int              g_range6_count  = 0;
static char             g_fifo_path[512] = {0};
static int              g_verbose       = 0;
static pthread_once_t   g_init_once     = PTHREAD_ONCE_INIT;

/* ─── Internal helpers ───────────────────────────────────────────────────── */

/* Parse "192.168.1.0/24" or plain "93.184.216.34" into AllowedRange */
static int parse_cidr(const char *entry, AllowedRange *out) {
    char buf[64];
    strncpy(buf, entry, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *slash = strchr(buf, '/');
    int prefix = 32;
    if (slash) {
        *slash = '\0';
        prefix = atoi(slash + 1);
    }

    struct in_addr addr;
    if (inet_pton(AF_INET, buf, &addr) != 1) return -1;

    uint32_t mask = prefix == 0 ? 0 : (~0u << (32 - prefix));
    out->network = ntohl(addr.s_addr) & mask;
    out->mask    = mask;
    return 0;
}

static int parse_cidr6(const char *entry, AllowedRange6 *out) {
    char buf[128];
    strncpy(buf, entry, sizeof(buf) - 1);
    buf[sizeof(buf) - 1] = '\0';

    char *slash = strchr(buf, '/');
    int prefix = 128;
    if (slash) {
        *slash = '\0';
        prefix = atoi(slash + 1);
    }

    struct in6_addr addr;
    if (inet_pton(AF_INET6, buf, &addr) != 1) return -1;

    memset(&out->mask, 0, sizeof(out->mask));
    for (int i = 0; i < 16; i++) {
        if (prefix >= 8) {
            out->mask.s6_addr[i] = 0xff;
            prefix -= 8;
        } else if (prefix > 0) {
            out->mask.s6_addr[i] = (uint8_t)(0xff << (8 - prefix));
            prefix = 0;
        }
        out->network.s6_addr[i] = addr.s6_addr[i] & out->mask.s6_addr[i];
    }
    return 0;
}

/* Write a single log line to the FIFO (non-blocking; drop if full) */
static void jail_log(const char *verdict, const char *ip, uint16_t port, const char *detail) {
    if (g_fifo_path[0] == '\0') return;

    char line[512];
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    snprintf(line, sizeof(line),
             "%ld.%03ld|%s|%s|%u|%s\n",
             (long)ts.tv_sec,
             (long)(ts.tv_nsec / 1000000L),
             verdict, ip, port, detail ? detail : "");

    int fd = open(g_fifo_path, O_WRONLY | O_NONBLOCK);
    if (fd >= 0) {
        (void)write(fd, line, strlen(line));
        close(fd);
    }
}

/* Returns 1 if the IPv4 address (host byte order) is allowed */
static int is_allowed(uint32_t host_addr) {
    for (int i = 0; i < g_range_count; i++) {
        if ((host_addr & g_ranges[i].mask) == g_ranges[i].network)
            return 1;
    }
    return 0;
}

static int is_allowed6(const struct in6_addr *host_addr) {
    for (int i = 0; i < g_range6_count; i++) {
        int match = 1;
        for (int j = 0; j < 16; j++) {
            if ((host_addr->s6_addr[j] & g_ranges6[i].mask.s6_addr[j]) != g_ranges6[i].network.s6_addr[j]) {
                match = 0;
                break;
            }
        }
        if (match) return 1;
    }
    return 0;
}

/* One-time initialiser: resolve the real connect, parse allow list */
static void jail_init(void) {
    g_orig_connect = (orig_connect_t)dlsym(RTLD_NEXT, "connect");

    const char *allow_env = getenv("JAIL_ALLOW_IPS");
    if (allow_env) {
        char *copy = strdup(allow_env);
        char *token = strtok(copy, ",");
        while (token) {
            if (strchr(token, ':')) {
                if (g_range6_count < MAX_RANGES && parse_cidr6(token, &g_ranges6[g_range6_count]) == 0)
                    g_range6_count++;
            } else {
                if (g_range_count < MAX_RANGES && parse_cidr(token, &g_ranges[g_range_count]) == 0)
                    g_range_count++;
            }
            token = strtok(NULL, ",");
        }
        free(copy);
    }

    const char *fifo_env = getenv("JAIL_LOG_FIFO");
    if (fifo_env) strncpy(g_fifo_path, fifo_env, sizeof(g_fifo_path) - 1);

    const char *verbose_env = getenv("JAIL_VERBOSE");
    if (verbose_env && verbose_env[0] == '1') g_verbose = 1;
}

/* ─── Hooked connect() ───────────────────────────────────────────────────── */

int connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    pthread_once(&g_init_once, jail_init);

    if (addr) {
        fprintf(stderr, "[libjail DEBUG] connect() called. sa_family: %d\n", addr->sa_family);
    } else {
        fprintf(stderr, "[libjail DEBUG] connect() called with NULL addr\n");
    }

    if (!g_orig_connect) {
        errno = ENOSYS;
        return -1;
    }

    if (addr && addr->sa_family == AF_INET) {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)addr;
        uint32_t host_addr = ntohl(sin->sin_addr.s_addr);
        uint16_t port      = ntohs(sin->sin_port);

        /* Always allow loopback (127.0.0.0/8) */
        if ((host_addr >> 24) == 127) {
            return g_orig_connect(sockfd, addr, addrlen);
        }

        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &sin->sin_addr, ip_str, sizeof(ip_str));

        if (!is_allowed(host_addr)) {
            jail_log("BLOCKED", ip_str, port, "not in allowlist");
            errno = ECONNREFUSED;
            return -1;
        }

        if (g_verbose) {
            jail_log("ALLOWED", ip_str, port, "");
        }
    } else if (addr && addr->sa_family == AF_INET6) {
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)addr;
        uint16_t port = ntohs(sin6->sin6_port);
        
        /* Always allow loopback (::1) */
        if (IN6_IS_ADDR_LOOPBACK(&sin6->sin6_addr)) {
            return g_orig_connect(sockfd, addr, addrlen);
        }

        char ip_str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &sin6->sin6_addr, ip_str, sizeof(ip_str));

        if (!is_allowed6(&sin6->sin6_addr)) {
            jail_log("BLOCKED", ip_str, port, "not in allowlist (IPv6)");
            errno = ECONNREFUSED;
            return -1;
        }

        if (g_verbose) {
            jail_log("ALLOWED", ip_str, port, "");
        }
    }

    return g_orig_connect(sockfd, addr, addrlen);
}
