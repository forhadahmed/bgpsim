/*
 * BGP Network Error Handling Tests
 * Tests socket and network error conditions
 */

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include "bgp.h"
#include "test_result.h"
#include "bgp_neighbor.h"

static int test_socketpair(int sv[2]) {
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) < 0) return -1;
    for (int i = 0; i < 2; i++) {
        if (bgp_configure_peer_socket(sv[i]) < 0 || fcntl(sv[i], F_SETFL, O_NONBLOCK) < 0) {
            close(sv[0]);
            close(sv[1]);
            return -1;
        }
    }
    return 0;
}

static int write_test_data(int sv[2], const void *data, size_t size) {
    ssize_t count;
    do count = write(sv[1], data, size); while (count < 0 && errno == EINTR);
    if (count == (ssize_t)size) return 1;
    test_result(0, "Socket fixture did not deliver the intended input");
    close(sv[0]);
    close(sv[1]);
    return 0;
}

/*
 * Test 1: Invalid socket file descriptor
 */
void test_invalid_socket_fd() {
    bgp_neighbor_t neighbor = {0};
    neighbor.sock_fd = -1;

    // Attempt to send on invalid socket should fail
    int result = bgp_send_keepalive(&neighbor);

    test_result(result != 0, "Invalid socket fd handling in send");
}

/*
 * Test 2: Closed socket detection
 */
void test_closed_socket() {
    bgp_neighbor_t neighbor = {0};

    // Create and immediately close a socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock >= 0) {
        close(sock);
        neighbor.sock_fd = sock;

        // Try to send on closed socket
        int result = bgp_send_keepalive(&neighbor);

        test_result(result != 0, "Closed socket detection");
    } else {
        test_result(0, "Closed socket detection (socket creation failed)");
    }
}

/*
 * Test 3: Non-blocking socket with no data
 */
void test_nonblocking_no_data() {
    uint8_t buffer[1024];
    uint8_t msg_type;

    // Create a pair of sockets
    int sv[2];
    if (test_socketpair(sv) == 0) {
        // Try to receive when no data available
        int result = bgp_recv_message(sv[0], buffer, sizeof(buffer), &msg_type);

        // No data is not a closed or broken connection.
        int passed = (result == 0);

        close(sv[0]);
        close(sv[1]);

        test_result(passed, "Non-blocking socket with no data");
    } else {
        test_result(0, "Non-blocking socket with no data (socket setup failed)");
    }
}

/*
 * Test 4: Connection refused scenario
 */
void test_connection_refused() {
    int reserved = socket(AF_INET, SOCK_STREAM, 0);
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    int passed = 0;
    struct sockaddr_in addr = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t size = sizeof(addr);

    /*
     * Take a kernel-chosen port, then release it, so no service is guessed. The port must be closed when the connect
     * runs: Linux refuses a bound but unlistened port with RST, macOS drops the SYN and the connect only times out.
     */
    if (reserved < 0 || sock < 0 || bind(reserved, (struct sockaddr *)&addr, sizeof(addr)) < 0 ||
        getsockname(reserved, (struct sockaddr *)&addr, &size) < 0 ||
        fcntl(sock, F_SETFL, O_NONBLOCK) < 0) goto done;
    close(reserved);
    reserved = -1;
    if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        int error = errno;
        if (error == EINPROGRESS) {
            struct pollfd fd = {.fd = sock, .events = POLLOUT};
            size = sizeof(error);
            if (poll(&fd, 1, 1000) <= 0 || getsockopt(sock, SOL_SOCKET, SO_ERROR, &error, &size) < 0)
                goto done;
        }
        passed = error == ECONNREFUSED;
    }
done:
    if (sock >= 0) close(sock);
    if (reserved >= 0) close(reserved);
    test_result(passed, "Connection refused handling");
}

/*
 * Test 5: Socket creation with invalid parameters
 */
void test_invalid_socket_creation() {
    // Try to create socket with invalid domain
    int sock = socket(999, SOCK_STREAM, 0);

    int passed = (sock < 0);
    if (sock >= 0) close(sock);

    test_result(passed, "Invalid socket creation parameters");
}

/*
 * Test 6: Partial message reception
 */
void test_partial_message() {
    int sv[2];
    if (test_socketpair(sv) != 0) {
        test_result(0, "Partial message test (socket setup failed)");
        return;
    }

    // Send only part of a BGP header (19 bytes)
    uint8_t partial_header[10];
    memset(partial_header, 0xFF, 10);

    if (!write_test_data(sv, partial_header, sizeof(partial_header))) return;

    // Try to receive - should detect incomplete message
    uint8_t buffer[1024];
    uint8_t msg_type;

    int result = bgp_recv_message(sv[0], buffer, sizeof(buffer), &msg_type);

    int passed = (result == 0);

    close(sv[0]);
    close(sv[1]);

    test_result(passed, "Partial message reception handling");
}

/*
 * Test 7: Invalid message marker
 */
void test_invalid_marker() {
    int sv[2];
    if (test_socketpair(sv) != 0) {
        test_result(0, "Invalid marker test (socket setup failed)");
        return;
    }

    // Create a message with invalid marker
    uint8_t bad_msg[BGP_HEADER_SIZE];
    memset(bad_msg, 0xAA, BGP_HEADER_SIZE);  /* Wrong marker */

    // Set length and type
    uint16_t *length_ptr = (uint16_t *)&bad_msg[16];
    *length_ptr = htons(BGP_HEADER_SIZE);
    bad_msg[18] = BGP_MSG_KEEPALIVE;

    if (!write_test_data(sv, bad_msg, sizeof(bad_msg))) return;

    uint8_t buffer[1024];
    uint8_t msg_type;

    int result = bgp_recv_message(sv[0], buffer, sizeof(buffer), &msg_type);

    // Should fail validation
    int passed = (result < 0);

    close(sv[0]);
    close(sv[1]);

    test_result(passed, "Invalid BGP marker detection");
}

/*
 * Test 8: Message too short
 */
void test_message_too_short() {
    int sv[2];
    if (test_socketpair(sv) != 0) {
        test_result(0, "Message too short test (socket setup failed)");
        return;
    }

    // Create valid header but declare length < BGP_HEADER_SIZE
    uint8_t short_msg[BGP_HEADER_SIZE];
    memset(short_msg, 0xFF, BGP_MARKER_SIZE);

    uint16_t *length_ptr = (uint16_t *)&short_msg[16];
    *length_ptr = htons(10);  /* Too short! */
    short_msg[18] = BGP_MSG_KEEPALIVE;

    if (!write_test_data(sv, short_msg, sizeof(short_msg))) return;

    uint8_t buffer[1024];
    uint8_t msg_type;

    int result = bgp_recv_message(sv[0], buffer, sizeof(buffer), &msg_type);

    // Should fail validation
    int passed = (result < 0);

    close(sv[0]);
    close(sv[1]);

    test_result(passed, "Message length too short detection");
}

/*
 * Test 9: Message too long
 */
void test_message_too_long() {
    int sv[2];
    if (test_socketpair(sv) != 0) {
        test_result(0, "Message too long test (socket setup failed)");
        return;
    }

    // Create header with excessive length - but within reasonable bounds
    uint8_t long_msg_hdr[BGP_HEADER_SIZE];
    memset(long_msg_hdr, 0xFF, BGP_MARKER_SIZE);

    uint16_t *length_ptr = (uint16_t *)&long_msg_hdr[16];
    *length_ptr = htons(5000);  /* Larger than typical BGP_MAX_MESSAGE_SIZE */
    long_msg_hdr[18] = BGP_MSG_UPDATE;

    if (!write_test_data(sv, long_msg_hdr, sizeof(long_msg_hdr))) return;

    uint8_t buffer[BGP_MAX_MESSAGE_SIZE];
    uint8_t msg_type;

    int result = bgp_recv_message(sv[0], buffer, sizeof(buffer), &msg_type);

    // Should fail validation
    int passed = (result < 0);

    close(sv[0]);
    close(sv[1]);

    test_result(passed, "Message length too long detection");
}

/*
 * Test 10: Invalid message type
 */
void test_invalid_message_type() {
    int sv[2];
    if (test_socketpair(sv) != 0) {
        test_result(0, "Invalid message type test (socket setup failed)");
        return;
    }

    // Create valid header with invalid type
    uint8_t bad_type_msg[BGP_HEADER_SIZE];
    memset(bad_type_msg, 0xFF, BGP_MARKER_SIZE);

    uint16_t *length_ptr = (uint16_t *)&bad_type_msg[16];
    *length_ptr = htons(BGP_HEADER_SIZE);
    bad_type_msg[18] = 99;  /* Invalid type */

    if (!write_test_data(sv, bad_type_msg, sizeof(bad_type_msg))) return;

    uint8_t buffer[1024];
    uint8_t msg_type;

    int rc = bgp_recv_message(sv[0], buffer, sizeof(buffer), &msg_type);

    // This low-level reader returns the header type; the runtime validates it.
    int passed = rc == BGP_HEADER_SIZE && msg_type == 99;

    close(sv[0]);
    close(sv[1]);

    test_result(passed, "Reader preserves header type for the runtime validator");
}

/*
 * Test 11: Socket buffer overflow protection
 */
void test_buffer_overflow_protection() {
    /*
     * NOTE: This test is disabled as passing a buffer smaller than BGP_HEADER_SIZE
     * to bgp_recv_message is undefined behavior. The function expects at least
     * BGP_HEADER_SIZE bytes available. In practice, callers should always provide
     * a buffer of at least BGP_MAX_MESSAGE_SIZE.
     */
    TEST_PRINT_SKIP("Undersized receive buffer is outside the reader's API contract");
}

/*
 * Test 12: EOF on socket read
 */
void test_eof_handling() {
    int sv[2];
    if (test_socketpair(sv) != 0) {
        test_result(0, "EOF handling test (socket setup failed)");
        return;
    }

    // Close write end to trigger EOF
    close(sv[1]);

    uint8_t buffer[1024];
    uint8_t msg_type;

    int result = bgp_recv_message(sv[0], buffer, sizeof(buffer), &msg_type);

    int passed = (result < 0);

    close(sv[0]);

    test_result(passed, "EOF on socket read handling");
}

/*
 * Test 13: Multiple rapid sends
 */
void test_rapid_sends() {
    bgp_neighbor_t neighbor = {0};

    int sv[2];
    if (test_socketpair(sv) != 0) {
        test_result(0, "Rapid sends test (socket setup failed)");
        return;
    }

    neighbor.sock_fd = sv[0];

    // Send multiple keepalives rapidly
    int success_count = 0;
    for (int i = 0; i < 10; i++) {
        if (bgp_send_keepalive(&neighbor) == 0) {
            success_count++;
        }
    }

    // All ten small messages fit in a fresh socketpair; accepting loss hides failures.
    int passed = success_count == 10 && neighbor.tx_keepalive == 10;
    uint8_t message[BGP_HEADER_SIZE], type;
    for (int i = 0; passed && i < 10; i++) {
        passed = bgp_recv_message(sv[1], message, sizeof(message), &type) == BGP_HEADER_SIZE &&
                 type == BGP_MSG_KEEPALIVE;
    }

    close(sv[0]);
    close(sv[1]);

    test_result(passed, "Rapid multiple sends handling");
}

/*
 * Test 14: Socket state after failed send
 */
void test_socket_state_after_failure() {
    bgp_neighbor_t neighbor = {0};
    neighbor.sock_fd = -1;

    // Failed send shouldn't corrupt neighbor state
    uint64_t before_tx = neighbor.tx_keepalive;
    int result = bgp_send_keepalive(&neighbor);

    // Counter shouldn't increment on failure
    int passed = result != 0 && neighbor.tx_keepalive == before_tx;

    test_result(passed, "Socket state integrity after failed send");
}

/*
 * Test 15: Listen socket creation on used port
 */
void test_port_already_in_use() {
    int                sock1 = socket(AF_INET, SOCK_STREAM, 0);
    int                sock2 = -1;
    struct sockaddr_in addr = {0};
    socklen_t          addr_len = sizeof(addr);
    int                result;
    int                passed;

    if (sock1 < 0) {
        test_result(0, "Port in use test (socket creation failed)");
        return;
    }

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(0);

    if (bind(sock1, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sock1);
        test_result(0, "Port in use test (bind failed)");
        return;
    }

    if (getsockname(sock1, (struct sockaddr *)&addr, &addr_len) < 0 || addr.sin_port == 0) {
        close(sock1);
        test_result(0, "Port in use test (getsockname failed)");
        return;
    }

    if (listen(sock1, 5) < 0) {
        close(sock1);
        test_result(0, "Port in use test (listen failed)");
        return;
    }

    sock2 = socket(AF_INET, SOCK_STREAM, 0);
    if (sock2 < 0) {
        close(sock1);
        test_result(0, "Port in use test (second socket creation failed)");
        return;
    }

    result = bind(sock2, (struct sockaddr *)&addr, sizeof(addr));
    passed = result < 0 && errno == EADDRINUSE;

    close(sock1);
    close(sock2);

    test_result(passed, "Port already in use detection");
}

/*
 * Test 16: Partial body must not be consumed before the full message arrives
 */
void test_partial_body_then_complete_message() {
    int                sv[2];
    uint8_t            tx_buffer[1024];
    uint8_t            rx_buffer[1024];
    uint8_t            msg_type = 0;
    bgp_capabilities_t caps = {0};
    int                msg_len;
    int                first_result;
    int                second_result;

    if (test_socketpair(sv) != 0) {
        test_result(0, "Partial body preserves stream state (socket setup failed)");
        return;
    }

    msg_len = bgp_build_open_with_capabilities(tx_buffer, sizeof(tx_buffer), 65001, 0x01010101, &caps);
    if (msg_len <= BGP_HEADER_SIZE) {
        close(sv[0]);
        close(sv[1]);
        test_result(0, "Partial body preserves stream state (open build failed)");
        return;
    }

    if (!write_test_data(sv, tx_buffer, BGP_HEADER_SIZE + 1)) return;
    first_result = bgp_recv_message(sv[0], rx_buffer, sizeof(rx_buffer), &msg_type);
    if (!write_test_data(sv, tx_buffer + BGP_HEADER_SIZE + 1, msg_len - (BGP_HEADER_SIZE + 1))) return;
    second_result = bgp_recv_message(sv[0], rx_buffer, sizeof(rx_buffer), &msg_type);

    test_result(first_result == 0 &&
                second_result == msg_len &&
                msg_type == BGP_MSG_OPEN && memcmp(tx_buffer, rx_buffer, (size_t)msg_len) == 0,
                "Partial body preserves stream state");

    close(sv[0]);
    close(sv[1]);
}

/*
 * Test 17: Partial body followed by EOF must be treated as connection loss
 */
void test_partial_body_then_eof_is_error() {
    int                sv[2];
    uint8_t            tx_buffer[1024];
    uint8_t            rx_buffer[1024];
    uint8_t            msg_type = 0;
    bgp_capabilities_t caps = {0};
    int                msg_len;
    int                result;

    if (test_socketpair(sv) != 0) {
        test_result(0, "Partial body followed by EOF is rejected (socket setup failed)");
        return;
    }

    msg_len = bgp_build_open_with_capabilities(tx_buffer, sizeof(tx_buffer), 65001, 0x01010101, &caps);
    if (msg_len <= BGP_HEADER_SIZE) {
        close(sv[0]);
        close(sv[1]);
        test_result(0, "Partial body followed by EOF is rejected (open build failed)");
        return;
    }

    if (!write_test_data(sv, tx_buffer, BGP_HEADER_SIZE + 1)) return;
    close(sv[1]);
    result = bgp_recv_message(sv[0], rx_buffer, sizeof(rx_buffer), &msg_type);

    test_result(result < 0, "Partial body followed by EOF is rejected");

    close(sv[0]);
}

int main() {
    printf("BGP Network Error Handling Tests\n");
    printf("=================================\n\n");

    // Run all tests
    test_invalid_socket_fd();
    test_closed_socket();
    test_nonblocking_no_data();
    test_connection_refused();
    test_invalid_socket_creation();
    test_partial_message();
    test_invalid_marker();
    test_message_too_short();
    test_message_too_long();
    test_invalid_message_type();
    test_buffer_overflow_protection();
    test_eof_handling();
    test_rapid_sends();
    test_socket_state_after_failure();
    test_port_already_in_use();
    test_partial_body_then_complete_message();
    test_partial_body_then_eof_is_error();

    // Print summary
    printf("\n=================================\n");
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_failed);
    printf("=================================\n");

    return (tests_failed == 0) ? 0 : 1;
}
