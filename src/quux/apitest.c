
#include <stdint.h>
#include <ctype.h>
#include <stdio.h>
#include <arpa/inet.h>

#include "api.h"

#define BUF_LEN 8192
static uint8_t buf[BUF_LEN];
size_t bytes_read;

void server_writeable(quux_stream stream) {
	printf("server_writeable\n");

	int i;
	for (i = 0; i < bytes_read; ++i) {
		buf[i] = toupper(buf[i]);
	}

	size_t wrote = quux_write(stream, buf, bytes_read);

	if (wrote == 0) {
		printf("quux_write: 0\n");
		/* we'll get another callback when it's ready */
		return;
	}

	printf("quux_write: %s", buf);
}
void server_readable(quux_stream stream) {
	printf("server_readable\n");

	bytes_read = quux_read(stream, buf, BUF_LEN-1);
	buf[bytes_read] = '\0';

	if (bytes_read == 0) {
		printf("quux_read: 0\n");
		/* we'll get another callback when it's ready */
		return;
	}

	printf("quux_read: %s", buf);
	server_writeable(stream);
}
void server_acceptable(quux_peer peer) {
	printf("server_acceptable\n");
	quux_stream stream = quux_accept(peer, server_readable, server_writeable);
	server_readable(stream);
}

void client_readable(quux_stream stream) {
	printf("client_readable\n");

	bytes_read = quux_read(stream, buf, BUF_LEN-1);
	buf[bytes_read] = '\0';

	if (bytes_read == 0) {
		printf("quux_read: 0\n");
		/* we'll get another callback when it's ready */
		return;
	}

	printf("quux_read: %s", buf);
}
void client_writeable(quux_stream stream) {
	printf("client_writeable\n");
	const uint8_t hello[] = { 'h', 'e', 'l', 'l', 'o', '!', '\n' };
	size_t wrote = quux_write(stream, hello, sizeof(hello));

	if (wrote == 0) {
		printf("quux_write: 0\n");
		/* we'll get another callback when it's ready */
		return;
	}

	printf("quux_write: %s", hello);
	client_readable(stream);
}
void client_acceptable(quux_peer peer) {
	// ignore
}

int main(int argc, char** argv) {
#ifdef SHADOW
	struct sockaddr_in addr = { AF_INET, htons(8443), { htonl(0x0b000002) } };
#else
	struct sockaddr_in addr = { AF_INET, htons(8443), { htonl(INADDR_LOOPBACK) } };
#endif

	quux_init_loop();

	if (argc > 1) {
		quux_peer peer = quux_open((struct sockaddr*) &addr, client_acceptable);
		quux_stream stream = quux_connect(peer, client_readable, client_writeable);
		client_writeable(stream);

	} else {
		quux_listen((struct sockaddr*) &addr, server_acceptable);
	}

	printf("quux_loop()\n");
	quux_loop();

	return 0;
}
