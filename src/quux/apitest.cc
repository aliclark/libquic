#include <netinet/in.h>
#include <quux/api.h>
#include <stdlib.h>
#include <sys/uio.h>
#include <cstdint>

void server_accept(quux_stream stream) {
	printf("################ quux_server_accept\n");
}
void server_readable(quux_stream stream) {
	printf("################## quux_server_readable\n");

	const size_t buflen = 8192;
	uint8_t buf[buflen];
	struct iovec iovec = { buf, buflen - 1 };

	int bytes_read = quux_read(stream, &iovec);
	buf[bytes_read] = '\0';

	printf("received: \"%s\"\n", buf);
}
void server_writeable(quux_stream stream) {
}

void client_writeable(quux_stream stream) {
	printf("################## quux_client_writeable\n");
	const uint8_t hello[] = { 'h', 'e', 'l', 'l', 'o', '!', '\n' };
	struct iovec iovec = { (void*) hello, 7 };
	quux_write(stream, &iovec);
}
void client_readable(quux_stream stream) {
}

int main(int argc, char** argv) {
	sockaddr_in addr = { AF_INET, htons(8443), htonl(INADDR_LOOPBACK) };

	quux_init();

	if (argc > 1) {
		quux_conn peer = quux_peer((sockaddr*) &addr);
		quux_stream stream = quux_connect(peer, client_writeable,
				client_readable);
		quux_write_please(stream);

	} else {
		quux_listen((sockaddr*) &addr, server_accept, server_writeable,
				server_readable);
	}

	quux_loop();

	return 0;
}
