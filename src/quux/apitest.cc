#include <netinet/in.h>
#include <quux/api.h>
#include <stddef.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <cctype>
#include <cstdint>

const size_t buflen = 8192;
uint8_t buf[buflen];
size_t bytes_read;

void server_accept(quux_stream stream) {
	printf("server_accept\n");
	quux_read_please(stream);
}
void server_readable(quux_stream stream) {
	printf("server_readable\n");

	struct iovec iovec = { buf, buflen - 1 };
	bytes_read = quux_read(stream, &iovec);
	buf[bytes_read] = '\0';

	if (bytes_read == 0) {
		printf("quux_read: 0\n");
		// we'll get another callback when it's ready
		return;
	}

	printf("quux_read: %s", buf);
	quux_write_please(stream);
}
void server_writeable(quux_stream stream) {
	printf("server_writeable\n");

	for (int i = 0; i < bytes_read; ++i) {
		buf[i] = toupper(buf[i]);
	}

	struct iovec iovec = { buf, bytes_read };
	quux_write(stream, &iovec);

	printf("quux_write: %s", buf);
}

void client_writeable(quux_stream stream) {
	printf("client_writeable\n");
	const uint8_t hello[] = { 'h', 'e', 'l', 'l', 'o', '!', '\n' };
	struct iovec iovec = { (void*) hello, 7 };
	size_t wrote = quux_write(stream, &iovec);

	if (wrote == 0) {
		printf("quux_write: 0\n");
		// we'll get another callback when it's ready
		return;
	}

	printf("quux_write: %s", hello);
	quux_read_please(stream);
}
void client_readable(quux_stream stream) {
	printf("client_readable\n");

	struct iovec iovec = { buf, buflen - 1 };
	bytes_read = quux_read(stream, &iovec);
	buf[bytes_read] = '\0';

	if (bytes_read == 0) {
		printf("quux_read: 0\n");
		// we'll get another callback when it's ready
		return;
	}

	printf("quux_read: %s", buf);
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

	printf("quux_loop()\n");
	quux_loop();

	return 0;
}
