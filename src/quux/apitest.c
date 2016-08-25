
#include <stdio.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <ctype.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <quux.h>

#define SHADOW 0

#define BUF_LEN 8192
static uint8_t buf[BUF_LEN];
size_t bytes_read;

void info(const char *format, ...) {
	va_list ap;
	va_start(ap, format);
	vfprintf(stderr, format, ap);
	fputc('\n', stderr);
	va_end(ap);
}

void server_writeable(quux_stream stream) {
	info("server_writeable");

	int i;
	for (i = 0; i < bytes_read; ++i) {
		buf[i] = toupper(buf[i]);
	}

	size_t wrote = quux_write(stream, buf, bytes_read);

	if (wrote == 0) {
		info("quux_write: 0");
		/* we'll get another callback when it's ready */
		return;
	}

	info("quux_write: %s", buf);
	quux_write_close(stream);
}
void server_readable(quux_stream stream) {
	info("server_readable");

	bytes_read = quux_read(stream, buf, BUF_LEN-1);
	buf[bytes_read] = '\0';

	if (bytes_read == 0) {
		info("quux_read: 0");
		/* we'll get another callback when it's ready */
		return;
	}

	info("quux_read: %s", buf);
	quux_read_close(stream);
	server_writeable(stream);
}
void server_closed(quux_stream stream) {
	info("server_closed");
	quux_free_stream(stream);
}
void server_accept(quux_stream stream) {
	info("server_accept");
	quux_set_readable_cb(stream, server_readable);
	quux_set_writeable_cb(stream, server_writeable);
	quux_set_closed_cb(stream, server_closed);
	server_readable(stream);
}

void server_connected(quux_peer peer) {
	info("server_connected");
	quux_set_accept_cb(peer, server_accept);

	void client_readable(quux_stream stream);
	void client_writeable(quux_stream stream);
	void client_closed(quux_stream stream);

	quux_stream stream2 = quux_connect(peer);
	quux_set_readable_cb(stream2, client_readable);
	quux_set_writeable_cb(stream2, client_writeable);
	quux_set_closed_cb(stream2, client_closed);
	client_writeable(stream2);
}

void client_readable(quux_stream stream) {
	info("client_readable");

	bytes_read = quux_read(stream, buf, BUF_LEN-1);
	buf[bytes_read] = '\0';

	if (bytes_read == 0) {
		info("quux_read: 0");
		/* we'll get another callback when it's ready */
		return;
	}

	info("quux_read: %s", buf);
	quux_read_close(stream);
}
void client_writeable(quux_stream stream) {
	info("client_writeable");
	const uint8_t hello[] = { 'h', 'e', 'l', 'l', 'o', '!', '\n' };
	size_t wrote = quux_write(stream, hello, sizeof(hello));

	if (wrote == 0) {
		info("quux_write: 0");
		/* we'll get another callback when it's ready */
		return;
	}

	info("quux_write: %s", hello);
	quux_write_close(stream);
	client_readable(stream);
}
void client_accept(quux_stream stream) {
	info("client_accept");
	quux_set_readable_cb(stream, server_readable);
	quux_set_writeable_cb(stream, server_writeable);
	quux_set_closed_cb(stream, server_closed);
	server_readable(stream);
}
void client_closed(quux_stream stream) {
	info("client_closed");
	quux_free_stream(stream);
}

int main(int argc, char** argv) {
#if SHADOW
	struct sockaddr_in addr = { AF_INET, htons(8443), { htonl(0x0b000002) } };
#else
	struct sockaddr_in addr = { AF_INET, htons(8443), { htonl(INADDR_LOOPBACK) } };
#endif

	quux_init_loop();

	if (argc > 1) {
		quux_peer peer = quux_open("example.com", (struct sockaddr*) &addr);
		quux_set_accept_cb(peer, client_accept);

		quux_stream stream = quux_connect(peer);
		quux_set_readable_cb(stream, client_readable);
		quux_set_writeable_cb(stream, client_writeable);
		quux_set_closed_cb(stream, client_closed);

		client_writeable(stream);

	} else {
		quux_listen((struct sockaddr*) &addr, server_connected);
	}

	info("quux_loop()");
	quux_loop();

	return 0;
}
