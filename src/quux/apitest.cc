#include <netinet/in.h>
#include <quux/api.h>
#include <stdlib.h>
#include <sys/uio.h>
#include <cstdint>

void server_accept(quux_c_impl* stream) {
	printf("################ quux_server_accept\n");
}
void server_readable(quux_c_impl* stream) {
	printf("################## quux_server_readable\n");
	uint8_t* buf = (uint8_t*) calloc(8192, 1);
	struct iovec iovec = { (void*) buf, 8191 };
	quux_read(stream, &iovec);
	printf("received: \"%s\"\n", buf);
}
void server_writeable(quux_c_impl* stream) {
}

void client_writeable(quux_c_impl* stream) {
	printf("################## quux_client_writeable\n");
	const uint8_t hello[] = { 'h', 'e', 'l', 'l', 'o', '!', '\n' };
	struct iovec iovec = { (void*) hello, 7 };
	quux_write(stream, &iovec);
}
void client_readable(quux_c_impl* stream) {
}

int main(int argc, char** argv) {
	sockaddr_in addr = { AF_INET, htons(8443), htonl(INADDR_LOOPBACK) };

	quux_init();

	if (argc > 1) {
		quux_p_impl* peer = quux_peer((sockaddr*) &addr);
		quux_c_impl* stream = quux_connect(peer, client_writeable,
				client_readable);
		quux_write_please(stream);

	} else {
		quux_listen((sockaddr*) &addr, server_accept, server_writeable,
				server_readable);
	}

	quux_loop();

	return 0;
}
