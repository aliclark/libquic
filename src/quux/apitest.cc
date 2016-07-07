#include "api.h"

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/uio.h>

const void quux_server_accept(quux_c_impl* stream) {

}

const void quux_server_readable(quux_c_impl* stream) {

}

const void quux_server_writeable(quux_c_impl* stream) {

}

//

const void quux_client_writeable(quux_c_impl* stream) {
		printf("################## quux_client_writeable\n");
		const uint8_t hello[] = { 'h', 'i', '\n' };
		struct iovec iovec = { (void*) hello, 3 };
		ssize_t written = quux_write(stream, &iovec);

}

const void quux_client_readable(quux_c_impl* stream) {

}

int main(int argc, char** argv) {
	uint16_t local_port = 8443;

	quux_init();

	if (argc > 1) {
		struct sockaddr_in peer_sock;
		peer_sock.sin_family = AF_INET;
		peer_sock.sin_port = htons(local_port);
		peer_sock.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

		quux_p_impl* peer = quux_peer((struct sockaddr*) &peer_sock);

		quux_c_impl* stream = quux_connect(peer, &quux_client_writeable,
				&quux_client_readable);

		quux_write_please(stream);

	} else {
		struct sockaddr_in self;
		self.sin_family = AF_INET;
		self.sin_port = htons(local_port);
		self.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

		quux_s server = quux_listen((struct sockaddr*) &self,
				&quux_server_accept, &quux_server_writeable,
				&quux_server_readable);
	}

	quux_loop();

	return 0;
}
