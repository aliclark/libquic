/*
 * Stream.h
 *
 *  Created on: Jun 30, 2016
 *      Author: user
 */

#ifndef SRC_QUUX_STREAM_H_
#define SRC_QUUX_STREAM_H_

#include <net/quic/quic_protocol.h>
#include <net/quic/quic_stream_sequencer.h>
#include <net/quic/quic_types.h>
#include <net/quic/reliable_quic_stream.h>
#include <quux/quux_internal.h>
#include <stddef.h>
#include <cstdio>

class quux_c_impl;

// circular include
//#include "client.h"

namespace quux {

namespace client {
class Session;
}

class Stream: public net::ReliableQuicStream {
public:
	Stream(net::QuicStreamId id, quux::client::Session* session, quux_c_impl* ctx);

	void OnDataAvailable() override {
		printf("quux::client::Stream::OnDataAvailable\n");

		if (read_wanted) {
			read_wanted = false;
			quux::c_readable_cb(ctx)(ctx);
		}
	}

	// ReliableQuicStream::WritevData is protected,
	// so this can be used to write to it instead
	net::QuicConsumedData WritevData(const struct iovec* iov, int iov_count,
	bool fin, net::QuicAckListenerInterface* ack_listener) {

		return net::ReliableQuicStream::WritevData(iov, iov_count, fin,
				ack_listener);
	}

	virtual ~Stream() {
	}

	// access to protected stuff
	int Readv(const struct iovec* iov, size_t iov_len) {
		return sequencer()->Readv(iov, iov_len);
	}

	quux_c_impl* ctx;
	bool read_wanted = false;
};

} /* namespace quux */

#endif /* SRC_QUUX_STREAM_H_ */
