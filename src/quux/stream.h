/*
 * Stream.h
 *
 *  Created on: Jun 30, 2016
 *      Author: user
 */

#ifndef SRC_QUUX_STREAM_H_
#define SRC_QUUX_STREAM_H_

#include "../net/quic/quic_protocol.h"
#include "../net/quic/quic_spdy_stream.h"
#include "../net/quic/quic_types.h"
#include "../net/quic/reliable_quic_stream.h"

// circular include
//#include "client.h"

namespace quux {

namespace client {
class Session;
}

class Stream: public net::ReliableQuicStream {
public:
	Stream(net::QuicStreamId id, quux::client::Session* session);

	void OnDataAvailable() override {
		printf("stream::ondataavailable\n");
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
};

} /* namespace quux */

#endif /* SRC_QUUX_STREAM_H_ */
