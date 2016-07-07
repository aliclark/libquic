/*
 * stream.cc
 *
 *  Created on: Jul 4, 2016
 *      Author: user
 */

#include <net/quic/quic_spdy_stream.h>
#include <quux/client.h>
#include <quux/stream.h>

namespace quux {

Stream::Stream(net::QuicStreamId id, quux::client::Session* session, quux_c_impl* ctx) :
		ReliableQuicStream(id, session), ctx(ctx) {

	session->RegisterStreamPriority(id, net::kDefaultPriority);
	session->ActivateStream(this);
}

} // namespace quux
