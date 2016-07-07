/*
 * stream.cc
 *
 *  Created on: Jul 4, 2016
 *      Author: user
 */

#include "stream.h"

#include "client.h"

namespace quux {

Stream::Stream(net::QuicStreamId id, quux::client::Session* session) :
		ReliableQuicStream(id, session) {

	session->RegisterStreamPriority(id, net::kDefaultPriority);
	session->ActivateStream(this);
}

} // namespace quux
