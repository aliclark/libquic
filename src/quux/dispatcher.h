/*
 * Dispatcher.h
 *
 *  Created on: Jul 1, 2016
 *      Author: user
 */

#ifndef SRC_QUUX_DISPATCHER_H_
#define SRC_QUUX_DISPATCHER_H_

#include <cassert>

#include "../net/base/ip_endpoint.h"
#include "../net/quic/crypto/quic_crypto_server_config.h"
#include "../net/quic/quic_alarm_factory.h"
#include "../net/quic/quic_connection.h"
#include "../net/quic/quic_packet_writer.h"
#include "../net/quic/quic_protocol.h"
#include "../net/quic/quic_server_session_base.h"
#include "server/quic_dispatcher.h"
#include "server.h"

namespace quux {

/*
 * XXX: Unfortunately due to being descended from demo code,
 * QuicServerSessionBase is derived from QuicSpdySession even though we don't want SPDY.
 *
 * Might need to make changes from QuicDispatcher to get to what we want.
 */

class Dispatcher: public net::QuicDispatcher {
public:
	using net::QuicDispatcher::QuicDispatcher;

	net::QuicServerSessionBase* CreateQuicSession(
			net::QuicConnectionId connection_id,
			const net::IPEndPoint& client_address) override {

		// The QuicServerSessionBase takes ownership of |connection| below.
		net::QuicConnection* connection = new net::QuicConnection(connection_id,
				client_address, helper(), alarm_factory(), writer(),
				false, net::Perspective::IS_SERVER, GetSupportedVersions());

#if 0
		net::QuicServerSessionBase* session = new net::QuicSimpleServerSession(
				config_, connection, this, session_helper_.get(),
				crypto_config_, &compressed_certs_cache_);
#endif

		net::QuicServerSessionBase* session = new quux::server::Session(config(),
				connection, this, session_helper(), crypto_config(),
				compressed_certs_cache());

		return session;

		assert(0);
		return nullptr;
	}

	virtual ~Dispatcher() {
		// TODO Auto-generated destructor stub
	}
};

} /* namespace quux */

#endif /* SRC_QUUX_DISPATCHER_H_ */
