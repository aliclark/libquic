/*
 * Dispatcher.h
 *
 *  Created on: Jul 1, 2016
 *      Author: user
 */

#ifndef SRC_QUUX_DISPATCHER_H_
#define SRC_QUUX_DISPATCHER_H_

#include <net/base/ip_endpoint.h>
#include <net/quic/crypto/quic_compressed_certs_cache.h>
#include <net/quic/crypto/quic_crypto_server_config.h>
#include <net/quic/quic_alarm_factory.h>
#include <net/quic/quic_config.h>
#include <net/quic/quic_connection.h>
#include <net/quic/quic_packet_writer.h>
#include <net/quic/quic_protocol.h>
#include <net/quic/quic_server_session_base.h>
#include <quux/connection.h>
#include <quux/server/quic_dispatcher.h>
#include <quux/server.h>

namespace quux {

/*
 * XXX: Unfortunately due to being descended from demo code,
 * QuicServerSessionBase is derived from QuicSpdySession even though we don't want SPDY.
 *
 * Might need to make changes from QuicDispatcher to get to what we want.
 */

class Dispatcher: public net::QuicDispatcher {
public:
	Dispatcher(const net::QuicConfig& config,
			const net::QuicCryptoServerConfig* crypto_config,
			const net::QuicVersionVector& supported_versions,
			std::unique_ptr<net::QuicConnectionHelperInterface> helper,
			std::unique_ptr<net::QuicServerSessionBase::Helper> session_helper,
			std::unique_ptr<net::QuicAlarmFactory> alarm_factory, int sd,
			const net::IPEndPoint* self_endpoint,
			std::set<quux_listener>* writes_ready_set, quux_listener ctx) :

			sd(sd), self_endpoint(self_endpoint), writer(writes_ready_set, ctx), QuicDispatcher(
					config, crypto_config, supported_versions,
					std::move(helper), std::move(session_helper),
					std::move(alarm_factory)) {

		InitializeWithWriter(&writer);
	}

	net::QuicServerSessionBase* CreateQuicSession(
			net::QuicConnectionId connection_id,
			const net::IPEndPoint& client_address) override {

		// The QuicServerSessionBase takes ownership of |connection| below.
		net::QuicConnection* connection = new net::QuicConnection(connection_id,
				client_address, helper(), alarm_factory(), &writer,
				false, net::Perspective::IS_SERVER, GetSupportedVersions());

#if 0
		net::QuicConnectionDebugVisitor* debug_visitor =
				new quux::connection::Logger();
		connection->set_debug_visitor(debug_visitor);
#endif

#if 0
		net::QuicServerSessionBase* session = new net::QuicSimpleServerSession(
				config_, connection, this, session_helper_.get(),
				crypto_config_, &compressed_certs_cache_);
#endif

		// should know both of these
//		quux_conn_impl* conn = new quux_conn_impl(sd, self_endpoint,
//				client_address);
		// if we place this ctx on the session, we can get hold of it again for the incoming stream

		net::QuicServerSessionBase* session = new quux::server::Session(
				config(), connection, this, session_helper(), crypto_config(),
				compressed_certs_cache());

		return session;
	}

	virtual ~Dispatcher() {
		// TODO Auto-generated destructor stub
	}

	const int sd;
	const net::IPEndPoint* self_endpoint;

	quux::server::packet::Writer writer;
};

} /* namespace quux */

#endif /* SRC_QUUX_DISPATCHER_H_ */
