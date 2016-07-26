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
			const net::IPEndPoint& self_endpoint,
			std::set<quux_listener>* writes_ready_set, quux_listener ctx) :

			QuicDispatcher(config, crypto_config, supported_versions,
					std::move(helper), std::move(session_helper),
					std::move(alarm_factory)), sd(sd), self_endpoint(
					self_endpoint), ctx(ctx), writer(writes_ready_set, ctx) {

		InitializeWithWriter(&writer);
	}

	net::QuicServerSessionBase* CreateQuicSession(
			net::QuicConnectionId connection_id,
			const net::IPEndPoint& client_address) override {

		quux_peer conn_ctx = quux::server::session::create_context(sd, self_endpoint, client_address,
				connection_id, helper(), alarm_factory(), &writer,
				GetSupportedVersions(), config(), this, session_helper(), crypto_config(),
				compressed_certs_cache(), ctx);

		quux::server::connected_cb(ctx)(conn_ctx);

		return quux::server::session::get(conn_ctx);
	}

	const int sd;
	const net::IPEndPoint self_endpoint;
	quux_listener ctx;

	quux::server::packet::Writer writer;
};

} /* namespace quux */

#endif /* SRC_QUUX_DISPATCHER_H_ */
