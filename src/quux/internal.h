#ifndef SRC_QUUX_INTERNAL_H_
#define SRC_QUUX_INTERNAL_H_

#include <net/quic/quic_server_session_base.h>
#include <net/quic/quic_protocol.h>
#include <quux/api.h>

class quux_peer_client_s;

namespace quux {

typedef std::set<quux_stream> CryptoConnectInterestSet;
typedef std::set<quux_peer_client_s*> WritesReadySet;

extern struct event_base *event_base;

namespace client {

class Stream;
class Session;

namespace session {

void register_stream_priority(quux::client::Session* session,
		net::QuicStreamId id);
void activate_stream(quux::client::Session* session,
		quux::client::Stream* stream);

} // namespace session

quux_stream create_incoming_stream_context(net::QuicStreamId id,
		quux::client::Session* session);
net::ReliableQuicStream* get_incoming_stream(quux_stream ctx);

} // namespace client

namespace server {

class Stream;
class Session;

namespace session {

void activate_stream(quux::server::Session* session,
		quux::server::Stream* stream);

} // namespace session

quux_peer create_peer_context(int sd, const net::IPEndPoint& self_endpoint,
		const net::IPEndPoint& client_address,
		net::QuicConnectionId connection_id,
		net::QuicConnectionHelperInterface* connection_helper,
		net::QuicAlarmFactory* alarm_factory, net::QuicPacketWriter* writer,
		const net::QuicVersionVector& supported_versions,

		const net::QuicConfig& config,
		net::QuicServerSessionBase::Visitor* visitor,
		net::QuicServerSessionBase::Helper* helper,
		const net::QuicCryptoServerConfig* crypto_config,
		net::QuicCompressedCertsCache* compressed_certs_cache,
		quux_listener listener_ctx);

net::QuicServerSessionBase* get_session(quux_peer ctx);

quux_stream create_incoming_stream_context(net::QuicStreamId id,
		quux::server::Session* session);
net::QuicSpdyStream* get_spdy_incoming_stream(quux_stream server);

} // namespace server

quux_cb c_readable_cb(quux_stream ctx);
quux_cb c_writeable_cb(quux_stream ctx);
quux_acceptable listener_acceptable_cb(quux_listener ctx);
quux_acceptable peer_acceptable_cb(quux_peer ctx);
std::list<quux_stream>* peer_acceptables(quux_peer conn);

} // namespace quux

#endif /* SRC_QUUX_INTERNAL_H_ */
