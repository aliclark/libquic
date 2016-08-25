#ifndef SRC_QUUX_INTERNAL_H_
#define SRC_QUUX_INTERNAL_H_

#include <net/quic/quic_server_session_base.h>
#include <net/quic/quic_protocol.h>
#include <quux/quux.h>

class quux_peer_client_s;

namespace quux {

typedef std::set<quux_stream> CryptoConnectInterestSet;
typedef std::set<quux_peer_client_s*> WritesReadySet;

int64_t get_now_clock_micros(void);

void log(const char* format, ...);

quux_cb accept_cb(quux_peer ctx);
quux_cb readable_cb(quux_stream ctx);
quux_cb writeable_cb(quux_stream ctx);

void set_stream_closed(quux_stream ctx);

bool* read_wanted_ref(quux_stream ctx);
bool* write_wanted_ref(quux_stream ctx);

void set_peer_closed(quux_peer ctx);

extern struct event_base *event_base;

namespace server {

class Session;
class Stream;

quux_connected connected_cb(quux_listener ctx);

namespace session {

quux_peer create_context(int sd, const net::IPEndPoint& self_endpoint,
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

net::QuicServerSessionBase* get(quux_peer ctx);

void activate_stream(quux::server::Session* session, quux::server::Stream* stream);

} // namespace session

namespace stream {

quux_stream create_incoming_context(net::QuicStreamId id, quux::server::Session* session);
net::QuicSpdyStream* get_incoming_spdy(quux_stream server);

} // namespace stream

} // namespace server

namespace client {

class Stream;
class Session;

namespace session {

void register_stream(quux::client::Session* session,
		net::QuicStreamId id);
void unregister_stream(quux::client::Session* session,
		net::QuicStreamId id);
void activate_stream(quux::client::Session* session,
		quux::client::Stream* stream);

} // namespace session

namespace stream {

quux_stream create_incoming_context(net::QuicStreamId id, quux::client::Session* session);
net::ReliableQuicStream* get_incoming(quux_stream ctx);

} // namespace stream

} // namespace client

} // namespace quux

#endif /* SRC_QUUX_INTERNAL_H_ */
