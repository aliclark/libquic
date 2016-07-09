#ifndef SRC_QUUX_INTERNAL_H_
#define SRC_QUUX_INTERNAL_H_

#include <net/quic/quic_protocol.h>
#include <quux/api.h>

namespace quux {

typedef std::set<quux_stream> CryptoConnectInterestSet;

namespace client {

class Stream;
class Session;

namespace session {

void register_stream_priority(quux::client::Session* session,
		net::QuicStreamId id);
void activate_stream(quux::client::Session* session,
		quux::client::Stream* stream);

} // namespace session

quux::client::Stream* create_stream(net::QuicStreamId id,
		quux::client::Session* session, quux_stream ctx);
net::ReliableQuicStream* create_reliable_stream(net::QuicStreamId id,
		quux::client::Session* session, quux_stream ctx);

} // namespace client

namespace server {

class Stream;
class Session;

namespace session {

void activate_stream(quux::server::Session* session,
		quux::server::Stream* stream);

} // namespace session

quux::server::Stream* create_stream(net::QuicStreamId id,
		quux::server::Session* session, quux_stream ctx);
net::QuicSpdyStream* create_spdy_stream(net::QuicStreamId id,
		quux::server::Session* session, quux_stream ctx);

} // namespace server

quux_cb c_readable_cb(quux_stream ctx);
quux_cb c_writeable_cb(quux_stream ctx);

} // namespace quux

#endif /* SRC_QUUX_INTERNAL_H_ */
