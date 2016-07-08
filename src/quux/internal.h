#ifndef SRC_QUUX_INTERNAL_H_
#define SRC_QUUX_INTERNAL_H_

#include <net/quic/quic_protocol.h>
#include <quux/api.h>

namespace quux {

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

quux::client::Session* peer_session(quux_conn peer);
quux_cb c_readable_cb(quux_stream ctx);
quux_cb c_writeable_cb(quux_stream ctx);

} // namespace quux

#endif /* SRC_QUUX_INTERNAL_H_ */
