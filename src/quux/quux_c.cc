
#include "quux_c.h"
#include "client.h"
#include "quux_internal.h"

quux_c_impl::quux_c_impl(quux_p_impl* peer, quux_cb quux_writeable,
                         quux_cb quux_readable) :
        peer(peer), quux_writeable(quux_writeable), quux_readable(
                quux_readable), stream(
                        quux::peer_session(peer)->GetNextOutgoingStreamId(), quux::peer_session(peer)), session(quux::peer_session(peer)) {
}
