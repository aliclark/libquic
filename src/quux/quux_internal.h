
#ifndef SRC_QUUX_INTERNAL_H_
#define SRC_QUUX_INTERNAL_H_

namespace quux {
        namespace client {
                class Session;
        }

        quux::client::Session* peer_session(quux_p_impl*);
        quux_cb c_readable_cb(quux_c_impl* ctx);

} // namespace quux

#endif /* SRC_QUUX_INTERNAL_H_ */
