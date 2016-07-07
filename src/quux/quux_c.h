
#ifndef SRC_QUUX_C_H_
#define SRC_QUUX_C_H_

#include "api.h"
#include "stream.h"

class quux_c_impl {
public:
        explicit quux_c_impl(quux_p_impl* peer, quux_cb quux_writeable,
                             quux_cb quux_readable);

        quux_p peer;
        quux_cb quux_writeable;
        quux_cb quux_readable;
        quux::Stream stream;
        quux::client::Session* session;
};

#endif /* SRC_QUUX_C_H_ */
