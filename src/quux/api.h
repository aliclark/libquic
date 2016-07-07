#ifndef SRC_QUUX_API_H_
#define SRC_QUUX_API_H_

#include <sys/socket.h>
#include <stdio.h>

class quux_c_impl;
class quux_p_impl;
class quux_s_impl;

#ifdef __cplusplus
typedef const class quux_s_impl* quux_s;
typedef const class quux_c_impl* quux_c;
typedef const class quux_p_impl* quux_p;
extern "C" {

#else
typedef const struct quux_s_impl* quux_s;
typedef const struct quux_c_impl* quux_c;
typedef const struct quux_p_impl* quux_p;
#endif // __cplusplus

typedef const void (*quux_cb)(quux_c_impl*);

/*
 * Callbacks are triggered once when IO becomes actionable, at which point no callback will be triggered until
 * the read/write operation on that stream has returned 0.
 *
 * quux_c begins in triggered state for both read/write, which means IO can be attempted (albeit may return 0).
 *
 * quux_read_please();quux_read_please(); can be used to register the callbacks
 * without attempting IO.
 */

/**
 * Initialise the module
 */
bool quux_init(void);

/**
 * Register listener for new streams on IPv4 ip:port
 *
 * quux_accept is called when a fresh client connects.
 *
 * TODO: error if there is already a server listening on ip:port
 */
quux_s quux_listen(const struct sockaddr* self, quux_cb quux_accept,
		quux_cb quux_writeable, quux_cb quux_readable);

/**
 * A handle representing an IPv4 connection to the peer
 */
quux_p_impl* quux_peer(const struct sockaddr* peer);

/**
 * Create a new stream with the peer
 */
quux_c_impl* quux_connect(quux_p_impl* peer, quux_cb quux_writeable,
		quux_cb quux_readable);

/**
 * Pass up to iov->iov_len from iov->iov_base to the stream for send.
 *
 * Returned amount tells us how much data was transfered.
 * 0 indicates that no data could be written at this time, but the callback has been re-registered.
 * -1 indicates that the write stream is closed.
 *
 * The initial behaviour will be that once quux_read_close();quux_write_close(); have been called,
 * it's at the discretion of the impl to wait as long as necessary to receive acks for data before tearing down.
 * At some point more functions could be added to query the status of buffered data and force remove if needed.
 */
ssize_t quux_write(quux_c_impl* stream, const struct iovec* iov);

/**
 * Re-registers the callback
 */
void quux_write_please(quux_c_impl* stream);

/**
 * Indicate we don't want to write any additional data to the stream.
 */
void quux_write_close(quux_c stream);

/**
 * Read up to iov->iov_len amount of data from the stream into iov->iov_base
 *
 * Returned amount tells us how much data was transfered.
 * 0 indicates that no data could be read at this time, but the callback has been re-registered.
 * -1 indicates that the read stream is closed.
 */
ssize_t quux_read(quux_c stream, struct iovec* iov);

/**
 * Re-registers the callback
 */
void quux_read_please(quux_c_impl* stream);

/**
 * Indicate we don't want to read any additional data from the stream.
 */
void quux_read_close(quux_c stream);

/**
 * Stop accepting connections
 */
void quux_shutdown(quux_s server);

/**
 * Do a single event loop run
 */
void quux_loop(void);

#ifdef __cplusplus
}
#endif

#endif /* SRC_QUUX_API_H_ */
