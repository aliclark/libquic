#ifndef QUUX_API_H_
#define QUUX_API_H_

#ifdef __cplusplus
class quux_listener_s;
class quux_peer_s;
class quux_stream_s;
typedef class quux_listener_s* quux_listener;
typedef class quux_peer_s* quux_peer;
typedef class quux_stream_s* quux_stream;
extern "C" {

#else
typedef struct quux_listener_s* quux_listener;
typedef struct quux_peer_s* quux_peer;
typedef struct quux_stream_s* quux_stream;
#endif /* __cplusplus */

typedef void (*quux_connected)(quux_peer);
typedef void (*quux_cb)(quux_stream);

/*
 * Callbacks are triggered once when IO becomes actionable, at which point no callback will be triggered until
 * the read/write operation on that stream has returned 0.
 *
 * quux_c begins in triggered state for both read/write, which means IO can be attempted (albeit may return 0).
 *
 * XXX: perhaps instead of:
 * quux_stream quux_connect(quux_peer, quux_cb quux_readable, quux_cb quux_writeable);
 *
 * quux_stream quux_connect(quux_peer);
 */

/**
 * Initialise the module, specifying that the built in quux_loop will be used.
 */
int quux_init_loop(void);

struct event_base;

/**
 * Initialise the module, with your own libevent loop being used
 *
 * EVLOOP_ONCE *must* be used in the event_base_loop call,
 * otherwise quux's internal time cache will start to go stale.
 */
void quux_event_base_loop_init(struct event_base*);

void quux_set_peer_context(quux_peer, void* ctx);
void* quux_get_peer_context(quux_peer);

void quux_set_stream_context(quux_stream, void* ctx);
void* quux_get_stream_context(quux_stream);

#define QUUX_NO_ERR 0

/**
 * Return the most recent error major code number.
 */
int quux_errno(void);

/**
 * Human-readable English description of the error provided as a helpful utility.
 * Includes a trailing \n\0. Don't try to parse this, it may change.
 */
const char* quux_error_description(void);

void quux_reset_errno(void);

/**
 * Start a listener for new streams on IPv4 addr.
 *
 * TODO: error if there is already a server listening on ip:port
 *
 * TODO: quux_set_connected_cb instead
 *
 * quux_connected cb is called with the peer when a fresh client connects.
 */
quux_listener quux_listen(const struct sockaddr* addr, quux_connected cb);

/**
 * A handle representing an IPv4 connection to the peer.
 *
 * This will kick off the crypto handshake in the background.
 *
 * TODO: FIXME: somehow fail to connect if cert doesn't match hostname UTF8.
 */
quux_peer quux_open(const char* hostname, const struct sockaddr* addr);

/**
 * Nb. the sockaddr* will be valid for as long as the quux_peer,
 * therefore please make a copy if persistence is needed.
 */
// TODO:
// const struct sockaddr* quux_get_remote_addr(quux_peer);
// const struct sockaddr* quux_get_bind_addr(quux_peer);

/**
 * Create a new stream on the connection conn.
 *
 * ctx will automatically be supplied to the callbacks when they activate
 */
quux_stream quux_connect(quux_peer peer);

/**
 * If the accept callback is not installed then incoming streams will be rejected.
 */
void quux_set_accept_cb(quux_peer, quux_cb quux_accept);

void quux_set_readable_cb(quux_stream, quux_cb quux_readable);
void quux_set_writeable_cb(quux_stream, quux_cb quux_writeable);

/**
 * When either side has decided to both stop reading and stop writing data,
 * this function will be called.
 *
 * The stream handle is still valid at this point.
 *
 * Call quux_free to free the memory.
 */
void quux_set_closed_cb(quux_stream, quux_cb quux_closed);

quux_peer quux_get_peer(quux_stream);

/**
 * Pass up to 'count' octets from 'buf' to the stream for send.
 *
 * Returned amount tells us how much data was transfered.
 * 0 indicates that no data could be written at this time, but the callback has been re-registered.
 * Call 'quux_write_is_closed' to find out if the stream is no longer writeable.
 *
 * The initial behaviour will be that once quux_read_close();quux_write_close(); have been called,
 * it's at the discretion of the impl to wait as long as necessary to receive acks for data before tearing down.
 * At some point more functions could be added to query the status of buffered data and force remove if needed.
 */
size_t quux_write(quux_stream stream, const uint8_t* buf, size_t count);

/**
 * Indicate we don't want to write any additional data to the stream.
 */
void quux_write_close(quux_stream stream);

/**
 * 1 if the stream is fully closed, 0 otherwise.
 */
int quux_write_stream_status(quux_stream stream);

/**
 * Read up to 'count' octets from the stream into 'buf'
 *
 * Unlike quux_read, this will not consume the data from the stream,
 * so a subsequent peek or read will return the same data.
 *
 * Returned amount tells us how much data was transfered.
 * 0 indicates that no data could be read at this time, but the callback has been re-registered.
 * Call 'quux_read_is_closed' to find out if the stream is no longer readable.
 */
size_t quux_peek(quux_stream stream, uint8_t* buf, size_t count);

/**
 * Read up to 'count' octets from the stream into 'buf'
 *
 * Returned amount tells us how much data was transfered.
 * 0 indicates that no data could be read at this time, but the callback has been re-registered.
 * Call 'quux_read_is_closed' to find out if the stream is no longer readable.
 */
size_t quux_read(quux_stream stream, uint8_t* buf, size_t count);

/**
 * If 'count' octets are contiguously readable from the stream,
 * return a pointer to those octets.
 *
 * The pointer *must* be used before any further QUIC operations
 * and before the function returns, or it can become invalid.
 *
 * This function should only be used where the performance
 * overhead of memcpy might matter.
 *
 * NULL indicates that the requested amount is not available at the moment.
 * This function will not result in callbacks being reregistered in that case.
 *
 * quux_peek or quux_read should be used instead if NULL is returned,
 * since the data may be available, albeit not already in a contiguous buffer.
 *
 * Otherwise, call quux_read_consume afterwards to remove the data from input.
 */
uint8_t* quux_peek_reference(quux_stream stream, size_t count);

/**
 * Consume up to 'count' bytes from the stream input,
 * or the entirety if there was less than that amount available to read.
 */
void quux_read_consume(quux_stream stream, size_t count);

/**
 * Indicate we don't want to read any additional data from the stream.
 */
void quux_read_close(quux_stream stream);

/**
 * 1 if the stream is fully closed, 0 otherwise.
 */
int quux_read_stream_status(quux_stream stream);

/**
 * Fully close the stream and free its memory.
 *
 * After this point, the handle will point to invalid memory and must not be used.
 */
void quux_free_stream(quux_stream stream);

/**
 * Stop accepting connections
 */
void quux_shutdown(quux_listener server);

/**
 * Run the built-in epoll event loop forever.
 *
 * The function will return after timeout_ms has elapsed,
 * or never if timeout_ms is set to -1
 */
void quux_loop(void);

/**
 * Run the built-in epoll event loop.
 *
 * The function will return after timeout_ms has elapsed.
 */
// TODO: void quux_loop_with_timeout(int timeout_ms);

/**
 * Run this just after libevent wait wakes up.
 *
 * It updates the approximate time internal to QUIC.
 */
void quux_event_base_loop_before(void);

/**
 * Run this just before going into libevent wait.
 *
 * It sends any packets that were generated in the previous event loop run.
 */
void quux_event_base_loop_after(void);

#ifdef __cplusplus
}
#endif

#endif /* QUUX_API_H_ */
