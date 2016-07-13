#include <base/at_exit.h>
#include <base/command_line.h>
#include <base/logging.h>
#include <base/strings/string_piece.h>
#include <base/time/time.h>
#include <net/base/ip_endpoint.h>
#include <net/base/privacy_mode.h>
#include <net/quic/crypto/proof_verifier.h>
#include <net/quic/crypto/quic_crypto_client_config.h>
#include <net/quic/crypto/quic_crypto_server_config.h>
#include <net/quic/quic_clock.h>
#include <net/quic/quic_config.h>
#include <net/quic/quic_connection.h>
#include <net/quic/quic_protocol.h>
#include <net/quic/quic_server_id.h>
#include <net/quic/quic_simple_buffer_allocator.h>
#include <net/quic/quic_spdy_stream.h>
#include <net/quic/quic_time.h>
#include <net/quic/quic_types.h>
#include <netinet/in.h>
#include <quux/alarm.h>
#include <quux/api.h>
#include <quux/client.h>
#include <quux/connection.h>
#include <quux/dispatcher.h>
#include <quux/isaacrandom.h>
#include <quux/proof.h>
#include <quux/server.h>
#include <sys/epoll.h>
#include <sys/uio.h>
#include <unistd.h>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <map>
#include <memory>
#include <set>
#include <utility>

/*
 * XXX: Possible over-sharing of context things like packet-writer
 * - not sure if some of those are meant to be connection-specific
 *
 * TODO: comparisons against other impl to find missing things
 *
 * XXX: interesting idea: send outgoing connections from the existing "listen" socket,
 * or a dedicated "outward" socket.
 * This would mean packets for outgoing connections would also need to run through
 * a dispatcher, but would only need one recvmmsg and sendmmsg call instead of N.
 *
 * XXX: For multithreaded I'd like to have one socket per thread
 * with the "listen" socket and its connections having a dedicated thread
 * and shard self-initiated OR->OR connections over the remaining threads.
 * To be effective, this design should follow into Tor land,
 * so work for each OR->OR only happens on that thread.
 * OTOH, the same effect can be achieved using `nproc` Tor processes.
 */

namespace {

#define EVER_AND_EVER ;;

typedef const void (*cbfunc)(const net::QuicTime& approx_time, uint32_t events,
		void* ctx);

typedef struct cbpair {
	cbfunc callback;
	void* ctx;
} cbpair_t;

// Ming. Used by common_cert_sets(CommonCertSets::GetInstanceQUIC()) at least
static const base::AtExitManager exit_manager;

static const net::QuicVersionVector supported_versions(
		net::QuicSupportedVersions());

static const net::QuicWallTime NULL_WALL_TIME = net::QuicWallTime::Zero();
net::QuicWallTime cur_wall_time = NULL_WALL_TIME;
static base::TimeTicks approx_time_ticks = base::TimeTicks::Now();

// A QuicClock that only updates once per event loop run
class CacheClock: public net::QuicClock {
public:
	net::QuicTime Now() const override {
		return net::QuicTime(approx_time_ticks);
	}
	net::QuicWallTime WallNow() const override {
		if (cur_wall_time.IsZero()) {
			// const is cheated by using a global
			cur_wall_time = net::QuicWallTime::FromUNIXMicroseconds(
					base::Time::Now().ToJavaTime() * 1000);
		}
		return cur_wall_time;
	}
};

static CacheClock quic_clock;
static quux::IsaacRandom quux_random;
static net::SimpleBufferAllocator buffer_allocator;
static quux::connection::Helper helper((net::QuicClock*) &quic_clock,
		&quux_random, &buffer_allocator);

typedef std::set<quux_conn> WritesReadySet;
static WritesReadySet client_writes_ready_set;
typedef std::set<quux_listener> ListenWritesReadySet;
static ListenWritesReadySet listen_writes_ready_set;

typedef std::multimap<int64_t, quux::Alarm*> TimeToAlarmMap;
static TimeToAlarmMap time_to_alarm_map;
static quux::alarm::Factory alarm_factory(&time_to_alarm_map);

static net::ProofVerifyContext verify_context;
static quux::proof::Verifier proof_verifier;
static net::QuicCryptoClientConfig crypto_client_config(&proof_verifier);
static quux::proof::Handler proof_handler;

static base::StringPiece source_address_token_secret;
static quux::proof::Source proof_source;
static net::QuicCryptoServerConfig crypto_server_config(
		source_address_token_secret, &quux_random, &proof_source);

static net::QuicConfig create_config(void) {
	net::QuicConfig config;
	// TODO: confirm this fixes max_open_incoming/outgoing_streams to be high enough
	config.SetMaxStreamsPerConnection(65536, 0); // "lots"
	config.SetInitialStreamFlowControlWindowToSend(64 * 1024);
	config.SetInitialSessionFlowControlWindowToSend(1 * 1024 * 1024);
	return config;
}
static const net::QuicConfig config = create_config();

static const int EPOLL_SIZE_HINT = 256;
// Setting this too low could be bad for socket QoS,
// if there's a risk the same sockets kept popping up and not others?
static const int MAX_EVENTS = EPOLL_SIZE_HINT;
static const int mainepolld = epoll_create(EPOLL_SIZE_HINT);
static struct epoll_event events[MAX_EVENTS];

static const int NUM_MESSAGES = 128;
// XXX: This should be the same size as the socket recv buffer
// so we can recvmmsg the entire recv buffer in exactly one call
uint8_t buf[net::kMaxPacketSize * NUM_MESSAGES];
struct iovec iov[NUM_MESSAGES];
struct mmsghdr peer_messages[NUM_MESSAGES];
struct mmsghdr listen_messages[NUM_MESSAGES];
struct sockaddr_in listen_sockaddrs[NUM_MESSAGES];
// TODO: create a struct of the above structs for better per-packet cache locality?

static void quux_listen_cb(const net::QuicTime& approx_time, uint32_t events,
		quux_listener ctx);
static void quux_peer_cb(const net::QuicTime& approx_time, uint32_t events,
		quux_conn ctx);

} // namespace

class quux_listener_impl {
public:
	explicit quux_listener_impl(int sd, const net::IPEndPoint& self_endpoint,
			quux_cb quux_accept, quux_cb quux_writeable, quux_cb quux_readable) :

			sd(sd), self_endpoint(self_endpoint), quux_accept(quux_accept), quux_writeable(
					quux_writeable), quux_readable(quux_readable), cbp( {
					(cbfunc) quux_listen_cb, (void*) this }), dispatcher(config,
					&crypto_server_config, supported_versions,
					std::unique_ptr<quux::connection::Helper>(
							new quux::connection::Helper(&quic_clock,
									&quux_random, &buffer_allocator)),
					std::unique_ptr<quux::server::session::Helper>(
							new quux::server::session::Helper()),
					std::unique_ptr<quux::alarm::Factory>(
							new quux::alarm::Factory(&time_to_alarm_map)), sd,
					&self_endpoint, &listen_writes_ready_set, this), out_messages(
					dispatcher.writer.out_messages), num(&dispatcher.writer.num) {
	}

	const int sd;
	const net::IPEndPoint self_endpoint;
	quux_cb quux_accept;
	quux_cb quux_writeable;
	quux_cb quux_readable;
	const cbpair_t cbp;

	quux::Dispatcher dispatcher;

	// handy references
	struct mmsghdr* out_messages;
	int* num;
};

class quux_conn_impl {
public:
	// TODO: confer with connection ID creation of other impls - uses a cache thing?
	// We clear the lower bit so it can be used for reset connection ID
	explicit quux_conn_impl(int sd, const net::IPEndPoint& self_endpoint,
			const net::IPEndPoint& peer_endpoint) :
			sd(sd), self_endpoint(self_endpoint), peer_endpoint(peer_endpoint), cbp(
					{ (cbfunc) quux_peer_cb, (void*) this }), writer(
					&client_writes_ready_set, this), connection(
					net::QuicConnectionId(quux_random.RandUint64() & ~1),
					peer_endpoint, &helper, &alarm_factory, &writer,
					false, net::Perspective::IS_CLIENT, supported_versions), session(
					&connection, config,
					net::QuicServerId(peer_endpoint.ToStringWithoutPort(),
							peer_endpoint.port(), net::PRIVACY_MODE_DISABLED),
					&verify_context, &crypto_client_config, &proof_handler), out_messages(
					writer.out_messages), num(&writer.num) {

#if 0
		connection.set_debug_visitor(&debug_visitor);
#endif
	}

	const int sd;
	const net::IPEndPoint self_endpoint;
	const net::IPEndPoint peer_endpoint;
	const cbpair_t cbp;

	quux::client::packet::Writer writer;

	quux::connection::Logger debug_visitor;
	net::QuicConnection connection;
	quux::client::Session session;

	// handy references
	struct mmsghdr* out_messages;
	int* num;
};

class quux_stream_impl {
public:
	enum Type {
		SERVER, CLIENT
	};
	explicit quux_stream_impl(Type type, quux_cb quux_writeable,
			quux_cb quux_readable, bool *crypto_connected,
			quux::CryptoConnectInterestSet* cconnect_interest_set,
			bool* read_wanted) :
			type(type), quux_writeable(quux_writeable), quux_readable(
					quux_readable), crypto_connected(crypto_connected), cconnect_interest_set(
					cconnect_interest_set), read_wanted(read_wanted) {
	}

	virtual net::QuicConsumedData WritevData(const struct iovec* iov) = 0;

	virtual int Readv(const struct iovec* iov) = 0;

	virtual ~quux_stream_impl() {
	}

	Type type;

	quux_cb quux_writeable;
	quux_cb quux_readable;

	// handy references
	bool *crypto_connected;
	quux::CryptoConnectInterestSet* cconnect_interest_set;

	bool* read_wanted;
};

class quux_stream_client_impl: public quux_stream_impl {
public:
	explicit quux_stream_client_impl(quux_conn peer, quux_cb quux_writeable,
			quux_cb quux_readable) :
			quux_stream_impl(Type::CLIENT, quux_writeable, quux_readable,
					&peer->session.crypto_connected,
					&peer->session.cconnect_interest_set, &stream.read_wanted), peer(
					peer), stream(peer->session.GetNextOutgoingStreamId(),
					&peer->session, this) {
	}

	net::QuicConsumedData WritevData(const struct iovec* iov) override {
		return stream.WritevData(iov, 1, false, nullptr);
	}
	int Readv(const struct iovec* iov) override {
		return stream.Readv(iov, 1);
	}

	quux_conn peer;
	quux::client::Stream stream;
};

class quux_stream_server_impl: public quux_stream_impl {
public:
	explicit quux_stream_server_impl(net::QuicStreamId id,
			quux::server::Session* session) :
			quux_stream_impl(Type::SERVER,
					session->listener_ctx->quux_writeable,
					session->listener_ctx->quux_readable,
					&server_crypto_connected, &server_cconnect_interest_set,
					&stream.read_wanted), stream(id, session, this) {
	}

	net::QuicConsumedData WritevData(const struct iovec* iov) override {
		return stream.WritevData(iov, 1, false, nullptr);
	}
	int Readv(const struct iovec* iov) override {
		return stream.Readv(iov, 1);
	}

	// crypto is necessarily already set up for server streams
	bool server_crypto_connected = true;
	quux::CryptoConnectInterestSet server_cconnect_interest_set;

	quux::server::Stream stream;
};

namespace quux {

namespace client {

namespace session {

void register_stream_priority(quux::client::Session* session,
		net::QuicStreamId id) {
	session->RegisterStreamPriority(id, net::kDefaultPriority);
}
void activate_stream(quux::client::Session* session,
		quux::client::Stream* stream) {
	session->ActivateStream(stream);
}

} // namespace session

quux::client::Stream* create_stream(net::QuicStreamId id,
		quux::client::Session* session, quux_stream ctx) {
	return new quux::client::Stream(id, session, ctx);
}
net::ReliableQuicStream* create_reliable_stream(net::QuicStreamId id,
		quux::client::Session* session, quux_stream ctx) {
	return create_stream(id, session, ctx);
}

} // namespace client

namespace server {

namespace session {

void activate_stream(quux::server::Session* session,
		quux::server::Stream* stream) {
	session->ActivateStream(stream);
}

} // namespace session

quux_stream_impl* create_stream_context(net::QuicStreamId id,
		quux::server::Session* session) {
	return new quux_stream_server_impl(id, session);
}
net::QuicSpdyStream* get_spdy_stream(quux_stream ctx) {
	if (ctx->type != quux_stream_impl::SERVER) {
		assert(0);
		return nullptr;
	}
	quux_stream_server_impl* server = (quux_stream_server_impl*) ctx;
	return &server->stream;
}

} // namespace server

quux_cb c_readable_cb(quux_stream ctx) {
	return ctx->quux_readable;
}
quux_cb c_writeable_cb(quux_stream ctx) {
	return ctx->quux_writeable;
}
quux_cb listener_accept_cb(quux_listener ctx) {
	return ctx->quux_accept;
}

} // namespace quux

namespace {

// Called *often*
static void quux_listen_cb(const net::QuicTime& approx_time, uint32_t events,
		quux_listener ctx) {

	quux::Dispatcher& dispatcher = ctx->dispatcher;
	const net::IPEndPoint& self_endpoint = ctx->self_endpoint;
	net::IPEndPoint peer_endpoint;

	int num = recvmmsg(ctx->sd, listen_messages, NUM_MESSAGES, 0, nullptr);

	for (int i = 0; i < num; ++i) {
		net::QuicReceivedPacket packet((char*) iov[i].iov_base,
				listen_messages[i].msg_len, approx_time);
		(void) peer_endpoint.FromSockAddr(
				(struct sockaddr*) &listen_sockaddrs[i],
				sizeof(struct sockaddr_in));
		dispatcher.ProcessPacket(self_endpoint, peer_endpoint, packet);
	}
}

// Called *often*
static void quux_peer_cb(const net::QuicTime& approx_time, uint32_t events,
		quux_conn ctx) {

	net::QuicConnection& connection = ctx->connection;
	const net::IPEndPoint& self_endpoint = ctx->self_endpoint;
	const net::IPEndPoint& peer_endpoint = ctx->peer_endpoint;

	int num = recvmmsg(ctx->sd, peer_messages, NUM_MESSAGES, 0, nullptr);

	for (int i = 0; i < num; ++i) {
		net::QuicReceivedPacket packet((char*) iov[i].iov_base,
				peer_messages[i].msg_len, approx_time);

		connection.ProcessUdpPacket(self_endpoint, peer_endpoint, packet);
	}
}

} // namespace

int quux_init(void) {

	if (mainepolld == -1) {
		return -1;
	}

	for (int i = 0; i < NUM_MESSAGES; ++i) {
		// used by both peer and listen messages, not at same time
		iov[i].iov_base = (void*) &buf[net::kMaxPacketSize * i];
		iov[i].iov_len = net::kMaxPacketSize;

		peer_messages[i].msg_hdr.msg_iov = &iov[i];
		peer_messages[i].msg_hdr.msg_iovlen = 1;

		// XXX: this assumes IPv4
		listen_messages[i].msg_hdr.msg_name = (void*) &listen_sockaddrs[i];
		listen_messages[i].msg_hdr.msg_namelen = sizeof(struct sockaddr_in);
		listen_messages[i].msg_hdr.msg_iov = &iov[i];
		listen_messages[i].msg_hdr.msg_iovlen = 1;
	}

#if 0
	// required for logging
	base::CommandLine::Init(0, nullptr);

	char logName[255];
	snprintf(logName, 255, "/tmp/quicsock.log.%d", getpid());

	logging::LoggingSettings settings;
	settings.logging_dest = logging::LOG_TO_ALL;
	settings.log_file = logName;
	settings.lock_log = logging::LOCK_LOG_FILE;
	settings.delete_old = logging::DELETE_OLD_LOG_FILE;
	logging::InitLogging(settings);
	logging::SetMinLogLevel(-1);
#endif

	crypto_server_config.AddDefaultConfig(helper.GetRandomGenerator(),
			helper.GetClock(), net::QuicCryptoServerConfig::ConfigOptions());

	return 0;
}

quux_listener quux_listen(const struct sockaddr* self_sockaddr,
		quux_cb quux_accept, quux_cb quux_writeable, quux_cb quux_readable) {

	// Possible support for INET6 in future
	if (self_sockaddr->sa_family != AF_INET) {
		printf("Sorry, socket type currently unsupported\n");
		return nullptr;
	}
	socklen_t self_sockaddr_len = sizeof(struct sockaddr_in);

	int sd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
	if (sd < 0) {
		printf("%s", strerror(errno));
		return nullptr;
	}

	if (bind(sd, self_sockaddr, self_sockaddr_len) < 0) {
		printf("%s", strerror(errno));
		return nullptr;
	}

	net::IPEndPoint self_endpoint;
	if (!self_endpoint.FromSockAddr(self_sockaddr, self_sockaddr_len)) {
		return nullptr;
	}

	quux_listener ctx = new quux_listener_impl(sd, self_endpoint, quux_accept,
			quux_writeable, quux_readable);

	struct epoll_event ev = { EPOLLIN, { (void*) &ctx->cbp } };
	if (epoll_ctl(mainepolld, EPOLL_CTL_ADD, sd, &ev) < 0) {
		printf("%s", strerror(errno));
		return nullptr;
	}

	return ctx;
}

quux_conn quux_peer(const struct sockaddr* peer_sockaddr) {

	// Possible support for INET6 in future
	if (peer_sockaddr->sa_family != AF_INET) {
		printf("Sorry, socket type currently unsupported\n");
		return nullptr;
	}
	socklen_t peer_sockaddr_len = sizeof(struct sockaddr_in);

	/* create the client socket and get a socket descriptor */
	int sd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
	if (sd < 0) {
		printf("%s", strerror(errno));
		return nullptr;
	}

	struct sockaddr_in self_sockaddr = { AF_INET, 0, { 0 } };
	socklen_t self_sockaddr_len = sizeof(self_sockaddr);

	// set address for recvmmsg to use
	if (bind(sd, (struct sockaddr*) &self_sockaddr, self_sockaddr_len) < 0) {
		printf("%s", strerror(errno));
		return nullptr;
	}

	// set address for sendmmsg to use
	if (connect(sd, peer_sockaddr, peer_sockaddr_len) < 0) {
		printf("%s", strerror(errno));
		return nullptr;
	}

	if (getsockname(sd, (struct sockaddr*) &self_sockaddr, &self_sockaddr_len)
			< 0) {
		printf("%s", strerror(errno));
		return nullptr;
	}

	net::IPEndPoint self_endpoint;
	net::IPEndPoint peer_endpoint;

	if (!self_endpoint.FromSockAddr((struct sockaddr*) &self_sockaddr,
			self_sockaddr_len)) {
		return nullptr;
	}
	if (!peer_endpoint.FromSockAddr(peer_sockaddr, peer_sockaddr_len)) {
		return nullptr;
	}

	quux_conn ctx = new quux_conn_impl(sd, self_endpoint, peer_endpoint);

	struct epoll_event ev = { EPOLLIN, { (void*) &ctx->cbp } };
	if (epoll_ctl(mainepolld, EPOLL_CTL_ADD, sd, &ev) < 0) {
		return nullptr;
	}

	return ctx;
}

quux_stream quux_connect(quux_conn peer, quux_cb quux_writeable,
		quux_cb quux_readable) {

	return new quux_stream_client_impl(peer, quux_writeable, quux_readable);
}

void quux_write_please(quux_stream stream) {
	if (!*stream->crypto_connected) {
		stream->cconnect_interest_set->insert(stream);
		return;
	}

	// FIXME: If we already think the stream is writeable, callback immediately,
	// else just set write_wanted without callback
	//*stream->write_wanted = true;

	stream->quux_writeable(stream);
}

ssize_t quux_write(quux_stream stream, const struct iovec* iov) {
	if (!*stream->crypto_connected) {
		stream->cconnect_interest_set->insert(stream);
		return 0;
	}

	net::QuicConsumedData consumed(stream->WritevData(iov));

	if (consumed.bytes_consumed == 0) {
		// FIXME: add a callback for the flow controller and whatever
		// else becoming unblocked
	}

	// XXX: somehow indicate the socket as needing flush

	return consumed.bytes_consumed;
}

void quux_write_close(quux_stream stream) {

}

void quux_read_please(quux_stream stream) {

	// FIXME: If we already think the stream is readable, callback immediately,
	// else just set read_wanted without doing the callback
	//*stream->read_wanted = true;

	stream->quux_readable(stream);
}

ssize_t quux_read(quux_stream stream, struct iovec* iov) {
	int data_read = stream->Readv(iov);
	if (data_read == 0) {
		// re-register an interest in reading
		*stream->read_wanted = true;
	}
	return data_read;
}

void quux_read_close(quux_stream stream) {

}

// TODO: we may want to give special consideration to the 'listen' fd,
// since it is likely to send/recv traffic at a greater rate than connections we initiate ourself
//
// Is there any gain from doing things in passes, like timeouts have priority?
// What does QoS mean in the context of timeouts,reads,writes?
//
// We should map events to streams early, then QoS within those,
// but presumably very costly to determine the stream cryptographic-ally
void quux_loop(void) {
	int ed = mainepolld;

	approx_time_ticks = base::TimeTicks::Now();
	int64_t approx_micros = approx_time_ticks.ToInternalValue();

	// An empty loop runs in ~4 micros on my machine (~250k/s)
	// including gettime(), epoll_wait(0ms) and printf
	for (EVER_AND_EVER) {
		// Run *often*. timers, out/ingoing packets, out/ingoing app data

		// The aim is to read all datagrams off sockets immediately and ply those into the QuicConnections
		// (which should promptly drop if the decrypted packet is for a stream that is already full)
		// If a stream is constantly busy, it *should* slow down as we start dropping the packets.
		// Otherwise, a spoofer may be sending large packets to us, but there's nothing we can do
		// before a (rudimentary) ip:port check
		//
		// This means that like a network card, the udp socket recv buffers can actually be quite small,
		// just big enough that they won't fill in the time between loop runs.
		// The internal quic stream buffers should have buffers comparable with TCP conns,
		// eg. 8Mbit*250ms = 256KB per stream

		// default to an infinite timeout if the alarm map is empty
		int wake_after_millis = -1;
		bool has_fired = false;

		TimeToAlarmMap::iterator end = time_to_alarm_map.end();
		for (TimeToAlarmMap::iterator it = time_to_alarm_map.begin(); it != end;
				) {

			// XXX: hopefully the time recorded after epoll_wait
			// is still accurate enough to trigger most of the alarms now,
			// and not skew us too far into future
			wake_after_millis = (it->first - approx_micros) / 1000;

			// Nb. we include == 0 because the division above would wipe of 999 surplus micros,
			// leading to up to a millisecond early firing of the timer.
			// Instead the behaviour now will be to loop until at least that time has passed,
			// plus whatever time the loop took to run.
			if (wake_after_millis >= 0) {
				break;
			}

			has_fired = true;
			TimeToAlarmMap::iterator prev = it++;
			prev->second->Fire();
			time_to_alarm_map.erase(prev);
		}

		// There may have been new alarms added in the loop run above.
		// We continue with the event loop so we can do some other stuff like read and write
		// sockets if they're ready, but we need to set an earlier timeout
		// for any new alarms to fire at the right time.
		if (has_fired) {
			TimeToAlarmMap::iterator it = time_to_alarm_map.begin();
			if (it != time_to_alarm_map.end()) {
				wake_after_millis = it->first - approx_micros;
				if (wake_after_millis > 0) {
					wake_after_millis /= 1000;
				} else {
					// wake up immediately. this is still useful because
					// epoll will also tell us the readable fd's at that time
					wake_after_millis = 0;
				}
			} else {
				// all alarms have been fired and none added
				wake_after_millis = -1;
			}
		}

		// XXX: After this point we don't have any code that could set a timer

		for (auto& peer : client_writes_ready_set) {
			sendmmsg(peer->sd, peer->out_messages, *peer->num, 0);
			// XXX: for now we just drop anything that didn't successfully send
			*peer->num = 0;
		}
		client_writes_ready_set.clear();

		for (auto& ctx : listen_writes_ready_set) {
			sendmmsg(ctx->sd, ctx->out_messages, *ctx->num, 0);
			// XXX: for now we just drop anything that didn't successfully send
			*ctx->num = 0;
		}
		listen_writes_ready_set.clear();

		// XXX: millisecond resolution of alarms is ok because with division 999micros -> 0ms.
		// The worst case is that we poll quite heavily for the 999micros up to each alarm
		int nReadyFDs = epoll_wait(ed, events, MAX_EVENTS, wake_after_millis);

		// XXX: hopefully this is still accurate enough by the end of the loop
		// nb. also used by the timer loop run above
		approx_time_ticks = base::TimeTicks::Now();
		approx_micros = approx_time_ticks.ToInternalValue();
		net::QuicTime approx_quictime(approx_time_ticks);
		// not always needed, so let it be lazily generated later
		cur_wall_time = NULL_WALL_TIME;

		for (int i = 0; i < nReadyFDs; i++) {
			struct cbpair* pair = (struct cbpair*) events[i].data.ptr;
			pair->callback(approx_quictime, events[i].events, pair->ctx);
		}
	}
}

void quux_shutdown(quux_listener server) {

}
