#include <fcntl.h>
#include <stddef.h>
#include <sys/socket.h>
#include <cassert>
#include <cstdio>

#define SHADOW_NO

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
#include <quux/quux.h>
#include <quux/client.h>
#include <quux/connection.h>
#include <quux/dispatcher.h>
#include <quux/isaacrandom.h>
#include <quux/internal.h>
#include <quux/proof.h>
#include <quux/server.h>
#include <quux/internal.h>
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
#include <stdarg.h>

/*
 * TODO: comparisons against other impl to find missing things
 *
 * TODO: send outgoing connections from the existing "listen" socket,
 * or a dedicated "outward" socket.
 * This would mean packets for outgoing connections would also need to run through
 * a dispatcher, but would only need one recvmmsg and sendmmsg call instead of N.
 * If we continue to ignore IP migration, that could be done by keeping a map of
 * peer_ip:port -> listener|peer
 *
 * Recommended usage for multithreaded:
 * Spawn 1 process for each core with its own listener on a unique port;
 * If only a single port can be advertised, use iptables to load balance
 * incoming packets based on the other ip:port address.
 */

namespace {

#define EVER_AND_EVER ;;

typedef const void (*cbfunc)(const net::QuicTime& approx_time, void* ctx);

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
	CacheClock() {
	}
	net::QuicTime ApproximateNow() const override {
		if (approx_time_ticks.is_null()) {
			approx_time_ticks = base::TimeTicks::Now();
		}
		return net::QuicTime(approx_time_ticks);
	}
	net::QuicTime Now() const override {
		return ApproximateNow();
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

static const CacheClock quic_clock;
static quux::IsaacRandom quux_random;
static net::SimpleBufferAllocator buffer_allocator;
static quux::connection::Helper helper((net::QuicClock*) &quic_clock,
		&quux_random, &buffer_allocator);

static quux::WritesReadySet client_writes_ready_set;
typedef std::set<quux_listener> ListenWritesReadySet;
static ListenWritesReadySet listen_writes_ready_set;

static quux::TimeToAlarmMap time_to_alarm_map;
static quux::alarm::Factory alarm_factory(&time_to_alarm_map);
static quux::alarm::LibeventFactory libevent_alarm_factory;

static net::ProofVerifyContext verify_context;
static net::QuicCryptoClientConfig crypto_client_config(new quux::proof::Verifier());
static quux::proof::Handler proof_handler;

static base::StringPiece source_address_token_secret;
static net::QuicCryptoServerConfig crypto_server_config(
		source_address_token_secret, &quux_random, new quux::proof::Source());

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
// Storage large enough for IPv6, but can be used for IPv4
struct sockaddr_in6 listen_sockaddrs[NUM_MESSAGES];
// TODO: create a struct of the above structs for better per-packet cache locality?

static int q_errno = QUUX_NO_ERR;

static FILE* log_fileh = stderr;

static void quux_listen_cb(const net::QuicTime& approx_time, quux_listener ctx);
static void quux_peer_cb(const net::QuicTime& approx_time,
		quux_peer_client_s* ctx);

} // namespace

class quux_listener_s {
public:
	explicit quux_listener_s(int sd, const net::IPEndPoint& self_endpoint,
			quux_connected connected_cb) :

			sd(sd), self_endpoint(self_endpoint), connected_cb(connected_cb), cbp(
					{ (cbfunc) quux_listen_cb, (void*) this }), dispatcher(
					config, &crypto_server_config, supported_versions,
					std::unique_ptr<quux::connection::Helper>(
							new quux::connection::Helper(&quic_clock,
									&quux_random, &buffer_allocator)),
					std::unique_ptr<quux::server::session::Helper>(
							new quux::server::session::Helper()),
					std::unique_ptr<net::QuicAlarmFactory>(
							quux::event_base ?
									(net::QuicAlarmFactory*) new quux::alarm::LibeventFactory() :
									(net::QuicAlarmFactory*) new quux::alarm::Factory(
											&time_to_alarm_map)), sd,
					self_endpoint, &listen_writes_ready_set, this), out_messages(
					dispatcher.writer.out_messages), num(&dispatcher.writer.num) {
	}

	const int sd;
	const net::IPEndPoint self_endpoint;
	quux_connected const connected_cb;
	const cbpair_t cbp;

	quux::Dispatcher dispatcher;

	// handy references
	struct mmsghdr* const out_messages;
	int* const num;
};

class quux_peer_s {
public:
	enum Type {
		SERVER, CLIENT
	};
	// TODO: confer with connection ID creation of other impls - uses a cache thing?
	// We clear the lower bit so it can be used for reset connection ID
	explicit quux_peer_s(Type type, int sd,
			const net::IPEndPoint& self_endpoint,
			const net::IPEndPoint& peer_endpoint) :
			type(type), sd(sd), self_endpoint(self_endpoint), peer_endpoint(
					peer_endpoint), accept_cb(nullptr), arg(nullptr) {
	}

	virtual ~quux_peer_s() {
	}

	const Type type;

	const int sd;
	const net::IPEndPoint self_endpoint;
	const net::IPEndPoint peer_endpoint;

	quux_cb accept_cb;

	// handy slot for application code to associate an arbitrary structure
	void* arg;
};

class quux_peer_client_s: public quux_peer_s {
public:
	explicit quux_peer_client_s(int sd, const net::IPEndPoint& self_endpoint,
			const net::IPEndPoint& peer_endpoint) :
			quux_peer_s(Type::CLIENT, sd, self_endpoint, peer_endpoint), cbp( {
					(cbfunc) quux_peer_cb, (void*) this }), writer(
					&client_writes_ready_set, this), connection(
					net::QuicConnectionId(quux_random.RandUint64() & ~1),
					peer_endpoint, &helper,
					quux::event_base ?
							(net::QuicAlarmFactory*) &libevent_alarm_factory :
							(net::QuicAlarmFactory*) &alarm_factory, &writer,
					false, net::Perspective::IS_CLIENT, supported_versions), session(
					&connection, config,
					net::QuicServerId(peer_endpoint.ToStringWithoutPort(),
							peer_endpoint.port(), net::PRIVACY_MODE_DISABLED),
					&verify_context, &crypto_client_config, &proof_handler, this), out_messages(
					writer.out_messages), num(&writer.num) {
#if 0
		connection.set_debug_visitor(&debug_visitor);
#endif
	}

	const cbpair_t cbp;

	quux::client::packet::Writer writer;

	quux::connection::Logger debug_visitor;
	net::QuicConnection connection;
	quux::client::Session session;

	// handy references
	struct mmsghdr* const out_messages;
	int* const num;
};

class quux_peer_server_s: public quux_peer_s {
public:
	explicit quux_peer_server_s(int sd, const net::IPEndPoint& self_endpoint,
			const net::IPEndPoint& peer_endpoint,

			net::QuicConnectionId connection_id,
			net::QuicConnectionHelperInterface* connection_helper,
			net::QuicAlarmFactory* alarm_factory, net::QuicPacketWriter* writer,
			const net::QuicVersionVector& supported_versions,

			const net::QuicConfig& config,
			net::QuicServerSessionBase::Visitor* visitor,
			net::QuicServerSessionBase::Helper* helper,
			const net::QuicCryptoServerConfig* crypto_server_config,
			net::QuicCompressedCertsCache* compressed_certs_cache,
			quux_listener listener_ctx) :

			quux_peer_s(Type::SERVER, sd, self_endpoint, peer_endpoint), connection(
					connection_id, peer_endpoint, connection_helper,
					alarm_factory, writer,
					false, net::Perspective::IS_SERVER, supported_versions), session(
					config, &connection, visitor, helper, crypto_server_config,
					compressed_certs_cache, listener_ctx, this) {
#if 0
		connection->set_debug_visitor(&debug_visitor);
#endif
	}

	quux::connection::Logger debug_visitor;
	net::QuicConnection connection;
	quux::server::Session session;
};

class quux_stream_s {
public:
	enum Type {
		SERVER, CLIENT
	};
	explicit quux_stream_s(Type type, quux_peer peer, bool *crypto_connected,
			quux::CryptoConnectInterestSet* cconnect_interest_set,
			bool* read_wanted, bool* write_wanted) :
			type(type), peer(peer), quux_writeable(nullptr), quux_readable(
					nullptr), crypto_connected(crypto_connected), cconnect_interest_set(
					cconnect_interest_set), read_wanted(read_wanted), write_wanted(write_wanted), arg(
					nullptr) {
	}

	virtual net::QuicConsumedData WritevData(const struct iovec* iov) = 0;

	virtual int Readv(const struct iovec* iov) = 0;

	virtual void StopReading() = 0;
	virtual void CloseWriteSide() = 0;

	virtual ~quux_stream_s() {
	}

	const Type type;

	quux_peer const peer;

	quux_cb quux_writeable;
	quux_cb quux_readable;

	// handy references
	bool* const crypto_connected;
	quux::CryptoConnectInterestSet* const cconnect_interest_set;

	bool* const read_wanted;
	bool* const write_wanted;

	// handy slot for application code to associate an arbitrary structure
	void* arg;
};

class quux_stream_client_s: public quux_stream_s {
public:
	explicit quux_stream_client_s(quux_peer_client_s* peer) :
			quux_stream_s(Type::CLIENT, peer,
					&peer->session.crypto_connected,
					&peer->session.cconnect_interest_set, &stream.read_wanted, &stream.write_wanted),
					stream(peer->session.GetNextOutgoingStreamId(),
					&peer->session, this) {
	}

	net::QuicConsumedData WritevData(const struct iovec* iov) override {
		return stream.WritevData(iov, 1, false, nullptr);
	}
	int Readv(const struct iovec* iov) override {
		return stream.Readv(iov, 1);
	}
	void StopReading() override {
		stream.StopReading();
	}
	void CloseWriteSide() override {
		stream.CloseWriteSide();
	}

	quux::client::Stream stream;
};

class quux_stream_server_s: public quux_stream_s {
public:
	explicit quux_stream_server_s(quux_peer_server_s* peer) :
			quux_stream_s(Type::CLIENT, peer,
					&server_crypto_connected, &server_cconnect_interest_set,
					&stream.read_wanted, &stream.write_wanted), stream(
					peer->session.GetNextOutgoingStreamId(), &peer->session,
					this) {
	}

	net::QuicConsumedData WritevData(const struct iovec* iov) override {
		return stream.WritevData(iov, 1, false, nullptr);
	}
	int Readv(const struct iovec* iov) override {
		return stream.Readv(iov, 1);
	}
	void StopReading() override {
		stream.StopReading();
	}
	void CloseWriteSide() override {
		stream.CloseWriteSide();
	}

	bool server_crypto_connected = true;
	quux::CryptoConnectInterestSet server_cconnect_interest_set;

	quux::server::Stream stream;
};

class quux_stream_client_incoming_s: public quux_stream_s {
public:
	explicit quux_stream_client_incoming_s(net::QuicStreamId id,
			quux::client::Session* session) :
			quux_stream_s(Type::CLIENT, session->peer_ctx,
					&server_crypto_connected, &server_cconnect_interest_set,
					&stream.read_wanted, &stream.write_wanted), stream(id, session, this) {
	}

	net::QuicConsumedData WritevData(const struct iovec* iov) override {
		return stream.WritevData(iov, 1, false, nullptr);
	}
	int Readv(const struct iovec* iov) override {
		return stream.Readv(iov, 1);
	}
	void StopReading() override {
		stream.StopReading();
	}
	void CloseWriteSide() override {
		stream.CloseWriteSide();
	}

	// crypto is necessarily already set up for incoming streams
	bool server_crypto_connected = true;
	quux::CryptoConnectInterestSet server_cconnect_interest_set;

	quux::client::Stream stream;
};

class quux_stream_server_incoming_s: public quux_stream_s {
public:
	explicit quux_stream_server_incoming_s(net::QuicStreamId id,
			quux::server::Session* session) :
			quux_stream_s(Type::SERVER, session->peer_ctx,
					&server_crypto_connected, &server_cconnect_interest_set,
					&stream.read_wanted, &stream.write_wanted), stream(id, session, this) {
	}

	net::QuicConsumedData WritevData(const struct iovec* iov) override {
		return stream.WritevData(iov, 1, false, nullptr);
	}
	int Readv(const struct iovec* iov) override {
		return stream.Readv(iov, 1);
	}
	void StopReading() override {
		stream.StopReading();
	}
	void CloseWriteSide() override {
		stream.CloseWriteSide();
	}

	// crypto is necessarily already set up for incoming streams
	bool server_crypto_connected = true;
	quux::CryptoConnectInterestSet server_cconnect_interest_set;

	quux::server::Stream stream;
};

namespace quux {

void log(const char *format, ...) {
	va_list ap;
	va_start(ap, format);
	vfprintf(log_fileh, format, ap);
	va_end(ap);
}

int64_t get_now_clock_micros(void) {
	if (approx_time_ticks.is_null()) {
		approx_time_ticks = base::TimeTicks::Now();
	}
	return approx_time_ticks.ToInternalValue();
}

quux_cb accept_cb(quux_peer ctx) {
	return ctx->accept_cb;
}
quux_cb readable_cb(quux_stream ctx) {
	return ctx->quux_readable;
}
quux_cb writeable_cb(quux_stream ctx) {
	return ctx->quux_writeable;
}

// This will be set if we're using libevent
struct event_base *event_base;

namespace server {

quux_connected connected_cb(quux_listener ctx) {
	return ctx->connected_cb;
}

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
		const net::QuicCryptoServerConfig* crypto_server_config,
		net::QuicCompressedCertsCache* compressed_certs_cache,
		quux_listener listener_ctx) {

	return new quux_peer_server_s(sd, self_endpoint, client_address,
			connection_id, connection_helper, alarm_factory, writer,
			supported_versions, config, visitor, helper,
			crypto_server_config, compressed_certs_cache, listener_ctx);
}

net::QuicServerSessionBase* get(quux_peer ctx) {
	if (ctx->type != quux_peer_s::SERVER) {
		assert(0);
		return nullptr;
	}
	quux_peer_server_s* peer = (quux_peer_server_s*) ctx;
	return &peer->session;
}

void activate_stream(quux::server::Session* session, quux::server::Stream* stream) {
	session->ActivateStream(stream);
}

} // namespace session

namespace stream {

quux_stream create_incoming_context(net::QuicStreamId id,
		quux::server::Session* session) {
	return new quux_stream_server_incoming_s(id, session);
}
net::QuicSpdyStream* get_incoming_spdy(quux_stream ctx) {
	if (ctx->type != quux_stream_s::SERVER) {
		assert(0);
		return nullptr;
	}
	quux_stream_server_incoming_s* server = (quux_stream_server_incoming_s*) ctx;
	return &server->stream;
}

} // namespace stream

} // namespace server

namespace client {

namespace session {

void register_stream(quux::client::Session* session,
		net::QuicStreamId id) {
	session->RegisterStream(id, net::kDefaultPriority);
}
void unregister_stream(quux::client::Session* session,
		net::QuicStreamId id) {
	session->UnregisterStream(id);
}
void activate_stream(quux::client::Session* session,
		quux::client::Stream* stream) {
	session->ActivateStream(stream);
}

} // namespace session

namespace stream {

quux_stream create_incoming_context(net::QuicStreamId id,
		quux::client::Session* session) {
	return new quux_stream_client_incoming_s(id, session);
}
net::ReliableQuicStream* get_incoming(quux_stream ctx) {
	if (ctx->type != quux_stream_s::CLIENT) {
		assert(0);
		return nullptr;
	}
	quux_stream_client_incoming_s* client = (quux_stream_client_incoming_s*) ctx;
	return &client->stream;
}

} // namespace stream

} // namespace client

} // namespace quux

namespace {

// Called *often*
static void quux_listen_cb(const net::QuicTime& approx_time,
		quux_listener ctx) {

	quux::Dispatcher& dispatcher = ctx->dispatcher;
	const net::IPEndPoint& self_endpoint = ctx->self_endpoint;
	net::IPEndPoint peer_endpoint;

#ifdef SHADOW
	listen_messages[0].msg_len = recvfrom(ctx->sd, iov[0].iov_base,
			iov[0].iov_len, 0, (struct sockaddr*) &listen_sockaddrs[0],
			&listen_messages[0].msg_hdr.msg_namelen);
	int num = 1;
#else
	int num = recvmmsg(ctx->sd, listen_messages, NUM_MESSAGES, 0, nullptr);
#endif
	quux::log("listener read %d packets from %d\n", num, ctx->sd);

	for (int i = 0; i < num; ++i) {
		net::QuicReceivedPacket packet((char*) iov[i].iov_base,
				listen_messages[i].msg_len, approx_time);
		(void) peer_endpoint.FromSockAddr(
				(struct sockaddr*) &listen_sockaddrs[i],
				sizeof(struct sockaddr_in6));

		quux::log("listener %s read %d packet from %s on sock %d\n",
				self_endpoint.ToString().c_str(),
				listen_messages[i].msg_len,
				peer_endpoint.ToString().c_str(), ctx->sd);

		dispatcher.ProcessPacket(self_endpoint, peer_endpoint, packet);
	}
}

// Called *often*
static void quux_listen_libevent_cb(int socket, short what, void* arg) {
	quux_listener ctx = (quux_listener) arg;
	if (approx_time_ticks.is_null()) {
		approx_time_ticks = base::TimeTicks::Now();
	}
	net::QuicTime approx_time(approx_time_ticks);
	quux::Dispatcher& dispatcher = ctx->dispatcher;
	const net::IPEndPoint& self_endpoint = ctx->self_endpoint;
	net::IPEndPoint peer_endpoint;

#ifndef SHADOW
	listen_messages[0].msg_len = recvfrom(ctx->sd, iov[0].iov_base,
			iov[0].iov_len, 0, (struct sockaddr*) &listen_sockaddrs[0],
			&listen_messages[0].msg_hdr.msg_namelen);
	int num = 1;
#else
	int num = recvmmsg(ctx->sd, listen_messages, NUM_MESSAGES, 0, nullptr);
#endif
	quux::log("listener read %d packets from %d\n", num, ctx->sd);

	for (int i = 0; i < num; ++i) {
		net::QuicReceivedPacket packet((char*) iov[i].iov_base,
				listen_messages[i].msg_len, approx_time);
		(void) peer_endpoint.FromSockAddr(
				(struct sockaddr*) &listen_sockaddrs[i],
				sizeof(struct sockaddr_in6));

		quux::log("listener %s read %d packet from %s on sock %d\n",
				self_endpoint.ToString().c_str(),
				listen_messages[i].msg_len,
				peer_endpoint.ToString().c_str(), ctx->sd);

		dispatcher.ProcessPacket(self_endpoint, peer_endpoint, packet);
	}

}

// Called *often*
static void quux_peer_cb(const net::QuicTime& approx_time,
		quux_peer_client_s* ctx) {

	net::QuicConnection& connection = ctx->connection;
	const net::IPEndPoint& self_endpoint = ctx->self_endpoint;
	const net::IPEndPoint& peer_endpoint = ctx->peer_endpoint;

#ifdef SHADOW
	peer_messages[0].msg_len = recv(ctx->sd, iov[0].iov_base, iov[0].iov_len,
			0);
	int num = 1;
#else
	int num = recvmmsg(ctx->sd, peer_messages, NUM_MESSAGES, 0, nullptr);
	//quux::log("client read %d packets from %d\n", num, ctx->sd);
#endif

	for (int i = 0; i < num; ++i) {
		net::QuicReceivedPacket packet((char*) iov[i].iov_base,
				peer_messages[i].msg_len, approx_time);

		quux::log("client %s read %d packet from %s on sock %d\n",
				self_endpoint.ToString().c_str(),
				peer_messages[i].msg_len,
				peer_endpoint.ToString().c_str(), ctx->sd);

		connection.ProcessUdpPacket(self_endpoint, peer_endpoint, packet);
	}
}

// Called *often*
static void quux_peer_libevent_cb(int socket, short what, void* arg) {
	quux_peer_client_s* ctx = (quux_peer_client_s*) arg;
	if (approx_time_ticks.is_null()) {
		approx_time_ticks = base::TimeTicks::Now();
	}
	net::QuicTime approx_time(approx_time_ticks);
	net::QuicConnection& connection = ctx->connection;
	const net::IPEndPoint& self_endpoint = ctx->self_endpoint;
	const net::IPEndPoint& peer_endpoint = ctx->peer_endpoint;

#ifdef SHADOW
	peer_messages[0].msg_len = recv(ctx->sd, iov[0].iov_base, iov[0].iov_len,
			0);
	int num = 1;
#else
	int num = recvmmsg(ctx->sd, peer_messages, NUM_MESSAGES, 0, nullptr);
	//quux::log("client read %d packets from %d\n", num, ctx->sd);
#endif

	for (int i = 0; i < num; ++i) {
		net::QuicReceivedPacket packet((char*) iov[i].iov_base,
				peer_messages[i].msg_len, approx_time);

		quux::log("client %s read %d packet from %s on sock %d\n",
				self_endpoint.ToString().c_str(),
				peer_messages[i].msg_len,
				peer_endpoint.ToString().c_str(), ctx->sd);

		connection.ProcessUdpPacket(self_endpoint, peer_endpoint, packet);
	}
}

static void quux_init_common(void) {

	for (int i = 0; i < NUM_MESSAGES; ++i) {
		// used by both peer and listen messages, not at same time
		iov[i].iov_base = (void*) &buf[net::kMaxPacketSize * i];
		iov[i].iov_len = net::kMaxPacketSize;

		peer_messages[i].msg_hdr.msg_iov = &iov[i];
		peer_messages[i].msg_hdr.msg_iovlen = 1;

		listen_messages[i].msg_hdr.msg_name = (void*) &listen_sockaddrs[i];
		listen_messages[i].msg_hdr.msg_namelen = sizeof(struct sockaddr_in6);
		listen_messages[i].msg_hdr.msg_iov = &iov[i];
		listen_messages[i].msg_hdr.msg_iovlen = 1;
	}

	crypto_server_config.AddDefaultConfig(helper.GetRandomGenerator(),
			helper.GetClock(), net::QuicCryptoServerConfig::ConfigOptions());

	char quuxLogName[255];
	snprintf(quuxLogName, 255, "/tmp/quux.log.%d", getpid());
	//log_fileh = fopen(quuxLogName, "w");

#if 0
	// required for logging
	base::CommandLine::Init(0, nullptr);

	char logName[255];
	snprintf(logName, 255, "/tmp/quic.log.%d", getpid());

	logging::LoggingSettings settings;
	settings.logging_dest = logging::LOG_TO_ALL;
	settings.log_file = logName;
	settings.lock_log = logging::LOCK_LOG_FILE;
	settings.delete_old = logging::DELETE_OLD_LOG_FILE;
	logging::InitLogging(settings);
	logging::SetMinLogLevel(-1);
#endif

}

} // namespace

int quux_init_loop(void) {

	if (quux::event_base) {
		quux::log("Cannot use quux_init with libevent initialisation\n");
		return -1;
	}

	if (mainepolld == -1) {
		return -1;
	}

	quux_init_common();

	return 0;
}

// TODO: put this in a separate static lib
// so users aren't required to depend on libevent if they don't like
#define EV_READ		0x02
#define EV_PERSIST	0x10
struct event *event_new(struct event_base *base, int sock, short what,
		void (*cb)(int, short, void *), void *arg);
int event_add(struct event *ev, const struct timeval *timeout);

void quux_event_base_loop_init(struct event_base *base) {
	quux::event_base = base;

	quux_init_common();
}

int quux_errno(void) {
	return q_errno;
}

const char* quux_error_description(void) {
	return "All is fine\n";
}

void quux_reset_errno(void) {
	q_errno = QUUX_NO_ERR;
}

quux_listener quux_listen(const struct sockaddr* self_sockaddr,
		quux_connected connected_cb) {

	socklen_t self_sockaddr_len;

	if (self_sockaddr->sa_family == AF_INET) {
		self_sockaddr_len = sizeof(struct sockaddr_in);

	} else if (self_sockaddr->sa_family == AF_INET6) {
		self_sockaddr_len = sizeof(struct sockaddr_in6);

	} else {
		quux::log("Sorry, listen socket type currently unsupported: %d\n", self_sockaddr->sa_family);
		return nullptr;
	}

	int sd = socket(self_sockaddr->sa_family, SOCK_DGRAM | SOCK_NONBLOCK, 0);
	if (sd < 0) {
		quux::log("%s", strerror(errno));
		return nullptr;
	}

	if (bind(sd, self_sockaddr, self_sockaddr_len) < 0) {
		quux::log("%s", strerror(errno));
		return nullptr;
	}

	net::IPEndPoint self_endpoint;
	if (!self_endpoint.FromSockAddr(self_sockaddr, self_sockaddr_len)) {
		quux::log("Couldn't get endpoint from sockaddr\n");
		return nullptr;
	}

	quux_listener ctx = new quux_listener_s(sd, self_endpoint, connected_cb);

	if (quux::event_base) {
		struct event *ev = event_new(quux::event_base, sd,
		EV_READ | EV_PERSIST, quux_listen_libevent_cb, ctx);
		if (event_add(ev, nullptr) < 0) {
			quux::log("event_add fail\n");
			return nullptr;
		}
	} else {
		struct epoll_event ev = { EPOLLIN, { (void*) &ctx->cbp } };
		if (epoll_ctl(mainepolld, EPOLL_CTL_ADD, sd, &ev) < 0) {
			quux::log("%s", strerror(errno));
			return nullptr;
		}
	}

	return ctx;
}

// mostly useful for use with the quux_accept callback.
void quux_set_peer_context(quux_peer peer, void* arg) {
	peer->arg = arg;
}
void* quux_get_peer_context(quux_peer peer) {
	return peer->arg;
}

// mostly useful for use with the quux_accept callback.
void quux_set_stream_context(quux_stream stream, void* arg) {
	stream->arg = arg;
}
void* quux_get_stream_context(quux_stream stream) {
	return stream->arg;
}

/*
 * TODO: instead of creating a socket each time, we should have a single
 * socket ready made for outbound connections and multiplex connections
 * over it based on the IP:port of the other side.
 */

quux_peer quux_open(const char* hostname, const struct sockaddr* peer_sockaddr) {

	struct sockaddr_in6 self_sockaddr;
	socklen_t peer_sockaddr_len;

	if (peer_sockaddr->sa_family == AF_INET) {
		struct sockaddr_in* self_sockaddr_in = (struct sockaddr_in*)&self_sockaddr;
		peer_sockaddr_len = sizeof(struct sockaddr_in);
		self_sockaddr_in->sin_family = AF_INET;
		self_sockaddr_in->sin_port = 0;
		self_sockaddr_in->sin_addr.s_addr = 0;
#ifdef SHADOW
		self_sockaddr_in->sin_addr.s_addr = htonl(0x0b000001);
#endif

	} else if (peer_sockaddr->sa_family == AF_INET6) {
#ifdef SHADOW
		log("not sure ip6 on shadow will work yet\n");
		return nullptr
#else
		peer_sockaddr_len = sizeof(struct sockaddr_in6);
		memset(&self_sockaddr, 0, sizeof(struct sockaddr_in6));
		self_sockaddr.sin6_family = AF_INET6;
#endif

	} else {
		quux::log("Sorry, open socket type currently unsupported: %d\n", peer_sockaddr->sa_family);
		return nullptr;
	}

	socklen_t self_sockaddr_len = peer_sockaddr_len;

	/* create the client socket and get a socket descriptor */
	int sd = socket(peer_sockaddr->sa_family, SOCK_DGRAM | SOCK_NONBLOCK, 0);
	if (sd < 0) {
		quux::log("%s", strerror(errno));
		return nullptr;
	}

	// set address for recvmmsg to use
	if (bind(sd, (struct sockaddr*) &self_sockaddr, self_sockaddr_len) < 0) {
		quux::log("%s", strerror(errno));
		return nullptr;
	}

	// set address for sendmmsg to use
	if (connect(sd, peer_sockaddr, peer_sockaddr_len) < 0) {
		quux::log("%s", strerror(errno));
		return nullptr;
	}

	if (getsockname(sd, (struct sockaddr*) &self_sockaddr, &self_sockaddr_len)
			< 0) {
		quux::log("%s", strerror(errno));
		return nullptr;
	}

	net::IPEndPoint self_endpoint;
	net::IPEndPoint peer_endpoint;

	if (!self_endpoint.FromSockAddr((struct sockaddr*) &self_sockaddr,
			self_sockaddr_len)) {
		quux::log("Couldn't get self endpoint from sockaddr\n");
		return nullptr;
	}
	if (!peer_endpoint.FromSockAddr(peer_sockaddr, peer_sockaddr_len)) {
		quux::log("Couldn't get peer endpoint from sockaddr\n");
		return nullptr;
	}

	quux_peer_client_s* ctx = new quux_peer_client_s(sd, self_endpoint, peer_endpoint);

	if (quux::event_base) {
		struct event *ev = event_new(quux::event_base, sd,
		EV_READ | EV_PERSIST, quux_peer_libevent_cb, ctx);
		if (event_add(ev, nullptr) < 0) {
			quux::log("event_add fail\n");
			return nullptr;
		}
	} else {
		struct epoll_event ev = { EPOLLIN, { (void*) &ctx->cbp } };
		if (epoll_ctl(mainepolld, EPOLL_CTL_ADD, sd, &ev) < 0) {
			return nullptr;
		}
	}

	return ctx;
}

quux_stream quux_connect(quux_peer conn) {
	if (conn->type == quux_peer_s::SERVER) {
		return new quux_stream_server_s((quux_peer_server_s*)conn);
	} else {
		return new quux_stream_client_s((quux_peer_client_s*)conn);
	}
}

void quux_set_accept_cb(quux_peer peer, quux_cb quux_accept) {
	peer->accept_cb = quux_accept;
}
void quux_set_readable_cb(quux_stream stream, quux_cb quux_readable) {
	stream->quux_readable = quux_readable;
}
void quux_set_writeable_cb(quux_stream stream, quux_cb quux_writeable) {
	stream->quux_writeable = quux_writeable;
}

quux_peer quux_get_peer(quux_stream stream) {
	return stream->peer;
}

size_t quux_write(quux_stream stream, const uint8_t* buf, size_t count) {
	struct iovec iov = { (void*) buf, count };
	if (!*stream->crypto_connected) {
		stream->cconnect_interest_set->insert(stream);
		return 0;
	}

	net::QuicConsumedData consumed(stream->WritevData(&iov));

	if (consumed.bytes_consumed == 0) {
		*stream->write_wanted = true;
	}
	return consumed.bytes_consumed;
}

void quux_write_close(quux_stream stream) {

	// FIXME: this will not wait for all bytes to be acked !!!!!!

	stream->CloseWriteSide();
}

int quux_write_is_closed(quux_stream stream) {
	return 0;
}

size_t quux_read(quux_stream stream, uint8_t* buf, size_t count) {
	struct iovec iov = { buf, count };
	int data_read = stream->Readv(&iov);
	if (data_read == 0) {
		// re-register an interest in reading
		*stream->read_wanted = true;
	}
	return data_read;
}

void quux_read_close(quux_stream stream) {
	stream->StopReading();
}

int quux_read_is_closed(quux_stream stream) {
	return 0;
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

	if (quux::event_base) {
		quux::log("Cannot use quux_loop with libevent initialisation\n");
		return;
	}

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

		quux::TimeToAlarmMap::iterator end = time_to_alarm_map.end();
		for (quux::TimeToAlarmMap::iterator it = time_to_alarm_map.begin();
				it != end;) {

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
			quux::TimeToAlarmMap::iterator prev = it++;
			prev->second->Fire();
			time_to_alarm_map.erase(prev);
		}

		// There may have been new alarms added in the loop run above.
		// The only ones that may be eligible would have timeout 0.
		// We should make progress on other stuff first before running
		// but we need to check if our timeout should be changed to be earlier
		if (has_fired) {
			quux::TimeToAlarmMap::iterator it = time_to_alarm_map.begin();
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
#ifdef SHADOW
			for (int i = 0; i < *peer->num; ++i) {
				send(peer->sd, peer->out_messages[i].msg_hdr.msg_iov->iov_base,
						peer->out_messages[i].msg_hdr.msg_iov->iov_len, 0);
			}
#else
			int sent = sendmmsg(peer->sd, peer->out_messages, *peer->num, 0);
#endif
			quux::log("client wrote %d packets to %d (%d successful)\n", *peer->num, peer->sd, sent);
			// XXX: for now we just drop anything that didn't successfully send
			*peer->num = 0;
		}
		client_writes_ready_set.clear();

		for (auto& ctx : listen_writes_ready_set) {
#ifdef SHADOW
			for (int i = 0; i < *ctx->num; ++i) {
				sendto(ctx->sd, ctx->out_messages[i].msg_hdr.msg_iov->iov_base,
						ctx->out_messages[i].msg_hdr.msg_iov->iov_len, 0,
						(struct sockaddr*) ctx->out_messages[i].msg_hdr.msg_name,
						ctx->out_messages[i].msg_hdr.msg_namelen);
			}
#else
			int sent = sendmmsg(ctx->sd, ctx->out_messages, *ctx->num, 0);
#endif
			quux::log("listener wrote %d packets to %d (%d successful)\n", *ctx->num, ctx->sd, sent);
			// XXX: for now we just drop anything that didn't successfully send
			*ctx->num = 0;
		}
		listen_writes_ready_set.clear();

#ifdef SHADOW
		if (wake_after_millis == 0) {
			wake_after_millis = 1;
		}
#endif
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
			pair->callback(approx_quictime, pair->ctx);
		}
	}
}

void quux_event_base_loop_before(void) {
	approx_time_ticks = base::TimeTicks(); // null
	cur_wall_time = NULL_WALL_TIME;
}

/*
 * Write any packets that were generated by the previous event loop run's callbacks
 */
void quux_event_base_loop_after(void) {
	for (auto& peer : client_writes_ready_set) {
#ifndef SHADOW
		for (int i = 0; i < *peer->num; ++i) {
			send(peer->sd, peer->out_messages[i].msg_hdr.msg_iov->iov_base,
					peer->out_messages[i].msg_hdr.msg_iov->iov_len, 0);

			quux::log("client %s wrote %d packet to %s on sock %d\n",
					peer->self_endpoint.ToString().c_str(),
					peer->out_messages[i].msg_hdr.msg_iov->iov_len,
					peer->peer_endpoint.ToString().c_str(), peer->sd);
		}
#else
		int sent = sendmmsg(peer->sd, peer->out_messages, *peer->num, 0);
		quux::log("client wrote %d packets to %d (%d successful)\n", *peer->num, peer->sd, sent);
#endif
		// XXX: for now we just drop anything that didn't successfully send
		*peer->num = 0;
	}
	client_writes_ready_set.clear();

	for (auto& ctx : listen_writes_ready_set) {
#ifndef SHADOW
		for (int i = 0; i < *ctx->num; ++i) {
			sendto(ctx->sd, ctx->out_messages[i].msg_hdr.msg_iov->iov_base,
					ctx->out_messages[i].msg_hdr.msg_iov->iov_len, 0,
					(struct sockaddr*) ctx->out_messages[i].msg_hdr.msg_name,
					ctx->out_messages[i].msg_hdr.msg_namelen);

			net::IPEndPoint their_end;
			(void) their_end.FromSockAddr(
					(struct sockaddr*) ctx->out_messages[i].msg_hdr.msg_name,
					ctx->out_messages[i].msg_hdr.msg_namelen);

			quux::log("listener %s wrote %d packet to %s on sock %d\n",
					ctx->self_endpoint.ToString().c_str(),
					ctx->out_messages[i].msg_hdr.msg_iov->iov_len,
					their_end.ToString().c_str(), ctx->sd);
		}
#else
		int sent = sendmmsg(ctx->sd, ctx->out_messages, *ctx->num, 0);
		quux::log("listener wrote %d packets to %d (%d successful)\n", *ctx->num, ctx->sd, sent);
#endif
		// XXX: for now we just drop anything that didn't successfully send
		*ctx->num = 0;
	}
	listen_writes_ready_set.clear();
}

void quux_shutdown(quux_listener server) {

}
