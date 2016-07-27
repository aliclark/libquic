/*
 * server.h
 *
 *  Created on: Jul 3, 2016
 *      Author: user
 */

#ifndef SRC_QUUX_SERVER_H_
#define SRC_QUUX_SERVER_H_

#include <net/base/ip_address.h>
#include <net/base/ip_endpoint.h>
#include <net/quic/quic_bandwidth.h>
#include <net/quic/quic_crypto_server_stream.h>
#include <net/quic/quic_packet_writer.h>
#include <net/quic/quic_protocol.h>
#include <net/quic/quic_server_session_base.h>
#include <net/quic/quic_spdy_stream.h>
#include <net/quic/quic_stream_sequencer.h>
#include <net/quic/quic_types.h>
#include <net/quic/reliable_quic_stream.h>
#include <net/spdy/spdy_protocol.h>
#include <stddef.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <set>
#include <string>
#include <utility>

namespace quux {

namespace server {

namespace packet {

static const int NUM_OUT_MESSAGES = 256;

/**
 * similar to client packet writer but
 * 1) needs to record the destination IPs
 * 2) could probably get away with a boolean flag instead of a set,
 * if we fix the API to max one listener
 */
class Writer: public net::QuicPacketWriter {
public:
	Writer(std::set<quux_listener>* writes_ready_set, quux_listener ctx) :
			writes_ready_set(writes_ready_set), ctx(ctx) {

		memset(out_messages, 0, sizeof(out_messages));

		for (int i = 0; i < NUM_OUT_MESSAGES; ++i) {
			iov[i].iov_base = (void*) &buf[net::kMaxPacketSize * i];

			out_messages[i].msg_hdr.msg_iov = &iov[i];
			out_messages[i].msg_hdr.msg_iovlen = 1;
			out_messages[i].msg_hdr.msg_name = &out_sockaddrs[i];
			out_messages[i].msg_hdr.msg_namelen = sizeof(struct sockaddr_in6);
		}
	}

	net::WriteResult WritePacket(const char* buffer, size_t buf_len,
			const net::IPAddress& self_address,
			const net::IPEndPoint& peer_address, net::PerPacketOptions* options)
					override {

		if (num >= NUM_OUT_MESSAGES || buf_len > net::kMaxPacketSize) {
			// XXX: just tail drop for now...
			return net::WriteResult(net::WRITE_STATUS_OK, buf_len);
		}

		memcpy(&buf[net::kMaxPacketSize * num], buffer, buf_len);
		iov[num].iov_len = buf_len;
		(void) peer_address.ToSockAddr(
				(struct sockaddr*) out_messages[num].msg_hdr.msg_name,
				&out_messages[num].msg_hdr.msg_namelen);
		num++;

		writes_ready_set->insert(ctx);
		return net::WriteResult(net::WRITE_STATUS_OK, buf_len);
	}

	bool IsWriteBlockedDataBuffered() const override {
		return false;
	}

	bool IsWriteBlocked() const override {
		return false;
	}

	void SetWritable() override {
		assert(0);
	}

	net::QuicByteCount GetMaxPacketSize(
			const net::IPEndPoint& peer_address) const override {
		// TODO: confer with other impls
		return net::kMaxPacketSize;
	}

	uint8_t buf[net::kMaxPacketSize * NUM_OUT_MESSAGES];
	struct iovec iov[NUM_OUT_MESSAGES];
	struct mmsghdr out_messages[NUM_OUT_MESSAGES];
	struct sockaddr_in6 out_sockaddrs[NUM_OUT_MESSAGES];
	int num = 0;

	std::set<quux_listener>* writes_ready_set;

	quux_listener ctx;
};

} /* namespace packet */

namespace session {

class Helper: public net::QuicServerSessionBase::Helper {
public:
	// Is it OK for this to be deterministic? I assume so given the param
	net::QuicConnectionId GenerateConnectionIdForReject(
			net::QuicConnectionId connection_id) const override {

		// valid by ensuring elsewhere that connection_id%2==0.
		// fast but quite wasteful of id space
		return net::QuicConnectionId(connection_id + 1);
	}

	bool CanAcceptClientHello(const net::CryptoHandshakeMessage& message,
			const net::IPEndPoint& self_address,
			std::string* error_details) const override {

		// XXX: ming
		return true;
	}
};

} /* namespace session */

class Session: public net::QuicServerSessionBase {
public:
	explicit Session(const net::QuicConfig& config,
			net::QuicConnection* connection, Visitor* visitor, Helper* helper,
			const net::QuicCryptoServerConfig* crypto_config,
			net::QuicCompressedCertsCache* compressed_certs_cache,
			quux_listener listener_ctx, quux_peer peer_ctx) :
			QuicServerSessionBase(config, connection, visitor, helper,
					crypto_config, compressed_certs_cache), listener_ctx(
					listener_ctx), peer_ctx(peer_ctx) {

		Initialize();
	}

	net::QuicSpdyStream* CreateIncomingDynamicStream(net::QuicStreamId id)
			override {

		quux_cb cb = quux::accept_cb(peer_ctx);
		if (!cb) {
			return nullptr;
		}

		quux_stream ctx = quux::server::stream::create_incoming_context(id,
				this);
		cb(ctx);
		return quux::server::stream::get_incoming_spdy(ctx);
	}

	net::QuicSpdyStream* CreateOutgoingDynamicStream(net::SpdyPriority priority)
			override {
		assert(0);
		return nullptr;
	}

	net::QuicCryptoServerStreamBase* CreateQuicCryptoServerStream(
			const net::QuicCryptoServerConfig* crypto_config,
			net::QuicCompressedCertsCache* compressed_certs_cache) override {

		return new net::QuicCryptoServerStream(crypto_config,
				compressed_certs_cache,
				false, this);
	}

	/// exposing protected methods

	void ActivateStream(net::ReliableQuicStream* stream) override {
		QuicSession::ActivateStream(stream);
	}

	net::QuicStreamId GetNextOutgoingStreamId() {
		return QuicSession::GetNextOutgoingStreamId();
	}

	quux_listener listener_ctx;
	quux_peer peer_ctx;
};

// FIXME: hack at the QuicDispatcher to make it not depend on SPDY :(
class Stream: public net::QuicSpdyStream {
public:
	Stream(net::QuicStreamId id, quux::server::Session* spdy_session,
			quux_stream ctx) :
			QuicSpdyStream(id, spdy_session), ctx(ctx), read_wanted(false) {

		// nb. QuicSpdyStream() already registered stream priority for us
		quux::server::session::activate_stream(spdy_session, this);

		// QuicSpdyStream() set sequencer() blocked for headers,
		// but on MarkHeadersConsumed(0) it will be set unblocked again
		OnInitialHeadersComplete(false, 0);
		MarkHeadersConsumed(0);
	}

	~Stream() {
		StopReading();
		CloseWriteSide();
	}

	void OnDataAvailable() override {
		if (read_wanted) {
			read_wanted = false;
			quux::readable_cb(ctx)(ctx);
		}
	}

	/// exposing protected methods

	net::QuicConsumedData WritevData(const struct iovec* iov, int iov_count,
	bool fin, net::QuicAckListenerInterface* ack_listener) {

		return QuicSpdyStream::WritevData(iov, iov_count, fin, ack_listener);
	}

	void StopReading() override {
		QuicSpdyStream::StopReading();
	}
	void CloseWriteSide() override {
		QuicSpdyStream::CloseWriteSide();
	}

	quux_stream ctx;

	bool read_wanted;
};

} /* namespace server */

} /* namespace quux */

#endif /* SRC_QUUX_SERVER_H_ */
