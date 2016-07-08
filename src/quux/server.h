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
			out_messages[i].msg_hdr.msg_namelen = sizeof(struct sockaddr_in);
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

	virtual ~Writer() {
	}

	uint8_t buf[net::kMaxPacketSize * NUM_OUT_MESSAGES];
	struct iovec iov[NUM_OUT_MESSAGES];
	struct mmsghdr out_messages[NUM_OUT_MESSAGES];
	struct sockaddr_in out_sockaddrs[NUM_OUT_MESSAGES];
	int num = 0;

	quux_listener ctx;
	std::set<quux_listener>* writes_ready_set;
};

} /* namespace packet */

namespace session {

class Helper: public net::QuicServerSessionBase::Helper {
public:
	Helper() {
	}

	// Is it OK for this to be deterministic? I assume so given the param
	net::QuicConnectionId GenerateConnectionIdForReject(
			net::QuicConnectionId connection_id) const override {
#if 0

		uint64_t value;
		crypto::RandBytes(&value, sizeof(value));
#endif

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

	virtual ~Helper() {
	}

};

} /* namespace session */

class Stream: public net::QuicSpdyStream {
public:
	Stream(net::QuicStreamId id, net::QuicSpdySession* spdy_session,
			quux_stream ctx) :
			QuicSpdyStream(id, spdy_session), ctx(ctx) {

		// QuicSpdyStream::QuicSpdyStream set it blocked for SPDY reasons - undo that
		sequencer()->SetUnblocked();
	}

	virtual void OnStreamFrame(const net::QuicStreamFrame& frame) override {
		QuicSpdyStream::OnStreamFrame(frame);
	}

	virtual void OnDataAvailable() override {
		printf("quux::server::Stream::OnDataAvailable\n");

		if (read_wanted) {
			printf("read wanted\n");
			read_wanted = false;
			quux::c_readable_cb(ctx)(ctx);
		}
	}

	quux_stream ctx;
	bool read_wanted = false;
};

class Session: public net::QuicServerSessionBase {
public:
	explicit Session(const net::QuicConfig& config,
			net::QuicConnection* connection, Visitor* visitor, Helper* helper,
			const net::QuicCryptoServerConfig* crypto_config,
			net::QuicCompressedCertsCache* compressed_certs_cache) :
			QuicServerSessionBase(config, connection, visitor, helper,
					crypto_config, compressed_certs_cache) {
		Initialize();
	}

	net::QuicSpdyStream* CreateIncomingDynamicStream(net::QuicStreamId id)
			override {

		// FIXME: around here we can create the ctx for this stream
		// and do quux_accept(ctx)

//		quux_stream_impl* c = new quux_stream_impl(peer, quux_writeable, quux_readable);
		quux_stream ctx = nullptr;

		Stream* stream = new Stream(id, this, ctx);
		ActivateStream(stream);

		return stream;
	}

	net::QuicSpdyStream* CreateOutgoingDynamicStream(net::SpdyPriority priority)
			override {
		assert(0);
		printf("CreateOutgoingDynamicStream(%d)\n", priority);

		return nullptr;
	}

	net::QuicCryptoServerStreamBase* CreateQuicCryptoServerStream(
			const net::QuicCryptoServerConfig* crypto_config,
			net::QuicCompressedCertsCache* compressed_certs_cache) override {

		return new net::QuicCryptoServerStream(crypto_config,
				compressed_certs_cache,
				false, this);
	}

	virtual ~Session() {
	}
};

} /* namespace server */

} /* namespace quux */

#endif /* SRC_QUUX_SERVER_H_ */
