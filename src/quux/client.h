/*
 * client.h
 *
 *  Created on: Jul 3, 2016
 *      Author: user
 */

#ifndef SRC_QUUX_CLIENT_H_
#define SRC_QUUX_CLIENT_H_

#include <net/base/ip_address.h>
#include <net/quic/crypto/proof_verifier.h>
#include <net/quic/crypto/quic_crypto_client_config.h>
#include <net/quic/quic_bandwidth.h>
#include <net/quic/quic_crypto_client_stream.h>
#include <net/quic/quic_packet_writer.h>
#include <net/quic/quic_protocol.h>
#include <net/quic/quic_server_id.h>
#include <net/quic/quic_session.h>
#include <net/quic/quic_stream_sequencer.h>
#include <net/quic/quic_types.h>
#include <net/quic/quic_write_blocked_list.h>
#include <net/quic/reliable_quic_stream.h>
#include <net/spdy/spdy_protocol.h>
#include <quux/internal.h>
#include <stddef.h>
#include <sys/uio.h>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <set>
#include <utility>

namespace quux {

namespace client {

namespace packet {

static const int NUM_OUT_MESSAGES = 256;

class Writer: public net::QuicPacketWriter {
public:
	Writer(quux::WritesReadySet* writes_ready_set, quux_peer_client_s* peer) :
			QuicPacketWriter(), num(0), peer(peer), writes_ready_set(
					writes_ready_set) {

		memset(out_messages, 0, sizeof(out_messages));

		for (int i = 0; i < NUM_OUT_MESSAGES; ++i) {
			iov[i].iov_base = (void*) &buf[net::kMaxPacketSize * i];

			out_messages[i].msg_hdr.msg_iov = &iov[i];
			out_messages[i].msg_hdr.msg_iovlen = 1;
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
		num++;

		writes_ready_set->insert(peer);
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
	int num;

	quux_peer_client_s* peer;
	quux::WritesReadySet* writes_ready_set;
};

} /* namespace packet */

class Session: public net::QuicSession {
public:
	Session(net::QuicConnection* connection, const net::QuicConfig& config,
			const net::QuicServerId& server_id,
			net::ProofVerifyContext* verify_context,
			net::QuicCryptoClientConfig* crypto_config,
			net::QuicCryptoClientStream::ProofHandler* proof_handler, quux_peer peer_ctx) :

			QuicSession(connection, config), crypto_stream(server_id, this,
					verify_context, crypto_config, proof_handler), crypto_connected(
			false), peer_ctx(peer_ctx) {

		Initialize();
		crypto_stream.CryptoConnect();

		// This ugly hack is needed so the first stream ID
		// isn't the reserved SPDY headers stream ID (3)
		GetNextOutgoingStreamId();
	}

	net::ReliableQuicStream* CreateIncomingDynamicStream(net::QuicStreamId id)
			override {

		quux_cb cb = quux::accept_cb(peer_ctx);
		if (!cb) {
			return nullptr;
		}

		quux_stream ctx = quux::client::stream::create_incoming_context(id, this);
		cb(ctx);
		return quux::client::stream::get_incoming(ctx);
	}

	net::ReliableQuicStream* CreateOutgoingDynamicStream(
			net::SpdyPriority priority) override {
		assert(0);
		return nullptr;
	}

	net::QuicCryptoStream* GetCryptoStream() override {
		return &crypto_stream;
	}

	void OnCryptoHandshakeEvent(CryptoHandshakeEvent event) override {
		QuicSession::OnCryptoHandshakeEvent(event);

		if (!crypto_connected) {
			crypto_connected = true;

			for (quux_stream ctx : cconnect_interest_set) {
				quux::writeable_cb(ctx)(ctx);
			}
			cconnect_interest_set.clear();
		}
	}

	/// exposing protected methods

	void RegisterStream(net::QuicStreamId id, net::SpdyPriority priority) {
		write_blocked_streams()->RegisterStream(id, priority);
	}

	void UnregisterStream(net::QuicStreamId id) {
		write_blocked_streams()->UnregisterStream(id);
	}

	// because QuicSession::ActivateStream is protected
	void ActivateStream(net::ReliableQuicStream* stream) override {
		QuicSession::ActivateStream(stream);
	}

	net::QuicStreamId GetNextOutgoingStreamId() {
		return QuicSession::GetNextOutgoingStreamId();
	}

	quux_peer peer_ctx;

	net::QuicCryptoClientStream crypto_stream;

	bool crypto_connected;

	CryptoConnectInterestSet cconnect_interest_set;
};

class Stream: public net::ReliableQuicStream {
public:
	// ReliableQuic(id,session) needs to know Session is a QuicSession
	Stream(net::QuicStreamId id, quux::client::Session* session,
			quux_stream ctx) :
			ReliableQuicStream(id, session), ctx(ctx), read_wanted(false), write_wanted(false), sessionptr(session) {

		quux::client::session::register_stream(session, id);
		quux::client::session::activate_stream(session, this);
	}

	~Stream() {
		StopReading();
		CloseWriteSide();
		quux::client::session::unregister_stream(sessionptr, id());
	}

	void OnDataAvailable() override {
		if (read_wanted) {
			read_wanted = false;
			quux::readable_cb(ctx)(ctx);
		}
	}

	void OnCanWrite() override {
		if (write_wanted) {
			write_wanted = false;
			quux::writeable_cb(ctx)(ctx);
		}
	}

	/// exposing protected methods

	net::QuicConsumedData WritevData(const struct iovec* iov, int iov_count,
	bool fin, net::QuicAckListenerInterface* ack_listener) {

		return net::ReliableQuicStream::WritevData(iov, iov_count, fin,
				ack_listener);
	}

	// access to protected stuff
	int Readv(const struct iovec* iov, size_t iov_len) {
		return sequencer()->Readv(iov, iov_len);
	}

	void StopReading() override {
		ReliableQuicStream::StopReading();
	}
	void CloseWriteSide() override {
		ReliableQuicStream::CloseWriteSide();
	}

	quux_stream ctx;

	bool read_wanted;
	bool write_wanted;

	quux::client::Session* sessionptr;
};

} /* namespace client */

} /* namespace quux */

#endif /* SRC_QUUX_CLIENT_H_ */
