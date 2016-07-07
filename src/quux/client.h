/*
 * client.h
 *
 *  Created on: Jul 3, 2016
 *      Author: user
 */

#ifndef SRC_QUUX_CLIENT_H_
#define SRC_QUUX_CLIENT_H_

#include <stddef.h>
#include <sys/uio.h>
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <set>
#include <utility>

#include "quux_c.h"
#include "api.h"
#include "../net/base/ip_address.h"
#include "../net/quic/crypto/proof_verifier.h"
#include "../net/quic/crypto/quic_crypto_client_config.h"
#include "../net/quic/quic_bandwidth.h"
#include "../net/quic/quic_crypto_client_stream.h"
#include "../net/quic/quic_packet_writer.h"
#include "../net/quic/quic_protocol.h"
#include "../net/quic/quic_server_id.h"
#include "../net/quic/quic_session.h"
#include "../net/quic/quic_types.h"
#include "../net/quic/quic_write_blocked_list.h"
#include "../net/spdy/spdy_protocol.h"
#include "stream.h"

namespace quux {

namespace client {

namespace packet {

static const int NUM_OUT_MESSAGES = 256;

class Writer: public net::QuicPacketWriter {
public:

	Writer(std::set<quux_p_impl*>* writes_ready_set, quux_p_impl* peer) :
			writes_ready_set(writes_ready_set), peer(peer) {

		for (int i = 0; i < NUM_OUT_MESSAGES; ++i) {
			iov[i].iov_base = (void*) &buf[net::kMaxPacketSize * i];
			iov[i].iov_len = 0;
		}
	}

	net::WriteResult WritePacket(const char* buffer, size_t buf_len,
			const net::IPAddress& self_address,
			const net::IPEndPoint& peer_address, net::PerPacketOptions* options)
					override {

		printf("write packet\n");
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

	virtual ~Writer() {
	}

	uint8_t buf[net::kMaxPacketSize * NUM_OUT_MESSAGES];
	struct iovec iov[NUM_OUT_MESSAGES];
	int num = 0;

	quux_p_impl* peer;
	std::set<quux_p_impl*>* writes_ready_set;
};

} /* namespace packet */

class Session: public net::QuicSession {
public:

	Session(net::QuicConnection* connection, const net::QuicConfig& config,
			const net::QuicServerId& server_id,
			net::ProofVerifyContext* verify_context,
			net::QuicCryptoClientConfig* crypto_config,
			net::QuicCryptoClientStream::ProofHandler* proof_handler) :
			crypto_stream(
					new net::QuicCryptoClientStream(server_id, this,
							verify_context, crypto_config, proof_handler)), QuicSession(
					connection, config) {

		// XXX: dodgy virtual method call in constructor?
		Initialize();
		// XXX: Is it too early to do this?
		crypto_stream->CryptoConnect();
	}

	net::ReliableQuicStream* CreateIncomingDynamicStream(net::QuicStreamId id)
			override {
		printf("CreateIncomingDynamicStream(%d)\n", id);
		quux::Stream* stream = new quux::Stream(id, this);
		ActivateStream(stream);
		return stream;
	}

	net::ReliableQuicStream* CreateOutgoingDynamicStream(
			net::SpdyPriority priority) override {
		assert(0);
		printf("CreateOutgoingDynamicStream(%d)\n", priority);

		return nullptr;
	}

#if 0
	// Nb. not override, because we are returning quux::Stream* instead.
	// Since we appear to be the only users of the method we could ignore it
	// and do our own thing instead, but it doesn't matter anyway
	quux::Stream* CreateOutgoingDynamicStream(net::SpdyPriority priority) {
		uint32_t value;
		crypto::RandBytes(&value, sizeof(value));
		net::QuicStreamId id(value);
		quux::Stream* stream = new Stream(id, this);
		return stream;
	}
#endif

	net::QuicCryptoStream* GetCryptoStream() override {
		return crypto_stream;
	}

	void OnCryptoHandshakeEvent(CryptoHandshakeEvent event) override {
		QuicSession::OnCryptoHandshakeEvent(event);

		if (event == QuicSession::ENCRYPTION_FIRST_ESTABLISHED) {
			crypto_connected = true;

			for (quux_c_impl* ctx : cconnect_interest_set) {
				ctx->quux_writeable(ctx);
			}
			cconnect_interest_set.clear();
		}
	}

	/// exposing protected methods

	void RegisterStreamPriority(net::QuicStreamId id,
			net::SpdyPriority priority) {
		write_blocked_streams()->RegisterStream(id, priority);
	}

	// because QuicSession::ActivateStream is protected
	void ActivateStream(net::ReliableQuicStream* stream) override {
		QuicSession::ActivateStream(stream);
	}

	net::QuicStreamId GetNextOutgoingStreamId() {
		return QuicSession::GetNextOutgoingStreamId();
	}

	virtual ~Session() {
	}

	net::QuicCryptoClientStream* crypto_stream;
	bool crypto_connected = false;

	typedef std::set<quux_c_impl*> CryptoConnectInterestSet;
	CryptoConnectInterestSet cconnect_interest_set;
};

} /* namespace client */

} /* namespace quux */

#endif /* SRC_QUUX_CLIENT_H_ */
