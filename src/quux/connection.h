/*
 * ConnectionHelper.h
 *
 *  Created on: Jun 28, 2016
 *      Author: user
 */

#ifndef SRC_QUUX_CONNECTION_H_
#define SRC_QUUX_CONNECTION_H_

#include <net/quic/quic_connection.h>
#include <net/quic/quic_protocol.h>
#include <net/quic/quic_time.h>
#include <quux/random.h>
#include <cstdio>
#include <string>

namespace quux {
class Random;
} /* namespace quux */

namespace quux {

namespace connection {

class Helper: public net::QuicConnectionHelperInterface {
public:
	explicit Helper(const net::QuicClock *clock, quux::Random* quic_random,
			net::QuicBufferAllocator* buffer_allocator) :
			clock(clock), quic_random(quic_random), buffer_allocator(
					buffer_allocator) {
	}

	const net::QuicClock* GetClock() const override {
		return clock;
	}

	// Returns a QuicRandom to be used for all random number related functions.
	net::QuicRandom* GetRandomGenerator() override {
		return quic_random;
	}

	// Returns a QuicBufferAllocator to be used for all stream frame buffers.
	net::QuicBufferAllocator* GetBufferAllocator() override {
		return buffer_allocator;
	}

	virtual ~Helper() {
	}

	const net::QuicClock* clock;
	quux::Random* quic_random;
	net::QuicBufferAllocator* buffer_allocator;
};

class Logger : public net::QuicConnectionDebugVisitor {

	  // Called when a packet has been sent.
	  virtual void OnPacketSent(const net::SerializedPacket& serialized_packet,
	                            net::QuicPathId original_path_id,
	                            net::QuicPacketNumber original_packet_number,
								net::TransmissionType transmission_type,
	                            net::QuicTime sent_time) {printf("[LOG] %s\n", __FUNCTION__);}

	  // Called when a packet has been received, but before it is
	  // validated or parsed.
	  virtual void OnPacketReceived(const net::IPEndPoint& self_address,
	                                const net::IPEndPoint& peer_address,
	                                const net::QuicEncryptedPacket& packet) {printf("[LOG] %s\n", __FUNCTION__);}

	  // Called when the unauthenticated portion of the header has been parsed.
	  virtual void OnUnauthenticatedHeader(const net::QuicPacketHeader& header) {printf("[LOG] %s\n", __FUNCTION__);}

	  // Called when a packet is received with a connection id that does not
	  // match the ID of this connection.
	  virtual void OnIncorrectConnectionId(net::QuicConnectionId connection_id) {printf("[LOG] %s\n", __FUNCTION__);}

	  // Called when an undecryptable packet has been received.
	  virtual void OnUndecryptablePacket() {printf("[LOG] %s\n", __FUNCTION__);}

	  // Called when a duplicate packet has been received.
	  virtual void OnDuplicatePacket(net::QuicPacketNumber packet_number) {printf("[LOG] %s\n", __FUNCTION__);}

	  // Called when the protocol version on the received packet doensn't match
	  // current protocol version of the connection.
	  virtual void OnProtocolVersionMismatch(net::QuicVersion version) {printf("[LOG] %s\n", __FUNCTION__);}

	  // Called when the complete header of a packet has been parsed.
	  virtual void OnPacketHeader(const net::QuicPacketHeader& header) {printf("[LOG] %s\n", __FUNCTION__);}

	  // Called when a StreamFrame has been parsed.
	  virtual void OnStreamFrame(const net::QuicStreamFrame& frame) {printf("[LOG] %s\n", __FUNCTION__);}

	  // Called when a AckFrame has been parsed.
	  virtual void OnAckFrame(const net::QuicAckFrame& frame) {printf("[LOG] %s\n", __FUNCTION__);}

	  // Called when a StopWaitingFrame has been parsed.
	  virtual void OnStopWaitingFrame(const net::QuicStopWaitingFrame& frame) {printf("[LOG] %s\n", __FUNCTION__);}

	  // Called when a net::QuicPaddingFrame has been parsed.
	  virtual void OnPaddingFrame(const net::QuicPaddingFrame& frame) {printf("[LOG] %s\n", __FUNCTION__);}

	  // Called when a Ping has been parsed.
	  virtual void OnPingFrame(const net::QuicPingFrame& frame) {printf("[LOG] %s\n", __FUNCTION__);}

	  // Called when a GoAway has been parsed.
	  virtual void OnGoAwayFrame(const net::QuicGoAwayFrame& frame) {printf("[LOG] %s\n", __FUNCTION__);}

	  // Called when a RstStreamFrame has been parsed.
	  virtual void OnRstStreamFrame(const net::QuicRstStreamFrame& frame) {printf("[LOG] %s\n", __FUNCTION__);}

	  // Called when a ConnectionCloseFrame has been parsed.
	  virtual void OnConnectionCloseFrame(const net::QuicConnectionCloseFrame& frame) {printf("[LOG] %s\n", __FUNCTION__);}

	  // Called when a WindowUpdate has been parsed.
	  virtual void OnWindowUpdateFrame(const net::QuicWindowUpdateFrame& frame) {printf("[LOG] %s\n", __FUNCTION__);}

	  // Called when a BlockedFrame has been parsed.
	  virtual void OnBlockedFrame(const net::QuicBlockedFrame& frame) {printf("[LOG] %s\n", __FUNCTION__);}

	  // Called when a PathCloseFrame has been parsed.
	  virtual void OnPathCloseFrame(const net::QuicPathCloseFrame& frame) {printf("[LOG] %s\n", __FUNCTION__);}

	  // Called when a public reset packet has been received.
	  virtual void OnPublicResetPacket(const net::QuicPublicResetPacket& packet) {printf("[LOG] %s\n", __FUNCTION__);}

	  // Called when a version negotiation packet has been received.
	  virtual void OnVersionNegotiationPacket(
	      const net::QuicVersionNegotiationPacket& packet) {printf("[LOG] %s\n", __FUNCTION__);}

	  // Called when the connection is closed.
	  virtual void OnConnectionClosed(net::QuicErrorCode error,
	                                  const std::string& error_details,
									  net::ConnectionCloseSource source) {printf("[LOG] %s\n", __FUNCTION__);}

	  // Called when the version negotiation is successful.
	  virtual void OnSuccessfulVersionNegotiation(const net::QuicVersion& version) {printf("[LOG] %s\n", __FUNCTION__);}

	  // Called when a CachedNetworkParameters is sent to the client.
	  virtual void OnSendConnectionState(
	      const net::CachedNetworkParameters& cached_network_params) {printf("[LOG] %s\n", __FUNCTION__);}

	  // Called when a CachedNetworkParameters are recieved from the client.
	  virtual void OnReceiveConnectionState(
	      const net::CachedNetworkParameters& cached_network_params) {printf("[LOG] %s\n", __FUNCTION__);}

	  // Called when the connection parameters are set from the supplied
	  // |config|.
	  virtual void OnSetFromConfig(const net::QuicConfig& config) {printf("[LOG] %s\n", __FUNCTION__);}

	  // Called when RTT may have changed, including when an RTT is read from
	  // the config.
	  virtual void OnRttChanged(net::QuicTime::Delta rtt) const {printf("[LOG] %s\n", __FUNCTION__);}
};

} /* namespace connection */

} /* namespace quux */

#endif /* SRC_QUUX_CONNECTION_H_ */
