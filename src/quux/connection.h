/*
 * ConnectionHelper.h
 *
 *  Created on: Jun 28, 2016
 *      Author: user
 */

#ifndef SRC_QUUX_CONNECTION_H_
#define SRC_QUUX_CONNECTION_H_

#include "../net/quic/quic_connection.h"
#include "random.h"

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

} /* namespace connection */

} /* namespace quux */

#endif /* SRC_QUUX_CONNECTION_H_ */
