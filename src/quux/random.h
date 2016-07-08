/*
 * Random.h
 *
 *  Created on: Jul 1, 2016
 *      Author: user
 */

#ifndef SRC_QUUX_RANDOM_H_
#define SRC_QUUX_RANDOM_H_

#include <crypto/random.h>
#include <net/quic/crypto/quic_random.h>
#include <cstdint>

namespace quux {

/**
 * Same as net::DefaultRandom, but without the dependency on base::Singleton
 */
class Random: public net::QuicRandom {
public:
	Random() {
	}

	// FIXME: this is way expensive, reads /dev/urandom each time
	void RandBytes(void* data, size_t len) override {
		crypto::RandBytes(data, len);
	}

	uint64_t RandUint64() override {
#if 0
		uint64_t value;
		RandBytes(&value, sizeof(value));
		return value;
#endif

		return cur+2;
	}

	void Reseed(const void* additional_entropy, size_t entropy_len) override {

	}

	virtual ~Random() {
	}

	uint64_t cur = 5;
};

} /* namespace quux */

#endif /* SRC_QUUX_RANDOM_H_ */
