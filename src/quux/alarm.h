/*
 * Alarm.h
 *
 *  Created on: Jul 2, 2016
 *      Author: user
 */

#ifndef SRC_QUUX_ALARM_H_
#define SRC_QUUX_ALARM_H_

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <map>
#include <utility>

#include "../net/quic/quic_alarm.h"
#include "../net/quic/quic_alarm_factory.h"
#include "../net/quic/quic_arena_scoped_ptr.h"
#include "../net/quic/quic_time.h"

namespace quux {

class Alarm: public net::QuicAlarm {
public:
	explicit Alarm(net::QuicArenaScopedPtr<Delegate> delegate,
			std::multimap<int64_t, Alarm*>* alarm_time_map) :
			alarm_time_map(alarm_time_map), QuicAlarm(std::move(delegate)) {
	}

	void SetImpl() override {
		alarm_time_map->insert(
				std::make_pair(
						deadline().Subtract(net::QuicTime::Zero()).ToMicroseconds(),
						this));
	}

	void CancelImpl() override {
		// maybe cheaper than clearing from the map, I guess
		gogogo = false;
	}

	void Fire() {
		if (!gogogo) {
			return;
		}
		QuicAlarm::Fire();
	}

	virtual ~Alarm() {
	}

	std::multimap<int64_t, Alarm*>* alarm_time_map;
	bool gogogo = true;
};

namespace alarm {

class Factory: public net::QuicAlarmFactory {
public:
	Factory(std::multimap<int64_t, Alarm*>* alarm_time_map) : alarm_time_map(alarm_time_map) {
	}

	net::QuicAlarm* CreateAlarm(net::QuicAlarm::Delegate* delegate) override {
		return new Alarm(
				net::QuicArenaScopedPtr<net::QuicAlarm::Delegate>(delegate), alarm_time_map);
	}

	net::QuicArenaScopedPtr<net::QuicAlarm> CreateAlarm(
			net::QuicArenaScopedPtr<net::QuicAlarm::Delegate> delegate,
			net::QuicConnectionArena* arena) override {
		if (arena != nullptr) {
			return arena->New<Alarm>(std::move(delegate), alarm_time_map);
		}
		return net::QuicArenaScopedPtr<net::QuicAlarm>(
				new Alarm(std::move(delegate), alarm_time_map));
	}

	virtual ~Factory() {

	}

	std::multimap<int64_t, Alarm*>* alarm_time_map;
};

} /* namespace alarm */

} /* namespace quux */

#endif /* SRC_QUUX_ALARM_H_ */
