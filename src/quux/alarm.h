/*
 * Alarm.h
 *
 *  Created on: Jul 2, 2016
 *      Author: user
 */

#ifndef SRC_QUUX_ALARM_H_
#define SRC_QUUX_ALARM_H_

#include <net/quic/quic_alarm.h>
#include <net/quic/quic_alarm_factory.h>
#include <net/quic/quic_arena_scoped_ptr.h>
#include <net/quic/quic_time.h>
#include <quux/internal.h>
#include <sys/time.h>
#include <algorithm>
#include <cstdint>
#include <map>
#include <utility>

extern "C" {
struct event *event_new(struct event_base *base, int sock, short what,
              void (*cb)(int, short, void *), void *arg);
int event_add(struct event *ev, const struct timeval *timeout);
int event_del(struct event *);
}

namespace quux {

class Alarm;
typedef std::multimap<int64_t, quux::Alarm*> TimeToAlarmMap;

namespace alarm {

static void libevent_timeout_cb(int socket, short what, void* arg);

} // namespace alarm

class Alarm: public net::QuicAlarm {
public:
	explicit Alarm(net::QuicArenaScopedPtr<Delegate> delegate,
			quux::TimeToAlarmMap* alarm_time_map) :
			QuicAlarm(std::move(delegate)), alarm_time_map(alarm_time_map), gogogo(
			true) {
	}

	void SetImpl() override {
		alarm_time_map->insert(
				std::make_pair(
						deadline().Subtract(net::QuicTime::Zero()).ToMicroseconds(),
						this));
	}

	void CancelImpl() override {
		gogogo = false;

		typedef quux::TimeToAlarmMap::iterator iterator;
		std::pair<iterator, iterator> iterpair = alarm_time_map->equal_range(deadline().Subtract(net::QuicTime::Zero()).ToMicroseconds());

		iterator it = iterpair.first;
		for (; it != iterpair.second; ++it) {
		    if (it->second == this) {
		    	alarm_time_map->erase(it);
		        break;
		    }
		}
	}

	void Fire() {
		if (!gogogo) {
			return;
		}
		QuicAlarm::Fire();
	}

	quux::TimeToAlarmMap* alarm_time_map;

	bool gogogo;
};

class LibeventAlarm: public net::QuicAlarm {
public:
	explicit LibeventAlarm(net::QuicArenaScopedPtr<Delegate> delegate) :
			QuicAlarm(std::move(delegate)), gogogo(
			true), tev(nullptr) {
	}

	void SetImpl() override {
		int64_t abs_micros = deadline().Subtract(net::QuicTime::Zero()).ToMicroseconds();
		int64_t abs_secs = abs_micros / 1000000;
		int64_t rem_micros = abs_micros - (abs_secs * 1000000);
#ifdef SHADOW
		// XXX: is this needed?
		if (abs_secs == 0 && rem_micros == 0) {
			rem_micros = 1;
		}
#endif
		struct timeval deadline_timeval = { abs_secs, rem_micros };
		tev = event_new(quux::event_base, -1, 0, alarm::libevent_timeout_cb, this);
		event_add(tev, &deadline_timeval);
	}

	void CancelImpl() override {
		gogogo = false;
		event_del(tev);
	}

	void Fire() {
		if (!gogogo) {
			return;
		}
		QuicAlarm::Fire();
	}

	bool gogogo;
	struct event *tev;
};

namespace alarm {

static void libevent_timeout_cb(int socket, short what, void* arg) {
	LibeventAlarm* alarm = (LibeventAlarm*)arg;
	alarm->Fire();
}

class Factory: public net::QuicAlarmFactory {
public:
	Factory(quux::TimeToAlarmMap* alarm_time_map) :
			QuicAlarmFactory(), alarm_time_map(alarm_time_map) {
	}

	net::QuicAlarm* CreateAlarm(net::QuicAlarm::Delegate* delegate) override {
		return new Alarm(
				net::QuicArenaScopedPtr<net::QuicAlarm::Delegate>(delegate),
				alarm_time_map);
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

	quux::TimeToAlarmMap* alarm_time_map;
};

class LibeventFactory: public net::QuicAlarmFactory {
public:
	net::QuicAlarm* CreateAlarm(net::QuicAlarm::Delegate* delegate) override {
		return new LibeventAlarm(
				net::QuicArenaScopedPtr<net::QuicAlarm::Delegate>(delegate));
	}

	net::QuicArenaScopedPtr<net::QuicAlarm> CreateAlarm(
			net::QuicArenaScopedPtr<net::QuicAlarm::Delegate> delegate,
			net::QuicConnectionArena* arena) override {
		if (arena != nullptr) {
			return arena->New<LibeventAlarm>(std::move(delegate));
		}
		return net::QuicArenaScopedPtr<net::QuicAlarm>(
				new LibeventAlarm(std::move(delegate)));
	}
};

} /* namespace alarm */

} /* namespace quux */

#endif /* SRC_QUUX_ALARM_H_ */
