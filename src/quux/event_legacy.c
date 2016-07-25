
// For use with libevent 1.x

#include <stdlib.h>
#include <event.h>

struct event* event_new(struct event_base *base, int sock, short what,
		void (*cb)(int, short, void *), void *arg) {
	struct event *e = malloc(sizeof(struct event));
	event_set(e, sock, what, cb, arg);
	event_base_set(base, e);
	return e;
}
