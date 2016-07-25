
struct event_base;
struct event;
struct timeval;

struct event* event_new(struct event_base *base, int sock, short what,
		void (*cb)(int, short, void *), void *arg) {
	return 0;
}

int event_add(struct event *ev, const struct timeval *timeout) {
	return 0;
}

int event_del(struct event* ev) {
	return 0;
}
