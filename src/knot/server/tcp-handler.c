/*  Copyright (C) 2011 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#ifdef HAVE_SYS_UIO_H			// struct iovec (OpenBSD)
#include <sys/uio.h>
#endif // HAVE_SYS_UIO_H
#ifdef HAVE_CAP_NG_H
#include <cap-ng.h>
#endif /* HAVE_CAP_NG_H */

#include "common/sockaddr.h"
#include "common-knot/fdset.h"
#include "common/macros.h"
#include "common/mempool.h"
#include "common/net.h"

#include "dnssec/random.h"
#include "libknot/packet/wire.h"
#include "libknot/processing/overlay.h"

#include "knot/knot.h"
#include "knot/server/tcp-handler.h"
#include "knot/nameserver/process_query.h"

/*! \brief TCP context data. */
typedef struct tcp_context {
	struct knot_overlay overlay;/*!< Query processing overlay. */
	server_t *server;           /*!< Name server structure. */
	struct iovec iov[2];        /*!< TX/RX buffers. */
	unsigned client_threshold;  /*!< Index of first TCP client. */
	timev_t last_poll_time;     /*!< Time of the last socket poll. */
	fdset_t set;                /*!< Set of server/client sockets. */
	unsigned thread_id;         /*!< Thread identifier. */
} tcp_context_t;

/*
 * Forward decls.
 */
#define TCP_THROTTLE_LO 5 /*!< Minimum recovery time on errors. */
#define TCP_THROTTLE_HI 50 /*!< Maximum recovery time on errors. */

/*! \brief Calculate TCP throttle time (random). */
static inline int tcp_throttle() {
	return TCP_THROTTLE_LO + (dnssec_random_uint16_t() % TCP_THROTTLE_HI);
}

/*! \brief Sweep TCP connection. */
static enum fdset_sweep_state tcp_sweep(fdset_t *set, int i, void *data)
{
	UNUSED(data);
	assert(set && i < set->n && i >= 0);

	int fd = set->pfd[i].fd;

	struct sockaddr_storage ss;
	socklen_t len = sizeof(struct sockaddr_storage);
	memset(&ss, 0, len);
	if (getpeername(fd, (struct sockaddr*)&ss, &len) < 0) {
		dbg_net("tcp: sweep getpeername() on invalid socket=%d\n", fd);
		return FDSET_SWEEP;
	}

	/* Translate */
	char addr_str[SOCKADDR_STRLEN] = {0};
	sockaddr_tostr(&ss, addr_str, sizeof(addr_str));

	log_notice("connection terminated due to inactivity, address '%s'", addr_str);
	close(fd);
	return FDSET_SWEEP;
}

/*!
 * \brief TCP event handler function.
 */
static int tcp_handle(tcp_context_t *tcp, int fd,
                      struct iovec *rx, struct iovec *tx)
{
	/* Create query processing parameter. */
	struct sockaddr_storage ss;
	memset(&ss, 0, sizeof(struct sockaddr_storage));
	struct process_query_param param = {0};
	param.socket = fd;
	param.remote = &ss;
	param.server = tcp->server;
	param.thread_id = tcp->thread_id;
	rx->iov_len = KNOT_WIRE_MAX_PKTSIZE;
	tx->iov_len = KNOT_WIRE_MAX_PKTSIZE;

	/* Receive peer name. */
	socklen_t addrlen = sizeof(struct sockaddr_storage);
	if (getpeername(fd, (struct sockaddr *)&ss, &addrlen) < 0) {
		;
	}

	/* Timeout. */
	struct timeval tmout = { conf()->max_conn_reply, 0 };

	/* Receive data. */
	int ret = tcp_recv_msg(fd, rx->iov_base, rx->iov_len, &tmout);
	if (ret <= 0) {
		dbg_net("tcp: client on fd=%d disconnected\n", fd);
		if (ret == KNOT_EAGAIN) {
			rcu_read_lock();
			char addr_str[SOCKADDR_STRLEN] = {0};
			sockaddr_tostr(&ss, addr_str, sizeof(addr_str));
			log_warning("connection timed out, address '%s', "
			            "timeout %d seconds",
			            addr_str, conf()->max_conn_idle);
			rcu_read_unlock();
		}
		return KNOT_ECONNREFUSED;
	} else {
		rx->iov_len = ret;
	}

	/* Create packets. */
	mm_ctx_t *mm = tcp->overlay.mm;
	knot_pkt_t *ans = knot_pkt_new(tx->iov_base, tx->iov_len, mm);
	knot_pkt_t *query = knot_pkt_new(rx->iov_base, rx->iov_len, mm);

	/* Initialize processing overlay. */
	knot_overlay_init(&tcp->overlay, mm);
	knot_overlay_add(&tcp->overlay, NS_PROC_QUERY, &param);

	/* Input packet. */
	int state = knot_overlay_in(&tcp->overlay, query);

	/* Resolve until NOOP or finished. */
	ret = KNOT_EOK;
	while (state & (KNOT_NS_PROC_FULL|KNOT_NS_PROC_FAIL)) {
		state = knot_overlay_out(&tcp->overlay, ans);

		/* Send, if response generation passed and wasn't ignored. */
		if (ans->size > 0 && !(state & (KNOT_NS_PROC_FAIL|KNOT_NS_PROC_NOOP))) {
			if (tcp_send_msg(fd, ans->wire, ans->size) != ans->size) {
				ret = KNOT_ECONNREFUSED;
				break;
			}
		}
	}

	/* Reset after processing. */
	knot_overlay_finish(&tcp->overlay);
	knot_overlay_deinit(&tcp->overlay);

	/* Cleanup. */
	knot_pkt_free(&query);
	knot_pkt_free(&ans);

	return ret;
}

int tcp_accept(int fd)
{
	/* Accept incoming connection. */
	int incoming = accept(fd, 0, 0);

	/* Evaluate connection. */
	if (incoming < 0) {
		int en = errno;
		if (en != EINTR && en != EAGAIN) {
			log_error("cannot accept connection (%d)", errno);
			if (en == EMFILE || en == ENFILE ||
			    en == ENOBUFS || en == ENOMEM) {
				int throttle = tcp_throttle();
				log_error("throttling TCP connection pool for "
				          "%d seconds, too many allocated "
				          "resources", throttle);
				sleep(throttle);
			}

		}
	} else {
		dbg_net("tcp: accepted connection fd=%d\n", incoming);
		/* Set recv() timeout. */
#ifdef SO_RCVTIMEO
		struct timeval tv;
		rcu_read_lock();
		tv.tv_sec = conf()->max_conn_idle;
		rcu_read_unlock();
		tv.tv_usec = 0;
		if (setsockopt(incoming, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
			log_warning("cannot set up TCP connection watchdog "
			            "timer, fd %d", incoming);
		}
#endif
	}

	return incoming;
}

static int tcp_event_accept(tcp_context_t *tcp, unsigned i)
{
	/* Accept client. */
	int fd = tcp->set.pfd[i].fd;
	int client = tcp_accept(fd);
	if (client >= 0) {
		/* Assign to fdset. */
		int next_id = fdset_add(&tcp->set, client, POLLIN, NULL);
		if (next_id < 0) {
			close(client);
			return next_id; /* Contains errno. */
		}

		/* Update watchdog timer. */
		rcu_read_lock();
		fdset_set_watchdog(&tcp->set, next_id, conf()->max_conn_hs);
		rcu_read_unlock();
	}

	return KNOT_EOK;
}

static int tcp_event_serve(tcp_context_t *tcp, unsigned i)
{
	int fd = tcp->set.pfd[i].fd;
	int ret = tcp_handle(tcp, fd, &tcp->iov[0], &tcp->iov[1]);

	/* Flush per-query memory. */
	mp_flush(tcp->overlay.mm->ctx);

	if (ret == KNOT_EOK) {
		/* Update socket activity timer. */
		rcu_read_lock();
		fdset_set_watchdog(&tcp->set, i, conf()->max_conn_idle);
		rcu_read_unlock();
	}

	return ret;
}

static int tcp_wait_for_events(tcp_context_t *tcp)
{
	/* Wait for events. */
	fdset_t *set = &tcp->set;
	int nfds = poll(set->pfd, set->n, TCP_SWEEP_INTERVAL * 1000);

	/* Mark the time of last poll call. */
	time_now(&tcp->last_poll_time);

	/* Process events. */
	unsigned i = 0;
	while (nfds > 0 && i < set->n) {

		/* Terminate faulty connections. */
		int fd = set->pfd[i].fd;

		/* Active sockets. */
		if (set->pfd[i].revents & POLLIN) {
			--nfds; /* One less active event. */

			/* Indexes <0, client_threshold) are master sockets. */
			if (i < tcp->client_threshold) {
				/* Faulty master sockets shall be sorted later. */
				(void) tcp_event_accept(tcp, i);
			} else {
				if (tcp_event_serve(tcp, i) != KNOT_EOK) {
					fdset_remove(set, i);
					close(fd);
					continue; /* Stay on the same index. */
				}
			}

		}

		if (set->pfd[i].revents & (POLLERR|POLLHUP|POLLNVAL)) {
			--nfds; /* One less active event. */
			fdset_remove(set, i);
			close(fd);
			continue; /* Stay on the same index. */
		}

		/* Next socket. */
		++i;
	}

	return nfds;
}

int tcp_master(dthread_t *thread)
{
	if (!thread || !thread->data) {
		return KNOT_EINVAL;
	}

	iohandler_t *handler = (iohandler_t *)thread->data;
	unsigned *iostate = &handler->thread_state[dt_get_id(thread)];

	int ret = KNOT_EOK;
	ref_t *ref = NULL;
	tcp_context_t tcp;
	memset(&tcp, 0, sizeof(tcp_context_t));

	/* Create big enough memory cushion. */
	mm_ctx_t mm;
	mm_ctx_mempool(&mm, 4 * sizeof(knot_pkt_t));

	/* Create TCP answering context. */
	tcp.server = handler->server;
	tcp.thread_id = handler->thread_id[dt_get_id(thread)];
	tcp.overlay.mm = &mm;

	/* Prepare structures for bound sockets. */
	fdset_init(&tcp.set, list_size(&conf()->ifaces) + CONFIG_XFERS);

	/* Create iovec abstraction. */
	for (unsigned i = 0; i < 2; ++i) {
		tcp.iov[i].iov_len = KNOT_WIRE_MAX_PKTSIZE;
		tcp.iov[i].iov_base = malloc(tcp.iov[i].iov_len);
		if (tcp.iov[i].iov_base == NULL) {
			ret = KNOT_ENOMEM;
			goto finish;
		}
	}

	/* Initialize sweep interval. */
	timev_t next_sweep = {0};
	time_now(&next_sweep);
	next_sweep.tv_sec += TCP_SWEEP_INTERVAL;

	for(;;) {

		/* Check handler state. */
		if (unlikely(*iostate & ServerReload)) {
			*iostate &= ~ServerReload;

			/* Cancel client connections. */
			for (unsigned i = tcp.client_threshold; i < tcp.set.n; ++i) {
				close(tcp.set.pfd[i].fd);
			}

			ref_release(ref);
			ref = server_set_ifaces(handler->server, &tcp.set, IO_TCP);
			if (tcp.set.n == 0) {
				break; /* Terminate on zero interfaces. */
			}

			tcp.client_threshold = tcp.set.n;
		}

		/* Check for cancellation. */
		if (dt_is_cancelled(thread)) {
			break;
		}

		/* Serve client requests. */
		tcp_wait_for_events(&tcp);

		/* Sweep inactive clients. */
		if (tcp.last_poll_time.tv_sec >= next_sweep.tv_sec) {
			fdset_sweep(&tcp.set, &tcp_sweep, NULL);
			time_now(&next_sweep);
			next_sweep.tv_sec += TCP_SWEEP_INTERVAL;
		}
	}

finish:
	free(tcp.iov[0].iov_base);
	free(tcp.iov[1].iov_base);
	mp_delete(mm.ctx);
	fdset_clear(&tcp.set);
	ref_release(ref);

	return ret;
}
