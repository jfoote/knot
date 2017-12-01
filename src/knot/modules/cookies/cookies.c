/*  Copyright (C) 2017 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>

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

#include <pthread.h>
#include <unistd.h>

#include "knot/include/module.h"
#include "knot/nameserver/process_query.h"
#include "libknot/cookies/server.h"
#include "libknot/rrtype/opt-cookie.h"
#include "contrib/time.h"
#include "contrib/openbsd/siphash.h"
#include "dnssec/lib/dnssec/random.h"

#define COOKIES_SECRET_LEN 8
#define COOKIES_SC_LEN 16
#define COOKIES_CC_LEN KNOT_OPT_COOKIE_CLNT
#define COOKIES_NONCE_LEN 8
#define COOKIES_HASH_LEN 8

#define MOD_SECRET_LIFETIME "\x0F""secret-lifetime"
#define MOD_BADCOOKIE_SLIP  "\x0E""badcookie-slip"

#ifdef HAVE_ATOMIC
#define ATOMIC_SET(dst, val) __atomic_store(&(dst), &(val), __ATOMIC_RELAXED)
#define ATOMIC_GET(src, dst) __atomic_load(&(src), &(dst), __ATOMIC_RELAXED)
#define ATOMIC_ADD(dst, val) __atomic_add_fetch(&(dst), (val), __ATOMIC_RELAXED)
#else
#define ATOMIC_SET(dst, val) ((dst) = (val))
#define ATOMIC_GET(src, dst) ((dst) = (src))
#define ATOMIC_ADD(dst, val) ((dst) += (val))
#endif

const yp_item_t cookies_conf[] = {
	{ MOD_SECRET_LIFETIME, YP_TINT, YP_VINT = { 1, 36*24*3600, 26*3600 } },
	{ MOD_BADCOOKIE_SLIP,  YP_TINT, YP_VINT = { 1, INT32_MAX, 1 } },
	{ NULL }
};

typedef struct knot_sc_private knot_sc_private_t;
typedef struct knot_sc_alg knot_sc_alg_t;
typedef struct knot_sc_input knot_sc_input_t;

typedef struct {
	SIPHASH_KEY server_secret;
	uint16_t badcookie_ctr; // Counter for BADCOOKIE answers
	pthread_t update_secret;
	uint32_t secret_lifetime;
	uint32_t badcookie_slip;
} cookies_ctx_t;

static void update_ctr(cookies_ctx_t *ctx)
{
	assert(ctx);

	ATOMIC_ADD(ctx->badcookie_ctr, 1);
	if (ctx->badcookie_ctr == ctx->badcookie_slip) {
		uint16_t zero = 0;
		ATOMIC_SET(ctx->badcookie_ctr, zero);
	}
}

static int generate_secret(cookies_ctx_t *ctx)
{
	assert(ctx);

	// Generate a new secret and store it atomically
	SIPHASH_KEY new_secret;
	int ret = dnssec_random_buffer((uint8_t *)&new_secret.k0, COOKIES_SECRET_LEN);
	if (ret != KNOT_EOK) {
		return ret;
	}
	ret = dnssec_random_buffer((uint8_t *)&new_secret.k1, COOKIES_SECRET_LEN);
	if (ret != KNOT_EOK) {
		return ret;
	}

	__atomic_load(&ctx->server_secret, &new_secret, __ATOMIC_RELAXED);
	//ATOMIC_SET(ctx->server_secret, new_secret);

	return KNOT_EOK;
}

static void *update_secret(void *data)
{
	knotd_mod_t *mod = (knotd_mod_t *)data;
	cookies_ctx_t *ctx = knotd_mod_ctx(mod);

	while (true) {
		pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
		if (generate_secret(ctx) != KNOT_EOK) {
			knotd_mod_log(mod, LOG_DEBUG, "failed to generate a secret");
		};
		pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
		sleep(ctx->secret_lifetime);
	}

	return NULL;
}

// Inserts the current cookie option into the answer's OPT RR
static int put_cookie(cookies_ctx_t *ctx, knotd_qdata_t *qdata, knot_pkt_t *pkt,
                      const uint8_t *cc, knot_sc_private_t *srvr_data)
{
	assert(ctx && qdata && pkt && cc && srvr_data);

	// Reserve space in the answer's OPT RR
	uint8_t *wire_ptr = NULL;
	uint16_t size = knot_edns_opt_cookie_data_len(COOKIES_CC_LEN, COOKIES_SC_LEN);
	int ret = knot_edns_reserve_option(&qdata->opt_rr, KNOT_EDNS_OPTION_COOKIE,
	                                   size, &wire_ptr, qdata->mm);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// Compute the new server cookie
	uint8_t sc[COOKIES_SC_LEN];

	// First 8 bytes are the current time
	knot_time_t timestamp = (knot_time_t)time(NULL);
	memcpy(sc, &timestamp, COOKIES_NONCE_LEN);

	knot_sc_input_t sc_input = {
		.cc = cc,
		.cc_len = COOKIES_CC_LEN,
		.nonce = sc,
		.nonce_len = COOKIES_NONCE_LEN,
		.srvr_data = srvr_data
	};

	// Second 8 bytes are the hash
	uint64_t hash = generate_server_cookie(&sc_input);
	memcpy(sc + COOKIES_NONCE_LEN, &hash, COOKIES_HASH_LEN);

	// Write the prepared cookie to the wire
	ret = knot_edns_opt_cookie_write(cc, COOKIES_CC_LEN, sc, COOKIES_SC_LEN,
	                                 wire_ptr, size);
	if (ret <= 0) {
		return ret;
	}

	// Reserve the extra space for OPT RR in the answer packet
	return knot_pkt_reserve(pkt, knot_edns_wire_size(&qdata->opt_rr));
}

static knotd_state_t cookies_process(knotd_state_t state, knot_pkt_t *pkt,
                                     knotd_qdata_t *qdata, knotd_mod_t *mod)
{
	assert(pkt && qdata && mod);

	cookies_ctx_t *ctx = knotd_mod_ctx(mod);

	// Check if OPT RR is present
	if (qdata->query->opt_rr == NULL) {
		return state;
	}

	// Check if cookie option is present
	uint8_t *cookie_opt = knot_edns_get_option(qdata->query->opt_rr, KNOT_EDNS_OPTION_COOKIE);
	if (cookie_opt == NULL) {
		return state;
	}

	// Increment the statistics counter.
	knotd_mod_stats_incr(mod, 0, 0, 1);

	// Parse the cookie from wireformat
	uint16_t cookie_len = knot_edns_opt_get_length(cookie_opt);
	knot_dns_cookies_t cookies = { 0 };
	cookie_opt += 2 * sizeof(uint16_t); // Skip RCODE and length
	int ret = knot_edns_opt_cookie_parse(cookie_opt, cookie_len,
	                                     &cookies.cc, &cookies.cc_len,
	                                     &cookies.sc, &cookies.sc_len);
	if (ret != KNOT_EOK) {
		qdata->rcode = KNOT_RCODE_FORMERR;
		return KNOTD_STATE_FAIL;
	}

	// Prepare data for server cookie computation
	SIPHASH_KEY new_secret = { 0 };
	ATOMIC_GET(ctx->server_secret, new_secret);
	knot_sc_private_t srvr_data = {
		.clnt_sockaddr = (struct sockaddr *)qdata->params->remote,
		.secret = new_secret
	};

	// If this is a TCP connection, just answer with the current server cookie
	if (!(qdata->params->flags & KNOTD_QUERY_FLAG_LIMIT_SIZE)) {
		ret = put_cookie(ctx, qdata, pkt, cookies.cc, &srvr_data);
		if (ret != KNOT_EOK) {
			qdata->rcode = KNOT_RCODE_SERVFAIL;
			return KNOTD_STATE_FAIL;
		}
		return state;
	}

	// Compare server cookies
	ret = knot_sc_check(COOKIES_NONCE_LEN, &cookies, &srvr_data);

	if (ret == KNOT_EOK) {
		ret = put_cookie(ctx, qdata, pkt, cookies.cc, &srvr_data);
		if (ret != KNOT_EOK) {
			qdata->rcode = KNOT_RCODE_SERVFAIL;
			return KNOTD_STATE_FAIL;
		}
		return state;
	} else {
		if (ctx->badcookie_ctr > 0) {
			// Silently drop the response
			update_ctr(ctx);
			return KNOTD_STATE_NOOP;
		} else {
			if (ctx->badcookie_slip > 1) {
				update_ctr(ctx);
			}
			ret = put_cookie(ctx, qdata, pkt, cookies.cc, &srvr_data);
			if (ret != KNOT_EOK) {
				qdata->rcode = KNOT_RCODE_SERVFAIL;
				return KNOTD_STATE_FAIL;
			}
			qdata->rcode = KNOT_RCODE_BADCOOKIE;
			return KNOTD_STATE_FAIL;
		}
	}

	return state;
}

int cookies_load(knotd_mod_t *mod)
{
	// Create module context.
	cookies_ctx_t *ctx = calloc(1, sizeof(cookies_ctx_t));
	if (ctx == NULL) {
		return KNOT_ENOMEM;
	}

	// Initialize BADCOOKIE counter.
	ctx->badcookie_ctr = 0;

	// Set up configurable items.
	knotd_conf_t conf = knotd_conf_mod(mod, MOD_SECRET_LIFETIME);
	ctx->secret_lifetime = conf.single.integer;

	conf = knotd_conf_mod(mod, MOD_BADCOOKIE_SLIP);
	ctx->badcookie_slip = conf.single.integer;

	// Set up statistics counters.
	int ret = knotd_mod_stats_add(mod, "presence", 1, NULL);
	if (ret != KNOT_EOK) {
		free(ctx);
		return ret;
	}

	knotd_mod_ctx_set(mod, ctx);

	// Start the secret rollover thread.
	if (pthread_create(&ctx->update_secret, NULL, update_secret, (void *)mod)) {
		knotd_mod_log(mod, LOG_DEBUG, "failed to create the secret rollover thread");
	};

#ifndef HAVE_ATOMIC
	knotd_mod_log(mod, LOG_WARNING, "the module might work slightly wrong on this platform");
	ctx->badcookie_slip = 1;
#endif

	return knotd_mod_hook(mod, KNOTD_STAGE_BEGIN, cookies_process);
}

void cookies_unload(knotd_mod_t *mod)
{
	cookies_ctx_t *ctx = knotd_mod_ctx(mod);
	(void)pthread_cancel(ctx->update_secret);
	(void)pthread_join(ctx->update_secret, NULL);
	free(ctx);
}

KNOTD_MOD_API(cookies, KNOTD_MOD_FLAG_SCOPE_ANY | KNOTD_MOD_FLAG_OPT_CONF,
              cookies_load, cookies_unload, cookies_conf, NULL);
