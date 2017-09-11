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

#include "knot/include/module.h"
#include "knot/nameserver/process_query.h"
#include "libknot/cookies/server.h"
#include "libknot/cookies/alg-fnv64.h"
#include "libknot/rrtype/opt-cookie.h"
#include "contrib/time.h"
#include "dnssec/lib/dnssec/random.h"

#define COOKIES_SECRET_LEN 8
#define COOKIES_SC_LEN 16
#define COOKIES_CC_LEN KNOT_OPT_COOKIE_CLNT
#define COOKIES_NONCE_LEN 8
#define COOKIES_HASH_LEN 8
#define COOKIES_BADCOOKIE_DROP_RATE 2

typedef struct knot_sc_private knot_sc_private_t;
typedef struct knot_dns_cookies knot_dns_cookies_t;
typedef struct knot_sc_alg knot_sc_alg_t;
typedef struct knot_sc_input knot_sc_input_t;

typedef struct {
	uint8_t *server_secret;
	knot_time_t secret_gen_time; // Last time the server secret was generated
	uint16_t badcookie_ctr; // Counter for BADCOOKIE answers
} cookies_ctx_t;

static void update_ctr(cookies_ctx_t *ctx)
{
	if (++ctx->badcookie_ctr == COOKIES_BADCOOKIE_DROP_RATE) {
		ctx->badcookie_ctr = 0;
	}
}

static int generate_secret(cookies_ctx_t *ctx)
{
	// Free the previous secret if present
	if (ctx->server_secret != NULL) {
		free(ctx->server_secret);
	}

	// Generate new secret
	int ret = dnssec_random_buffer(ctx->server_secret, COOKIES_SECRET_LEN);
	if (ret != KNOT_EOK) {
		return ret;
	}

	// Update generation time
	ctx->secret_gen_time = (knot_time_t)time(NULL);

	return KNOT_EOK;
}

// Inserts the current cookie option into the answer's OPT RR
static int put_cookie(knotd_qdata_t *qdata, knot_pkt_t *pkt,
                             const uint8_t *cc, knot_sc_private_t *srvr_data)
{
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
	knot_time_t timestamp = (knot_time_t)time(NULL);

	// First 8 bytes are the current time
	memcpy(sc, &timestamp, COOKIES_NONCE_LEN);

	knot_sc_input_t sc_input = {
		.cc = cc,
		.cc_len = COOKIES_CC_LEN,
		.nonce = sc,
		.nonce_len = COOKIES_NONCE_LEN,
		.srvr_data = srvr_data
	};

	// Second 8 bytes are the hash
	uint16_t hash_len = knot_sc_alg_fnv64.hash_func(&sc_input, sc + COOKIES_NONCE_LEN,
	                                                COOKIES_HASH_LEN);
	if (hash_len != COOKIES_HASH_LEN) {
		return KNOT_EINVAL;
	}

	// Write the prepared cookie to the wire
	ret = knot_edns_opt_cookie_write(cc, COOKIES_CC_LEN, sc, COOKIES_SC_LEN,
	                                 wire_ptr, size);
	if (ret != KNOT_EOK) {
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
	knot_sc_private_t srvr_data = {
		.clnt_sockaddr = (struct sockaddr *)qdata->params->remote,
		.secret_data = ctx->server_secret,
		.secret_len = COOKIES_SECRET_LEN
	};

	// If this is a TCP connection, just answer with the current server cookie
	if (!(qdata->params->flags & KNOTD_QUERY_FLAG_LIMIT_SIZE)) {
		ret = put_cookie(qdata, pkt, cookies.cc, &srvr_data);
		if (ret != KNOT_EOK) {
			qdata->rcode = KNOT_RCODE_SERVFAIL;
			return KNOTD_STATE_FAIL;
		}
		return state;
	}

	// Compare server cookies
	ret = knot_sc_check(COOKIES_NONCE_LEN, &cookies, &srvr_data, &knot_sc_alg_fnv64);

	if (ret == KNOT_EOK) {
		ret = put_cookie(qdata, pkt, cookies.cc, &srvr_data);
		if (ret != KNOT_EOK) {
			qdata->rcode = KNOT_RCODE_SERVFAIL;
			return KNOTD_STATE_FAIL;
		}
		return state;
	}
	else {
		if (ctx->badcookie_ctr > 0) {
			// Silently drop the response
			update_ctr(ctx);
			return KNOTD_STATE_NOOP;
		}
		else {
			update_ctr(ctx);
			ret = put_cookie(qdata, pkt, cookies.cc, &srvr_data);
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
	// Create module context
	cookies_ctx_t *ctx = calloc(1, sizeof(cookies_ctx_t));
	if (ctx == NULL) {
		return KNOT_ENOMEM;
	}

	// Generate the first server secret
	int ret = generate_secret(ctx);
	if (ret != KNOT_EOK) {
		return knot_error_from_libdnssec(ret);
	}

	// Initialize BADCOOKIE counter
	ctx->badcookie_ctr = 0;

	knotd_mod_ctx_set(mod, ctx);

	return knotd_mod_hook(mod, KNOTD_STAGE_BEGIN, cookies_process);
}

void cookies_unload(knotd_mod_t *mod)
{
	cookies_ctx_t *ctx = knotd_mod_ctx(mod);
	free(ctx->server_secret);
	free(ctx);
}

KNOTD_MOD_API(cookies, KNOTD_MOD_FLAG_SCOPE_ANY | KNOTD_MOD_FLAG_OPT_CONF,
              cookies_load, cookies_unload, NULL, NULL);
