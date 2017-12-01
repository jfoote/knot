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

#pragma once

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>

#include "contrib/openbsd/siphash.h"

/*!
 * \brief Convenience structure holding both, server and client, cookies.
 */
typedef struct knot_dns_cookies {
	const uint8_t *cc; /*!< Client cookie. */
	uint16_t cc_len;   /*!< Client cookie size. */
	const uint8_t *sc; /*!< Server cookie. */
	uint16_t sc_len;   /*!< Server cookie size. */
} knot_dns_cookies_t;

/*!
 * \brief Private data known to the server.
 *
 * \note Contains data needed to check the inbound server cookie and to
 *       generate a new one.
 */
typedef struct knot_sc_private {
	const struct sockaddr *clnt_sockaddr; /*!< Client (remote) socket address. */
	SIPHASH_KEY secret; /*!< Server secret data. */
} knot_sc_private_t;

/*!
 * \brief Inbound server cookie content structure.
 *
 * \note These data are obtained from an incoming server cookie.
 */
typedef struct knot_sc_content {
	const uint8_t *nonce; /*!< Some value prefixed to the hash. */
	uint16_t nonce_len;   /*!< Nonce data length. */
	const uint8_t *hash;  /*!< Hash data. */
	uint16_t hash_len;    /*!< Hash data length. */
} knot_sc_content_t;

/*!
 * \brief Input data needed to compute the server cookie value.
 *
 * \note All these data are needed to generate a new server cookie hash.
 */
typedef struct knot_sc_input {
	const uint8_t *cc;    /*!< Client cookie. */
	uint16_t cc_len;      /*!< Client cookie size. */
	const uint8_t *nonce; /*!< Some value prefixed before the hash. */
	uint16_t nonce_len;   /*!< Nonce data length. */
	const knot_sc_private_t *srvr_data; /*!< Private data known to the server. */
} knot_sc_input_t;

/*!
 * \brief Check server cookie input data for basic sanity.
 *
 * \param input  Data which to generate the cookie from.
 *
 * \retval true if input contains client cookie and server secret data
 * \retval false if input is insufficient or NULL pointer passed
 */
bool knot_sc_input_is_valid(const knot_sc_input_t *input);

/*!
 * \brief Reads a server cookie that contains \a nonce_len bytes of data
 *        prefixed before the actual hash.
 *
 * \see DNS Cookies, RFC 7873, Appendix B.1 and B.2
 *
 * \param nonce_len  Expected nonce data size.
 * \param sc         Server cookie.
 * \param sc_len     Server cookie length.
 * \param content    Server cookie content structure to be set.
 *
 * \retval KNOT_EOK
 * \retval KNOT_EINVAL
 */
int knot_sc_parse(uint16_t nonce_len, const uint8_t *sc, uint16_t sc_len,
                  knot_sc_content_t *content);


uint64_t generate_server_cookie(const knot_sc_input_t *input);

/*!
 * \brief Check whether supplied client and server cookies match.
 *
 * \param nonce_len  Expected nonce data size.
 * \param cookies    Cookie data.
 * \param srvr_data  Data known to the server needed for cookie validation.
 *
 * \retval KNOT_EOK
 * \retval KNOT_EINVAL
 */
int knot_sc_check(uint16_t nonce_len, const knot_dns_cookies_t *cookies,
                  const knot_sc_private_t *srvr_data);
