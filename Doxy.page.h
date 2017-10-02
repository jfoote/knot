/*!

\defgroup server            Server module
\defgroup threading         Threading API
\defgroup config            Server configuration
\defgroup query_processing  DNS query processing
\defgroup logging           Server logging API
\defgroup ctl               Control module
\defgroup zone_scanner      Zone scanner (core)
\defgroup zone_scanner_test Zone scanner testing environment
\defgroup knot_utils        DNS utilities

\mainpage Knot API documentation.

\par Knot DNS libraries
- \subpage libknot-page
- \subpage libdnssec-page
- \subpage libzscanner-page

\par Knot DNS documentation
- <a href="https://www.knot-dns.cz/documentation/">Documentation</a>

 
\par Git repository
  https://gitlab.labs.nic.cz/knot/knot-dns

\par Issue tracker
https://gitlab.labs.nic.cz/knot/knot-dns/issues

\par Mailing list
 knot-dns-users@lists.nic.cz

\copyright 2013-2017 CZ.NIC, z.s.p.o.

\copyright Licensed under the terms of
 [GNU General Public License](https://www.gnu.org/licenses/gpl-3.0.txt)
 version 3 or later.


\page libknot-page libknot - DNS-related functions

\ref libknot


\page libdnssec-page libdnssec - DNSSEC library used by Knot DNS

The \c libdnssec is a DNSSEC library for authoritative name servers and
similar solutions for DNSSEC management on the server side. Primarily,
the library is designed for use in the [Knot DNS](https://www.knot-dns.cz)
server.

\page libdnssec-page DNSSEC library overview

\section dependencies Library dependencies

In order to compile Knot DNS with \c libdnssec, following libraries
are required:

- [GnuTLS](http://www.gnutls.org) >= 3.0
  for cryptographic operations.
- [Nettle](http://www.lysator.liu.se/~nisse/nettle/) >= 2.4
  for Base64 encoding.
- [LibYAML](http://pyyaml.org/wiki/LibYAML) >= 0.1
  for YAML parsing and writing.

 On Debian based distributions, install following packages:

    libgnutls28-dev nettle-dev libyaml-dev

On Fedora based distributions, install following packages:
    gnutls-devel nettle-devel libyaml-devel

The library also utilizes following libraries, which are bundled with
\c libdnssec:

 - [LibUCW](http://www.ucw.cz/libucw/) for various internal structures.
 - [C TAP Harness](http://www.eyrie.org/~eagle/software/c-tap-harness/)
   for unit tests writing and execution.

\section organization Library organization

The library is structured into modules. Interface of each module is covered
by a separate header file.

It is recommended to include only required modules, for instance:

~~~~ {.c}
#include <dnssec/binary.h>
#include <dnssec/key.h>
~~~~

In order to include all headers, following header can be used:

~~~~ {.c}
#include <dnssec/dnssec.h>
~~~~


\section libdnssec-content DNSSEC library modules

This is the API documentation for the \c libdnssec library.

 - \ref binary - \copybrief binary
 - \ref crypto - \copybrief crypto
 - \ref error
 - \ref key - \copybrief key
 - \ref keyid - \copybrief keyid
 - \ref keystore - \copybrief keystore 
 - \ref keytag - \copybrief keytag
 - \ref list
 - \ref nsec - \copybrief nsec
 - \ref random - \copybrief random
 - \ref sign
 - \ref tsig - \copybrief tsig

\page libzscanner-page libzscanner - Zone scanner tool

\ref libknot

 */
