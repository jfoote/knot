ACLOCAL_AMFLAGS = -I $(top_srcdir)/m4
SUBDIRS = zscanner dnssec contrib/dnstap .

.PHONY: check-compile
check-compile:
	$(MAKE) $(AM_MAKEFLAGS) -C zscanner $@
	$(MAKE) $(AM_MAKEFLAGS) -C dnssec $@

lib_LTLIBRARIES =				\
	libknot.la
noinst_LTLIBRARIES = 				\
	libcontrib.la

AM_CPPFLAGS = \
	-include $(top_builddir)/src/config.h	\
	-DCONFIG_DIR='"${config_dir}"'		\
	-DSTORAGE_DIR='"${storage_dir}"'	\
	-DRUN_DIR='"${run_dir}"'		\
	-DMODULE_DIR='"${module_dir}"'		\
	-DMODULE_INSTDIR='"${module_instdir}"'	\
	-I$(srcdir)/dnssec/lib

######################
# Knot DNS Libraries #
######################

EXTRA_DIST =					\
	contrib/licenses/0BSD			\
	contrib/licenses/BSD-3-Clause		\
	contrib/licenses/LGPL-2.0		\
	contrib/licenses/OLDAP-2.8		\
	contrib/lmdb/LICENSE			\
	contrib/openbsd/LICENSE			\
	contrib/ucw/LICENSE			\
	utils/pykeymgr/pykeymgr.in

# static: libcontrib sources
libcontrib_la_SOURCES = 			\
	contrib/asan.h				\
	contrib/base32hex.c			\
	contrib/base32hex.h			\
	contrib/base64.c			\
	contrib/base64.h			\
	contrib/ctype.h				\
	contrib/dynarray.h			\
	contrib/endian.h			\
	contrib/files.c				\
	contrib/files.h				\
	contrib/getline.c			\
	contrib/getline.h			\
	contrib/macros.h			\
	contrib/mempattern.c			\
	contrib/mempattern.h			\
	contrib/net.c				\
	contrib/net.h				\
	contrib/qp-trie/trie.c			\
	contrib/qp-trie/trie.h			\
	contrib/sockaddr.c			\
	contrib/sockaddr.h			\
	contrib/string.c			\
	contrib/string.h			\
	contrib/strtonum.h			\
	contrib/time.c				\
	contrib/time.h				\
	contrib/tolower.h			\
	contrib/trim.h				\
	contrib/wire.h				\
	contrib/wire_ctx.h			\
	contrib/openbsd/siphash.c		\
	contrib/openbsd/siphash.h		\
	contrib/openbsd/strlcat.c		\
	contrib/openbsd/strlcat.h		\
	contrib/openbsd/strlcpy.c		\
	contrib/openbsd/strlcpy.h		\
	contrib/ucw/array-sort.h		\
	contrib/ucw/binsearch.h			\
	contrib/ucw/heap.c			\
	contrib/ucw/heap.h			\
	contrib/ucw/lists.c			\
	contrib/ucw/lists.h			\
	contrib/ucw/mempool.c			\
	contrib/ucw/mempool.h

if !HAVE_LMDB
libcontrib_la_SOURCES +=			\
	contrib/lmdb/lmdb.h			\
	contrib/lmdb/mdb.c			\
	contrib/lmdb/midl.c			\
	contrib/lmdb/midl.h
endif !HAVE_LMDB

libcontrib_la_CPPFLAGS = $(AM_CPPFLAGS) $(CFLAG_VISIBILITY)
libcontrib_la_LDFLAGS  = $(AM_LDFLAGS) $(LDFLAG_EXCLUDE_LIBS)

# libknot headers
libknot_ladir = $(includedir)
nobase_libknot_la_HEADERS =			\
	libknot/attribute.h			\
	libknot/codes.h				\
	libknot/consts.h			\
	libknot/control/control.h		\
	libknot/cookies.h			\
	libknot/descriptor.h			\
	libknot/dname.h				\
	libknot/errcode.h			\
	libknot/error.h				\
	libknot/libknot.h			\
	libknot/lookup.h			\
	libknot/mm_ctx.h			\
	libknot/db/db.h				\
	libknot/db/db_lmdb.h			\
	libknot/db/db_trie.h			\
	libknot/packet/compr.h			\
	libknot/packet/pkt.h			\
	libknot/packet/rrset-wire.h		\
	libknot/packet/wire.h			\
	libknot/rdata.h				\
	libknot/rdataset.h			\
	libknot/rrset-dump.h			\
	libknot/rrset.h				\
	libknot/rrtype/aaaa.h			\
	libknot/rrtype/dnskey.h			\
	libknot/rrtype/ds.h			\
	libknot/rrtype/naptr.h			\
	libknot/rrtype/nsec.h			\
	libknot/rrtype/nsec3.h			\
	libknot/rrtype/nsec3param.h		\
	libknot/rrtype/opt.h			\
	libknot/rrtype/rdname.h			\
	libknot/rrtype/rrsig.h			\
	libknot/rrtype/soa.h			\
	libknot/rrtype/tsig.h			\
	libknot/rrtype/txt.h			\
	libknot/tsig-op.h			\
	libknot/tsig.h				\
	libknot/yparser/yparser.h		\
	libknot/yparser/ypformat.h		\
	libknot/yparser/ypschema.h		\
	libknot/yparser/yptrafo.h		\
	libknot/version.h

# dynamic: libknot sources
libknot_la_SOURCES =				\
	libknot/codes.c				\
	libknot/control/control.c		\
	libknot/cookies.c			\
	libknot/descriptor.c			\
	libknot/dname.c				\
	libknot/error.c				\
	libknot/db/db_lmdb.c			\
	libknot/db/db_trie.c			\
	libknot/packet/compr.c			\
	libknot/packet/pkt.c			\
	libknot/packet/rrset-wire.c		\
	libknot/packet/wire.c			\
	libknot/rdataset.c			\
	libknot/rrset-dump.c			\
	libknot/rrset.c				\
	libknot/rrtype/aaaa.c			\
	libknot/rrtype/dnskey.c			\
	libknot/rrtype/ds.c			\
	libknot/rrtype/naptr.c			\
	libknot/rrtype/nsec3.c			\
	libknot/rrtype/nsec3param.c		\
	libknot/rrtype/opt.c			\
	libknot/rrtype/rrsig.c			\
	libknot/rrtype/soa.c			\
	libknot/rrtype/tsig.c			\
	libknot/tsig-op.c			\
	libknot/tsig.c				\
	libknot/yparser/yparser.c		\
	libknot/yparser/ypbody.c		\
	libknot/yparser/ypformat.c		\
	libknot/yparser/ypschema.c		\
	libknot/yparser/yptrafo.c		\
	$(nobase_libknot_la_HEADERS)

libknot_la_CPPFLAGS = $(AM_CPPFLAGS) $(CFLAG_VISIBILITY) $(lmdb_CFLAGS)
libknot_la_LDFLAGS  = $(AM_LDFLAGS) $(libknot_VERSION_INFO) $(lmdb_LIBS) \
                      $(LDFLAG_EXCLUDE_LIBS)
libknot_la_LIBADD   = dnssec/libdnssec.la libcontrib.la

# pkg-config
pkgconfig_DATA = knotd.pc libknot.pc

# static: utilities shared
libknotus_la_SOURCES =				\
	utils/common/cert.c			\
	utils/common/cert.h			\
	utils/common/exec.c			\
	utils/common/exec.h			\
	utils/common/hex.c			\
	utils/common/hex.h			\
	utils/common/lookup.c			\
	utils/common/lookup.h			\
	utils/common/msg.c			\
	utils/common/msg.h			\
	utils/common/netio.c			\
	utils/common/netio.h			\
	utils/common/params.c			\
	utils/common/params.h			\
	utils/common/resolv.c			\
	utils/common/resolv.h			\
	utils/common/sign.c			\
	utils/common/sign.h			\
	utils/common/tls.c			\
	utils/common/tls.h			\
	utils/common/token.c			\
	utils/common/token.h

libknotus_la_CPPFLAGS = $(AM_CPPFLAGS) $(CFLAG_VISIBILITY) $(libidn2_LIBS) \
                        $(libidn_CFLAGS) $(libedit_CFLAGS) $(gnutls_CFLAGS)
libknotus_la_LDFLAGS  = $(AM_LDFLAGS) $(LDFLAG_EXCLUDE_LIBS)
libknotus_la_LIBADD   = libcontrib.la libknot.la $(libidn2_LIBS) $(libidn_LIBS) \
                        $(libedit_LIBS) $(gnutls_LIBS)

libknotd_la_SOURCES =				\
	knot/conf/base.c			\
	knot/conf/base.h			\
	knot/conf/conf.c			\
	knot/conf/conf.h			\
	knot/conf/confdb.c			\
	knot/conf/confdb.h			\
	knot/conf/confio.c			\
	knot/conf/confio.h			\
	knot/conf/migration.c			\
	knot/conf/migration.h			\
	knot/conf/module.h			\
	knot/conf/module.c			\
	knot/conf/schema.c			\
	knot/conf/schema.h			\
	knot/conf/tools.c			\
	knot/conf/tools.h			\
	knot/ctl/commands.c			\
	knot/ctl/commands.h			\
	knot/ctl/process.c			\
	knot/ctl/process.h			\
	knot/dnssec/context.c			\
	knot/dnssec/context.h			\
	knot/dnssec/kasp/kasp_db.c		\
	knot/dnssec/kasp/kasp_db.h		\
	knot/dnssec/kasp/kasp_zone.c		\
	knot/dnssec/kasp/kasp_zone.h		\
	knot/dnssec/kasp/keystate.c		\
	knot/dnssec/kasp/keystate.h		\
	knot/dnssec/kasp/keystore.c		\
	knot/dnssec/kasp/keystore.h		\
	knot/dnssec/kasp/policy.h		\
	knot/dnssec/key-events.c		\
	knot/dnssec/key-events.h		\
	knot/dnssec/nsec-chain.c		\
	knot/dnssec/nsec-chain.h		\
	knot/dnssec/nsec3-chain.c		\
	knot/dnssec/nsec3-chain.h		\
	knot/dnssec/policy.c			\
	knot/dnssec/policy.h			\
	knot/dnssec/rrset-sign.c		\
	knot/dnssec/rrset-sign.h		\
	knot/dnssec/zone-events.c		\
	knot/dnssec/zone-events.h		\
	knot/dnssec/zone-keys.c			\
	knot/dnssec/zone-keys.h			\
	knot/dnssec/zone-nsec.c			\
	knot/dnssec/zone-nsec.h			\
	knot/dnssec/zone-sign.c			\
	knot/dnssec/zone-sign.h			\
	knot/events/events.c			\
	knot/events/events.h			\
	knot/events/handlers.h			\
	knot/events/handlers/dnssec.c		\
	knot/events/handlers/expire.c		\
	knot/events/handlers/flush.c		\
	knot/events/handlers/freeze_thaw.c	\
	knot/events/handlers/load.c		\
	knot/events/handlers/notify.c		\
	knot/events/handlers/nsec3resalt.c	\
	knot/events/handlers/refresh.c		\
	knot/events/handlers/update.c		\
	knot/events/handlers/parent_ds_query.c	\
	knot/events/log.c			\
	knot/events/log.h			\
	knot/events/replan.c			\
	knot/events/replan.h			\
	knot/nameserver/axfr.c			\
	knot/nameserver/axfr.h			\
	knot/nameserver/chaos.c			\
	knot/nameserver/chaos.h			\
	knot/nameserver/internet.c		\
	knot/nameserver/internet.h		\
	knot/nameserver/ixfr.c			\
	knot/nameserver/ixfr.h			\
	knot/nameserver/log.h			\
	knot/nameserver/notify.c		\
	knot/nameserver/notify.h		\
	knot/nameserver/nsec_proofs.c		\
	knot/nameserver/nsec_proofs.h		\
	knot/nameserver/process_query.c		\
	knot/nameserver/process_query.h		\
	knot/nameserver/query_module.c		\
	knot/nameserver/query_module.h		\
	knot/nameserver/tsig_ctx.c		\
	knot/nameserver/tsig_ctx.h		\
	knot/nameserver/update.c		\
	knot/nameserver/update.h		\
	knot/nameserver/xfr.c			\
	knot/nameserver/xfr.h			\
	knot/query/capture.c			\
	knot/query/capture.h			\
	knot/query/layer.h			\
	knot/query/query.c			\
	knot/query/query.h			\
	knot/query/requestor.c			\
	knot/query/requestor.h			\
	knot/common/evsched.c			\
	knot/common/evsched.h			\
	knot/common/fdset.c			\
	knot/common/fdset.h			\
	knot/common/log.c			\
	knot/common/log.h			\
	knot/common/process.c			\
	knot/common/process.h			\
	knot/common/ref.c			\
	knot/common/ref.h			\
	knot/common/stats.c			\
	knot/common/stats.h			\
	knot/server/dthreads.c			\
	knot/server/dthreads.h			\
	knot/journal/journal.c			\
	knot/journal/journal.h			\
	knot/journal/serialization.c		\
	knot/journal/serialization.h		\
	knot/server/server.c			\
	knot/server/server.h			\
	knot/server/tcp-handler.c		\
	knot/server/tcp-handler.h		\
	knot/server/udp-handler.c		\
	knot/server/udp-handler.h		\
	knot/updates/acl.c			\
	knot/updates/acl.h			\
	knot/updates/apply.c			\
	knot/updates/apply.h			\
	knot/updates/changesets.c		\
	knot/updates/changesets.h		\
	knot/updates/ddns.c			\
	knot/updates/ddns.h			\
	knot/updates/zone-update.c		\
	knot/updates/zone-update.h		\
	knot/worker/pool.c			\
	knot/worker/pool.h			\
	knot/worker/queue.c			\
	knot/worker/queue.h			\
	knot/zone/contents.c			\
	knot/zone/contents.h			\
	knot/zone/node.c			\
	knot/zone/node.h			\
	knot/zone/semantic-check.c		\
	knot/zone/semantic-check.h		\
	knot/zone/serial.c			\
	knot/zone/serial.h			\
	knot/zone/timers.c			\
	knot/zone/timers.h			\
	knot/zone/zone-diff.c			\
	knot/zone/zone-diff.h			\
	knot/zone/zone-dump.c			\
	knot/zone/zone-dump.h			\
	knot/zone/zone-load.c			\
	knot/zone/zone-load.h			\
	knot/zone/zone-tree.c			\
	knot/zone/zone-tree.h			\
	knot/zone/zone.c			\
	knot/zone/zone.h			\
	knot/zone/zonedb-load.c			\
	knot/zone/zonedb-load.h			\
	knot/zone/zonedb.c			\
	knot/zone/zonedb.h			\
	knot/zone/zonefile.c			\
	knot/zone/zonefile.h

libknotd_la_CPPFLAGS = $(AM_CPPFLAGS) $(CFLAG_VISIBILITY) $(systemd_CFLAGS) \
                       $(liburcu_CFLAGS) -DKNOTD_MOD_STATIC
libknotd_la_LDFLAGS  = $(AM_LDFLAGS) -export-symbols-regex '^knotd_'
libknotd_la_LIBADD   = libknot.la zscanner/libzscanner.la $(systemd_LIBS) \
                       $(liburcu_LIBS) $(atomic_LIBS)

###################
# Knot DNS Daemon #
###################

if HAVE_DAEMON

sbin_PROGRAMS = knotc knotd keymgr
sbin_SCRIPTS = utils/pykeymgr/pykeymgr
noinst_LTLIBRARIES += libknotd.la libknotus.la
CLEAN_FILES = $(sbin_SCRIPTS)

knotddir = $(includedir)/knot
knotd_HEADERS =					\
	knot/include/module.h

knotc_SOURCES =					\
	utils/knotc/commands.c			\
	utils/knotc/commands.h			\
	utils/knotc/estimator.c			\
	utils/knotc/estimator.h			\
	utils/knotc/interactive.c		\
	utils/knotc/interactive.h		\
	utils/knotc/process.c			\
	utils/knotc/process.h			\
	utils/knotc/main.c

knotd_SOURCES =					\
	utils/knotd/main.c

keymgr_SOURCES = 				\
	utils/keymgr/bind_privkey.c		\
	utils/keymgr/bind_privkey.h		\
	utils/keymgr/functions.c		\
	utils/keymgr/functions.h		\
	utils/keymgr/main.c

knotd_CPPFLAGS  = $(AM_CPPFLAGS) $(CFLAG_VISIBILITY) $(liburcu_CFLAGS)
knotd_LDADD     = libknotd.la libcontrib.la $(liburcu_LIBS)
knotd_LDFLAGS   = $(AM_LDFLAGS) -rdynamic
knotc_CPPFLAGS  = $(AM_CPPFLAGS) $(CFLAG_VISIBILITY) $(libedit_CFLAGS)
knotc_LDADD     = libknotd.la libcontrib.la libknotus.la $(libedit_LIBS)
knotc_LDFLAGS   = $(AM_LDFLAGS) -rdynamic
keymgr_CPPFLAGS = $(AM_CPPFLAGS) -I$(srcdir)/dnssec/lib/dnssec \
                  -I$(srcdir)/dnssec $(gnutls_CFLAGS)
keymgr_LDADD    = libknotd.la libcontrib.la libknotus.la dnssec/libdnssec.la \
                  dnssec/libshared.la zscanner/libzscanner.la

####################################
# Optional Knot DNS Daemon modules #
####################################

# Create storage and run-time directories
install-data-hook:
	$(INSTALL) -d $(DESTDIR)/@config_dir@
	$(INSTALL) -d $(DESTDIR)/@run_dir@
	$(INSTALL) -d $(DESTDIR)/@storage_dir@

endif # HAVE_DAEMON

######################
# Knot DNS Utilities #
######################

if HAVE_UTILS

bin_PROGRAMS = kdig khost knsec3hash knsupdate
if HAVE_DAEMON
bin_PROGRAMS += kzonecheck kjournalprint
endif # HAVE_DAEMON

kdig_SOURCES =					\
	utils/kdig/kdig_exec.c			\
	utils/kdig/kdig_exec.h			\
	utils/kdig/kdig_main.c			\
	utils/kdig/kdig_params.c		\
	utils/kdig/kdig_params.h

khost_SOURCES =					\
	utils/kdig/kdig_exec.c			\
	utils/kdig/kdig_exec.h			\
	utils/kdig/kdig_params.c		\
	utils/kdig/kdig_params.h		\
	utils/khost/khost_main.c		\
	utils/khost/khost_params.c		\
	utils/khost/khost_params.h

knsec3hash_SOURCES =				\
	utils/knsec3hash/knsec3hash.c

knsupdate_SOURCES =				\
	utils/knsupdate/knsupdate_exec.c	\
	utils/knsupdate/knsupdate_exec.h	\
	utils/knsupdate/knsupdate_main.c	\
	utils/knsupdate/knsupdate_params.c	\
	utils/knsupdate/knsupdate_params.h

kzonecheck_SOURCES =				\
	utils/kzonecheck/main.c			\
	utils/kzonecheck/zone_check.c		\
	utils/kzonecheck/zone_check.h

kjournalprint_SOURCES = 			\
	utils/kjournalprint/main.c

# bin programs
kdig_CPPFLAGS          = $(AM_CPPFLAGS) $(gnutls_CFLAGS)
kdig_LDADD             = libknotus.la
khost_CPPFLAGS         = $(AM_CPPFLAGS) $(gnutls_CFLAGS)
khost_LDADD            = libknotus.la
knsupdate_CPPFLAGS     = $(AM_CPPFLAGS) $(gnutls_CFLAGS)
knsupdate_LDADD        = libknotus.la zscanner/libzscanner.la
knsec3hash_CPPFLAGS    = $(AM_CPPFLAGS) -I$(srcdir)/dnssec -I$(srcdir)/dnssec/lib/dnssec
knsec3hash_LDADD       = libknot.la libcontrib.la dnssec/libdnssec.la dnssec/libshared.la
kzonecheck_CPPFLAGS    = $(AM_CPPFLAGS)
kzonecheck_LDADD       = libknotd.la libcontrib.la
kjournalprint_CPPFLAGS = $(AM_CPPFLAGS) $(gnutls_CFLAGS)
kjournalprint_LDADD    = libknotd.la libcontrib.la

#######################################
# Optional Knot DNS Utilities modules #
#######################################

if HAVE_DNSTAP
kdig_LDADD          += $(DNSTAP_LIBS) contrib/dnstap/libdnstap.la
khost_LDADD         += $(DNSTAP_LIBS) contrib/dnstap/libdnstap.la
kdig_CPPFLAGS       += $(DNSTAP_CFLAGS)
khost_CPPFLAGS      += $(DNSTAP_CFLAGS)
endif # HAVE_DNSTAP

endif # HAVE_UTILS

KNOTD_MOD_CPPFLAGS = $(AM_CPPFLAGS) $(CFLAG_VISIBILITY)
KNOTD_MOD_LDFLAGS  = $(AM_LDFLAGS) -module -shared -avoid-version

pkglibdir = $(module_instdir)
pkglib_LTLIBRARIES =

include $(srcdir)/knot/modules/cookies/Makefile.inc
include $(srcdir)/knot/modules/dnsproxy/Makefile.inc
include $(srcdir)/knot/modules/dnstap/Makefile.inc
include $(srcdir)/knot/modules/noudp/Makefile.inc
include $(srcdir)/knot/modules/onlinesign/Makefile.inc
include $(srcdir)/knot/modules/rrl/Makefile.inc
include $(srcdir)/knot/modules/stats/Makefile.inc
include $(srcdir)/knot/modules/synthrecord/Makefile.inc
include $(srcdir)/knot/modules/whoami/Makefile.inc
