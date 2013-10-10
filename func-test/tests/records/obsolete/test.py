#!/usr/bin/env python3

'''Test for support of obsolete records over XFR'''

import dnstest

t = dnstest.DnsTest()

master = t.server("bind")
slave = t.server("knot")
zone = t.zone("obsolete.", "obsolete.zone")

t.link(zone, master, slave)

t.start()

master.zones_wait(zone)
slave.zones_wait(zone)

t.xfr_diff(master, slave, zone)

t.end()
