#!/usr/bin/env python3

'''cookies module functionality test'''

import dns.exception
import dns.message
import dns.query
import dns.edns
import os
import time

from dnstest.libknot import libknot
from dnstest.test import Test
from dnstest.module import ModCookies
from dnstest.utils import *

clientCookie = bytearray(b'\xde\xad\xbe\xef\xfe\xeb\xda\xed')
clientCookieLen = 8
cookieOpcode = 10
rcodeNoerror = 0
rcodeBadcookie = 23

def reconfigure(server, secret_lifetime, badcookie_slip):
    """
    Reconfigure server module.
    """
    server.clear_modules(None)
    server.add_module(None, ModCookies(secret_lifetime=secret_lifetime, badcookie_slip=badcookie_slip))
    server.gen_confile()
    server.reload()

def check_rcode(server, query, rcode):
    try:
        response = dns.query.udp(query, server.addr, port=server.port, timeout=0.05)
    except dns.exception.Timeout:
        response = None
    if response is None:
        return None
    compare(response.rcode(), rcode, "RCODE")
    return response

t = Test()

ModCookies.check()

knot = t.server("knot")
zone = t.zone("example.com", storage=".")


t.link(zone, knot)

t.start()

reconfigure(knot, 5, 1)

# Try a query without EDNS
query = dns.message.make_query("dns1.example.com", "A", use_edns=False)
check_rcode(knot, query, rcodeNoerror)

# Try a query without a cookie option
query = dns.message.make_query("dns1.example.com", "A", use_edns=True)
check_rcode(knot, query, rcodeNoerror)

# Try a query without a server cookie 
cookieOpt = dns.edns.option_from_wire(cookieOpcode, clientCookie, 0, clientCookieLen)
query = dns.message.make_query("dns1.example.com", "A", use_edns=True, options=[cookieOpt])
response = check_rcode(knot, query, rcodeBadcookie)

# Try a query with the received cookie
cookieOpt = response.options[0]
query = dns.message.make_query("dns1.example.com", "A", use_edns=True, options=[cookieOpt])
check_rcode(knot, query, rcodeNoerror)

# Try the same cookie after the secret rollover
time.sleep(5)
response = check_rcode(knot, query, rcodeBadcookie)

# Try a query with the new received cookie
cookieOpt = response.options[0]
query = dns.message.make_query("dns1.example.com", "A", use_edns=True, options=[cookieOpt])
response = check_rcode(knot, query, rcodeNoerror)

reconfigure(knot, 1000000, 4)

cookieOpt = dns.edns.option_from_wire(cookieOpcode, clientCookie, 0, clientCookieLen)
query = dns.message.make_query("dns1.example.com", "A", use_edns=True, options=[cookieOpt]);
response = check_rcode(knot, query, rcodeBadcookie)

# Next 3 attempts to get the server cookie should timeout
for i in range(3):
    query = dns.message.make_query("dns1.example.com", "A", use_edns=True, options=[cookieOpt]);
    response = check_rcode(knot, query, rcodeNoerror)
    compare(response, None, "BADCOOKIE TIMEOUT")

# THe 4th attempt should succeed
query = dns.message.make_query("dns1.example.com", "A", use_edns=True, options=[cookieOpt]);
check_rcode(knot, query, rcodeBadcookie)

t.end()
