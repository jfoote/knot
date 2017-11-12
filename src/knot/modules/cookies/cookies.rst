.. _mod-cookies:

``cookies`` — DNS Cookies
================================

DNS Cookies (RFC 7873) is a lightweight security mechanism
against denial-of-service and amplification attacks. The server keeps a secret value (the server secret), which is used
to generate a cookie, which is sent to the client in the OPT RR. The server then verifies the authenticity of the client
by the presence of a correct cookie. Both the server and the client have to support DNS Cookies, otherwise they are not used.

.. NOTE:: This module introduces a statistics counter: the number of queries containing the COOKIE option.

Example
-------

It is recommended to enable DNS Cookies globally, not per zone.

::

    mod-cookies:
      - id: default
        secret-lifetime: 30h # The server secret is regenerated every 30 hours
        badcookie-slip: 3    # The server replies only to every third query with a wrong cookie

    template:
      - id: default
        global-module: mod-cookies/default # Enable DNS Cookies globally

Module reference
----------------

::

    mod-cookies:
      - id: STR
        secret-lifetime: TIME
        badcookie-slip: INT

.. _mod-cookies_id:

id
..

A module identifier.

.. _mod-cookies_secret-lifetime:

secret-lifetime
...............

This option configures how often the server secret is regenerated. The recommended value (RFC 7873) is between 26 hours and 36 days,
the allowed range for this option is between 1 second and 36 days.

*Default:* 26 hours

.. _mod-cookies_badcookie-slip:

badcookie-slip
..............

This option configures how often the server responds to queries containing an invalid cookie by sending them
the correct cookie.
Valid values are integers between 1 and 2147483647.

- The value **1** means that the server responds to every query.
- The value **2** means that the server responds to every second query with an invalid cookie, the rest of the queries is dropped.
- The value **N > 2** means that the server responds to every Nth query with an invalid cookie, the rest of the queries is dropped.

*Default:* 1
