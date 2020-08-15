

.. image:: https://travis-ci.org/katzenpost/mailproxy.svg?branch=master
  :target: https://travis-ci.org/katzenpost/mailproxy

.. image:: https://godoc.org/github.com/katzenpost/mailproxy?status.svg
  :target: https://godoc.org/github.com/katzenpost/mailproxy


mailproxy - POP/SMTP to Katzenpost proxy server
===============================================

This is a implementation of a proxy server that exposes a POP/SMTP interface
to Katzenpost based mix networks. It is intended to run on a user's localhost
to allow standard mail clients to send and receive mail over the mixnet.


Building
--------

Requires golang 1.11 or later. Dependencies pinned using go-modules.
For more info about go-modules, see: https://github.com/golang/go/wiki/Modules

Build the mix server like this:
::

   export GO111MODULE=on
   cd cmd/mailproxy
   go build


Basic Usage
--------

Mailproxy can generate the keys, configuration file and perform the registration
via HTTP all in one call using the `-r` option:
::

   ./mailproxy -r -authority 127.0.0.1:29483 -authorityKey "o4w1Nyj/nKNwho5SWfAIfh7SMU8FRx52nMHGgYsMHqQ=" -registrationAddr 127.0.0.1:8000 -registrationWithoutHttps -provider provider1 -providerKey "2krwfNDfbakZCSTUUZYKXwdduzlEgS9Jfwm7eyZ0sCg=" -account alice


The daemon can then be run using:
::

   ./mailproxy -f ~/.mailproxy/mailproxy.toml

Now you can either set up any mail client or use swaks and curl.
Sending test messages with swaks:
::

   swaks --from alice@provider1 --to bob@provider2 --server 127.0.0.1:2525

Listing the inbox and receiving the first message with:
::

   curl --user alice@provider1:pw pop3://127.0.0.1:2524
   curl --user alice@provider1:pw pop3://127.0.0.1:2524/1

Manual Registration
--------

In case HTTP registration is not available the user needs to be created at the provider using the management socket.
::

    socat unix:/<path-to-data-dir>/management_sock STDOUT
    ADD_USER alice X25519_link_public_key_in_hex_or_base64
    SET_USER_IDENTITY alice X25519_identity_public_key_in_hex_or_base64
    
The keys can be found in the mailproxy data dir (default is ~/.mailproxy) as 'link.public.pem' and 'identity.public.pem' respectively.

author
======

Yawning Angel (yawning at schwanenlied dot me)


license
=======

AGPL: see LICENSE file for details.


supported by
============

.. image:: https://katzenpost.mixnetworks.org/_static/images/eu-flag-tiny.jpg

This project has received funding from the European Union’s Horizon 2020
research and innovation programme under the Grant Agreement No 653497, Privacy
and Accountability in Networks via Optimized Randomized Mix-nets (Panoramix).
