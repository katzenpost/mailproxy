

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
