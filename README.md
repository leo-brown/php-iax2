PHP IAX2 Interface Classes
============================

Author: Leo Brown <leo@netfuse.org>

These classes were written to help systems integrators deal
with the common actions of the IAX2 protocol. These were based
predominantly on the protocol overview provided in the IETF
draft, revision three, currently located at:

  http://ietfreport.isoc.org/all-ids/draft-guy-iax-03.txt

Requirements
------------
These classes require PHP5 with mhash support.

Usage
-----

The classes are designed to be stubs that are used by your software
as necessary by assessing what functionality they provide and integrating
with the files on the basis of comments and function definitions.

However, some tools have been provided in the examples/ directory, where:

    ./raw      Deals with raw pipes/files in libpcap format
    ./hex      Deals with hex dumps provided by TCPDUMP
    ./actions  Deals with specific IAX2 features (originate, transfer, ping)
    
For instance, to dump to screen details on all IAX2 communication visible
on the system's network adapters, use this syntax:

    cd examples/raw
    tcpdump -U -w- -s0 port 4569 | ./info.php

This will then output all messages read, e.g.:

    82.13.209.232   ->  213.126.5.119     *new*
    213.126.5.119   ->  82.13.209.232     *auth_challenge*
    82.13.209.232   ->  213.126.5.119     auth_response
    213.126.5.119   ->  82.13.209.232     accept
    82.13.209.232   ->  213.126.5.119     acknowledge
    114.75.202.167  ->  82.13.209.232     register_attempt
    82.13.209.232   ->  114.75.202.167    register_accept
    194.75.202.167  ->  82.13.209.232     acknowledge
    213.126.5.119   ->  82.13.209.232     voice
    213.126.5.119   ->  82.13.209.232     hangup

Similarly, the ping tool can be used directly as so:
    cd examples/actions
    ./iaxping testserver
  
Giving output similar to the following

    Ping to testserver took 3.1ms
    Ping to testserver took 1.8ms
    Ping to testserver took 1.6ms
    Ping to testserver took 1.6ms