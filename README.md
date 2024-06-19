rfc3394
=====

[![Build Status](https://github.com/sg2342/erl_rfc3394/workflows/Common%20Test/badge.svg)](https://github.com/sg2342/erl_rfc3394/actions?query=branch%3Amain+workflow%3A"Common+Test")

Advanced Encryption Standard (AES) Key Wrap Algorithm

https://datatracker.ietf.org/doc/html/rfc3394.html


Build
-----

    $ rebar3 compile
	
	
Test
-----

    $ rebar3 as test do lint,dialyzer,xref,ct,cover
