rfc3394
=====

[![Build Status](https://github.com/sg2342/erl_rfc3394/workflows/Common%20Test/badge.svg)](https://github.com/sg2342/erl_rfc3394/actions?query=branch%3Amain+workflow%3A"Common+Test")
[![Hex.pm](https://img.shields.io/hexpm/v/rfc3394.svg)](https://hex.pm/packages/rfc3394)
[![Docs](https://img.shields.io/badge/hex-docs-green.svg?style=flat)](https://hexdocs.pm/rfc3394)


Advanced Encryption Standard (AES) Key Wrap Algorithm

https://datatracker.ietf.org/doc/html/rfc3394.html


Build
-----

    $ rebar3 compile
	
	
Test
-----

    $ rebar3 as test do lint,dialyzer,xref,ct,cover
