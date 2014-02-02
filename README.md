pgocrypto
=========

Simple symmetric encryption between Go and PostgreSQL (with pgcrypto).

This project contains functions for encrypting and decrypting data in a uniform
way in Go and in PostgreSQL to allow a simple way of encrypting data as close
to its source as possible.  On the PostgreSQL side, in addition to this
extension, only pgcrypto is required.  Only the standard library is used on the
Go side.

This extension should be installed into the same schema with pgcrypto.

Requires PostgreSQL 9.1 or later.

[![Build Status](https://travis-ci.org/johto/pgocrypto.png?branch=master)](https://travis-ci.org/johto/pgocrypto)
