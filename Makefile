# pgocrypto/Makefile

EXTENSION = pgocrypto
DATA = pgocrypto--1.0.sql

PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
