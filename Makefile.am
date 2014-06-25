

bin_PROGRAMS = dhcpload dltest

#old_SOURCES = dhcpload.c util.c util.h

SOURCES = dhcp.c queue.c queue.h list.h pool.c pool.h log.h log.c util.c util.h

dltest_SOURCES = $(SOURCES) test.c list.c
dltest_CFLAGS = -DTEST
dltest_LDADD = -lpthread -lrt

dhcpload_SOURCES = $(SOURCES)
dhcpload_LDADD = -lpthread -lrt


