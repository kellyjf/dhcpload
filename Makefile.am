

bin_PROGRAMS = dhcpload dlng old

old_SOURCES = dhcpload.c util.c util.h

SOURCES = dhcp.c queue.c queue.h list.h list.c  pool.c pool.h log.h log.c util.c util.h

dlng_SOURCES = $(SOURCES) test.c
dlng_CFLAGS = -DTEST
dlng_LDADD = -lpthread -lrt

dhcpload_SOURCES = $(SOURCES)
dhcpload_LDADD = -lpthread -lrt


