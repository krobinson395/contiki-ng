CONTIKI_PROJECT = udp-server 
all: $(CONTIKI_PROJECT)

CONTIKI_SOURCEFILES += PacketDrillHandlerTask.c

CFLAGS += -ggdb3
LDFLAGS += -lpcap -pthread -ggdb3

CONTIKI=../..
include $(CONTIKI)/Makefile.include
