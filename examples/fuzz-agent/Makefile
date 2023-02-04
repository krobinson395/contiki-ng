CONTIKI_PROJECT = udp-server 
all: $(CONTIKI_PROJECT)

#CONTIKI_SOURCEFILES += PacketDrillHandlerTask.c
# Adding asan flags caused the -Werror=stringop-truncation error
#-Wno-error=maybe-uninitialized -Wno-error=stringop-truncation 
CFLAGS += -ggdb3 -fPIE
LDFLAGS += -lpcap -pthread -ggdb3

CONTIKI=../..
include $(CONTIKI)/Makefile.include
