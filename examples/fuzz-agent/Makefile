CONTIKI_PROJECT = udp-server 
all: $(CONTIKI_PROJECT)

#CONTIKI_SOURCEFILES += PacketDrillHandlerTask.c
# Adding asan flags caused the -Werror=stringop-truncation error
#-Wno-error=maybe-uninitialized -Wno-error=stringop-truncation 
CFLAGS += -ggdb3 -fPIE -fsanitize=address -fprofile-instr-generate -fcoverage-mapping
LDFLAGS += -lpcap -pthread -ggdb3 -fsanitize=address -fprofile-instr-generate -fcoverage-mapping
CLANG= 1
CC=CLANG
CONTIKI=../..
include $(CONTIKI)/Makefile.include
