KDIR	:= /lib/modules/$(shell uname -r)/build
PWD	:= $(shell pwd)
CC	:= gcc

CFLAGS	:= -I$(KDIR)/include -W -Wall
LDFLAGS := 

TARGETS	:= dst

all: $(TARGETS)
	@echo "Compilation has been successfully finished."

dst: dst.c
	$(CC) $(CFLAGS) $^ -o $@

clean:
	@rm -f *.o *~ $(TARGETS)
