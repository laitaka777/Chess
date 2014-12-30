all: microwine 
clean:
	$(RM) microwine.ld microwine.o thunk.o microwine

CC = gcc
ifeq ($(shell uname),Darwin)
CFLAGS = -Wall -Os -arch x86_64
ASFLAGS = -arch x86_64
LDFLAGS = -arch x86_64 -Wl,-pagezero_size,1000 -Wl,-stack_addr,0x2200000 -Wl,-stack_size,0x2000000 -Wl,-allow_stack_execute

microwine: microwine.o thunk.o
	$(CC) $(LDFLAGS) -o $@ microwine.o thunk.o
	strip microwine

else
CFLAGS = -Wall -Os
ASFLAGS = 
LDFLAGS = # -s

# Hackery to extract the default linker script from "ld --verbose" and change the start address.
microwine.ld:
	ld --verbose | grep -A 99999 '===' | grep -B 99999 '^\}$$' | grep -v '===' | sed 's/0x400000/0x20000000/g' > $@

microwine: microwine.ld microwine.o thunk.o
	$(CC) $(LDFLAGS) -T microwine.ld microwine.o thunk.o -o $@
endif

