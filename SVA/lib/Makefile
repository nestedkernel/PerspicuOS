#
# Makefile
#

CFLAGS := -g -I../include -O2 -fno-omit-frame-pointer -mno-aes -mno-avx -mcmodel=kernel -mno-red-zone -mno-mmx -msoft-float  -fno-asynchronous-unwind-tables -ffreestanding
OFILES = init.o secmem.o handlers.o mmu.o mmuasm.o interrupt.o state.o debug.o \
         stateasm.o

libsva.a: $(OFILES)
	$(AR) -r $@ $(OFILES)

clean:
	rm -f *.a *.o

