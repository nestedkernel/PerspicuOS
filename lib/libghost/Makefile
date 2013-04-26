#
# Makefile
#

CC := clang
CXX := clang++
CFLAGS := -g -I../include -O2 -fno-omit-frame-pointer -mno-aes -mno-avx -mcmodel=kernel -mno-red-zone -mno-mmx -msoft-float  -fno-asynchronous-unwind-tables -ffreestanding
OFILES = ghost.o

libghost.a: $(OFILES)
	$(AR) -r $@ $(OFILES)

clean:
	rm -f *.a *.o test


