#
# Makefile
#
#

# Location of the LLVM Tools
#LLVMTOOLS=/home/dautenh1/projects/sva/sva.svn/llvm
#LLVMTOOLS=../../llvm-obj

#CC=${LLVMTOOLS}/Release+Asserts/bin/clang
#CXX=${LLVMTOOLS}/Release+Asserts/bin/clang++
#CPP=${LLVMTOOLS}/Release+Asserts/bin/clang-cpp
CC=/usr/bin/clang
CXX=/usr/bin/clang++
CPP=/usr/bin/clang-cpp

CFLAGS := -I../include -O2 -fno-omit-frame-pointer -mno-aes -mno-avx -mcmodel=kernel -mno-red-zone -mno-mmx -msoft-float  -fno-asynchronous-unwind-tables -ffreestanding
#CFLAGS := -I../include

OFILES = init.o secmem.o handlers.o mmu.o interrupt.o state.o debug.o \
         stateasm.o invoke.o invokeasm.o checks.o keys.o \
		 dummy.o

HFILES = $(wildcard ../include/sva/*.h)

libnk.a: $(OFILES)
	$(AR) -r $@ $(OFILES)

$(OFILES): $(HFILES)

clean:
	rm -f *.a *.o

