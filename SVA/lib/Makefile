#
# Makefile
#
#
SVA_HOME=/home/dautenh1/projects/sva/sva.svn
CC=${SVA_HOME}/llvm/Release+Asserts/bin/clang -I${SVA_HOME}/SVA/include
CXX=${SVA_HOME}/llvm/Release+Asserts/bin/clang++ -I${SVA_HOME}/SVA/include  
CPP=${SVA_HOME}/llvm/Release+Asserts/bin/clang-cpp -I${SVA_HOME}/SVA/include 

CFLAGS := -g -I../include -O2 -fno-omit-frame-pointer -mno-aes -mno-avx -mcmodel=kernel -mno-red-zone -mno-mmx -msoft-float  -fno-asynchronous-unwind-tables -ffreestanding
OFILES = init.o secmem.o handlers.o mmu.o mmuasm.o interrupt.o state.o debug.o \
         stateasm.o invoke.o invokeasm.o

libsva.a: $(OFILES)
	$(AR) -r $@ $(OFILES)

clean:
	rm -f *.a *.o

