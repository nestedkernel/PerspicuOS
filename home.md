### Welcome to the Nested Kernel.
Monolithic operating system designs undermine the security of computing systems
by allowing single exploits anywhere in the kernel to enjoy full supervisor
privileges. The nested kernel operating system architecture addresses this
problem by “nesting” a small, isolated kernel within a traditional monolithic
kernel. The “nested kernel” interposes on all updates to virtual memory
translations to assert protections on physical memory, thus significantly
reducing the trusted computing base for memory access control enforcement. 

We incorporated the nested kernel architecture into FreeBSD on x86-64 hardware
by write-protecting MMU translations and de- privileging the untrusted part of
the kernel, thereby enabling the entire operating system, trusted and untrusted
components alike, to operate at the highest hardware privilege level. Our
implementation inherently enforces kernel code integrity while still allowing
dynamically loaded kernel modules, thus defending against code injection
attacks. 

We also demonstrate, by introducing write-mediation and write-logging services,
that the nested kernel architecture allows kernel developers to isolate memory
in ways not possible in monolithic kernels. Performance of the nested kernel
prototype shows modest overheads: < 1% average for Apache, <3.7% average for
SSHD, and 2.7% average for kernel compile. Overall, our results and experience
show that the nested kernel design can be retrofitted to existing monolithic
kernels, providing important security benefits.

### Links
Our full ASPLOS '15 paper can be found on
[here](http://nathandautenhahn.com/downloads/publications/asplos200-dautenhahn.pdf).

A link to the presentation given at ASPLOS '15:
http://prezi.com/in6qr3l92ffc/?utm_campaign=share&utm_medium=copy

### Build Instructions

!!!!!! These Are Under Construction and Require Testing !!!!!!

Our current nested kernel implementation for x86-64 FreeBSD is called
PerspicuOS. 

1. Install FreeBSD 9.0:
    http://ftp-archive.freebsd.org/pub/FreeBSD-Archive/old-releases/amd64/ISO-IMAGES/9.0/
1. In FreeBSD 9.0 System, clone the repo
    $ clone git@github.com:nestedkernel/nestedkernel.git nestedkernel
2. Build the nested kernel
    $ cd nestedkernel
    $ make 
3. Configure FreeBSD /etc/src.conf
    \# This setting to build world without -Werror:
    NO_WERROR=
    \# This setting to build kernel without -Werror:
    WERROR=
    \# Set the library path to the nested kernel lib
    CFLAGS+=-I/PATH/TO/NESTEDKERNEL/include
4. Make PerspicuOS: Use FreeBSD building instructions
    selecting the NK kernel configuration
5. Install and Boot (you can use either the base harddrive or
        a VM tool Like Qemu, VirtualBox, or VMWare)

### Comment on Code
