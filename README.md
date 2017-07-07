# PerspicuOS

## Introduction:

PerspicuOS is a prototype operating system that realizes the Nested Kernel, a
new operating architecture that restricts access to a device's memory
management unit so that it can then perform memory isolation within the kernel.
The key challenge that PerspicuOS addresses is how to virtualize the MMU on
real hardware, AMD64, in a real operating system, FreeBSD 9.0, while not
assuming any hardware privilege separation or kernel integrity properties such
as control flow integrity. PerspicuOS presents a technique that allows both
trusted and untrusted code to operate at the same hardware privilege level,
thereby virtualizing Ring 0 supervisor privilege.

PerspicuOS does this by virtualizing the MMU, which requires memory protections
for Page Tables and CPU protections for control register isolation. PerspicuOS
protects the page tables by intializing all mappings in the system so that Page
Table Pages are mapped as read-only, and then introduces a technique that we
call de-privileging to ensure those privileges are never bypassed at runtime.
PerspicuOS de-previleges the untrusted portion of the kernel by removing all
MMU modifying instructions from the untrusted code's source, which statically
reduces its privilege. Then PerspicuOS enforces lifetime kernel code integrity
(mapping all code pages as read-only), denies execution of kernel data (using
no-execute hardware), and denies execution of user mode code and data pages
while in supervisor mode (using supervisor mode execution prevention).

By design PerspicuOS defends against a large class of attacks in code injection
because of it's code integrity properties. We also use PerspicuOS to explore
protection of the system call vector table, recording modifications of the
allproc processor list data structure, and to invoke a security monitor that
records audit records to a protected log. For more details on the design of
PerspicuOS please read our recent ASPLOS publication here.

## Authors and Contributors

PerspicuOS has several contributors: Nathan Dautenhahn, Theodoras Kasampalis,
Will Dietz, John Criswell, and Vikram Adve. This work was accomplished while
working at the University of Illinois at Urbana-Champaign in the LLVM research
group under the supervision of Vikram Adve.

## Build Instructions

Our current nested kernel implementation is for x86-64 FreeBSD is called
PerspicuOS.

1. Install FreeBSD 9.0: http://ftp-archive.freebsd.org/pub/FreeBSD-Archive/old-releases/amd64/ISO-IMAGES/9.0/

2. In FreeBSD 9.0 System, clone Nested Kernel PerspicuOS from GitHub

3. Build the nested kernel (assumes clang is in /usr/bin/clang) 
	```
	$ cd REPO_DIR/nk 
	$ make
	```

4. Configure FreeBSD /etc/src.conf 
	```
	# This setting to build world without -Werror: 
	NO_WERROR= 
	# This setting to build kernel without -Werror: 
	WERROR= 
	# Configure the system to use clang 
	CC=/PATH/TO/CLANG 
	CXX=/PATH/TO/CLANG 
	CPP=/PATH/TO/CLANG 
	# Export the nested kernel library directory for the linker script in FreeBSD. 
	NK_HOME=/PATH/TO/REPO_DIR 
	# Set the library path to the nested kernel lib 
	CFLAGS+=-I/PATH/TO/REPO_DIR/nk/include
	```

5. Make PerspicuOS: Use FreeBSD building instructions selecting the NK kernel
configuration 

6. Install and Boot (you can use either the base harddrive or a VM
tool Like Qemu, VirtualBox, or VMWare)

We have a tool that automates the kernel compile and install process in
"REPO_DIR/scripts/compile_install_test_sva.rb". You can use this, but make sure
to read the code to understand how it operates.

## Implementation Needs

  PerspicuOS does not implement the full nested kernel design. Make sure to
  review the paper to see a list of currently implemented features.  

  A few key features requiring further development include: 
    - SMP functionality
    - Complete NX configuration for non-code pages
    - Finish IDT, SMM, IOMMU

## Comment on PerspicuOS Repo

PerspicuOS was derived from a few other research projects and as such reflects
an odd arangement of naming conventions and unused functionality. The nested
kernel shared a similar interface as previous work using the SVA compiler based
virtual machine (SVA Github), but only includes a small subset of the entire
interface, namely the MMU, and modifies the functionality of the internal
policies for page-translation updates.

## Support or Contact

Having trouble with PerspicuOS? We are currently setting up a suitable method
for contact. Otherwise, submit a pull request to start some code specific
dialog.
