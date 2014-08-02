#!/usr/bin/env ruby
#

require 'fileutils'
require 'optparse';

# This hash will hold all of the options parsed from the command-line by
# OptionParser.
options = {}

svaBaseDir = ".."
kernelSourceDir = svaBaseDir+"/FreeBSD9"
imageDir = svaBaseDir+"/images"
imagePath = imageDir+"/sva_ndd.img"
llvmSourceDir = svaBaseDir+"/llvm-obj"
svaSourceDir = svaBaseDir+"/SVA"
kernCompileOpts = ""
qemuGDBOpt = ""
$instKernName = "perspicuos"

optparse = OptionParser.new do|opts|
    # Set a banner, displayed at the top
    # of the help screen.
    opts.banner = "\nUsage: Tool does several maintenance, install, and test actions for SVA." ,
                "\n       This file assumes that it is inside the scripts directory of " ,
                "\n       the sva repository." ,
                "\n"

    # Define the options, and what they do
    #opts.on('-c', '--chart-dir=String', '=String', 
            #"Base directory for chart: Default #{chartDir}"
           #) do |chart_dir| 
        #options["chart_dir"] = chart_dir
        #chartDir = chart_dir
    #end
    
    opts.on("-c", "--makeClean", "make clean any build targets") do 
        options[:clean] = true
    end
    opts.on("-k", "--buildKernel", "Build the SVA kernel") do 
       options[:buildKernel] = true
    end
    opts.on("-s", "--buildSVA", "Build SVA") do
       options[:buildSVA] = true
    end
    opts.on("-l", "--buildLLVM", "Build llvm, also builds SVA and the kernel.") do
       options[:buildLLVM] = true
    end
    opts.on("-r", "--rebuildAll", "Build llvm, sva, and kernel") do
       options[:rebuildAll] = true
    end
    opts.on("-t", "--instKernToMachDisk", "Install the sva kernel to machine disk") do
       options[:instKernToMachDisk] = true
    end
    opts.on("-i", "--instKernToQemuDisk", "Install the sva+llvm built kernel to Qemu disk") do
       options[:instKernToQemuDisk] = true
    end
    opts.on("-g", "--gdbQemuOpt", "Execute Qemu command with -s -S for GDB stub") do
       qemuGDBOpt = "-s -S" 
    end
    opts.on("-d", "--diskImage FILE", 
            "Path to the disk image file for intallation and qemu. ", 
            "\tDefault: #{imagePath}") do |f| 
        options[:imagePath] = true
        imagePath = f
    end
    opts.on("-q", "--testSVAQemu", "Boot the image in Qemu and test") do
       options[:testSVAQemu] = true
    end
    opts.on("-m", "--mountImage", "Mount the disk image [default: images/sva_ndd.img]") do
       options[:mountImage] = true
    end
    opts.on("-u", "--unMountImage", "Unmount the disk image [default: images/sva_ndd.img]") do
       options[:unMountImage] = true
    end
    opts.on("-e", "--debug-make", "Build with j=1 to get the error.") do
       options[:debugMake] = true
    end
    opts.on("-n", "--instType=type", "The type of security instrumentation to use <cfi,cfi+sfi,none> [default: #{$instKernName}].") do |name|
       options[:instName] = name
       $instKernName = name
    end
    
    opts.on("-p", "--kernSourceDir=path", "The path to the kernel source. Def: #{kernelSourceDir}") do |path|
       kernelSourceDir = path
    end

    opts.on("-S", "--scan-objects", "Run scanner on built binaries") do
        options[:runScanner] = true
    end

    # This displays the help screen, all programs are assumed to have this
    # option.  
    opts.on( '-h', '--help', 'Display this screen' ) do
        puts opts
        exit
    end
end

# Parse the command-line. Remember there are two forms of the parse method.
# The 'parse' method simply parses ARGV, while the 'parse!' method parses ARGV
# and removes any options found there, as well as any parameters for the options.
# What's left is the list of files to resize.  
#optparse.parse!
#
begin
    optparse.parse!
    # force these switches 
    #mandatory = []
    #missing = mandatory.select{ |param| options[param].nil? }
    #if not missing.empty?
        #puts "Missing options: #{missing.join(', ')}"
        #puts optparse
        #exit
    #end
    if (!options[:clean] && !options[:buildLLVM]) 
        kernCompileOpts = "-DNO_KERNELCLEAN -DNO_KERNELCONFIG " +
            "-DNO_KERNELDEPEND -DNO_KERNELOBJ"
    end
    if (options[:runScanner])
        kernCompileOpts += " -DRUN_SCANNER"
    end
rescue OptionParser::InvalidOption, OptionParser::MissingArgument
    puts $!.to_s        # Friendly output when parsing fails
    puts optparse
    exit
end 

# Mount command to both create a vnode and image file to mount
# Takes the path to the image, assumes we are mounting to /mnt also mounts to
# vnode 1
$mountDir = "/mnt/sva_qemu_image"
def mountImage(pathToImg)
    puts "Mounting disk image #{pathToImg} to #{$mountDir}"
    system("sudo mdconfig -a -t vnode -f #{pathToImg} -u 1")
    system("sudo mount /dev/md1p2 #{$mountDir}")
    unless($?.success?)
        puts "<<<< MOUNT FAILED >>>>"
        exit
    end
end

# Unmount command to both unmount the virtual disk and eliminate the vnode
# configuration. Takes the path to the image and assumes we are unmounting from
# /mnt and undoing the first vnode
def unMountImage()
    puts "Unmounting disk"
    system("sudo umount #{$mountDir}")
    system("sudo mdconfig -d -u 1")
    unless($?.success?)
        puts "<<<< UMOUNT FAILED >>>>"
        exit
    end
end

#
# Build llvm, make sure that the caller really wants to clean
#
# Args: path to the source directory of llvm and a boolean value denoting
#       whether or not the caller wants to perform a make clean 
def buildLLVM(llvmSourceDir, clean)
    puts "Building llvm\n\n"

    # CD to source dir, once block completes the function auto CDs back to orig
    Dir.chdir(llvmSourceDir) do
        if(clean)
            # Make sure they want to make clean llvm
            puts "Are you sure you want to clean LLVM? Rebuilding will take forever... [y/N]"
            if(gets.chomp =~ /[yY]/)
                puts "Cleaning llvm...\n\n"
                system("gmake clean") 
            end
        end 

        # Issue the make command -- note we use gmake here. It also asumes a 16
        # core machine
        system("gmake -j12")

        # If we failed we want to stop the compile chain so we can deal with it
        # now
        unless($?.success?)
            puts "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
            puts "!!!!!! Error: gmake failed !!!!!!"
            puts "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!"
            puts "If this is the first time you are compiling have you done a ./compile?"
            exit
        end
    end
end

#
# Build SVA. This assumes that either make.conf is set or SVA Makefile sets the
# clang compiler variables
#
# Args: Source dir of SVA and make clean boolean directive
#
def buildSVA(svaSourceDir, clean)
    puts "Building SVA\n\n"
    Dir.chdir(svaSourceDir) do
        system("make -j12 clean") if(clean)
        system("make -j12")
        unless($?.success?)
            puts "Error: Make failed!"
            exit
        end
    end
end

#
# Compile the kernel 
#
# Args: FreeBSD source dir and boolean clean directive
#
def buildKernel(kernelSourceDir, extraOpts, debug=false)
    puts "Compiling Kernel with SVA..."

    # CD to source dir, once block completes the function auto CDs back to orig
    puts extraOpts
    Dir.chdir(kernelSourceDir) do
        if(debug)
            system("make buildkernel KERNCONF=SVA #{extraOpts}")
        else
            system("make -j15 buildkernel KERNCONF=SVA #{extraOpts}")
        end
        unless($?.success?)
            puts "Error: Make failed!"
            exit
        end
    end
end

#===============================================================================
# Build options
#===============================================================================

# ------------------------------------------------------------------------------
# The order to rebuild all is: llvm, sva, then kernel Note llvm is built with
# gmake command, sva is built with llvm+cfi version of llvm, kernel is compiled
# with clang as produced by llvm and including the SVA library. If we are
# building llvm we assume that we need to also rebuild both SVA and the kernel
# because we must use the clang as generated from an llvm build to build the
# other two. 
# ------------------------------------------------------------------------------
#
if (options[:rebuildAll] || options[:buildLLVM]) then
    buildLLVM(llvmSourceDir, options[:clean])
    buildSVA(svaSourceDir, true)
    buildKernel(kernelSourceDir, kernCompileOpts)
end

if (options[:buildSVA]) then
    buildSVA(svaSourceDir, options[:clean])
end

if (options[:buildKernel]) then
    buildKernel(kernelSourceDir, kernCompileOpts, options[:debugMake])
end

#===============================================================================
# Install kernel to particular locations: machine root / or mounted disk image
#===============================================================================

# ------------------------------------------------------------------------------
# Install the kernel to the machine's root directory and boot /boot
# ------------------------------------------------------------------------------
if (options[:instKernToMachDisk]) then
    Dir.chdir(kernelSourceDir) do
        system("sudo make -j15 installkernel KERNCONF=SVA INSTKERNNAME=#{$instKernName}")
    end
end

# ------------------------------------------------------------------------------
# This option will mount the qemu disk image, change to the FreeBSD kernel
# directory and issue a make install kernel command to the qemu disk image. It
# unmounts the image when done. 
# ------------------------------------------------------------------------------
if (options[:instKernToQemuDisk]) then
    puts "Setting install to kernel disk\n"

    # mount the image
    mountImage(imagePath)

    puts "Changing to kernel source dir, compiling, and installing into disk image."
    Dir.chdir(kernelSourceDir) do
        puts "Executing install command from kernel build dir"
        cmd = "sudo make -j15 installkernel KERNCONF=SVA INSTKERNNAME=#{$instKernName} DESTDIR=#{$mountDir}"
        system(cmd)
    end

    # unmount the image
    unMountImage()
end

# Use this flag to boot up the disk image in qemu ncurses mode -- no gui needed
if (options[:testSVAQemu]) then
    diskImagesDir = svaBaseDir+"/"+"images"

    # check to see if we are currently mounted and if so exit
    if ( `mount` =~ /md1/ ) then puts "Drive still mounted, exiting."; exit; end

    # setup qemu options
    qemuOpts = "-curses -no-reboot -m 2G " + qemuGDBOpt

    # start qemu with specified disk image
    system("qemu-system-x86_64 #{qemuOpts} -hda #{imagePath}")
end

#===============================================================================
# Mount and unmount utilities to aid in manual copy of data
#===============================================================================
if(options[:mountImage]) then
    mountImage(imagePath)
end

if(options[:unMountImage]) then
    unMountImage()
end
