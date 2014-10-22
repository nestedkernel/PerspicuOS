#!/usr/local/bin/python

from optparse import OptionParser
import csv
import os
import subprocess

parser = OptionParser()
parser.add_option("-k","--kernel",action="store",type="string",dest="kernel")
parser.add_option("-s","--scanner-script",action="store",type="string",dest="scanner",default="./scanner-objdump.py")

def runScanner(scanner, kernel):
    cmd = [scanner, "--all", kernel]
    tmpFile = os.tmpfile()
    subprocess.check_call(cmd, stdout=tmpFile)
    return tmpFile

def scanKernel(scanner, kernel):
    print "Scan: Starting..."
    with runScanner(scanner, kernel) as tmpFile:
        print "Scan: Complete!"
        tmpFile.seek(0)
        splitLines = [line.split() for line in tmpFile]
        return [(vals[1], vals[5]) for vals in splitLines]

def getSyms(filename):
    cmd = ["nm","-n","-S",filename]
    tmpFile = os.tmpfile()
    subprocess.check_call(cmd, stdout=tmpFile)
    return tmpFile

def applyObjdump(filename):
    cmd = ["objdump","-s","-z","-d", "-j",".text",filename]
    tmpFile = os.tmpfile()
    subprocess.check_call(cmd, stdout=tmpFile)
    return tmpFile

def dumpIsnsAround(addr, isnsF):
    return

def printSymbolFor(addr, symsF):
    symsF.seek(0)
    hAddr = int(addr, 16)
    print hAddr
    for line in symsF:
        vals = line.split()
        if len(vals) < 4:
            continue
        print start
        start,size,symTy,symName = vals

        start = int(start ,16)
        size = int(size, 16)

        if hAddr < start:
            continue
        print start
        print hAddr
        print start+size
        if hAddr < start+size:
            print vals
        print "hAddr >= start+size??"
        return

        

def main():
    # parse command line arguments
    (options, args) = parser.parse_args()

    if not options.kernel and not args:
        raise OSError
    elif not options.kernel:
        kernel = args[0]
    else:
        kernel = options.kernel

    scanner = options.scanner

    # Run scanner and gather results
    results = scanKernel(scanner, kernel)

    # Get dis for matching
    isnsF = applyObjdump(kernel)

    # Get symbols too
    symsF = getSyms(kernel)

    for (mTy, mAddr) in results:
        dumpIsnsAround(mAddr, isnsF)
        printSymbolFor(mAddr, symsF)

    # Cleanup
    isnsF.close()
    symsF.close()


if __name__ == '__main__':
    main()
