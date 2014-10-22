#!/usr/local/bin/python

from optparse import OptionParser
import csv
import os
import subprocess
import shutil

parser = OptionParser()
parser.add_option("-k","--kernel",action="store",type="string",dest="kernel")
parser.add_option("-s","--scanner-script",action="store",type="string",dest="scanner",default="./scanner-objdump.py")
parser.add_option("-r","--scanner-log",action="store",type="string",dest="scanlog",default=None)
parser.add_option("-d","--dis-log",action="store",type="string",dest="dislog",default=None)

def cachedOrTmpExec(cachefile, f, name):
    if cachefile:
        if not os.path.isfile(cachefile):
            print "Specified file %s doesn't exist." % cachefile
            print "Running %s, and caching into it..." % name
            logFile = f()
            logFile.seek(0)
            cacheFile = open(cachefile, 'w')
            shutil.copyfileobj(logFile, cacheFile)
            logFile.close()
            cacheFile.close()
        else:
            print "Using existing file for %s" % name
        return open(cachefile, 'r')

    # Otherwise, no caching so just run the operation
    # and return the file ready to be used
    tmpFile = f()
    tmpFile.seek(0)
    return tmpFile



def runScanner(scanner, kernel):
    print "Scan: Starting..."
    cmd = [scanner, "--all", kernel]
    tmpFile = os.tmpfile()
    subprocess.check_call(cmd, stdout=tmpFile)
    print "Scan: Complete!"
    return tmpFile

def scanKernel(scanner, kernel, scanlog):
    scanFunc = lambda: runScanner(scanner, kernel)
    tmpFile = cachedOrTmpExec(scanlog, scanFunc, "scanner")
    splitLines = [line.split() for line in tmpFile]
    results = [(vals[1], vals[5]) for vals in splitLines]
    tmpFile.close()
    return results

def getSyms(filename):
    cmd = ["nm","-n","-S",filename]
    tmpFile = os.tmpfile()
    subprocess.check_call(cmd, stdout=tmpFile)
    return tmpFile

def applyObjdump(filename):
    cmd = ["objdump","-z","-d", "-j",".text",filename]
    tmpFile = os.tmpfile()
    subprocess.check_call(cmd, stdout=tmpFile)
    return tmpFile

def dumpIsnsAround(addr, isnsF):
    return

def getSymbolFor(addr, symsF):
    symsF.seek(0)
    hAddr = int(addr, 16)
    laststart,lastend,lastsize = 0, 0, 0
    lastSym = "??"
    for line in symsF:

        # Parse line...
        # TODO: D'oh, bet nm has flag to produce more readable output...
        vals = line.split()
        if len(vals) == 3:
            start,symTy,symName = vals
            size = "0"
        elif len(vals) == 4:
            start,size,symTy,symName = vals
        else:
            continue
        start = int(start ,16)
        size = int(size, 16)
        end = start+size

        if start > hAddr:
            if lastend > hAddr and laststart <= hAddr:
                # print "Found addr %x in %s" % (hAddr, lastSym)
                return lastSym
            elif lastend == laststart and laststart <= hAddr:
                # print "Found addr %x in %s (unsized, maybe)" % (hAddr, lastSym)
                return lastSym
            else:
                print "Address not found!!"
                raise Exception("Address not found")
            return

        # Store for checking next iter
        # (Needed for handling unsized symbols)
        laststart,lastend,lastsize = start,end,size
        lastSym = symName

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
    results = scanKernel(scanner, kernel, options.scanlog)

    # Get dis for matching
    objdumpFunc = lambda: applyObjdump(kernel)
    isnsF = cachedOrTmpExec(options.dislog, objdumpFunc, "objdump")

    # Get symbols too
    symsF = getSyms(kernel)

    for (mTy, mAddr) in results:
        dumpIsnsAround(mAddr, isnsF)
        sym = getSymbolFor(mAddr, symsF)

    # Cleanup
    isnsF.close()
    symsF.close()


if __name__ == '__main__':
    main()
