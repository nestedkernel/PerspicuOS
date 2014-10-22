#!/usr/local/bin/python

from optparse import OptionParser
import csv
import os
import re
import shutil
import subprocess

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

# Only dump bits that are needed!
def dumpRange(filename, start, end):
    cmd = ["objdump","-z","-d","-j",".text",filename,"--start-address=%d" % start,"--stop-address=%d" % end]
    tmpFile = os.tmpfile()
    subprocess.check_call(cmd, stdout=tmpFile)
    return tmpFile

def dumpInsnsAround(addr, kernel, symInfo):
    symName,symStart,symEnd = symInfo

    symPattern=re.compile("<%s>" % symName)
    dAddr = int(addr, 16)

    start = symStart
    if symEnd != symStart:
        endplus = symEnd
    else:
        INSN_LEN_MAX = 64 # No idea, should be plenty
        endplus = dAddr + INSN_LEN_MAX

    with dumpRange(kernel, start, endplus) as insnsF:
        insnsF.seek(0)
        for line in insnsF:
            symMatch = symPattern.search(line)
            if not symMatch:
                continue

            # Okay, now let's scan up to our addr
            last = None
            for line in insnsF:
                vals = line.split()
                if len(vals) < 2:
                    continue

                start = int(vals[0][:-1], 16)
                if start < dAddr:
                    last = line
                    continue
                print "%s in %s:" % (addr, symName)
                if last:
                    print "\t%s" % last.strip()
                print "\t%s" % line.strip()
                print "\t%s" % insnsF.next().strip()
                return

        print "Symbol %s for match %s not found in disasm!" % (symName, addr)
        raise Exception("Symbol not found")



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

        if symName == "start_exceptions":
            continue

        if start > hAddr:
            if lastend > hAddr and laststart <= hAddr:
                # print "Found addr %x in %s" % (hAddr, lastSym)
                return (lastSym,laststart,lastend)
            elif lastend == laststart and laststart <= hAddr:
                # print "Found addr %x in %s (unsized, maybe)" % (hAddr, lastSym)
                return (lastSym,laststart,lastend)
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

    # Get symbols too
    symsF = getSyms(kernel)

    for (mTy, mAddr) in results:
        sym = getSymbolFor(mAddr, symsF)
        dumpInsnsAround(mAddr, kernel, sym)

    # Cleanup
    symsF.close()


if __name__ == '__main__':
    main()
