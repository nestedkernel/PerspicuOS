#!/usr/local/bin/ruby
#

require 'fileutils'
require './AutoBench.rb'

opts = ABOpts.new("sshd")

FileUtils.mkdir_p(opts.dataDir)

resultsFP = opts.dataDir + opts.runType + opts.fileExt

opts.trials.times {|t| 
    puts "Running trial #{t} for all files"
    resultsFile = File.open(resultsFP, "a")
    # 21 corresponds to going up to a 1 GB file download
    21.times{ |i|
        fileSize = 2**i
        host = "trypticon.cs.illinois.edu"
        dlDir = "/usr/local/www/apache22/data/downloads"
        scpOpts = "-v -i ~/.ssh/id_dsa_sva"
        cmd = "scp #{scpOpts} #{host}:#{dlDir}/#{fileSize}kb.rand /tmp/ 2>&1"
        regMatch = /Bytes per second: sent (\d*\.\d*), received (\d*\.\d*).*$/
        sendBW, recBW = regMatch.match(`#{cmd}`).captures
        puts "\nExecuting test for: ",cmd,"\n"
        resultsFile << "\n" << fileSize << " " << sendBW << " " << recBW
    }
    resultsFile.close
}
