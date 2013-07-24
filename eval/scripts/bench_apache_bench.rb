#!/usr/local/bin/ruby
#
# Usage ./benchmark_apache.rb <run_type> 
#

require 'fileutils'
require './AutoBench.rb'

opts = ABOpts.new("apache_bench")

FileUtils.mkdir_p(opts.dataDir)

resultsFile = File.new(opts.dataDir + "/" + opts.runType + opts.fileExt, "a")

opts.trials.times {|t| 
    puts "Running trial #{t} for all files"
    11.times{ |i|
        fileSize = 2**i
        fileSize = 2**9
        outFileName = "#{fileSize}kb.#{opts.runType}#{opts.fileExt}"
        filepath = "#{opts.dataDir}#{outFileName}"
        puts filepath
        cmd = "ab -n 10000 -c 100 http://trypticon.cs.illinois.edu/downloads/#{fileSize}kb.rand"
        puts "\nExecuting test for: ",cmd,"\n"
        out = `#{cmd}`
        File.open(filepath, "a") { |f|
            f.puts out
        }
        resultsFile << "\n***** SCRIPT ****** Benchmarking: #{outFileName}\n"
        resultsFile << out
    }
}
resultsFile.close
