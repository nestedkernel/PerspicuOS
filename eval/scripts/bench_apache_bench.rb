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
    i = 1; e = 0;
    while i < 4096
        outFileName = "#{i}kb.#{opts.runType}.data"
        filepath = "#{opts.dataDir}/#{outFileName}"
        puts filepath
        cmd = "ab -n 5000 -c 25 http://trypticon.cs.illinois.edu/downloads/#{i}kb.zero"
        puts "\nExecuting test for: ",cmd,"\n"
        out = `#{cmd}`
        File.open(filepath, "a") { |f|
            f.puts out
        }
        resultsFile << out
        i = 2**e; e += 1;
    end
}
resultsFile.close
