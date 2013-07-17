#!/usr/local/bin/ruby
#

require 'fileutils'
require './AutoBench'

opts = ABOpts.new("postmark")

FileUtils.mkdir_p(opts.dataDir)

resultsFile = File.new(opts.dataDir + "/" + opts.runType + opts.fileExt, "a")

opts.trials.times {|i| 
    resultsFile << "\n---------------------------"
    resultsFile << "\nExecuting Round: #{i+1} "
    resultsFile << "\n---------------------------\n"
    puts "\nExecuting Trial: #{i+1} "
    out = `postmark #{opts.dataDir}postmark.conf`
    resultsFile << out
}

resultsFile.close()
