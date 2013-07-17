#!/usr/local/bin/ruby
#

require 'fileutils'
require './AutoBench'

opts = ABOpts.new("lmbench3")

FileUtils.cd("../apps/lmbench3")

opts.trials.times {|i| 
    print "Executing Round: #{i} "
    system("make rerun")
}
