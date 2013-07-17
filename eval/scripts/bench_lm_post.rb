#!/usr/local/bin/ruby
#

require 'fileutils'

runtype = "sva"

# Do lmbench 
system("./bench_lmbench3.rb -r #{runtype} -t 15")

# do postmark
system("./bench_postmark.rb -r #{runtype} -t 20")
