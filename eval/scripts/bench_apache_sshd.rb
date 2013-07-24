#!/usr/bin/ruby

if(ARGV.size != 1) 
    puts "Provide test runtype: sva, baseline, etc"
    exit
end

runtype = ARGV[0]

system("ruby bench_apache_bench.rb -r #{runtype} -t 10")
system("ruby ./bench_sshd.rb -r #{runtype} -t 10")
