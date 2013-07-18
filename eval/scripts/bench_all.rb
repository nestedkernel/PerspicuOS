#!/usr/local/bin/ruby
#

require 'fileutils'

if(ARGV.size != 1) 
    puts "Provide test runtype: sva, baseline, etc"
    exit
end

runtype = ARGV[0]

# setup system for tests
system("/sbin/mount -a")

# already got data for baseline
if(runtype == "sva")
    # Do lmbench 
    system("./bench_lmbench3.rb -r #{runtype} -t 15")

    # do postmark
    system("./bench_postmark.rb -r #{runtype} -t 20")
end

#
# Setup for sshd test
#
# Turn on networking
system("/etc/rc.d/netif start")

# Get an IP 
system("dhclient bge0")

# Activate SSHD
system("/etc/rc.d/sshd start")

# Turn on and prepare thttpd
system("../apps/thttpd-2.25b/thttpd -d /usr/local/ww/apache22/data")
