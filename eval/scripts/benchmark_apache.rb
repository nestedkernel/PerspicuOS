#!/usr/bin/ruby
#
# Usage ./benchmark_apache.rb <run_type> 
#

require 'optparse';
require 'fileutils'

# This hash will hold all of the options parsed from the command-line by
# OptionParser.
options = {}

# Variables holding options with defaults 
runType = ""
dataDir = "../data/apache_bench"

optparse = OptionParser.new do|opts|
    # Set a banner, displayed at the top
    # of the help screen.
    opts.banner = "Usage: benchmark_apache.rb [options] -r <run_type>"

    # Define the options, and what they do
    opts.on('-r', '--run-type=String', '=String', 
            'Define the type of run: baseline or sva') do |run_type| 
        options["run-type"] = run_type
        runType = run_type
    end
    
    opts.on('-d', '--data-dir=String', '=String', 
            'Base directory for results: Default "./data/apache_bench"'
           ) do |data_dir| 
        options["data-dir"] = data_dir
        dataDir = data_dir
    end
    
    #options[:logfile] = nil
    #opts.on( '-l', '--logfile FILE', 'Write log to FILE' ) do|file|
    #  options[:logfile] = file
    #end

    # This displays the help screen, all programs are assumed to have this
    # option.  
    opts.on( '-h', '--help', 'Display this screen' ) do
        puts opts
        exit
    end
end

# Parse the command-line. Remember there are two forms of the parse method.
# The 'parse' method simply parses ARGV, while the 'parse!' method parses ARGV
# and removes any options found there, as well as any parameters for the options.
# What's left is the list of files to resize.  
#optparse.parse!
#
begin
    optparse.parse!
    # force these switches 
    mandatory = ["run-type"]
    missing = mandatory.select{ |param| options[param].nil? }
    if not missing.empty?
        puts "Missing options: #{missing.join(', ')}"
        puts optparse
        exit
    end
rescue OptionParser::InvalidOption, OptionParser::MissingArgument
    puts $!.to_s        # Friendly output when parsing fails
    puts optparse
    exit
end 
p options
p ARGV
p runType
FileUtils.mkdir_p(dataDir)
i = 1; e = 0;
while i < 4096
    outFileName = "#{i}kb.#{runType}.data"
    filepath = "#{dataDir}/#{outFileName}"
    puts filepath
    cmd = "ab -n 5000 -c 25 http://trypticon.cs.illinois.edu/downloads/#{i}kb.zero"
    puts "\nExecuting test for: ",cmd,"\n"
    out = `#{cmd}`
    File.open(filepath, "a") { |f|
        f.puts out
    }
    i = 2**e; e += 1;
end

