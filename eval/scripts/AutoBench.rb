#!/usr/local/bin/ruby
#

class ABOpts
    require 'optparse';

    attr_reader :options, :trials, :dataDir, :runType, :fileExt

    def initialize(dataDirName)
        # This hash will hold all of the options parsed from the command-line by
        # OptionParser.
        @options = {}

        # Variables holding options with defaults 
        @trials = 10
        @runType = ""
        @dataBaseDir = "../data/"
        @dataDir = @dataBaseDir + dataDirName + "/"
        @scriptName = caller[0].split(':')[0]
        @fileExt = ".dat"

        @optparse = OptionParser.new do|opts|
            # Set a banner, displayed at the top
            # of the help screen.
            opts.banner = "Usage: #{@scriptName} [options] -r <run_type>"

            # Define the options, and what they do
            opts.on('-r', '--run-type=String', '=String', 
                    'Define the type of run: baseline or sva') do |run_type| 
                @options["run-type"] = run_type
                @runType = run_type
            end

            opts.on('-d', '--data-dir=String', '=String', 
                    'Base directory for results: Default "./data/apache_bench"'
                   ) do |data_dir| 
               @options["data-dir"] = data_dir
               @dataDir = data_dir
            end

            opts.on('-t=Numeric', Integer, "The number of trials to execute") do |trials|
                @options[:trials] = trials
                @trials = trials
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
            @optparse.parse!
            # force these switches 
            mandatory = ["run-type"]
            missing = mandatory.select{ |param| options[param].nil? }
            if not missing.empty?
                puts "Missing options: #{missing.join(', ')}"
                puts @optparse
                exit
            end
        rescue OptionParser::InvalidOption, OptionParser::MissingArgument
            puts $!.to_s        # Friendly output when parsing fails
            puts @optparse
            exit
        end 
    end

    def to_s
        puts "Data directory: #{@dataDir}\n"
        puts "Number of trials: #{@trials}\n"
        puts "Selected Options:"
        @options.each{|key,val|
            puts "\tOption: #{key} Argument: #{val}"
        }
    end
end
