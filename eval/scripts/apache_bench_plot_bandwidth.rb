#!/usr/bin/ruby
#
#

require 'fileutils'
require 'optparse';
require 'rubygems'
require 'rserve'
require 'ChartUtils'

class ApacheBenchRuns
    attr_reader :runType, :fileSize, :fileSizeKB, :aveBW
    attr_writer 
    def initialize(run_dir,run_file)
        @runDir = run_dir
        @runFile = run_file
        @filePath = "#{run_dir}/#{run_file}"
        fileNameArr = run_file.split('.')
        @fileSize = fileNameArr[0]
        @fileSizeKB = fileNameArr[0].split('kb')[0]
        @runType = fileNameArr[1]
        @numTrials = 0
        @totalBW = 0
        @numRequests = ""
        @concRequests = ""
        @aveBW = 0
        #puts "**** Initializing data for the test file size: " + @fileSize + "\n\n"
        parseFile()
    end
    def parseFile
        File.open(@filePath) do |file|
            file.each do |line|
                # add a deal here to detect runs that have a warning so don't
                # use it
                if(line =~ /Transfer rate:\s*(\d*\.\d*) /) 
                    @numTrials += 1
                    @totalBW += $1.to_f
                end
            end
        end
        @aveBW = @totalBW / @numTrials
        #puts @aveBW
    end
    def sizeIndex
        @fileSize =~ /(\d*).*/
        $&.to_i
    end
    def to_s
        "Runtype: #{@runType} Download Size: #@fileSize average bandwidth: #@aveBW"
    end
end

#-----------------------------------------------------------------------------
# Initialize some values used for the chart creation
#-----------------------------------------------------------------------------
dataDir = "../data/apache_bench/"
chartDir = "../charts"
chartBaseFileName = "apache_bench_bandwidth"
chartDataPath = chartDir + '/' + chartBaseFileName + '.dat'
chartFigurePath = chartDir + '/' + chartBaseFileName + '.png'
bwChartData = ChartData.new("Filesize")
dataXVals = [1,2,4,8,16,32,64,128,256,512,1024,2048]
dataSeries = ["baseline", "baseline_r3", "baseline_r4", "baseline_r5", 
    "baseline_r6", "baseline_r7", "baseline_r8", "baseline_r9"]
serverCopy = true

# This hash will hold all of the options parsed from the command-line by
# OptionParser.
options = {}

# Variables holding options with defaults 
dataDir = "../data/apache_bench"

optparse = OptionParser.new do|opts|
    # Set a banner, displayed at the top
    # of the help screen.
    opts.banner = "Usage: apache_bench_plot_bandwidth.rb [options]" +
        "\n\tThe script takes a directory of runs files as output directly" +
        "\n\tby Apache Bench, parses the *.run_type.*, produces a png plot" +
        "\n\tin the plot directory, then copies that data to the web server" +
        "\n\tdirectory."

    # Define the options, and what they do
    opts.on('-c', '--chart-dir=String', '=String', 
            "Base directory for chart: Default #{chartDir}"
           ) do |chart_dir| 
        options["chart_dir"] = chart_dir
        chartDir = chart_dir
    end
    
    opts.on('-d', '--data-dir=String', '=String', 
            "Base directory for data: Default #{dataDir}"
           ) do |data_dir| 
        options["data-dir"] = data_dir
        dataDir = data_dir
    end
    
    opts.on('-r', '--run-types=String', '=String', 
            "Comma separated list of the baseline runs to include in the plots, ",
            "E.g., baseline,sva. Default: #{dataSeries.join(',')}"
           ) do |run_types| 
        options["run-types"] = run_types
        dataSeries = run_types.split(',')
    end
    
    opts.on("-s", "--[no-]server-copy", "Copy to local http server. Default: #{serverCopy}"
           ) do |s|
       options.serverCopy = s
    end

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
    mandatory = []
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

#-----------------------------------------------------------------------------
# For each run file create an instance that will then be added to the data
# array. The data will be clustered by file download size.
#-----------------------------------------------------------------------------
Dir.foreach(dataDir){|f|
    next if (f == "." || f == "..")
    dataSeries.each {|ds| 
        if(f =~ /\.#{ds}\./)
            runInstance = ApacheBenchRuns.new(dataDir, f)
            bwChartData.addDataPoint(runInstance.sizeIndex,runInstance.runType,runInstance.aveBW)
        end
    }
}
puts "Finished processing data files."

#-----------------------------------------------------------------------------
# Generate the formatted output data where row is file download size and cols
# are data series, writing it to the specified file
#-----------------------------------------------------------------------------
bwChartData.setNormalize("baseline")
bwChartData.dataToFileWithIndices(chartDataPath)

r=Rserve::Connection.new
pwd = FileUtils.pwd()
r.void_eval <<-EOF
    # Read values from tab-delimited 
    data <- read.table("#{pwd}/#{chartDataPath}", header=T, row.names=1)

    # setup png output
    png("#{pwd}/#{chartFigurePath}")

    # plot the thing
    barplot(
            as.matrix(data),
            ylab="Bandwidth (KB)", 
            xlab="File Sizes (KB)", 
            beside=TRUE, 
            xpd=FALSE, 
            ylim=c(0,1.75), 
            space=c(0,2),
            width=c(.75),
            las=2,
            legend = rownames(data)
        )

    # output png
    dev.off()
EOF

if(serverCopy)
    FileUtils.cp(chartDataPath,"/srv/http/projects/sva/eval/",:verbose => true)
    FileUtils.cp(chartFigurePath,"/srv/http/projects/sva/eval/",:verbose => true)
end
