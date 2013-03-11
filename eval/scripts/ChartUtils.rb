#!/usr/bin/ruby
# 
# fundamentally a plot is an x,y value pair -- a 2D array
# Therfore, the base data structure representating a plot is that of a Matrix
# where the indices are provided to the object as hash values. The object can
# maintain multiple data series for each x data point. 
#

class ChartData
    attr_reader :xIndices
    def initialize(x_index_name)
        @xIndexName = x_index_name
        @normalize = false
        @data = Hash.new
        @dataSetNames = Hash.new
        @xIndices = Hash.new
    end
    # Adds a data point to the 2D hash data object. Val can be any object.
    def addDataPoint(xIndex, dataSeries, val)
        #@data[xIndex] = Hash.new if @data[xIndex].nil?
        #@data[xIndex][dataSeries] = val
        #@dataSetNames[dataSeries] = dataSeries
        @data[dataSeries] = Hash.new if @data[dataSeries].nil?
        @data[dataSeries][xIndex] = val
        @dataSetNames[dataSeries] = dataSeries
        @xIndices[xIndex] = xIndex
    end
    def getDataSet(dsName) 
        @data[dsName]
    end
    def getDataAtXVal(xval)
        ret = []
        ret << xval
        @data.sort.each{|ds,vals|
            ret << vals[xval]
        }
        #@data[xval].sort.each {|key,val| ret << val }
        ret
    end
    def dataToFileWithIndices (file)
        puts "Writing data to file #{file}, and overwriting existing"
        outFile = File.new(file,'w')
        outFile << self.to_s
        outFile.close
    end
    def setNormalize(dsName)
        @normalize = true
        @normalizeDS = dsName
    end
    def unsetNormalize
        @normalize = false
    end
    def to_s
        ret = ""
        # print the first row as indices and first col as data series
        ret << @xIndexName << " " << @xIndices.keys.sort.join(' ')
        ret << "\n"
        @data.each {|ds,dataVector|
            ret << ds
            dataVector.sort.each {|k,v|
                if(@normalize)
                    ret << " " << (v/@data[@normalizeDS][k]).to_s
                else
                    ret << " " << v.to_s 
                end
            }
            ret << "\n"
        }
        #@data.sort.each {|x_index,ds_hash|
            #ret <<  x_index.to_s 
            #ds_hash.sort.each {|k,v|
                #if(@normalize)
                    #ret << " " << (v/@data[x_index][@normalizeDS]).to_s
                #else
                    #ret << " " << v.to_s 
                #end
            #}
            #ret << "\n"
        #}
        ret
    end
end

