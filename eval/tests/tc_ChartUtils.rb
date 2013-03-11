#!/usr/bin/ruby
#

require 'test/unit'
require '../scripts/ChartUtils'

class TestChartUtils < Test::Unit::TestCase
    def setup
        @chart = ChartData.new("x")
        @chart.addDataPoint(1,"DS1",3)
        @chart.addDataPoint(1,"DS2",6)
        @chart.addDataPoint(2,"DS1",2)
        @chart.addDataPoint(2,"DS2",6)
        @chart.addDataPoint(3,"DS1",2)
        @chart.addDataPoint(3,"DS2",2)
        @compare_str = "x 1 2 3\nDS1 3 2 2\nDS2 6 6 2\n"
    end
    def teardown
    end
    def test_add_to_table
        assert_not_nil(@chart.getDataAtXVal(1))
    end
    def test_table_print
        assert_equal(@compare_str,@chart.to_s)
    end
    def test_write_table_to_file
        file_name = "tmp" + rand(9000).to_s
        @chart.dataToFileWithIndices(file_name)
        assert_equal(@compare_str,File.open(file_name,"r").read)
        File.delete(file_name)
    end
    def test_normalize_to_file
        @chart.setNormalize("DS1")
        compare_str = "x 1 2 3\nDS1 1 1 1\nDS2 2 3 1\n"
        file_name = "tmp" + rand(9000).to_s
        @chart.dataToFileWithIndices(file_name)
        assert_equal(compare_str,File.open(file_name,"r").read)
        File.delete(file_name)
    end
end
