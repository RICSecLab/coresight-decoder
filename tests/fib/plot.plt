#! /usr/bin/gnuplot

set grid
set title 'Performance comparison between cache mode and no-cache mode'
set ylabel 'execution time [us]'

plot non_cache_mode
replot cache_mode
pause -1
