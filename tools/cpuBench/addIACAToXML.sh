#!/bin/sh

set -x

./cpuBench.py -iaca "$1/iaca-version-2.1/bin/iaca.sh" -input "$2" -arch 'NHM' -output result_IACA.xml > output_NHM2.1.txt 2>error_NHM2.1.txt
./cpuBench.py -iaca "$1/iaca-version-2.2/bin/iaca.sh" -input result_IACA.xml -arch 'NHM' -output result_IACA.xml > output_NHM2.2.txt 2>error_NHM2.2.txt
./cpuBench.py -iaca "$1/iaca-version-2.1/bin/iaca.sh" -input result_IACA.xml -arch 'WSM' -output result_IACA.xml > output_WSM2.1.txt 2>error_WSM2.1.txt
./cpuBench.py -iaca "$1/iaca-version-2.2/bin/iaca.sh" -input result_IACA.xml -arch 'WSM' -output result_IACA.xml > output_WSM2.2.txt 2>error_WSM2.2.txt
./cpuBench.py -iaca "$1/iaca-version-2.1/bin/iaca.sh" -input result_IACA.xml -arch 'SNB' -output result_IACA.xml > output_SNB2.1.txt 2>error_SNB2.1.txt
./cpuBench.py -iaca "$1/iaca-version-2.2/bin/iaca.sh" -input result_IACA.xml -arch 'SNB' -output result_IACA.xml > output_SNB2.2.txt 2>error_SNB2.2.txt
./cpuBench.py -iaca "$1/iaca-version-2.3/bin/iaca.sh" -input result_IACA.xml -arch 'SNB' -output result_IACA.xml > output_SNB2.3.txt 2>error_SNB2.3.txt
./cpuBench.py -iaca "$1/iaca-version-2.1/bin/iaca.sh" -input result_IACA.xml -arch 'IVB' -output result_IACA.xml > output_IVB2.1.txt 2>error_IVB2.1.txt
./cpuBench.py -iaca "$1/iaca-version-2.2/bin/iaca.sh" -input result_IACA.xml -arch 'IVB' -output result_IACA.xml > output_IVB2.2.txt 2>error_IVB2.2.txt
./cpuBench.py -iaca "$1/iaca-version-2.3/bin/iaca.sh" -input result_IACA.xml -arch 'IVB' -output result_IACA.xml > output_IVB2.3.txt 2>error_IVB2.3.txt
./cpuBench.py -iaca "$1/iaca-version-2.1/bin/iaca.sh" -input result_IACA.xml -arch 'HSW' -output result_IACA.xml > output_HSW2.1.txt 2>error_HSW2.1.txt
./cpuBench.py -iaca "$1/iaca-version-2.2/bin/iaca.sh" -input result_IACA.xml -arch 'HSW' -output result_IACA.xml > output_HSW2.2.txt 2>error_HSW2.2.txt
./cpuBench.py -iaca "$1/iaca-version-2.3/bin/iaca.sh" -input result_IACA.xml -arch 'HSW' -output result_IACA.xml > output_HSW2.3.txt 2>error_HSW2.3.txt
./cpuBench.py -iaca "$1/iaca-version-3.0/iaca" -input result_IACA.xml -arch 'HSW' -output result_IACA.xml > output_HSW3.0.txt 2>error_HSW3.0.txt
./cpuBench.py -iaca "$1/iaca-version-2.2/bin/iaca.sh" -input result_IACA.xml -arch 'BDW' -output result_IACA.xml > output_BDW2.2.txt 2>error_BDW2.2.txt
./cpuBench.py -iaca "$1/iaca-version-2.3/bin/iaca.sh" -input result_IACA.xml -arch 'BDW' -output result_IACA.xml > output_BDW2.3.txt 2>error_BDW2.3.txt
./cpuBench.py -iaca "$1/iaca-version-3.0/iaca" -input result_IACA.xml -arch 'BDW' -output result_IACA.xml > output_BDW3.0.txt 2>error_BDW3.0.txt
./cpuBench.py -iaca "$1/iaca-version-2.3/bin/iaca.sh" -input result_IACA.xml -arch 'SKL' -output result_IACA.xml > output_SKL2.3.txt 2>error_SKL2.3.txt
./cpuBench.py -iaca "$1/iaca-version-3.0/iaca" -input result_IACA.xml -arch 'SKL' -output result_IACA.xml > output_SKL3.0.txt 2>error_SKL3.0.txt
./cpuBench.py -iaca "$1/iaca-version-2.3/bin/iaca.sh" -input result_IACA.xml -arch 'SKX' -output result_IACA.xml > output_SKX2.3.txt 2>error_SKX2.3.txt
./cpuBench.py -iaca "$1/iaca-version-3.0/iaca" -input result_IACA.xml -arch 'SKX' -output result_IACA.xml > output_SKX3.0.txt 2>error_SKX3.0.txt
