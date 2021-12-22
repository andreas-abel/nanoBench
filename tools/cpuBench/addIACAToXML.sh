#!/bin/sh

set -x

./cpuBench.py -iaca "$1/iaca-version-2.1/bin/iaca.sh" -input "$2" -arch 'NHM' > output_NHM2.1.txt 2>error_NHM2.1.txt
./cpuBench.py -iaca "$1/iaca-version-2.2/bin/iaca.sh" -input result.xml -arch 'NHM' > output_NHM2.2.txt 2>error_NHM2.2.txt
./cpuBench.py -iaca "$1/iaca-version-2.1/bin/iaca.sh" -input result.xml -arch 'WSM' > output_WSM2.1.txt 2>error_WSM2.1.txt
./cpuBench.py -iaca "$1/iaca-version-2.2/bin/iaca.sh" -input result.xml -arch 'WSM' > output_WSM2.2.txt 2>error_WSM2.2.txt
./cpuBench.py -iaca "$1/iaca-version-2.1/bin/iaca.sh" -input result.xml -arch 'SNB' > output_SNB2.1.txt 2>error_SNB2.1.txt
./cpuBench.py -iaca "$1/iaca-version-2.2/bin/iaca.sh" -input result.xml -arch 'SNB' > output_SNB2.2.txt 2>error_SNB2.2.txt
./cpuBench.py -iaca "$1/iaca-version-2.3/bin/iaca.sh" -input result.xml -arch 'SNB' > output_SNB2.3.txt 2>error_SNB2.3.txt
./cpuBench.py -iaca "$1/iaca-version-2.1/bin/iaca.sh" -input result.xml -arch 'IVB' > output_IVB2.1.txt 2>error_IVB2.1.txt
./cpuBench.py -iaca "$1/iaca-version-2.2/bin/iaca.sh" -input result.xml -arch 'IVB' > output_IVB2.2.txt 2>error_IVB2.2.txt
./cpuBench.py -iaca "$1/iaca-version-2.3/bin/iaca.sh" -input result.xml -arch 'IVB' > output_IVB2.3.txt 2>error_IVB2.3.txt
./cpuBench.py -iaca "$1/iaca-version-2.1/bin/iaca.sh" -input result.xml -arch 'HSW' > output_HSW2.1.txt 2>error_HSW2.1.txt
./cpuBench.py -iaca "$1/iaca-version-2.2/bin/iaca.sh" -input result.xml -arch 'HSW' > output_HSW2.2.txt 2>error_HSW2.2.txt
./cpuBench.py -iaca "$1/iaca-version-2.3/bin/iaca.sh" -input result.xml -arch 'HSW' > output_HSW2.3.txt 2>error_HSW2.3.txt
./cpuBench.py -iaca "$1/iaca-version-3.0/iaca" -input result.xml -arch 'HSW' > output_HSW3.0.txt 2>error_HSW3.0.txt
./cpuBench.py -iaca "$1/iaca-version-2.2/bin/iaca.sh" -input result.xml -arch 'BDW' > output_BDW2.2.txt 2>error_BDW2.2.txt
./cpuBench.py -iaca "$1/iaca-version-2.3/bin/iaca.sh" -input result.xml -arch 'BDW' > output_BDW2.3.txt 2>error_BDW2.3.txt
./cpuBench.py -iaca "$1/iaca-version-3.0/iaca" -input result.xml -arch 'BDW' > output_BDW3.0.txt 2>error_BDW3.0.txt
./cpuBench.py -iaca "$1/iaca-version-2.3/bin/iaca.sh" -input result.xml -arch 'SKL' > output_SKL2.3.txt 2>error_SKL2.3.txt
./cpuBench.py -iaca "$1/iaca-version-3.0/iaca" -input result.xml -arch 'SKL' > output_SKL3.0.txt 2>error_SKL3.0.txt
./cpuBench.py -iaca "$1/iaca-version-2.3/bin/iaca.sh" -input result.xml -arch 'SKX' > output_SKX2.3.txt 2>error_SKX2.3.txt
./cpuBench.py -iaca "$1/iaca-version-3.0/iaca" -input result.xml -arch 'SKX' > output_SKX3.0.txt 2>error_SKX3.0.txt
