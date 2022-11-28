#!/bin/sh

set -x

for arch in CON WOL NHM WSM SNB IVB HSW BDW SKL KBL CFL SKX CNL CLX ICL TGL RKL ADL-P ADL-E BNL AMT GLM GLP TRM ZEN+ ZEN2 ZEN3 ZEN4
do
./compareXML.py ~/code/html/instructions.xml $arch result_${arch}_measured.xml $arch -TP -lat -ports -TPMaxDiff 0.02
done
