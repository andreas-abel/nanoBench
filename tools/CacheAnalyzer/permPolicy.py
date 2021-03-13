#!/usr/bin/env python3

import argparse
import math
import os
import plotly.graph_objects as go
import re
import subprocess
import sys

from itertools import count
from collections import namedtuple, OrderedDict
from plotly.offline import plot

import cacheSim
from cacheLib import *
from cacheGraph import *

import logging
log = logging.getLogger(__name__)


def getPermutations(level, html, cacheSets=None, getInitialAges=True, maxAge=None, cBox=1, cSlice=0):
   assoc = getCacheInfo(level).assoc
   if not maxAge:
      maxAge=2*assoc

   hitEvent = 'L' + str(level) + '_HIT'
   missEvent = 'L' + str(level) + '_MISS'

   if getInitialAges:
      initBlocks = ['I' + str(i) for i in range(0, assoc)]
      seq = ' '.join(initBlocks)

      initAges, nbDict = getAgesOfBlocks(initBlocks, level, seq, cacheSets=cacheSets, clearHL=True, wbinvd=True, returnNbResults=True, maxAge=maxAge,
                                         cBox=cBox, cSlice=cSlice)

      accSeqStr = 'Access sequence: <wbinvd> ' + seq
      print(accSeqStr)
      print('Ages: {' + ', '.join(b + ': ' + str(initAges[b]) for b in initBlocks) + '}')

      event = (hitEvent if hitEvent in next(iter(nbDict.items()))[1][0] else missEvent)
      traces = [(b, [nb[event] for nb in nbDict[b]]) for b in initBlocks]
      html.append(getPlotlyGraphDiv(accSeqStr + ' <n fresh blocks> <block>?', '# of fresh blocks', hitEvent, traces))
   else:
      initBlocks = []

   blocks = ['B' + str(i) for i in range(0, assoc)]
   baseSeq = ' '.join(initBlocks + blocks)

   ages, nbDict = getAgesOfBlocks(blocks, level, baseSeq, cacheSets=cacheSets, clearHL=True, wbinvd=True, returnNbResults=True, maxAge=maxAge,
                                  cBox=cBox, cSlice=cSlice)

   accSeqStr = 'Access sequence: <wbinvd> ' + baseSeq
   print(accSeqStr)
   print('Ages: {' + ', '.join(b + ': ' + str(ages[b]) for b in blocks) + '}')

   event = (hitEvent if hitEvent in next(iter(nbDict.items()))[1][0] else missEvent)
   traces = [(b, [nb[event] for nb in nbDict[b]]) for b in blocks]
   html.append(getPlotlyGraphDiv(accSeqStr + ' <n fresh blocks> <block>?', '# of fresh blocks', hitEvent, traces))

   blocksSortedByAge = [a[0] for a in sorted(ages.items(), key=lambda x: -x[1])] # most recent block first

   for permI, permBlock in enumerate(blocksSortedByAge):
      seq = baseSeq + ' ' + permBlock
      permAges, nbDict = getAgesOfBlocks(blocks, level, seq, cacheSets=cacheSets, clearHL=True, wbinvd=True, returnNbResults=True, maxAge=maxAge,
                                         cBox=cBox, cSlice=cSlice)

      accSeqStr = 'Access sequence: <wbinvd> ' + seq
      traces = [(b, [nb[event] for nb in nbDict[b]]) for b in blocks]
      html.append(getPlotlyGraphDiv(accSeqStr + ' <n fresh blocks> <block>?', '# of fresh blocks', hitEvent, traces))

      perm = [-1] * assoc
      for bi, b in enumerate(blocksSortedByAge):
         permAge = permAges[b]
         if permAge < 1 or permAge > assoc:
            break
         perm[assoc-permAge] = bi

      print(u'\u03A0_' + str(permI) + ' = ' + str(tuple(perm)))


def main():
   parser = argparse.ArgumentParser(description='Replacement Policies')
   parser.add_argument("-level", help="Cache level (Default: 1)", type=int, default=1)
   parser.add_argument("-sets", help="Cache sets (if not specified, all cache sets are used)")
   parser.add_argument("-noInit", help="Do not fill sets with associativity many elements first", action='store_true')
   parser.add_argument("-maxAge", help="Maximum age", type=int)
   parser.add_argument("-cBox", help="cBox (default: 1)", type=int, default=1)
   parser.add_argument("-slice", help="Slice (within the cBox) (default: 0)", type=int, default=0)
   parser.add_argument("-sim", help="Simulate the given policy instead of running the experiment on the hardware")
   parser.add_argument("-simAssoc", help="Associativity of the simulated cache (default: 8)", type=int, default=8)
   parser.add_argument("-logLevel", help="Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)", default='WARNING')
   parser.add_argument("-output", help="Output file name", default='permPolicy.html')
   args = parser.parse_args()

   logging.basicConfig(stream=sys.stdout, format='%(message)s', level=logging.getLevelName(args.logLevel))

   if not args.sim:
      title = cpuid.cpu_name(cpuid.CPUID()) + ', Level: ' + str(args.level)

      html = ['<html>', '<head>',  '<title>' + title + '</title>', '<script src="https://cdn.plot.ly/plotly-latest.min.js"></script>', '</head>', '<body>']
      html += ['<h3>' + title + '</h3>']
      getPermutations(args.level, html, cacheSets=args.sets, getInitialAges=(not args.noInit), maxAge=args.maxAge, cBox=args.cBox, cSlice=args.slice)
      html += ['</body>', '</html>']

      with open(args.output ,'w') as f:
         f.write('\n'.join(html))
   else:
      policyClass = cacheSim.AllPolicies[args.sim]
      cacheSim.getPermutations(policyClass, args.simAssoc)


if __name__ == "__main__":
    main()
