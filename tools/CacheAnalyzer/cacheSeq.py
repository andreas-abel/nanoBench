#!/usr/bin/env python3

import argparse
import sys
from itertools import count, cycle, islice
from collections import namedtuple, OrderedDict

import cacheSim
from cacheLib import *

import logging
log = logging.getLogger(__name__)


def main():
   parser = argparse.ArgumentParser(description='Cache Benchmarks')
   parser.add_argument("-seq", help="Access sequence", required=True)
   parser.add_argument("-seq_init", help="Initialization sequence", default='')
   parser.add_argument("-level", help="Cache level (Default: 1)", type=int, default=1)
   parser.add_argument("-sets", help="Cache sets (if not specified, all cache sets are used)")
   parser.add_argument("-cBox", help="cBox (default: 1)", type=int, default=1) # use 1 as default, as, e.g., on SNB, box 0 only has 15 ways instead of 16
   parser.add_argument("-slice", help="Slice (within the cBox) (default: 0)", type=int, default=0)
   parser.add_argument("-noClearHL", help="Do not clear higher levels", action='store_true')
   parser.add_argument("-noUseOtherCBoxes", help="Do not use other CBoxes for clearing higher levels", action='store_true')
   parser.add_argument("-nMeasurements", help="Number of measurements", type=int, default=10)
   parser.add_argument("-agg", help="Aggregate function", default='med')
   parser.add_argument("-loop", help="Loop count (Default: 1)", type=int, default=1)
   parser.add_argument("-noWbinvd", help="Do not call wbinvd before each run", action='store_true')
   parser.add_argument("-logLevel", help="Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)", default='WARNING')
   parser.add_argument("-sim", help="Simulate the given policy instead of running the experiment on the hardware")
   parser.add_argument("-simAssoc", help="Associativity of the simulated cache (default: 8)", type=int, default=8)
   args = parser.parse_args()

   logging.basicConfig(stream=sys.stdout, format='%(message)s', level=logging.getLevelName(args.logLevel))

   if args.sim:
      policyClass = cacheSim.AllPolicies[args.sim]
      seq = args.seq_init + (' ' + args.seq) * args.loop
      hits = cacheSim.getHits(seq, policyClass, args.simAssoc, args.sets) / args.loop
      print('Hits: ' + str(hits))
   else:
      nb = runCacheExperiment(args.level, args.seq, initSeq=args.seq_init, cacheSets=args.sets, cBox=args.cBox, cSlice=args.slice, clearHL=(not args.noClearHL),
                              doNotUseOtherCBoxes=args.noUseOtherCBoxes, loop=args.loop, wbinvd=(not args.noWbinvd), nMeasurements=args.nMeasurements, agg=args.agg)
      printNB(nb)


if __name__ == "__main__":
    main()
