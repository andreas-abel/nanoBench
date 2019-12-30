#!/usr/bin/python
import argparse
import sys

from cacheLib import *
import cacheSim

import logging
log = logging.getLogger(__name__)


def main():
   parser = argparse.ArgumentParser(description='Outputs whether the last access of a sequence results in a hit or miss')
   parser.add_argument("-seq", help="Access sequence", required=True)
   parser.add_argument("-seq_init", help="Initialization sequence", default='')
   parser.add_argument("-level", help="Cache level (Default: 1)", type=int, default=1)
   parser.add_argument("-sets", help="Cache sets (if not specified, all cache sets are used)")
   parser.add_argument("-cBox", help="cBox (default: 1)", type=int, default=1) # use 1 as default, as, e.g., on SNB, box 0 only has 15 ways instead of 16
   parser.add_argument("-noClearHL", help="Do not clear higher levels", action='store_true')
   parser.add_argument("-loop", help="Loop count (Default: 1)", type=int, default=1)
   parser.add_argument("-noWbinvd", help="Do not call wbinvd before each run", action='store_true')
   parser.add_argument("-logLevel", help="Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)", default='WARNING')
   parser.add_argument("-sim", help="Simulate the given policy instead of running the experiment on the hardware")
   parser.add_argument("-simAssoc", help="Associativity of the simulated cache (default: 8)", type=int, default=8)
   args = parser.parse_args()

   logging.basicConfig(stream=sys.stdout, format='%(message)s', level=logging.getLevelName(args.logLevel))

   if args.sim:
      policyClass = cacheSim.AllPolicies[args.sim]
      seq = re.sub('[?!]', '', ' '.join([args.seq_init, args.seq])).strip() + '?'
      hits = cacheSim.getHits(seq, policyClass, args.simAssoc, args.sets)
      if hits > 0:
         print 'HIT'
         exit(1)
      else:
         print 'MISS'
         exit(0)
   else:
      setCount = len(parseCacheSetsStr(args.level, True, args.sets))
      seq = re.sub('[?!]', '', args.seq).strip() + '?'
      nb = runCacheExperiment(args.level, seq, initSeq=args.seq_init, cacheSets=args.sets, cBox=args.cBox, clearHL=(not args.noClearHL), loop=args.loop,
                              wbinvd=(not args.noWbinvd))
      if nb['L' + str(args.level) + '_HIT']/setCount > .5:
         print 'HIT'
         exit(1)
      else:
         print 'MISS'
         exit(0)


if __name__ == "__main__":
    main()
