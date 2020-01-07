#!/usr/bin/python
import argparse
import random
import sys

from numpy import median

from cacheLib import *
import cacheSim

import logging
log = logging.getLogger(__name__)


def getActualHits(seq, level, cacheSets, cBox, cSlice, nMeasurements=10):
   nb = runCacheExperiment(level, seq, cacheSets=cacheSets, cBox=cBox, cSlice=cSlice, clearHL=True, loop=1, wbinvd=True, nMeasurements=nMeasurements, agg='med')
   return int(nb['L' + str(level) + '_HIT']+0.1)


def findSmallCounterexample(policy, initSeq, level, sets, cBox, cSlice, assoc, seq, nMeasurements):
   seqSplit = seq.split()
   for seqPrefix in [seqSplit[:i] for i in range(assoc+1, len(seqSplit)+1)]:
      seq = initSeq + ' '.join(seqPrefix)
      actual = getActualHits(seq, level, sets, cBox, cSlice, nMeasurements)
      sim = cacheSim.getHits(seq, cacheSim.AllPolicies[policy], assoc, sets)
      print 'seq:' + seq + ', actual: ' + str(actual) + ', sim: ' + str(sim)
      if sim != actual:
         break

   for i in reversed(range(0, len(seqPrefix)-1)):
      tmpPrefix = seqPrefix[:i] + seqPrefix[(i+1):]
      seq = initSeq + ' '.join(tmpPrefix)
      actual = getActualHits(seq, level, sets, cBox, cSlice, nMeasurements)
      sim = cacheSim.getHits(seq, cacheSim.AllPolicies[policy], assoc, sets)
      print 'seq:' + seq + ', actual: ' + str(actual) + ', sim: ' + str(sim)
      if sim != actual:
         seqPrefix = tmpPrefix

   return ((initSeq + ' ') if initSeq else '') + ' '.join(seqPrefix)


def getRandomSeq(n):
   seq = [0]
   seqAct = ['']
   for _ in range(0,n):
      if random.choice([True, False]):
         seq.append(max(seq)+1)
         seqAct.append('')
      else:
         seq.append(random.choice(seq))
         if random.randint(0,8)==0:
            seqAct.append('?')
         else:
            seqAct.append('?')
   return ' '.join(str(s) + a for s, a in zip(seq, seqAct))


def main():
   parser = argparse.ArgumentParser(description='Replacement Policies')
   parser.add_argument("-level", help="Cache level (Default: 1)", type=int, default=1)
   parser.add_argument("-sets", help="Cache sets (if not specified, all cache sets are used)")
   parser.add_argument("-cBox", help="cBox (default: 0)", type=int)
   parser.add_argument("-slice", help="Slice (within the cBox) (default: 0)", type=int, default=0)
   parser.add_argument("-nMeasurements", help="Number of measurements", type=int, default=3)
   parser.add_argument("-rep", help="Number of repetitions of each experiment (Default: 1)", type=int, default=1)
   parser.add_argument("-findCtrEx", help="Tries to find a small counterexample for each policy (only available for deterministic policies)", action='store_true')
   parser.add_argument("-policies", help="Comma-separated list of policies to consider (Default: all deterministic policies)")
   parser.add_argument("-best", help="Find the best matching policy (Default: abort if no policy agrees with all results)", action='store_true')
   parser.add_argument("-randPolicies", help="Test randomized policies", action='store_true')
   parser.add_argument("-allQLRUVariants", help="Test all QLRU variants", action='store_true')
   parser.add_argument("-assoc", help="Override the associativity", type=int)
   parser.add_argument("-initSeq", help="Adds an initialization sequence to each sequence")
   parser.add_argument("-nRandSeq", help="Number of random sequences (default: 100)", type=int, default=100)
   parser.add_argument("-lRandSeq", help="Length of random sequences (default: 50)", type=int, default=50)
   parser.add_argument("-logLevel", help="Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)", default='WARNING')
   parser.add_argument("-output", help="Output file name", default='replPolicy.html')
   args = parser.parse_args()

   logging.basicConfig(stream=sys.stdout, format='%(message)s', level=logging.getLevelName(args.logLevel))

   policies = sorted(cacheSim.CommonPolicies.keys())
   if args.policies:
      policies = args.policies.split(',')
   elif args.allQLRUVariants:
      policies = sorted(set(cacheSim.CommonPolicies.keys())|set(cacheSim.AllDetQLRUVariants.keys()))
   elif args.randPolicies:
      if args.rep > 1:
         sys.exit('rep > 1 not supported for random policies')
      policies = sorted(cacheSim.AllRandPolicies.keys())

   if args.assoc:
      assoc = args.assoc
   else:
      assoc = getCacheInfo(args.level).assoc

   cBox = 0
   if args.cBox:
      cBox = args.cBox

   title = cpuid.cpu_name(cpuid.CPUID()) + ', Level: ' + str(args.level) + (', CBox: ' + str(cBox) if args.cBox else '')

   html = ['<html>', '<head>', '<title>' + title + '</title>', '</head>', '<body>']
   html += ['<h3>' + title + '</h3>']
   html += ['<table border="1" style="white-space:nowrap;">']
   html += ['<tr><th>Sequence</th><th>Actual</th>']
   html += ['<th>' + p.replace('_', '<br>_') + '</th>' for p in policies]
   html += ['</tr>']

   possiblePolicies = set(policies)
   counterExamples = dict()
   dists = {p: 0.0 for p in policies}

   seqList = []
   seqList.extend(getRandomSeq(args.lRandSeq) for _ in range(0,args.nRandSeq))

   for seq in seqList:
      fullSeq = ((args.initSeq + ' ') if args.initSeq else '') + seq
      print fullSeq

      html += ['<tr><td>' + fullSeq + '</td>']
      actualHits = set([getActualHits(fullSeq, args.level, args.sets, cBox, args.slice, args.nMeasurements) for _ in range(0, args.rep)])
      html += ['<td>' + ('{' if len(actualHits) > 1 else '') +  ', '.join(map(str, sorted(actualHits))) + ('}' if len(actualHits) > 1 else '') + '</td>']

      outp = ''
      for p in policies:
         if not args.randPolicies:
            sim = cacheSim.getHits(fullSeq, cacheSim.AllPolicies[p], assoc, args.sets)

            if sim not in actualHits:
               possiblePolicies.discard(p)
               dists[p] += 1
               color = 'red'
               if args.findCtrEx and not p in counterExamples:
                  counterExamples[p] = findSmallCounterexample(p, ((args.initSeq + ' ') if args.initSeq else ''), args.level, args.sets, cBox, args.slice,
                                                               assoc, seq, args.nMeasurements)
            elif len(actualHits) > 1:
               color = 'yellow'
            else:
               color = 'green'
         else:
            sim = median(sum(cacheSim.getHits(fullSeq, cacheSim.AllPolicies[p], assoc, args.sets) for _ in range(0, args.nMeasurements)))
            dist = (sim - actual) ** 2
            dists[p] += dist

            colorR = min(255, dist)
            colorG = max(0, min(255, 512 - dist))
            color = 'rgb(' + str(colorR) + ',' + str(colorG) + ',0)'

         html += ['<td style="background-color:' + color + ';">' + str(sim) + '</td>']

      html += ['</tr>']

      if not args.randPolicies and not args.best:
         print 'Possible policies: ' + ', '.join(possiblePolicies)
         if not possiblePolicies: break

   if not args.randPolicies and args.findCtrEx:
      print ''
      print 'Counter example(s): '
      for p, ctrEx in counterExamples.items():
         print '  ' + p + ': ' + ctrEx

   html += ['</table>', '</body>', '</html>']

   with open(args.output ,'w') as f:
      f.write('\n'.join(html))

   if not args.randPolicies and not args.best:
      print 'Possible policies: ' + ', '.join(possiblePolicies)
   else:
      for p, d in reversed(sorted(dists.items(), key=lambda d: d[1])):
         print p + ': ' + str(d)


if __name__ == "__main__":
    main()
