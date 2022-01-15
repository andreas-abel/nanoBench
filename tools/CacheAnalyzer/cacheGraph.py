#!/usr/bin/env python3

from itertools import count
from collections import namedtuple, OrderedDict

import argparse
import os
import sys

from cacheLib import *
import cacheSim

from plotly.offline import plot
import plotly.graph_objects as go

import logging
log = logging.getLogger(__name__)


# traces is a list of (name, y value list) pairs
def getPlotlyGraphDiv(title, x_title, y_title, traces):
   fig = go.Figure()
   fig.update_layout(title_text=title)
   fig.update_xaxes(title_text=x_title)
   fig.update_yaxes(title_text=y_title)

   for name, y_values in traces:
      fig.add_trace(go.Scatter(y=y_values, mode='lines+markers', name=name))

   return plot(fig, include_plotlyjs=False, output_type='div')

def main():
   parser = argparse.ArgumentParser(description='Generates a graph with the ages of each block')
   parser.add_argument("-seq", help="Access sequence", required=True)
   parser.add_argument("-seq_init", help="Initialization sequence", default='')
   parser.add_argument("-level", help="Cache level (Default: 1)", type=int, default=1)
   parser.add_argument("-sets", help="Cache set (if not specified, all cache sets are used)")
   parser.add_argument("-noClearHL", help="Do not clear higher levels", action='store_true')
   parser.add_argument("-noWbinvd", help="Do not call wbinvd before each run", action='store_true')
   parser.add_argument("-nMeasurements", help="Number of measurements", type=int, default=10)
   parser.add_argument("-agg", help="Aggregate function", default='med')
   parser.add_argument("-cBox", help="cBox (default: 1)", type=int, default=1)
   parser.add_argument("-slice", help="Slice (within the cBox) (default: 0)", type=int, default=0)
   parser.add_argument("-logLevel", help="Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)", default='WARNING')
   parser.add_argument("-blocks", help="Blocks to consider (default: all blocks in seq)")
   parser.add_argument("-maxAge", help="Maximum age", type=int)
   parser.add_argument("-output", help="Output file name", default='graph.html')
   parser.add_argument("-sim", help="Simulate the given policy instead of running the experiment on the hardware")
   parser.add_argument("-simAssoc", help="Associativity of the simulated cache (default: 8)", type=int, default=8)
   parser.add_argument("-simRep", help="Number of repetitions", type=int, default=1)
   args = parser.parse_args()

   logging.basicConfig(stream=sys.stdout, format='%(message)s', level=logging.getLevelName(args.logLevel))

   if args.blocks:
      blocksStr = args.blocks
   else:
      blocksStr = args.seq
   blocksStr = blocksStr.replace('<wbinvd>', '')
   blocks = list(OrderedDict.fromkeys(re.sub('[?!,;]', ' ', blocksStr).split()))

   html = ['<html>', '<head>', '<script src="https://cdn.plot.ly/plotly-latest.min.js">', '</script>', '</head>', '<body>']

   if args.sim:
      policyClass = cacheSim.AllPolicies[args.sim]
      if not args.maxAge:
         maxAge = 2*args.simAssoc
      else:
         maxAge = args.maxAge
      nSets = len(parseCacheSetsStr(args.level, True, args.sets))
      traces = cacheSim.getGraph(blocks, args.seq, policyClass, args.simAssoc, maxAge, nSets=nSets, nRep=args.simRep, agg=args.agg)
      title = 'Access Sequence: ' + args.seq.replace('?','').strip() + ' <n fresh blocks> <block>?'
      html.append(getPlotlyGraphDiv(title, '# of fresh blocks', 'Hits', traces))
   else:
      _, nbDict = getAgesOfBlocks(blocks, args.level, args.seq, initSeq=args.seq_init, cacheSets=args.sets, cBox=args.cBox, cSlice=args.slice,
                                  clearHL=(not args.noClearHL), wbinvd=(not args.noWbinvd), returnNbResults=True, maxAge=args.maxAge,
                                  nMeasurements=args.nMeasurements, agg=args.agg)
      for event in sorted(e for e in list(nbDict.values())[0][0].keys() if 'HIT' in e or 'MISS' in e):
         traces = [(b, [nb[event] for nb in nbDict[b]]) for b in blocks]
         title = 'Access Sequence: ' + (args.seq_init + ' ' + args.seq).replace('?','').strip() + ' <n fresh blocks> <block>?'
         html.append(getPlotlyGraphDiv(title, '# of fresh blocks', event, traces))

   html += ['</body>', '</html>']

   with open(args.output ,'w') as f:
      f.write('\n'.join(html))
      print('Graph written to ' + args.output)
   if not args.sim:
      os.chown(args.output, int(os.environ['SUDO_UID']), int(os.environ['SUDO_GID']))

if __name__ == "__main__":
    main()
