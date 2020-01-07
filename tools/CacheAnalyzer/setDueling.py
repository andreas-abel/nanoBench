#!/usr/bin/python
import argparse
import random

from plotly.offline import plot
import plotly.graph_objects as go

from cacheLib import *

import logging
log = logging.getLogger(__name__)


def main():
   parser = argparse.ArgumentParser(description='Tests if the L3 cache uses set dueling')
   parser.add_argument("-level", help="Cache level (Default: 3)", type=int, default=3)
   parser.add_argument("-nRuns", help="Maximum number of runs", type=int, default=25)
   parser.add_argument("-loop", help="Loop count", type=int, default=25)
   parser.add_argument("-length", help="Length of the acc. seq. (Default: associativity*4/3)", type=int)
   parser.add_argument("-noClearHL", help="Do not clear higher levels", action='store_true')
   parser.add_argument("-nMeasurements", help="Number of measurements", type=int, default=10)
   parser.add_argument("-output", help="Output file name", default='setDueling.html')
   parser.add_argument("-logLevel", help="Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)", default='INFO')
   args = parser.parse_args()

   logging.basicConfig(stream=sys.stdout, format='%(message)s', level=logging.getLevelName(args.logLevel))

   assoc = getCacheInfo(args.level).assoc
   nSets = getCacheInfo(args.level).nSets
   lineSize = getCacheInfo(1).lineSize
   nCBoxes = max(1, getNCBoxUnits())
   nSlicesPerCBox = 1
   if getCacheInfo(3).nSlices:
      nSlicesPerCBox = getCacheInfo(3).nSlices / getCacheInfo(3).nCboxes

   seqLength = (args.length if args.length is not None else assoc*4/3)
   seq = ' '.join('B' + str(i) + '?' for i in range(0, seqLength))
   hitSeq = ' '.join('B' + str(i) + '?' for i in range(0, assoc))
   missSeq = ' '.join('B' + str(i) + '?' for i in range(0, 3*assoc))

   title = cpuid.cpu_name(cpuid.CPUID()) + ', L' + str(args.level) + ' Hits'
   html = ['<html>', '<head>', '<title>' + title + '</title>', '<script src="https://cdn.plot.ly/plotly-latest.min.js">', '</script>', '</head>', '<body>']
   html += ['<h3>' + title + '</h3>']

   setsForSlice = {cBox: {cSlice: range(0,nSets) for cSlice in range(0, nSlicesPerCBox)} for cBox in range(0, nCBoxes)}
   yValuesForSlice = {cBox: {cSlice: [[] for s in range(0, nSets)]  for cSlice in range(0, nSlicesPerCBox)} for cBox in range(0, nCBoxes)}

   prevOti = ''
   i = -1
   notChanged = -1
   while notChanged < 10:
      for useHitSeq in [False, True]:
         i += 1
         notChanged += 1
         for cBox in range(0, nCBoxes):
            for cSlice in range(0, nSlicesPerCBox):
               yValuesList = yValuesForSlice[cBox][cSlice]

               curSets = setsForSlice[cBox][cSlice]
               random.shuffle(curSets)
               prevSets = curSets[:]

               for si, s in enumerate(prevSets):
                  codeSet = (s + random.randint(1, nSets - 100)) % nSets
                  codeOffset = lineSize * codeSet
                  yv = yValuesList[s]

                  ec = getCodeForCacheExperiment(args.level, seq, '', [s], cBox, cSlice, (not args.noClearHL), True)
                  nb = runCacheExperimentCode(ec.code, ec.init, prevOti + ec.oneTimeInit, loop=args.loop, warmUpCount=0, codeOffset=codeOffset,
                                              nMeasurements=args.nMeasurements, agg='med')
                  yv.append(nb['L' + str(args.level) + '_HIT'])
                  yv.sort()

                  yvStr = str(yv) if len(yv) <= 5 else '[%s, %s, ..., %s, %s]' % (yv[0], yv[1], yv[-2], yv[-1])
                  log.info('CBox ' + str(cBox) + ', slice: ' + str(cSlice) + ', run ' + str(i) + ', set: ' + str(si+1) + '/' + str(len(prevSets)) +
                           ' (' + str(s) + '), ' + yvStr)

                  if len(yv) > 1:
                     if yv[-1]-yv[0] > 1:
                        curSets.remove(s)
                        notChanged = 0
                     else:
                        if useHitSeq:
                           ec = getCodeForCacheExperiment(args.level, hitSeq, '', [s], cBox, cSlice, (not args.noClearHL), True)
                        else:
                           ec = getCodeForCacheExperiment(args.level, missSeq, '', [s], cBox, cSlice, (not args.noClearHL), True)
                        prevOti = ec.oneTimeInit + 'mov R15, 100; pLoop:' + ec.code + '; dec R15; jnz pLoop; '

   for cBox in range(0, nCBoxes):
      for cSlice in range(0, nSlicesPerCBox):
         fig = go.Figure()

         title = 'CBox ' + str(cBox)
         if nSlicesPerCBox > 1: title += ', Slice: ' + str(cSlice)
         title += ', Sequence (accessed ' + str(args.loop) + ' times in each set): ' + seq
         fig.update_layout(title_text=title)

         fig.update_layout(showlegend=True)
         fig.update_xaxes(title_text='Set')

         yValuesMinMax = [min(x) + (max(x)-min(x))/2 for x in yValuesForSlice[cBox][cSlice] if x]
         fig.add_trace(go.Scatter(y=yValuesMinMax, mode='lines+markers', name='Min+(Max-Min)/2'))

         yValuesMin = [min(x) for x in yValuesForSlice[cBox][cSlice] if x]
         fig.add_trace(go.Scatter(y=yValuesMin, mode='lines+markers', visible = 'legendonly', name='Min'))

         yValuesMax = [max(x) for x in yValuesForSlice[cBox][cSlice] if x]
         fig.add_trace(go.Scatter(y=yValuesMax, mode='lines+markers', visible = 'legendonly', name='Max'))

         html.append(plot(fig, include_plotlyjs=False, output_type='div'))

   html += ['</body>', '</html>']

   with open(args.output ,'w') as f:
      f.write('\n'.join(html))
      print 'Output written to ' + args.output


if __name__ == "__main__":
    main()
