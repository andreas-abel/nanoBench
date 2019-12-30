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
   parser.add_argument("-nMeasurements", help="Number of measurements", type=int, default=10)
   parser.add_argument("-output", help="Output file name", default='setDueling.html')
   parser.add_argument("-logLevel", help="Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)", default='INFO')
   args = parser.parse_args()

   logging.basicConfig(stream=sys.stdout, format='%(message)s', level=logging.getLevelName(args.logLevel))

   assoc = getCacheInfo(args.level).assoc
   nSets = getCacheInfo(args.level).nSets
   lineSize = getCacheInfo(1).lineSize
   nCBoxes = max(1, getNCBoxUnits())
   seq = ' '.join('B' + str(i) + '?' for i in range(0, assoc*4/3))

   title = cpuid.cpu_name(cpuid.CPUID()) + ', Level: ' + str(args.level)
   html = ['<html>', '<head>', '<title>' + title + '</title>', '<script src="https://cdn.plot.ly/plotly-latest.min.js">', '</script>', '</head>', '<body>']
   html += ['<h3>' + title + '</h3>']

   setsForCBox = {cBox: range(0,nSets) for cBox in range(0, nCBoxes)}
   yValuesForCBox = {cBox: [[] for s in range(0, nSets)] for cBox in range(0, nCBoxes)}

   i = -1
   notChanged = -1
   prevEc = ExperimentCode('', '', '')

   while notChanged < 10:
      i += 1
      notChanged += 1

      for cBox in range(0, nCBoxes):
         yValuesList = yValuesForCBox[cBox]

         curSets = setsForCBox[cBox]
         random.shuffle(curSets)
         prevSets = curSets[:]

         for si, s in enumerate(prevSets):
            codeSet = (s + random.randint(1, nSets - 100)) % nSets
            codeOffset = lineSize * codeSet

            ec = getCodeForCacheExperiment(args.level, seq, initSeq='', cacheSetList=[s], cBox=cBox, clearHL=True, wbinvd=True)
            oneTimeInit = prevEc.oneTimeInit + 'mov R15, ' + str(args.loop*args.nMeasurements) + '; pLoop:' + prevEc.code + '; dec R15; jnz pLoop; ' + ec.oneTimeInit

            nb = runCacheExperimentCode(ec.code, ec.init, oneTimeInit, loop=args.loop, warmUpCount=0, codeOffset=codeOffset, nMeasurements=args.nMeasurements, agg='med')
            hits = nb['L' + str(args.level) + '_HIT']

            yv = yValuesList[s]
            yv.append(hits)
            yv.sort()

            yvStr = str(yv) if len(yv) <= 5 else '[%s, %s, ..., %s, %s]' % (yv[0], yv[1], yv[-2], yv[-1])
            log.info('CBox ' + str(cBox) + ', run ' + str(i) + ', set: ' + str(si+1) + '/' + str(len(prevSets)) + ' (' + str(s) + '), ' + yvStr)

            if len(yv) >= 4 and yv[-1]-yv[0] > .5 and abs(yv[0]-yv[1]) < .5 and abs(yv[-1]-yv[-2]) < .5: #max(yValuesList[s]) - min(yValuesList[s]) > 0.1: #max(yValuesList[s]) > 2 and min(yValuesList[s]) < assoc/2:
               curSets.remove(s)
               notChanged = 0

            if yv[-1]-yv[0] < .5:
               prevEc = ec

   for cBox in range(0, nCBoxes):
      yValues = [min(x) + (max(x)-min(x))/2 for x in yValuesForCBox[cBox] if x]

      fig = go.Figure()
      fig.update_layout(title_text='CBox ' + str(cBox) + ', Sequence (accessed ' + str(args.loop) + ' times in each set): ' + seq)
      fig.update_layout(showlegend=True)
      fig.update_xaxes(title_text='Set')
      fig.add_trace(go.Scatter(y=yValues, mode='lines+markers', name='L3 Hits'))

      html.append(plot(fig, include_plotlyjs=False, output_type='div'))

   html += ['</body>', '</html>']

   with open(args.output ,'w') as f:
      f.write('\n'.join(html))
      print 'Output written to ' + args.output


if __name__ == "__main__":
    main()
