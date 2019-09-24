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
   parser.add_argument("-output", help="Output file name", default='setDueling.html')
   parser.add_argument("-logLevel", help="Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)", default='INFO')
   args = parser.parse_args()

   logging.basicConfig(stream=sys.stdout, format='%(message)s', level=logging.getLevelName(args.logLevel))

   assoc = getCacheInfo(args.level).assoc
   nSets = getCacheInfo(args.level).nSets
   nCBoxes = max(1, getNCBoxUnits())
   seq = ' '.join('B' + str(i) + '?' for i in range(0, assoc*4/3))

   title = cpuid.cpu_name(cpuid.CPUID()) + ', Level: ' + str(args.level)
   html = ['<html>', '<head>', '<title>' + title + '</title>', '<script src="https://cdn.plot.ly/plotly-latest.min.js">', '</script>', '</head>', '<body>']
   html += ['<h3>' + title + '</h3>']

   allSets = range(0,nSets)

   yValuesForCBox = {cBox: [[] for s in range(0, nSets)] for cBox in range(0, nCBoxes)}

   for i in range(0, args.nRuns):
      for cBox in range(0, nCBoxes):
         yValuesList = yValuesForCBox[cBox]
         for s in list(allSets) * 2 + list(reversed(allSets)) * 2:
            if yValuesList[s] and max(yValuesList[s]) > 2 and min(yValuesList[s]) < assoc/2:
               continue

            log.info('CBox ' + str(cBox) + ', run ' + str(i) + ', set: ' + str(s))

            nb = runCacheExperiment(args.level, seq, cacheSets=str(s), clearHL=True, loop=args.loop, wbinvd=False, cBox=cBox, nMeasurements=1, warmUpCount=0)
            yValuesList[s].append(nb['L' + str(args.level) + '_HIT'])

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
