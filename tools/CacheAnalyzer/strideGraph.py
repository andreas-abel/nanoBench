#!/usr/bin/env python3

import argparse
import math
import plotly.graph_objects as go
from plotly.offline import plot

from cacheLib import *

def main():
   parser = argparse.ArgumentParser(description='Generates a graph obtained by sweeping over a memory area repeatedly with a given stride')
   parser.add_argument("-stride", help="Stride (in bytes) (Default: 64)", type=int, default=64)
   parser.add_argument("-startSize", help="Start size of the memory area (in kB) (Default: 4)", type=int, default=4)
   parser.add_argument("-endSize", help="End size of the memory area (in kB) (Default: 32768)", type=int, default=32768)
   parser.add_argument("-loop", help="Loop count (Default: 100)", type=int, default=100)
   parser.add_argument("-output", help="Output file name", default='strideGraph.html')
   args = parser.parse_args()

   resetNanoBench()
   setNanoBenchParameters(config=getDefaultCacheConfig(), fixedCounters=True, nMeasurements=1, warmUpCount=0, unrollCount=1, loopCount=args.loop,
                          basicMode=False, noMem=True)

   nbDicts = []
   xValues = []
   nAddresses = []
   tickvals = []

   pt = args.startSize*1024
   while pt <= args.endSize*1024:
      tickvals.append(pt)
      for x in ([int(math.pow(2, math.log(pt, 2) + i/16.0)) for i in range(0,16)] if pt < args.endSize*1024 else [pt]):
         print(x//1024)
         xValues.append(str(x))
         addresses = list(range(0, x, args.stride))
         nAddresses.append(len(addresses))
         ec = getCodeForAddressLists([AddressList(addresses, False, False, False)], wbinvd=True)
         nbDicts.append(runNanoBench(code=ec.code, init=ec.init, oneTimeInit=ec.oneTimeInit))
      pt *= 2

   title = cpuid.cpu_name(cpuid.CPUID())
   html = ['<html>', '<head>', '<title>' + title + '</title>', '<script src="https://cdn.plot.ly/plotly-latest.min.js">', '</script>', '</head>', '<body>']
   html += ['<h3>' + title + '</h3>']

   for evtType in ['Core cycles', 'APERF', 'HIT', 'MISS']:
      if not any(e for e in nbDicts[0].keys() if evtType in e): continue

      fig = go.Figure()
      fig.update_layout(showlegend=True)
      fig.update_xaxes(title_text='Size (in kB)', type='category', tickvals=tickvals, ticktext=[x/1024 for x in tickvals])

      for event in sorted(e for e in nbDicts[0].keys() if evtType in e):
         yValues = [nb[event]/nAddr for nb, nAddr in zip(nbDicts, nAddresses)]
         fig.add_trace(go.Scatter(x=xValues, y=yValues, mode='lines+markers', name=event))

      html.append(plot(fig, include_plotlyjs=False, output_type='div'))

   html += ['</body>', '</html>']

   with open(args.output ,'w') as f:
      f.write('\n'.join(html))
      print('Graph written to ' + args.output)

if __name__ == "__main__":
    main()
