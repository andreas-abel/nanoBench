#!/usr/bin/env python3

import argparse
import os
import sys
from kernelNanoBench import *
from tools.CPUID.cpuid import CPUID, micro_arch

def writeHtmlFile(filename, title, head, body, includeDOCTYPE=True):
   with open(filename, 'w') as f:
      if includeDOCTYPE:
         f.write('<!DOCTYPE html>\n')
      f.write('<html>\n'
              '<head>\n'
              '<meta charset="utf-8"/>'
              '<title>' + title + '</title>\n'
              + head +
              '</head>\n'
              '<body>\n'
              + body +
              '</body>\n'
              '</html>\n')

def main():
   parser = argparse.ArgumentParser(description='Cycle-by-Cycle Measurements')
   parser.add_argument('-html', help='HTML filename [Default: graph.html]', nargs='?', const='', metavar='filename')
   parser.add_argument('-csv', help='CSV filename [Default: stdout]', nargs='?', const='', metavar='filename')
   parser.add_argument('-end_to_end', action='store_true', help='Do not try to remove overhead.')
   parser.add_argument('-asm', metavar='code', help='Assembler code string (in Intel syntax) to be benchmarked.')
   parser.add_argument('-asm_init', metavar='code', help='Assembler code string (in Intel syntax) to be executed once in the beginning.')
   parser.add_argument('-asm_late_init', metavar='code', help='Assembler code string (in Intel syntax) to be executed once immediately before the code to be benchmarked.')
   parser.add_argument('-asm_one_time_init', metavar='code', help='Assembler code string (in Intel syntax) to be executed once before the first measurement.')
   parser.add_argument('-code', metavar='filename', help='Binary file containing the code to be benchmarked.')
   parser.add_argument('-code_init', metavar='filename', help='Binary file containing code to be executed once in the beginning.')
   parser.add_argument('-code_late_init', metavar='filename', help='Binary file containing code to be executed once immediately before the code to be benchmarked.')
   parser.add_argument('-code_one_time_init', metavar='filename', help='Binary file containing code to be executed once before the first measurement.')
   parser.add_argument('-cpu', metavar='n', help='Pins the measurement thread to CPU n.')
   parser.add_argument('-config', metavar='filename', help='File with performance counter event specifications.', required=True)
   parser.add_argument('-unroll_count', metavar='n', help='Number of copies of the benchmark code inside the inner loop.', default=1)
   parser.add_argument('-loop_count', metavar='n', help='Number of iterations of the inner loop.')
   parser.add_argument('-n_measurements', metavar='n', help='Number of times the measurements are repeated.')
   parser.add_argument('-warm_up_count', metavar='n', help='Number of runs before the first measurement gets recorded.')
   parser.add_argument('-initial_warm_up_count', metavar='n', help='Number of runs before any measurement is performed.')
   parser.add_argument('-alignment_offset', metavar='n', help='Alignment offset.')
   parser.add_argument('-avg', action='store_const', const='avg', help='Selects the arithmetic mean (excluding the top and bottom 20%% of the values) as the '
                                                                       'aggregate function.')
   parser.add_argument('-median', action='store_const', const='med', help='Selects the median as the aggregate function.')
   parser.add_argument('-min', action='store_const', const='min', help='Selects the minimum as the aggregate function.')
   parser.add_argument('-max', action='store_const', const='max', help='Selects the maximum as the aggregate function.')
   parser.add_argument('-range', action='store_true', help='Outputs the range of the measured values (i.e., the minimum and the maximum).')
   parser.add_argument('-no_mem', action='store_true', help='The code for reading the perf. ctrs. does not make memory accesses.')
   parser.add_argument('-remove_empty_events', action='store_true', help='Removes events from the output that did not occur.')
   parser.add_argument('-verbose', action='store_true', help='Outputs the results of all performance counter readings.')

   args = parser.parse_args()

   uArch = micro_arch(CPUID())
   detP23 = (uArch in ['SNB', 'IVB', 'HSW', 'BDW', 'SKL', 'SKX', 'CLX', 'KBL', 'CFL', 'CNL'])

   setNanoBenchParameters(basicMode=True, drainFrontend=True)
   setNanoBenchParameters(config=readFile(args.config),
                          unrollCount=args.unroll_count,
                          loopCount=args.loop_count,
                          nMeasurements=args.n_measurements,
                          warmUpCount=args.warm_up_count,
                          initialWarmUpCount=args.initial_warm_up_count,
                          alignmentOffset=args.alignment_offset,
                          aggregateFunction=(args.avg or args.median or args.min or args.max or 'med'),
                          range=args.range,
                          noMem=args.no_mem,
                          verbose=args.verbose,
                          endToEnd=args.end_to_end)

   nbDict = runNanoBenchCycleByCycle(code=args.asm, codeBinFile=args.code,
                                 init=args.asm_init, initBinFile=args.code_init,
                                 lateInit=args.asm_late_init, lateInitBinFile=args.code_late_init,
                                 oneTimeInit=args.asm_one_time_init, oneTimeInitBinFile=args.code_one_time_init,
                                 cpu=args.cpu, detP23=detP23)

   if nbDict is None:
      print('Error: nanoBench did not return a valid result.', file=sys.stderr)
      if not args.end_to_end:
         print('Try using the -end_to_end option.', file=sys.stderr)
      exit(1)

   if (uArch in ['TGL', 'RKL']) and (not args.end_to_end):
      # on TGL and RKL, the wrmsr instruction sometimes appears to need an extra cycle
      print('Note: If the results look incorrect, try using the -end_to_end option.', file=sys.stderr)

   if args.remove_empty_events:
      for k in list(nbDict.keys()):
         if max(nbDict[k][0]) == 0:
            del nbDict[k]

   if args.csv is not None:
      if args.range:
         csvString = '\n'.join(k + ',' + ','.join(map(str, sum(zip(v, vMin, vMax), ()))) for k, (v, vMin, vMax) in nbDict.items())
      else:
         csvString = '\n'.join(k + ',' + ','.join(map(str, v)) for k, (v, _, _) in nbDict.items())
      if args.csv:
         with open(args.csv, 'w') as f:
            f.write(csvString + '\n')
         os.chown(args.csv, int(os.environ['SUDO_UID']), int(os.environ['SUDO_GID']))
      else:
         print(csvString)

   if (args.html is not None) or (args.csv is None):
      from plotly.offline import plot
      import plotly.graph_objects as go

      fig = go.Figure()
      fig.update_xaxes(title_text='Cycle')

      for name, (values, minValues, maxValues) in nbDict.items():
         e = None
         if args.range:
            array = [(m-v) for (v, m) in zip(values, maxValues)]
            arrayminus = [(v-m) for (v, m) in zip(values, minValues)]
            e = dict(type='data', symmetric=False, array=array, arrayminus=arrayminus)
         fig.add_trace(go.Scatter(y=values, error_y=e, mode='lines+markers', line_shape='linear', name=name, marker_size=5, hoverlabel = dict(namelength = -1)))

      config = {'displayModeBar': True,
                'modeBarButtonsToRemove': ['autoScale2d', 'select2d', 'lasso2d'],
                'modeBarButtonsToAdd': ['toggleSpikelines', 'hoverclosest', 'hovercompare',
                                        {'name': 'Toggle interpolation mode', 'icon': 'iconJS', 'click': 'interpolationJS'}]}
      body = plot(fig, include_plotlyjs='cdn', output_type='div', config=config)

      body = body.replace('"iconJS"', 'Plotly.Icons.drawline')
      body = body.replace('"interpolationJS"', 'function (gd) {Plotly.restyle(gd, "line.shape", gd.data[0].line.shape == "hv" ? "linear" : "hv")}')

      cmdLine = ' '.join(('"'+p+'"' if ((' ' in p) or (';' in p)) else p) for p in sys.argv)
      body += '<p><code>sudo ' + cmdLine + '</code></p>'

      htmlFilename = args.html or 'graph.html'
      writeHtmlFile(htmlFilename, 'Graph', '', body, includeDOCTYPE=False) # if DOCTYPE is included, scaling doesn't work properly
      print('Output written to ' + htmlFilename)


if __name__ == "__main__":
   main()
