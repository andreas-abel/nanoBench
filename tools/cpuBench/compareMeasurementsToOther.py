#!/usr/bin/python
import xml.etree.ElementTree as ET
import argparse
import sys
from utils import *

def main():
   parser = argparse.ArgumentParser(description='Compare results')
   parser.add_argument("-input", help="Input XML file", default='result.xml')
   parser.add_argument("-arch", help="Consider only this architecture")
   parser.add_argument("-ignoreLockRep", help="Ignore Instructions with lock and rep prefixes", action='store_true')
   parser.add_argument("-verbose", help="Verbose mode", action='store_true')
   args = parser.parse_args()

   root = ET.parse(args.input)

   instrArchNodes = []
   for instrNode in root.iter('instruction'):
      if args.ignoreLockRep and ('LOCK_' in instrNode.attrib['iform'] or 'REP_' in instrNode.attrib['iform']): continue
      archNode =  instrNode.find('./architecture[@name="{}"]'.format(args.arch))
      if archNode is not None:
         instrArchNodes.append((instrNode, archNode))

   nPortsMeasurementOnly = 0
   nPortsOtherOnly = 0
   nPortsBoth = 0
   nPortsEq = 0
   nPortsDiff = 0

   nUopsMeasurementOnly = 0
   nUopsOtherOnly = 0
   nUopsBoth = 0
   nUopsEq = 0
   nUopsEqPortsEq = 0
   nUopsEqPortsDiff = 0
   nUopsDiff = 0

   nLatMeasurementOnly = 0
   nLatOtherOnly = 0
   nLatBoth = 0
   nLatUB = 0
   nLatUBCorrect = 0
   nLatUBExact = 0
   nLatUBClose = 0
   nLatUBIncorrect = 0
   nLatNoUB = 0
   nLatNoUBMaxEq = 0
   nLatNoUBMaxDiff = 0

   for instrNode, archNode in instrArchNodes:
      measurementNode = archNode.find('measurement')
      nonMeasurementNodes = archNode.findall('./IACA') + archNode.findall('doc')

      otherPorts = [v for m in nonMeasurementNodes for a,v in m.attrib.items() if a.startswith('ports')]
      mPorts = ([v for a, v in measurementNode.attrib.items() if a.startswith('ports')] if measurementNode is not None else [])

      portsEq = False
      portsDiff = False

      if mPorts:
         if otherPorts:
            nPortsBoth += 1
            if any(m in otherPorts for m in mPorts):
               portsEq = True
               nPortsEq += 1
            else:
               portsDiff = True
               nPortsDiff += 1
               if args.verbose: print 'PortsDiff: {} - {} - {}'.format(instrNode.attrib['string'], mPorts, otherPorts)
         else:
            nPortsMeasurementOnly += 1
      else:
         if otherPorts:
            nPortsOtherOnly += 1
            if args.verbose: print 'PortsOtherOnly: ' + instrNode.attrib['string']

      otherUops = [v for m in nonMeasurementNodes for a,v in m.attrib.items() if a.startswith('uops') and v.replace('.','',1).isdigit()]
      mUops = ([v for a,v in measurementNode.attrib.items() if a.startswith('uops') and not 'retire_slots' in a] if measurementNode is not None else [])

      if mUops:
         if otherUops:
            nUopsBoth += 1
            if any(m in otherUops for m in mUops):
               nUopsEq += 1
               nUopsEqPortsEq += int(portsEq)
               nUopsEqPortsDiff += int(portsDiff)
            else:
               nUopsDiff += 1
               if args.verbose: print 'UopsDiff: {} - {} - {}'.format(instrNode.attrib['string'], mUops, otherUops)
         else:
            nUopsMeasurementOnly += 1
      else:
         if otherUops:
            nUopsOtherOnly += 1
            if args.verbose: print 'UopsOtherOnly: ' + instrNode.attrib['string']


      otherLatencies = [float(v) for m in nonMeasurementNodes for a,v in m.attrib.items() if a.startswith('latency') and v.replace('.','',1).isdigit()]

      latEntry = getLatencyTableEntry(measurementNode)
      if latEntry is not None:
         if otherLatencies:
            nLatBoth += 1
            _, _, _, maxLat, maxLatUB = latEntry
            if maxLatUB:
               nLatUB += 1
               if any(x for x in otherLatencies if x <= maxLat):
                  nLatUBCorrect += 1
                  if maxLat in otherLatencies:
                     nLatUBExact += 1
                  diff = min(abs(float(maxLat)-float(o)) for o in otherLatencies)
                  if diff <= 1.01:
                     nLatUBClose += 1
               else:
                  nLatUBIncorrect += 1
                  if args.verbose: print 'LatUBIncorrect: {} - {} - {}'.format(instrNode.attrib['string'], maxLat, otherLatencies)
            else:
               nLatNoUB += 1
               if maxLat in otherLatencies:
                  nLatNoUBMaxEq += 1
               else:
                  nLatNoUBMaxDiff += 1
                  if args.verbose: print 'LatNoUBMaxDiff: {} - {} - {}'.format(instrNode.attrib['string'], maxLat, otherLatencies)
         else:
            nLatMeasurementOnly += 1
      else:
         if otherLatencies:
            nLatOtherOnly += 1
            if args.verbose: print 'LatOtherOnly: ' + instrNode.attrib['string']

   print 'Ports:'
   print '  Measurement data only: ' + str(nPortsMeasurementOnly)
   print '  Other data only: ' + str(nPortsOtherOnly)
   print '  Both: ' + str(nPortsBoth)
   print '    Eq: ' + str(nPortsEq)
   print '    Diff: ' + str(nPortsDiff)
   print ''

   print 'Uops:'
   print '  Measurement data only: ' + str(nUopsMeasurementOnly)
   print '  Other data only: ' + str(nUopsOtherOnly)
   print '  Both: ' + str(nUopsBoth)
   print '    Eq: ' + str(nUopsEq)
   print '      PortsEq: ' + str(nUopsEqPortsEq)
   print '      PortsDiff: ' + str(nUopsEqPortsDiff)
   print '    Diff: ' + str(nUopsDiff)
   print ''

   print 'Latency:'
   print '  Measurement data only: ' + str(nLatMeasurementOnly)
   print '  Other data only: ' + str(nLatOtherOnly)
   print '  Both: ' + str(nLatBoth)
   print '    Exact: ' + str(nLatNoUB)
   print '      Eq (Max): ' + str(nLatNoUBMaxEq)
   print '      Diff (Max): ' + str(nLatNoUBMaxDiff)
   print '    Upper Bound: ' + str(nLatUB)
   print '      Correct: ' + str(nLatUBCorrect)
   print '        Exact: ' + str(nLatUBExact)
   print '        Close: ' + str(nLatUBClose)
   print '      Incorrect: ' + str(nLatUBIncorrect)
   print ''

   print 'Throughput:'
   for TP_m, TP_o in [('TP', 'TP'), ('TP_ports', 'TP'), ('TP', 'TP_ports'), ('TP_ports', 'TP_ports')]:
      nTPMeasurementOnly = 0
      nTPOtherOnly = 0
      nTPBoth = 0
      nTPEq = 0
      nTPDiff = 0
      nTPClose = 0
      nTPNotClose = 0

      for instrNode, archNode in instrArchNodes:
         measurementNode = archNode.find('measurement')
         nonMeasurementNodes = archNode.findall('./IACA') + archNode.findall('doc')

         otherTPs = [float(v) for m in nonMeasurementNodes for a,v in m.attrib.items() if a in [TP_o, TP_o+'_same_reg'] and v.replace('.','',1).isdigit()]
         mTPs = ([float(v) for a, v in measurementNode.attrib.items() if a in [TP_m, TP_m+'_same_reg']] if measurementNode is not None else [])

         if mTPs:
            if otherTPs:
               nTPBoth += 1
               if any(m in otherTPs for m in mTPs):
                  nTPEq += 1
               else:
                  nTPDiff += 1
                  if args.verbose: print 'TPDiff ({} (measurements) - {} (other)): {} - {} - {}'.format(TP_m, TP_o, instrNode.attrib['string'], mTPs, otherTPs)
               diff = min(abs(float(m)-float(o)) for o in otherTPs for m in mTPs)
               if diff <= .1:
                  nTPClose += 1
               else:
                  nTPNotClose += 1
                  if args.verbose: print 'TPNotClose ({} (measurements) - {} (other)): {} - {} - {}'.format(TP_m, TP_o, instrNode.attrib['string'], mTPs, otherTPs)
            else:
               nTPMeasurementOnly += 1
         else:
            if otherTPs:
               nTPOtherOnly += 1
               if args.verbose: print 'TPOtherOnly ({} (measurements) - {} (other)): {}'.format(TP_m, TP_o, instrNode.attrib['string'])

      print '  {} (measurements) - {} (other):'.format(TP_m, TP_o)
      print '    Measurement data only: ' + str(nTPMeasurementOnly)
      print '    Other data only: ' + str(nTPOtherOnly)
      print '    Both: ' + str(nTPBoth)
      print '      Eq: ' + str(nTPEq)
      print '      Diff: ' + str(nTPDiff)
      print '      Close: ' + str(nTPClose)
      print '      NotClose: ' + str(nTPNotClose)

if __name__ == "__main__":
    main()
