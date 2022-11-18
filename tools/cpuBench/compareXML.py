#!/usr/bin/env python3

import xml.etree.ElementTree as ET
from xml.dom import minidom
import argparse
import sys

# Shows the differences between two XML files for a specific microarchitecture
def main():
   parser = argparse.ArgumentParser(description='Compare XML files')
   parser.add_argument('inp1')
   parser.add_argument('arch1')
   parser.add_argument('inp2')
   parser.add_argument('arch2')
   parser.add_argument('-TP', action='store_true')
   parser.add_argument('-lat', action='store_true')
   parser.add_argument('-ports', action='store_true')
   args = parser.parse_args()

   root1 = ET.parse(args.inp1).getroot()
   root2 = ET.parse(args.inp2).getroot()

   instrNodeDict1 = {instrNode.attrib['string']: instrNode for instrNode in root1.iter('instruction')}
   instrNodeDict2 = {instrNode.attrib['string']: instrNode for instrNode in root2.iter('instruction')}

   tpDiff = 0
   latDiff = 0
   portsDiff = 0

   for instrStr in sorted(instrNodeDict1):
      instrNode1 = instrNodeDict1[instrStr]
      if not instrStr in instrNodeDict2:
         print('No matching entry found for ' + instrStr)
         continue
      instrNode2 = instrNodeDict2[instrStr]
      for mNode1 in instrNode1.findall('./architecture[@name="' + args.arch1 + '"]/measurement'):
         for mNode2 in instrNode2.findall('./architecture[@name="' + args.arch2 + '"]/measurement'):
            if args.TP:
               tp1 = min(map(float, [mNode1.attrib.get('TP_unrolled', sys.maxsize), mNode1.attrib.get('TP_loop', sys.maxsize), mNode1.attrib.get('TP', sys.maxsize)]))
               tp2 = min(map(float, [mNode2.attrib.get('TP_unrolled', sys.maxsize), mNode2.attrib.get('TP_loop', sys.maxsize), mNode2.attrib.get('TP', sys.maxsize)]))

               if tp1 != tp2:
                  tpDiff += 1
                  print(instrStr + ' - TP1: ' + str(tp1) + ' - TP2: ' + str(tp2))

            if args.lat:
               for latNode1, latNode2 in zip(mNode1.findall('./latency'), mNode2.findall('./latency')):
                  latStr1 = ET.tostring(latNode1, encoding='utf-8').decode().strip()
                  latStr2 = ET.tostring(latNode2, encoding='utf-8').decode().strip()
                  if latNode1.attrib != latNode2.attrib:
                     latDiff += 1
                     print(instrStr)
                     print('  ' + latStr1)
                     print('  ' + latStr2)

            if args.ports:
               p1 = mNode1.attrib.get('ports', '')
               p2 = mNode2.attrib.get('ports', '')
               if p1 != p2:
                  portsDiff += 1
                  print(instrStr + ' - P1: ' + p1 + ' - P2: ' + p2)

            if not args.TP and not args.lat and not args.ports:
               xmlStr1 = ET.tostring(mNode1, encoding='utf-8').decode().strip()
               xmlStr2 = ET.tostring(mNode2, encoding='utf-8').decode().strip()

               if xmlStr1 != xmlStr2:
                  print('-------------------------------')
                  print(instrStr)
                  print(xmlStr1)
                  print(xmlStr2)
                  print('-------------------------------')

   if args.TP:
      print('TPDiff: ' + str(tpDiff))

   if args.lat:
      print('LatDiff: ' + str(latDiff))

   if args.ports:
      print('portsDiff: ' + str(portsDiff))

if __name__ == "__main__":
    main()
