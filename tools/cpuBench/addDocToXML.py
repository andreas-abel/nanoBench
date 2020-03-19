#!/usr/bin/python
from collections import namedtuple
import xml.etree.ElementTree as ET
from xml.dom import minidom
import argparse

DocEntry = namedtuple('DocEntry', ['iform', 'regsize', 'mask', 'tp', 'lat'])

def main():
   parser = argparse.ArgumentParser(description="Add data to XML file from Intel's CSV doc")
   parser.add_argument('-xml')
   parser.add_argument('-csv')
   parser.add_argument('-outputXML')
   parser.add_argument('-arch')
   args = parser.parse_args()

   docDict = dict()

   with open(args.csv, 'r') as f:
      for i, line in enumerate(f):
         if i > 0:
            de = DocEntry(*line.strip().split(','))
            docDict.setdefault(de.iform, []).append(de)

   root = ET.parse(args.xml).getroot()


   for instrNode in root.iter('instruction'):
      iform = instrNode.attrib['iform']

      if iform in docDict:
         matchingDEs = set(docDict[iform])

         if len(matchingDEs) > 1:
            for de in list(matchingDEs):
               if de.regsize != '-':
                  if not instrNode.findall('./operand[@type="reg"][@width="{}"]'.format(de.regsize)):
                     matchingDEs.remove(de)

         for de in list(matchingDEs):
            if 'mask' in instrNode.attrib:
               if (instrNode.attrib['mask'] == '1' and de.mask == 'no') or (instrNode.attrib['mask'] == '0' and de.mask == 'yes'):
                  matchingDEs.remove(de)

         if len(matchingDEs) == 0:
            print 'No matching iform: ' + iform
         elif len(matchingDEs) > 1:
            print 'Multiple matching iforms: ' + iform
         else:
            de = next(iter(matchingDEs))

            archNode = instrNode.find('./architecture[@name="{}"]'.format(args.arch))
            if archNode is None:
               archNode = ET.SubElement(instrNode, "architecture")
               archNode.attrib['name'] = args.arch

            docNode = ET.SubElement(archNode, "doc")
            if de.tp: docNode.attrib['TP'] = de.tp
            if de.lat: docNode.attrib['latency'] = de.lat

   with open(args.outputXML, "w") as f:
      rough_string = ET.tostring(root, 'utf-8')
      reparsed = minidom.parseString(rough_string)
      f.write('\n'.join([line for line in reparsed.toprettyxml(indent=' '*2).split('\n') if line.strip()]))


if __name__ == "__main__":
    main()
