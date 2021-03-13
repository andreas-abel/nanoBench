#!/usr/bin/env python3

import xml.etree.ElementTree as ET
from xml.dom import minidom
import argparse
import datetime

# If inp2 contains a measurement node for an architecture for which inp1 does not contain a measurement node, the node is added to a copy of inp1.
def main():
   parser = argparse.ArgumentParser(description='Merge XML files')
   parser.add_argument('inp1')
   parser.add_argument('inp2')
   parser.add_argument('outp')
   args = parser.parse_args()

   root1 = ET.parse(args.inp1).getroot()
   root2 = ET.parse(args.inp2).getroot()
   instrNode2Dict = {instrNode.attrib['string']: instrNode for instrNode in root2.iter('instruction')}

   root1.attrib['date'] = str(datetime.date.today())

   for instrNode1 in root1.iter('instruction'):
      if instrNode1.attrib['string'] not in instrNode2Dict:
         print('no matching entry found for ' + instrNode1.attrib['string'])
         continue
      for instrNode2 in instrNode2Dict[instrNode1.attrib['string']]:
         for archNode2 in instrNode2.iter('architecture'):
            archNode1 = instrNode1.find('./architecture[@name="' + archNode2.attrib['name'] + '"]')
            if archNode1 is not None:
               if archNode1.findall('./measurement'): continue
               for measurementNode in archNode2.findall('./measurement'):
                  archNode1.append(measurementNode)
            else:
               instrNode1.append(archNode2)

   with open(args.outp, "w") as f:
      rough_string = ET.tostring(root1, 'utf-8')
      reparsed = minidom.parseString(rough_string)
      f.write('\n'.join([line for line in reparsed.toprettyxml(indent=' '*2).split('\n') if line.strip()]))


if __name__ == "__main__":
    main()
