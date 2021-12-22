#!/usr/bin/python
from sys import maxsize
import xml.etree.ElementTree as ET
import argparse
from utils import *

def getLink(instrNode, text, arch, tool, linkType, anchor=None):
   url = '/tmp/html-' + linkType + '/' + arch + '/' + canonicalizeInstrString(instrNode.attrib['string']) + '-' + tool + '.html'
   if anchor: url += '#' + anchor
   return '<a href="' + url + '">' + text + '</a>'

def main():
   parser = argparse.ArgumentParser(description='Generates a basic HTML table with the results for a microarchitecture')
   parser.add_argument("-input", help="Input XML file", default='result.xml')
   parser.add_argument("-arch", help="Consider only this architecture")
   args = parser.parse_args()

   root = ET.parse(args.input)

   TPSame = 0
   TPDiff = 0

   with open('instructions.html', "w") as f:
      f.write('<html>\n'
              '<head>\n'
              '<title>Instructions</title>\n'
              '<style>\n'
              'table, th, td {\n'
              '  font-size: 14px;\n'
              '  border: 1px solid black;\n'
              '  border-collapse: collapse;\n'
              '}\n'
              'th, td {\n'
              '  padding: 4px;\n'
              '}\n'
              'th {\n'
              '  text-align: left;\n'
              '}\n'
              '</style>\n'
              '<head>\n'
              '<body>\n')

      for XMLExtension in root.iter('extension'):
         if not XMLExtension.findall('.//measurement'):
            continue

         f.write('<h3>' + XMLExtension.attrib['name'] + '</h3>\n'
                 '<table>\n'
                 '  <tr>\n'
                 '    <th></th>\n'
                 '    <th>Lat</th>\n'
                 '    <th>TP (ports)</th>\n'
                 '    <th>TP (m)</th>\n'
                 '    <th>uops</th>\n'
                 '    <th>Ports</th>\n'
                 '  </tr>\n')

         for XMLInstr in sorted(XMLExtension.findall('./instruction'), key=lambda x: x.attrib['string']):
            for resultNode in XMLInstr.findall('./architecture[@name="' + args.arch + '"]/measurement'):
               f.write('  <tr>\n')
               f.write('    <th>' + XMLInstr.attrib['string'] + '</th>\n')

               lat = ''
               latTableEntry = getLatencyTableEntry(resultNode)
               if latTableEntry is not None:
                  lat = str(latTableEntry[0])
               f.write('    <td align="right">' + getLink(XMLInstr, lat, args.arch, 'Measurements', 'lat') + '</td>\n')

               TPPorts = float(resultNode.attrib.get('TP_ports', float("inf")))
               TPPortsStr = ("{:.2f}".format(TPPorts) if TPPorts < float("inf") else '')
               f.write('    <td align="right">' + TPPortsStr + '</td>\n')

               TPMeasured = min(float(resultNode.attrib.get('TP_loop', float("inf"))), float(resultNode.attrib.get('TP_unrolled', float("inf"))))
               TPMeasuredStr = ("{:.2f}".format(TPMeasured) if TPMeasured < float("inf") else '')

               uopsMS = int(resultNode.attrib.get('uops_MS', sys.maxsize))

               color = ''
               if TPPortsStr and TPMeasuredStr and (uopsMS == 0):
                  if abs(TPMeasured - TPPorts) < .02:
                     color = ' bgcolor="green"'
                     TPSame += 1
                  else:
                     color = ' bgcolor="orange"'
                     TPDiff += 1

               f.write('    <td align="right"' + color + '>' + getLink(XMLInstr, TPMeasuredStr, args.arch, 'Measurements', 'tp')  + '</td>\n')

               f.write('    <td align="right">' + resultNode.attrib.get('uops', '') + '</td>\n')
               f.write('    <td>' + getLink(XMLInstr, resultNode.attrib.get('ports', ''), args.arch, 'Measurements', 'ports') + '</td>\n')
               f.write('  <tr>\n')

         f.write('</table>\n')

      f.write('</body>\n')
      f.write('</html>\n')

   print('TPSame: ' + str(TPSame))
   print('TPDiff: ' + str(TPDiff))
   print('Result written to instructions.html')

if __name__ == "__main__":
    main()
