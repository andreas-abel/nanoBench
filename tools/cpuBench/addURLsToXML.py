#!/usr/bin/env python3

import xml.etree.ElementTree as ET
import argparse
import re
import urllib.request
from xml.dom import minidom
from utils import *

def main():
   parser = argparse.ArgumentParser(description='')
   parser.add_argument("input", help="Input XML file")
   parser.add_argument("output", help="Output XML file")
   args = parser.parse_args()

   html = urllib.request.urlopen('https://www.felixcloutier.com/x86/').read().decode('utf-8').replace(u'\u2013', '-').replace(u'\u2217', '*')
   lines = re.findall('href="\./(.*?)">(.*?)</a>.*?</td><td>(.*?)</td>', html) # Example: ('ADC.html', 'ADC', 'Add with Carry'),
   lineDict = {(line[0],line[1]):line for line in lines}

   root = ET.parse(args.input).getroot()
   for instrNode in root.iter('instruction'):
      iclass = instrNode.attrib['iclass']
      iform = instrNode.attrib['iform']
      extension = instrNode.attrib['extension']

      if extension in ['CET', 'MONITORX', 'SSE4a', 'SVM', 'TBM', 'TSX_LDTRK', 'XOP']:
         continue

      matchingLines = []
      if iclass == 'INT':
         matchingLines = [lineDict[('INTn:INTO:INT3:INT1.html', 'INT n')]]
      if iclass == 'MOV':
         matchingLines = [lineDict[('MOV.html', 'MOV')]]
      elif iclass == 'MOV_CR':
         matchingLines = [lineDict[('MOV-1.html', 'MOV')]]
      elif iclass == 'MOV_DR':
         matchingLines = [lineDict[('MOV-2.html', 'MOV')]]
      elif iclass == 'VMRESUME':
         matchingLines = [lineDict[('VMLAUNCH:VMRESUME.html', 'VMRESUME')]]
      elif iclass == 'SCASQ':
         matchingLines = [lineDict[('SCAS:SCASB:SCASW:SCASD.html', 'SCAS')]]
      elif iclass == 'UD2':
         matchingLines = [lineDict[('UD.html', 'UD')]]
      elif iclass in ['CMPSD', 'VCMPSD', 'CMPSD_XMM']:
         if extension == 'BASE':
            matchingLines = [lineDict[('CMPS:CMPSB:CMPSW:CMPSD:CMPSQ.html', 'CMPSD')]]
         else:
            matchingLines = [lineDict[('CMPSD.html', 'CMPSD')]]
      elif iclass in ['IRETW', 'IRETD', 'IRETQ']:
         matchingLines = [lineDict[('IRET:IRETD:IRETQ.html', 'IRET')]]
      elif iclass in ['MOVQ', 'VMOVQ']:
         if 'GPR' in iform:
            matchingLines = [lineDict[('MOVD:MOVQ.html', 'MOVQ')]]
         else:
            matchingLines = [lineDict[('MOVQ.html', 'MOVQ')]]
      elif iclass in ['MOVSD', 'VMOVSD', 'MOVSD_XMM']:
         if extension == 'BASE':
            matchingLines = [lineDict[('MOVS:MOVSB:MOVSW:MOVSD:MOVSQ.html', 'MOVSD')]]
         else:
            matchingLines = [lineDict[('MOVSD.html', 'MOVSD')]]
      elif iclass == 'VGATHERDPD':
         if '512' in extension:
            matchingLines = [lineDict[('VGATHERDPS:VGATHERDPD.html', 'VGATHERDPD')]]
         else:
            matchingLines = [lineDict[('VGATHERDPD:VGATHERQPD.html', 'VGATHERDPD')]]
      elif iclass == 'VGATHERDPS':
         if '512' in extension:
            matchingLines = [lineDict[('VGATHERDPS:VGATHERDPD.html', 'VGATHERDPS')]]
         else:
            matchingLines = [lineDict[('VGATHERDPS:VGATHERQPS.html', 'VGATHERDPS')]]
      elif iclass == 'VGATHERQPD':
         if '512' in extension:
            matchingLines = [lineDict[('VGATHERQPS:VGATHERQPD.html', 'VGATHERQPD')]]
         else:
            matchingLines = [lineDict[('VGATHERDPD:VGATHERQPD.html', 'VGATHERQPD')]]
      elif iclass == 'VGATHERQPS':
         if '512' in extension:
            matchingLines = [lineDict[('VGATHERQPS:VGATHERQPD.html', 'VGATHERQPS')]]
         else:
            matchingLines = [lineDict[('VGATHERDPS:VGATHERQPS.html', 'VGATHERQPS')]]
      elif iclass == 'VPGATHERDD':
         if '512' in extension:
            matchingLines = [lineDict[('VPGATHERDD:VPGATHERDQ.html', 'VPGATHERDD')]]
         else:
            matchingLines = [lineDict[('VPGATHERDD:VPGATHERQD.html', 'VPGATHERDD')]]
      elif iclass == 'VPGATHERDQ':
         if '512' in extension:
            matchingLines = [lineDict[('VPGATHERDD:VPGATHERDQ.html', 'VPGATHERDQ')]]
         else:
            matchingLines = [lineDict[('VPGATHERDQ:VPGATHERQQ.html', 'VPGATHERDQ')]]
      elif iclass == 'VPGATHERQD':
         if '512' in extension:
            matchingLines = [lineDict[('VPGATHERQD:VPGATHERQQ.html', 'VPGATHERQD')]]
         else:
            matchingLines = [lineDict[('VPGATHERDD:VPGATHERQD.html', 'VPGATHERQD')]]
      elif iclass == 'VPGATHERQQ':
         if '512' in extension:
            matchingLines = [lineDict[('VPGATHERQD:VPGATHERQQ.html', 'VPGATHERQQ')]]
         else:
            matchingLines = [lineDict[('VPGATHERDQ:VPGATHERQQ.html', 'VPGATHERQQ')]]
      elif iclass.startswith('PMOVSX') or iclass.startswith('VPMOVSX'):
         matchingLines = [lineDict[('PMOVSX.html', 'PMOVSX')]]
      elif iclass.startswith('PMOVZX') or iclass.startswith('VPMOVZX'):
         matchingLines = [lineDict[('PMOVZX.html', 'PMOVZX')]]
      elif iclass.startswith('REP'):
         matchingLines = [lineDict[('REP:REPE:REPZ:REPNE:REPNZ.html', 'REP')]]
      elif iclass.startswith('VBROADCAST'):
         matchingLines = [lineDict[('VBROADCAST.html', 'VBROADCAST')]]
      elif iclass.startswith('VMASKMOV'):
         matchingLines = [lineDict[('VMASKMOV.html', 'VMASKMOV')]]
      elif iclass.startswith('VPANDN'):
         matchingLines = [lineDict[('PANDN.html', 'PANDN')]]
      elif iclass.startswith('VPAND'):
         matchingLines = [lineDict[('PAND.html', 'PAND')]]
      elif iclass.startswith('VPBROADCASTM'):
         matchingLines = [lineDict[('VPBROADCASTM.html', 'VPBROADCASTM')]]
      elif iclass.startswith('VPMASKMOV'):
         matchingLines = [lineDict[('VPMASKMOV.html', 'VPMASKMOV')]]
      elif iclass.startswith('VPOR'):
         matchingLines = [lineDict[('POR.html', 'POR')]]
      elif iclass.startswith('VPXOR'):
         matchingLines = [lineDict[('PXOR.html', 'PXOR')]]
      else:
         for line in lines:
            mnemonic = line[1].upper()
            if iclass in [mnemonic, 'V'+mnemonic, mnemonic+'_LOCK', mnemonic+'_FAR', mnemonic+'_NEAR', mnemonic+'_SSE4', mnemonic+'64']:
               matchingLines.append(line)
            if 'CC' in mnemonic and iclass.startswith(mnemonic.replace('CC', '')) and not iclass in ['JMP', 'JMP_FAR', 'LOOP']:
               matchingLines.append(line)

      if len(matchingLines) > 1:
         print('Duplicate link found for ' + iclass)
         exit(1)

      instrNode.attrib['url'] = 'uops.info/html-instr/' + canonicalizeInstrString(instrNode.attrib['string']) + '.html'
      if matchingLines:
         instrNode.attrib['summary'] = str(matchingLines[0][2])
         instrNode.attrib['url-ref'] = 'felixcloutier.com/x86/' + matchingLines[0][0]

   with open(args.output, "w") as f:
      rough_string = ET.tostring(root, 'utf-8')
      reparsed = minidom.parseString(rough_string)
      f.write('\n'.join([line for line in reparsed.toprettyxml(indent=' '*2).split('\n') if line.strip()]))


if __name__ == "__main__":
    main()
