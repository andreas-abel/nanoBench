import re
import sys
from scipy.optimize import linprog

def addHTMLCodeForOperands(instrNode, html):
   if instrNode.find('operand') is not None:
      html.append('<h2>Operands</h2>')
      html.append('<ul>')
      for opNode in instrNode.iter('operand'):
         line = 'Operand ' + opNode.attrib['idx']
         properties = []
         for prop in ['r', 'w']:
            if opNode.attrib.get(prop, '0') == '1': properties.append(prop)
         if properties: properties = ['/'.join(properties)]
         if opNode.attrib.get('undef', '0') == '1': properties.append('undefined')
         if opNode.attrib.get('suppressed', '0') == '1': properties.append('suppressed')
         if opNode.attrib.get('optional', '0') == '1': properties.append('optional')
         line += ' (' + ', '.join(properties) + '): '
         if opNode.attrib['type'] == 'reg':
            line += 'Register (' + opNode.text.replace(',', ', ') + ')'
         elif opNode.attrib['type'] == 'mem':
            line += 'Memory'
            if 'asm-prefix' in opNode.attrib: line.append(' (' + opNode.attrib['asm-prefix'] + ')')
         elif opNode.attrib['type'] == 'flags':
            line += 'Flags ('
            first = True
            for k, v in opNode.attrib.items():
               if k.startswith('flag_'):
                  if not first: line += ', '
                  line += k[5:] + ': ' + v
                  first = False
            line += ')'
         elif opNode.attrib['type'] == 'imm':
            line += opNode.attrib['width'] + '-bit immediate'
            if opNode.attrib.get('implicit', '') == '1':
               line += ' (implicit): ' + opNode.text
         html.append('<li>' + line + '</li>')
      html.append('</ul>')

def canonicalizeInstrString(instrString):
   return re.sub('[(){}, ]+', '_', instrString).strip('_')

def getTP_LP(PU):
   if len(PU) == 0:
      return 0

   if len(PU) == 1:
      pc, uops = PU[0]
      return round(float(uops)/len(pc), 2)

   ports = list(set.union(*[set(pc) for pc, _ in PU]))

   zeroConstraint = []
   for p in ports:
      for pc, uops in PU:
         if not p in pc:
            zeroConstraint.append(1)
         else:
            zeroConstraint.append(0)
   zeroConstraint.append(0) #z

   nonZeroConstraints = []
   nonZeroConstraintsRHS = []
   for pu in PU:
      pc, uops = pu
      nonZeroConstraintsRHS.append(uops)
      nonZeroConstraint = []
      for p in ports:
         for pu2 in PU:
            if pu != pu2 or p not in pc:
               nonZeroConstraint.append(0)
            else:
               nonZeroConstraint.append(1)
      nonZeroConstraint.append(0) #z
      nonZeroConstraints.append(nonZeroConstraint)

   A_eq = [zeroConstraint] + nonZeroConstraints
   b_eq = [0] + nonZeroConstraintsRHS

   zConstraints = []
   for p in ports:
      zConstraint = []
      for p2 in ports:
         for pu in PU:
            if p != p2:
               zConstraint.append(0)
            else:
               zConstraint.append(1)
      zConstraint.append(-1)
      zConstraints.append(zConstraint)

   A_ub = zConstraints
   b_ub = [0] * len(zConstraints)

   c = [0]*(len(PU)*len(ports)) + [1]

   res = linprog(c, A_ub=A_ub, b_ub=b_ub, A_eq=A_eq, b_eq=b_eq)
   return round(res.fun, 2)


# Example output: "Latency operand 2 -> 1 (memory): <=3"
def latencyNodeToStr(latNode, sameReg, addr_mem):
   suffix = ('_'+addr_mem if addr_mem else '') + ('_same_reg' if sameReg else '')
   if not any((a in ['cycles'+suffix, 'min_cycles'+suffix]) for a in latNode.attrib):
      return None

   ret = 'Latency operand ' + latNode.attrib['start_op'] + ' &rarr; ' + latNode.attrib['target_op']
   if sameReg:
      ret += ', with the same register for different operands'
   if addr_mem == 'addr':
      ret += ' (address, base register)'
   elif addr_mem == 'addr_VSIB':
      ret += ' (address, index register)'
   elif addr_mem == 'mem':
      ret += ' (memory)'
   ret += ': '

   if 'cycles'+suffix in latNode.attrib:
      if latNode.attrib.get('cycles'+suffix+'_is_upper_bound', '') == '1':
         ret += '&le;'
      cycles = latNode.attrib['cycles'+suffix]
      ret += cycles
   else:
      minCycles = latNode.attrib['min_cycles'+suffix]
      maxCycles = latNode.attrib['max_cycles'+suffix]

      if latNode.attrib.get('min_cycles'+suffix+'_is_upper_bound', '') == '1':
         ret += '&le;' + minCycles
      else:
         ret += minCycles + ' &le; lat &le; ' + maxCycles

   return ret

# Returns (string, minLat, minLatUB, maxLat, maxLatUB)
# Example output: ("[1;<=7]", 1, False, 7, True)
def getLatencyTableEntry(measurementNode):
   if measurementNode is None or measurementNode.find('./latency') is None:
      return None

   minLat = sys.maxint
   maxLat = 0
   minLatUB = False
   maxLatUB = False

   for latNode in measurementNode.findall('./latency'):
      for sameReg in [False, True]:
         for addr_mem in ['', 'addr', 'mem']:
            suffix = ('_'+addr_mem if addr_mem else '') + ('_same_reg' if sameReg else '')
            if 'cycles'+suffix in latNode.attrib:
               cycles = int(latNode.attrib['cycles'+suffix])
               isUB = (latNode.attrib.get('cycles'+suffix+'_is_upper_bound', '') == '1')

               if cycles == maxLat:
                  maxLatUB = (maxLatUB and isUB)
               elif cycles > maxLat:
                  maxLat = cycles
                  maxLatUB = isUB

               if cycles == minLat:
                 minLatUB = (minLatUB or isUB)
               elif cycles < minLat:
                  minLat = cycles
                  minLatUB = isUB

            if 'max_cycles'+suffix in latNode.attrib:
               cycles = int(latNode.attrib['max_cycles'+suffix])
               isUB = (latNode.attrib.get('max_cycles'+suffix+'_is_upper_bound', '') == '1')
               if cycles == maxLat:
                  maxLatUB = (maxLatUB and isUB)
               elif cycles > maxLat:
                  maxLat = cycles
                  maxLatUB = isUB

            if 'min_cycles'+suffix in latNode.attrib:
               cycles = float(latNode.attrib['min_cycles'+suffix])
               isUB = (latNode.attrib.get('min_cycles'+suffix+'_is_upper_bound', '') == '1')
               if cycles == minLat:
                 minLatUB = (minLatUB or isUB)
               elif cycles < minLat:
                  minLat = cycles
                  minLatUB = isUB

   if minLat == maxLat:
      latStr = str(maxLat)
      if minLatUB or maxLatUB:
         latStr = '&le;' + latStr
   else:
      latStr = '['
      if minLatUB:
         latStr += '&le;'
      latStr += str(minLat)
      latStr += ';'
      if maxLatUB:
         latStr += '&le;'
      latStr += str(maxLat)
      latStr += ']'

   return (latStr, minLat, minLatUB, maxLat, maxLatUB)
