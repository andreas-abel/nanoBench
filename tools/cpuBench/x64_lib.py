import re
from collections import namedtuple

GPRegs = {'AH', 'AL', 'AX', 'BH', 'BL', 'BP', 'BPL', 'BX', 'CH', 'CL', 'CX', 'DH', 'DI', 'DIL', 'DL', 'DX', 'EAX',
   'EBP', 'EBX', 'ECX', 'EDI', 'EDX', 'ESI', 'ESP', 'R10', 'R10B', 'R10D', 'R10W', 'R11', 'R11B', 'R11D', 'R11W', 'R12',
   'R12B', 'R12D', 'R12W', 'R13', 'R13B', 'R13D', 'R13W', 'R14', 'R14B', 'R14D', 'R14W', 'R15', 'R15B', 'R15D', 'R15W',
   'R8', 'R8B', 'R8D', 'R8W', 'R9', 'R9B', 'R9D', 'R9W', 'RAX', 'RBP', 'RBX', 'RCX', 'RDI', 'RDX', 'RSI', 'RSP', 'SI',
   'SIL', 'SP', 'SPL'}

High8Regs = {'AH', 'BH', 'CH', 'DH'}
Low8Regs = {'AL', 'BL', 'BPL', 'CL', 'DIL', 'DL', 'R10B', 'R11B', 'R12B', 'R13B', 'R14B', 'R15B', 'R8B', 'R9B', 'SIL', 'SPL'}

STATUSFLAGS = {'CF', 'PF', 'AF', 'ZF', 'SF', 'OF'}
STATUSFLAGS_noAF = {'CF', 'PF', 'ZF', 'SF', 'OF'}

def regTo64(reg):
   if 'AX' in reg or 'AH' in reg or 'AL' in reg: return 'RAX'
   if 'BX' in reg or 'BH' in reg or 'BL' in reg: return 'RBX'
   if 'CX' in reg or 'CH' in reg or 'CL' in reg: return 'RCX'
   if 'DX' in reg or 'DH' in reg or 'DL' in reg: return 'RDX'
   if 'SP' in reg: return 'RSP'
   if 'BP' in reg: return 'RBP'
   if 'SI' in reg: return 'RSI'
   if 'DI' in reg: return 'RDI'
   if '8' in reg: return 'R8'
   if '9' in reg: return 'R9'
   if '10' in reg: return 'R10'
   if '11' in reg: return 'R11'
   if '12' in reg: return 'R12'
   if '13' in reg: return 'R13'
   if '14' in reg: return 'R14'
   if '15' in reg: return 'R15'

def regTo32(reg):
   if 'AX' in reg or 'AH' in reg or 'AL' in reg: return 'EAX'
   if 'BX' in reg or 'BH' in reg or 'BL' in reg: return 'EBX'
   if 'CX' in reg or 'CH' in reg or 'CL' in reg: return 'ECX'
   if 'DX' in reg or 'DH' in reg or 'DL' in reg: return 'EDX'
   if 'SP' in reg: return 'ESP'
   if 'BP' in reg: return 'EBP'
   if 'SI' in reg: return 'ESI'
   if 'DI' in reg: return 'EDI'
   if '8' in reg: return 'R8D'
   if '9' in reg: return 'R9D'
   if '10' in reg: return 'R10D'
   if '11' in reg: return 'R11D'
   if '12' in reg: return 'R12D'
   if '13' in reg: return 'R13D'
   if '14' in reg: return 'R14D'
   if '15' in reg: return 'R15D'

def regTo16(reg):
   if 'AX' in reg or 'AH' in reg or 'AL' in reg: return 'AX'
   if 'BX' in reg or 'BH' in reg or 'BL' in reg: return 'BX'
   if 'CX' in reg or 'CH' in reg or 'CL' in reg: return 'CX'
   if 'DX' in reg or 'DH' in reg or 'DL' in reg: return 'DX'
   if 'SP' in reg: return 'SP'
   if 'BP' in reg: return 'BP'
   if 'SI' in reg: return 'SI'
   if 'DI' in reg: return 'DI'
   if '8' in reg: return 'R8W'
   if '9' in reg: return 'R9W'
   if '10' in reg: return 'R10W'
   if '11' in reg: return 'R11W'
   if '12' in reg: return 'R12W'
   if '13' in reg: return 'R13W'
   if '14' in reg: return 'R14W'
   if '15' in reg: return 'R15W'

def regTo8(reg):
   if 'AX' in reg or 'AH' in reg or 'AL' in reg: return 'AL'
   if 'BX' in reg or 'BH' in reg or 'BL' in reg: return 'BL'
   if 'CX' in reg or 'CH' in reg or 'CL' in reg: return 'CL'
   if 'DX' in reg or 'DH' in reg or 'DL' in reg: return 'DL'
   if 'SP' in reg: return 'SPL'
   if 'BP' in reg: return 'BPL'
   if 'SI' in reg: return 'SIL'
   if 'DI' in reg: return 'DIL'
   if '8' in reg: return 'R8B'
   if '9' in reg: return 'R9B'
   if '10' in reg: return 'R10B'
   if '11' in reg: return 'R11B'
   if '12' in reg: return 'R12B'
   if '13' in reg: return 'R13B'
   if '14' in reg: return 'R14B'
   if '15' in reg: return 'R15B'

def regToSize(reg, size):
   if size == 8: return regTo8(reg)
   elif size == 16: return regTo16(reg)
   elif size == 32: return regTo32(reg)
   else: return regTo64(reg)

# Returns for a GPR the corresponding 64-bit registers, and for a (X|Y|Z)MM register the corresponding XMM register
def getCanonicalReg(reg):
   if reg in GPRegs:
      return regTo64(reg)
   elif 'MM' in reg:
      return re.sub('^[YZ]', 'X', reg)
   else:
      return reg

def getRegForMemPrefix(reg, memPrefix):
   return regToSize(reg, getSizeOfMemPrefix(memPrefix))

def getSizeOfMemPrefix(memPrefix):
   if 'zmmword' in memPrefix: return 512
   elif 'ymmword' in memPrefix: return 256
   elif 'xmmword' in memPrefix: return 128
   elif 'qword' in memPrefix: return 64
   elif 'dword' in memPrefix: return 32
   elif 'word' in memPrefix: return 16
   elif 'byte' in memPrefix: return 8
   else: return -1

def getRegSize(reg):
   if reg[-1] == 'L' or reg[-1] == 'H' or reg[-1] == 'B': return 8
   elif reg[-1] == 'W' or reg in ['AX', 'BX', 'CX', 'DX', 'SP', 'BP' 'SI', 'DI']: return 16
   elif reg[0] == 'E' or reg[-1] == 'D': return 32
   elif reg in GPRegs: return 64
   elif reg.startswith('MM'): return 64
   elif reg.startswith('XMM'): return 128
   elif reg.startswith('YMM'): return 256
   elif reg.startswith('ZMM'): return 512
   else: return -1

MemAddr = namedtuple('MemAddr', ['base', 'index', 'scale', 'displacement'])
def getMemAddr(memAddrAsm):
   base = index = None
   displacement = 0
   scale = 1
   for c in re.split(r'\+|-', re.search(r'\[(.*)\]', memAddrAsm).group(1)):
      if '0x' in c:
         displacement = int(c, 0)
         if '-0x' in memAddrAsm:
            displacement = -displacement
      elif '*' in c:
         index, scale = c.split('*')
         scale = int(scale)
      else:
         base = c
   return MemAddr(base, index, scale, displacement)