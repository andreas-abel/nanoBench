#!/usr/bin/python
import random

from itertools import count
from numpy import median

from cacheLib import *

import logging
log = logging.getLogger(__name__)


def rindex(lst, value):
   return len(lst) - lst[::-1].index(value) - 1


class ReplPolicySim(object):
   def __init__(self, assoc):
      self.assoc = assoc
      self.blocks = [None] * assoc

   def acc(self, block):
      raise NotImplementedError()

   def flush(self, block):
      if block in self.blocks:
         self.blocks[self.blocks.index(block)] = None


class FIFOSim(ReplPolicySim):
   def __init__(self, assoc):
      super(FIFOSim, self).__init__(assoc)

   def acc(self, block):
      hit = block in self.blocks
      if not hit:
         self.blocks = [block] + self.blocks[0:self.assoc-1]
      return hit


class LRUSim(ReplPolicySim):
   def __init__(self, assoc):
      super(LRUSim, self).__init__(assoc)

   def acc(self, block):
      hit = block in self.blocks
      self.blocks = [block] + [b for b in self.blocks if b!=block][0:self.assoc-1]
      return hit


class PLRUSim(ReplPolicySim):
   def __init__(self, assoc, linearInit=False, randLeaf=False, randRoot=False):
      super(PLRUSim, self).__init__(assoc)
      self.linearInit = linearInit
      self.randLeaf = randLeaf
      self.randRoot = randRoot
      self.bits = [[0 for _ in range(0, 2**(level))] for level in range(0, int(math.ceil(math.log(assoc,2))))]

   def acc(self, block):
      hit = block in self.blocks
      if hit:
         self.updateIndexBits(self.blocks.index(block))
      else:
         if self.linearInit and None in self.blocks:
            idx = self.blocks.index(None)
         else:
            idx = self.getIndexForBits()
         self.blocks[idx] = block
         self.updateIndexBits(idx)
      return hit

   def getIndexForBits(self, level=0, idx = 0):
      if level == len(self.bits) - 1:
         ret = 2*idx
         if self.randLeaf:
            ret += random.randint(0,1)
         else:
            ret += self.bits[level][idx]
         return min(self.assoc - 1, ret)
      elif level == 0 and self.randRoot:
         return self.getIndexForBits(level + 2, random.randint(0,2))
      else:
         return self.getIndexForBits(level + 1, 2*idx + self.bits[level][idx])

   def updateIndexBits(self, accIndex):
      lastIdx = accIndex
      for level in reversed(range(0, len(self.bits))):
         curIdx = lastIdx/2
         self.bits[level][curIdx] = 1 - (lastIdx % 2)
         lastIdx = curIdx


class PLRUlSim(PLRUSim):
   def __init__(self, assoc):
      super(PLRUlSim, self).__init__(assoc, linearInit=True)


class PLRURandSim(PLRUSim):
   def __init__(self, assoc):
      super(PLRURandSim, self).__init__(assoc, randLeaf=True)

class RandPLRUSim(PLRUSim):
   def __init__(self, assoc):
      super(RandPLRUSim, self).__init__(assoc, randRoot=True)


AllRandPLRUVariants = {
   'RandPLRU': RandPLRUSim,
   'PLRURand': PLRURandSim,
}

class QLRUSim(ReplPolicySim):
   def __init__(self, assoc, hitFunc, missFunc, replIdxFunc, updFunc, updOnMissOnly=False):
      super(QLRUSim, self).__init__(assoc)
      self.hitFunc = hitFunc
      self.missFunc = missFunc
      self.replIdxFunc = replIdxFunc
      self.updFunc = updFunc
      self.updOnMissOnly = updOnMissOnly
      self.bits = [3] * assoc

   def acc(self, block):
      hit = block in self.blocks

      if hit:
         index = self.blocks.index(block)
         self.bits[index] = self.hitFunc(self.bits[index])
      else:
         if self.updOnMissOnly:
            self.bits = self.updFunc(self.bits, -1)

         index = self.replIdxFunc(self.bits, self.blocks)
         self.blocks[index] = block
         self.bits[index] = self.missFunc()

      if not self.updOnMissOnly:
         self.bits = self.updFunc(self.bits, index)

      return hit

QLRUHitFuncs = {
   'H21': lambda x: {3:2, 2:1, 1:0, 0:0}[x],
   'H20': lambda x: {3:2, 2:0, 1:0, 0:0}[x],
   'H11': lambda x: {3:1, 2:1, 1:0, 0:0}[x],
   'H10': lambda x: {3:1, 2:0, 1:0, 0:0}[x],
   'H00': lambda x: {3:0, 2:0, 1:0, 0:0}[x],
}

QLRUMissFuncs = {
   'M0': lambda: 0,
   'M1': lambda: 1,
   'M2': lambda: 2,
   'M3': lambda: 3,
}

QLRUMissRandFuncs = {
   'MR32': lambda: (2 if random.randint(0,15) == 0 else 3),
   'MR31': lambda: (1 if random.randint(0,15) == 0 else 3),
   'MR30': lambda: (0 if random.randint(0,15) == 0 else 3),
   'MR21': lambda: (1 if random.randint(0,15) == 0 else 2),
   'MR20': lambda: (0 if random.randint(0,15) == 0 else 2),
   'MR10': lambda: (0 if random.randint(0,15) == 0 else 1),
}

QLRUReplIdxFuncs = {
   'R0': lambda bits, blocks: blocks.index(None) if None in blocks else bits.index(3), #CFL L3
   'R1': lambda bits, blocks: blocks.index(None) if None in blocks else (bits.index(3) if 3 in bits else 0), #IVB
   'R2': lambda bits, blocks: rindex(blocks, None) if None in blocks else bits.index(3), # CFL L2
}

QLRUUpdFuncs = {
   'U0': lambda bits, replIdx: [b + (3 - max(bits)) for b in bits], #CFL L3
   'U1': lambda bits, replIdx: [(b + (3 - max(bits[:replIdx]+bits[replIdx+1:])) if i != replIdx else b) for i, b in enumerate(bits)], #CFL L2
   'U2': lambda bits, replIdx: [b+1 for b in bits] if not 3 in bits else bits, # IVB
   'U3': lambda bits, replIdx: [((b+1) if i != replIdx else b) for i, b in enumerate(bits)] if not 3 in bits else bits,
}

# all deterministic QLRU variants
AllDetQLRUVariants = {
   'QLRU_' + hf[0] + '_' + mf[0] + '_' + rf[0] + '_' + uf[0] + ('_UMO' if umo else ''):
      type('QLRU_' + hf[0] + '_' + mf[0] + '_' + rf[0] + '_' + uf[0] + ('_UMO' if umo else ''), (QLRUSim,),
        {'__init__': lambda self, assoc, hfl=hf[1], mfl=mf[1], rfl=rf[1], ufl=uf[1], umol=umo: QLRUSim.__init__(self, assoc, hfl, mfl, rfl, ufl, umol)})
          for hf in QLRUHitFuncs.items()
            for mf in QLRUMissFuncs.items()
              for rf in QLRUReplIdxFuncs.items()
                for uf in QLRUUpdFuncs.items()
                  for umo in [False, True]
                    if not (rf[0] in ['R0', 'R2'] and uf[0] in ['U2', 'U3'])
}

# all randomized QLRU variants
AllRandQLRUVariants = {
   'QLRU_' + hf[0] + '_' + mf[0] + '_' + rf[0] + '_' + uf[0] + ('_UMO' if umo else ''):
      type('QLRU_' + hf[0] + '_' + mf[0] + '_' + rf[0] + '_' + uf[0] + ('_UMO' if umo else ''), (QLRUSim,),
        {'__init__': lambda self, assoc, hfl=hf[1], mfl=mf[1], rfl=rf[1], ufl=uf[1], umol=umo: QLRUSim.__init__(self, assoc, hfl, mfl, rfl, ufl, umol)})
          for hf in QLRUHitFuncs.items()
            for mf in QLRUMissRandFuncs.items()
              for rf in QLRUReplIdxFuncs.items()
                for uf in QLRUUpdFuncs.items()
                  for umo in [False, True]
                    if not (rf[0] in ['R0', 'R2'] and uf[0] in ['U2', 'U3'])
}


class MRUSim(ReplPolicySim):
   def __init__(self, assoc, updIfNotFull=True):
      super(MRUSim, self).__init__(assoc)
      self.bits = [1] * assoc
      self.updIfNotFull = updIfNotFull

   def acc(self, block):
      hit = block in self.blocks
      full = not (None in self.blocks)
      if hit:
         index = self.blocks.index(block)
      else:
         if not full:
            index = self.blocks.index(None)
         else:
            index = self.bits.index(1)
         self.blocks[index] = block

      if (full or self.updIfNotFull):
         self.bits[index] = 0

      if not 1 in self.bits:
         self.bits = [(1 if bi!=index else 0) for bi, _ in enumerate(self.bits)]

      return hit


class MRUNSim(MRUSim):
   def __init__(self, assoc):
      super(MRUNSim, self).__init__(assoc, False)


# according to ISCA'10 paper
class NRUSim(ReplPolicySim):
   def __init__(self, assoc):
      super(NRUSim, self).__init__(assoc)
      self.bits = [1] * assoc

   def acc(self, block):
      hit = block in self.blocks
      if hit:
         index = self.blocks.index(block)
         self.bits[index] = 0
      else:
         while not 1 in self.bits:
            self.bits = [1] * self.assoc
         index = self.bits.index(1)
         self.blocks[index] = block
         self.bits[index] = 0
      return hit


CommonPolicies = {
   'FIFO': FIFOSim,
   'LRU': LRUSim,
   'PLRU': PLRUSim,
   'PLRUl': PLRUlSim,
   'MRU': MRUSim, # NHM
   'MRU_N': MRUNSim, # SNB
   'NRU': NRUSim,
   'QLRU_H11_M1_R0_U0': AllDetQLRUVariants['QLRU_H11_M1_R0_U0'], # CFL L3
   'QLRU_H21_M1_R0_U0_UMO': AllDetQLRUVariants['QLRU_H21_M2_R0_U0_UMO'], # https://arxiv.org/pdf/1904.06278.pdf paper
   'QLRU_H11_M1_R1_U2': AllDetQLRUVariants['QLRU_H11_M1_R1_U2'], # IVB
   'QLRU_H00_M1_R2_U1': AllDetQLRUVariants['QLRU_H00_M1_R2_U1'], # CFL L2
   'QLRU_H00_M1_R0_U1': AllDetQLRUVariants['QLRU_H00_M1_R0_U1'], # CNL L2
   'SRRIP': AllDetQLRUVariants['QLRU_H00_M2_R0_U0_UMO'],
}

AllDetPolicies = dict(CommonPolicies.items() + AllDetQLRUVariants.items())
AllRandPolicies = dict(AllRandQLRUVariants.items() + AllRandPLRUVariants.items())
AllPolicies = dict(AllDetPolicies.items() + AllRandPolicies.items())


def getHits(seq, policySimClass, assoc, nSets):
   hits = 0
   policySims = [policySimClass(assoc) for _ in range(0, nSets)]

   for blockStr in seq.split():
      blockName = getBlockName(blockStr)
      if '!' in blockStr:
         for policySim in policySims:
            policySim.flush(blockName)
      else:
         for policySim in policySims:
            hit = policySim.acc(blockName)
            if '?' in blockStr:
               hits += int(hit)
   return hits


def getAges(blocks, seq, policySimClass, assoc):
   ages = {}
   for block in blocks:
      for i in count(0):
         curSeq = seq + ' ' + ' '.join('N' + str(n) for n in range(0,i)) + ' ' + block + '?'
         if getHits(policySimClass(assoc), curSeq) == 0:
            ages[block] = i
            break
   return ages


def getGraph(blocks, seq, policySimClass, assoc, maxAge, nSets=1, nRep=1, agg="med"):
   traces = []
   for block in blocks:
      trace = []
      for i in range(0, maxAge):
         curSeq = seq + ' ' + ' '.join('N' + str(n) for n in range(0,i)) + ' ' + block + '?'
         hits = [getHits(curSeq, policySimClass, assoc, nSets) for _ in range(0, nRep)]
         if agg == "med":
            aggValue = median(hits)
         elif agg == "min":
            aggValue = min(hits)
         else:
            aggValue = float(sum(hits))/nRep
         trace.append(aggValue)
      traces.append((block, trace))
   return traces


def getPermutations(policySimClass, assoc, maxAge=None):
   # initial ages
   initBlocks = ['I' + str(i) for i in range(0, assoc)]
   seq = ' '.join(initBlocks)

   initAges = getAges(initBlocks, seq, policySimClass, assoc)

   accSeqStr = 'Access sequence: <wbinvd> ' + seq
   print accSeqStr
   print 'Ages: {' + ', '.join(b + ': ' + str(initAges[b]) for b in initBlocks) + '}'

   blocks = ['B' + str(i) for i in range(0, assoc)]
   baseSeq = ' '.join(initBlocks + blocks)

   ages = getAges(blocks, baseSeq, policySimClass, assoc)

   accSeqStr = 'Access sequence: <wbinvd> ' + baseSeq
   print accSeqStr
   print 'Ages: {' + ', '.join(b + ': ' + str(ages[b]) for b in blocks) + '}'

   blocksSortedByAge = [a[0] for a in sorted(ages.items(), key=lambda x: -x[1])] # most recent block first

   for permI, permBlock in enumerate(blocksSortedByAge):
      seq = baseSeq + ' ' + permBlock
      permAges = getAges(blocks, seq, policySimClass, assoc)

      accSeqStr = 'Access sequence: <wbinvd> ' + seq

      perm = [-1] * assoc
      for bi, b in enumerate(blocksSortedByAge):
         permAge = permAges[b]
         if permAge < 1 or permAge > assoc:
            break
         perm[assoc-permAge] = bi

      print u'\u03A0_' + str(permI) + ' = ' + str(tuple(perm))

