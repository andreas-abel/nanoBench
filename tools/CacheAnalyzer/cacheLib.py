#!/usr/bin/python
from itertools import count
from collections import namedtuple

import math
import random
import re
import subprocess
import sys

sys.path.append('../..')
from kernelNanoBench import *

sys.path.append('../CPUID')
import cpuid

import logging
log = logging.getLogger(__name__)


def getEventConfig(event):
   arch = getArch()
   if event == 'L1_HIT':
      if arch in ['Core', 'EnhancedCore']: return '40.0E ' + event # L1D_CACHE_LD.MES
      if arch in ['NHM', 'WSM']: return 'CB.01 ' + event
      if arch in ['SNB', 'IVB', 'HSW', 'BDW', 'SKL', 'SKX', 'KBL', 'CFL', 'CNL', 'ICL']: return 'D1.01 ' + event
   if event == 'L1_MISS':
      if arch in ['Core', 'EnhancedCore']: return 'CB.01.CTR=0 ' + event
      if arch in ['IVB', 'HSW', 'BDW', 'SKL', 'SKX', 'KBL', 'CFL', 'CNL', 'ICL']: return 'D1.08 ' + event
      if arch in ['ZEN+']: return '064.70 ' + event
   if event == 'L2_HIT':
      if arch in ['Core', 'EnhancedCore']: return '29.7E ' + event # L2_LD.THIS_CORE.ALL_INCL.MES
      if arch in ['NHM', 'WSM']: return 'CB.02 ' + event
      if arch in ['SNB', 'IVB', 'HSW', 'BDW', 'SKL', 'SKX', 'KBL', 'CFL', 'CNL', 'ICL']: return 'D1.02 ' + event
      if arch in ['ZEN+']: return '064.70 ' + event
   if event == 'L2_MISS':
      if arch in ['Core', 'EnhancedCore']: return 'CB.04.CTR=0 ' + event
      if arch in ['IVB', 'HSW', 'BDW', 'SKL', 'SKX', 'KBL', 'CFL', 'CNL', 'ICL']: return 'D1.10 ' + event
      if arch in ['ZEN+']: return '064.08 ' + event
   if event == 'L3_HIT':
      if arch in ['NHM', 'WSM']: return 'CB.04 ' + event
      if arch in ['SNB', 'IVB', 'HSW', 'BDW', 'SKL', 'SKX', 'KBL', 'CFL', 'CNL', 'ICL']: return 'D1.04 ' + event
   if event == 'L3_MISS':
      if arch in ['NHM', 'WSM']: return 'CB.10 ' + event
      if arch in ['SNB', 'IVB', 'HSW', 'BDW', 'SKL', 'SKX', 'KBL', 'CFL', 'CNL', 'ICL']: return 'D1.20 ' + event
   return ''

def getDefaultCacheConfig():
   return '\n'.join(filter(None, [getEventConfig('L' + str(l) + '_' + hm) for l in range(1,4) for hm in ['HIT', 'MISS']]))


def getDefaultCacheMSRConfig():
   if 'Intel' in getCPUVendor() and 'L3' in getCpuidCacheInfo() and getCpuidCacheInfo()['L3']['complex']:
      if getArch() in ['CNL', 'ICL']:
         dist = 8
         ctrOffset = 2
      else:
         dist = 16
         ctrOffset = 6
      return '\n'.join('msr_0xE01=0x20000000.msr_' + format(0x700 + dist*cbo, 'x') + '=0x408F34 msr_' + format(0x700 + ctrOffset + dist*cbo, 'x') +
                       ' CACHE_LOOKUP_CBO_' + str(cbo) for cbo in range(0, getNCBoxUnits()))
   return ''


def isClose(a, b, rel_tol=1e-09, abs_tol=0.0):
    return abs(a-b) <= max(rel_tol * max(abs(a), abs(b)), abs_tol)


class CacheInfo:
   def __init__(self, level, assoc, lineSize, nSets, nSlices=None, nCboxes=None):
      self.level = level
      self.assoc = assoc
      self.lineSize = lineSize
      self.nSets = nSets
      self.waySize = lineSize * nSets
      self.size = self.waySize * assoc * (nSlices if nSlices is not None else 1)
      self.nSlices = nSlices
      self.nCboxes = nCboxes

   def __str__(self):
      return '\n'.join(['L' + str(self.level) + ':',
                        '  Size: ' + str(self.size/1024) + ' kB',
                        '  Associativity: ' + str(self.assoc),
                        '  Line Size: ' + str(self.lineSize) + ' B',
                        '  Number of sets' + (' (per slice)' if self.nSlices is not None else '') + ': ' + str(self.nSets),
                        '  Way size' + (' (per slice)' if self.nSlices is not None else '') + ': ' + str(self.waySize/1024) + ' kB',
                       ('  Number of CBoxes: ' + str(self.nCboxes) if self.nCboxes is not None else ''),
                       ('  Number of slices: ' + str(self.nSlices) if self.nSlices is not None else '')])


def getArch():
   if not hasattr(getArch, 'arch'):
      cpu = cpuid.CPUID()
      getArch.arch = cpuid.micro_arch(cpu)
   return getArch.arch

def getCPUVendor():
   if not hasattr(getCPUVendor, 'vendor'):
      cpu = cpuid.CPUID()
      getCPUVendor.vendor = cpuid.cpu_vendor(cpu)
   return getCPUVendor.vendor

def getCpuidCacheInfo():
   if not hasattr(getCpuidCacheInfo, 'cpuidCacheInfo'):
      cpu = cpuid.CPUID()
      log.debug(cpuid.get_basic_info(cpu))
      getCpuidCacheInfo.cpuidCacheInfo = cpuid.get_cache_info(cpu)

      if not len(set(c['lineSize'] for c in getCpuidCacheInfo.cpuidCacheInfo.values())) == 1:
         raise ValueError('All line sizes must be the same')
   return getCpuidCacheInfo.cpuidCacheInfo


def getCacheInfo(level):
   if level == 1:
      if not hasattr(getCacheInfo, 'L1CacheInfo'):
         cpuidInfo = getCpuidCacheInfo()['L1D']
         getCacheInfo.L1CacheInfo = CacheInfo(1, cpuidInfo['assoc'], cpuidInfo['lineSize'], cpuidInfo['nSets'])
      return getCacheInfo.L1CacheInfo
   elif level == 2:
      if not hasattr(getCacheInfo, 'L2CacheInfo'):
         cpuidInfo = getCpuidCacheInfo()['L2']
         getCacheInfo.L2CacheInfo = CacheInfo(2, cpuidInfo['assoc'], cpuidInfo['lineSize'], cpuidInfo['nSets'])
      return getCacheInfo.L2CacheInfo
   elif level == 3:
      if not hasattr(getCacheInfo, 'L3CacheInfo'):
         if not 'L3' in getCpuidCacheInfo():
            raise ValueError('invalid level')
         cpuidInfo = getCpuidCacheInfo()['L3']
         if not 'complex' in cpuidInfo or not cpuidInfo['complex']:
            getCacheInfo.L3CacheInfo = CacheInfo(3, cpuidInfo['assoc'], cpuidInfo['lineSize'], cpuidInfo['nSets'])
         else:
            lineSize = cpuidInfo['lineSize']
            assoc = cpuidInfo['assoc']
            nSets = cpuidInfo['nSets']

            stride = 2**((lineSize*nSets/getNCBoxUnits())-1).bit_length() # smallest power of two larger than lineSize*nSets/nCBoxUnits
            ms = findMaximalNonEvictingL3SetInCBox(0, stride, assoc, 0)
            log.debug('Maximal non-evicting L3 set: ' + str(len(ms)) + ' ' + str(ms))
            nCboxes = getNCBoxUnits()
            nSlices = nCboxes * int(math.ceil(float(len(ms))/assoc))

            getCacheInfo.L3CacheInfo = CacheInfo(3, assoc, lineSize, nSets/nSlices, nSlices, nCboxes)
      return getCacheInfo.L3CacheInfo
   else:
      raise ValueError('invalid level')


def getNCBoxUnits():
   if not hasattr(getNCBoxUnits, 'nCBoxUnits'):
      try:
         subprocess.check_output(['modprobe', 'msr'])
         cbo_config = subprocess.check_output(['rdmsr', '0x396'])
         if getArch() in ['CNL', 'ICL']:
            getNCBoxUnits.nCBoxUnits = int(cbo_config)
         else:
            getNCBoxUnits.nCBoxUnits = int(cbo_config) - 1
         log.debug('Number of CBox Units: ' + str(getNCBoxUnits.nCBoxUnits))
      except subprocess.CalledProcessError as e:
         log.critical('Error: ' + e.output)
         sys.exit()
      except OSError as e:
         log.critical("rdmsr not found. Try 'sudo apt install msr-tools'")
         sys.exit()
   return getNCBoxUnits.nCBoxUnits


def getCBoxOfAddress(address):
   if not hasattr(getCBoxOfAddress, 'cBoxMap'):
      getCBoxOfAddress.cBoxMap = dict()
   cBoxMap = getCBoxOfAddress.cBoxMap

   if not address in cBoxMap:
      setNanoBenchParameters(config='', msrConfig=getDefaultCacheMSRConfig(), nMeasurements=10, unrollCount=1, loopCount=10, aggregateFunction='min',
                             basicMode=True, noMem=True)

      ec = getCodeForAddressLists([AddressList([address], False, True, False)])
      nb = runNanoBench(code=ec.code, oneTimeInit=ec.oneTimeInit)

      nCacheLookups = [nb['CACHE_LOOKUP_CBO_'+str(cBox)] for cBox in range(0, getNCBoxUnits())]
      cBoxMap[address] = nCacheLookups.index(max(nCacheLookups))

   return cBoxMap[address]


def getNewAddressesInCBox(n, cBox, cacheSet, prevAddresses, notInCBox=False):
   if not prevAddresses:
      maxPrevAddress = cacheSet * getCacheInfo(3).lineSize
   else:
      maxPrevAddress = max(prevAddresses)
   addresses = []
   for addr in count(maxPrevAddress+getCacheInfo(3).waySize, getCacheInfo(3).waySize):
      if not notInCBox and getCBoxOfAddress(addr) == cBox:
         addresses.append(addr)
      if notInCBox and getCBoxOfAddress(addr) != cBox:
         addresses.append(addr)
      if len(addresses) >= n:
         return addresses


def getNewAddressesNotInCBox(n, cBox, cacheSet, prevAddresses):
   return getNewAddressesInCBox(n, cBox, cacheSet, prevAddresses, notInCBox=True)


pointerChasingInits = dict()

#addresses must not contain duplicates
def getPointerChasingInit(addresses):
   if tuple(addresses) in pointerChasingInits:
      return pointerChasingInits[tuple(addresses)]

   #addresses_tail = addresses[1:]
   #random.shuffle(addresses_tail)
   #adresses = [addresses[0]] + addresses_tail

   init = 'lea RAX, [R14+' + str(addresses[0]) + ']; '
   init += 'mov RBX, RAX; '

   i = 0
   while i < len(addresses)-1:
      stride = addresses[i+1] - addresses[i]
      init += '1: add RBX, ' + str(stride) + '; '
      init += 'mov [RAX], RBX; '
      init += 'mov RAX, RBX; '

      i += 1
      oldI = i

      while i < len(addresses)-1 and (addresses[i+1] - addresses[i]) == stride:
         i += 1

      if oldI != i:
         init += 'lea RCX, [R14+' + str(addresses[i]) + ']; '
         init += 'cmp RAX, RCX; '
         init += 'jne 1b; '

   init += 'mov qword ptr [R14 + ' + str(addresses[-1]) + '], 0; '
   pointerChasingInits[tuple(addresses)] = init
   return init


ExperimentCode = namedtuple('ExperimentCode', 'code init oneTimeInit')

def getCodeForAddressLists(codeAddressLists, initAddressLists=[], wbinvd=False, afterEveryAcc=''):
   distinctAddrLists = set(tuple(l.addresses) for l in initAddressLists+codeAddressLists)
   if len(distinctAddrLists) > 1 and set.intersection(*list(set(l) for l in distinctAddrLists)):
      raise ValueError('same address in different lists')

   code = []
   init = (['wbinvd; '] if wbinvd else [])
   oneTimeInit = []

   r14Size = getR14Size()
   alreadyAddedOneTimeInits = set()

   for addressLists, codeList, isInit in [(initAddressLists, init, True), (codeAddressLists, code, False)]:
      if addressLists is None: continue

      pfcEnabled = True
      for addressList in addressLists:
         if addressList.wbinvd:
            if addressList.exclude and pfcEnabled:
               codeList.append(PFC_STOP_ASM + '; ')
            codeList.append('wbinvd; ')
            if addressList.exclude and pfcEnabled:
               codeList.append(PFC_START_ASM + '; ')
            continue

         addresses = addressList.addresses
         if len(addresses) < 1: continue

         if any(addr >= r14Size for addr in addresses):
            sys.stderr.write('Size of memory area too small. Try increasing it with set-R14-size.sh.\n')
            exit(1)

         if not isInit:
            if addressList.exclude and pfcEnabled:
               codeList.append(PFC_STOP_ASM + '; ')
               pfcEnabled = False
            elif not addressList.exclude and not pfcEnabled:
               codeList.append(PFC_START_ASM + '; ')
               pfcEnabled = True

         # use multiple lfence instructions to make sure that the block is actually in the cache and not still in a fill buffer
         codeList.append('lfence; ' * 10)

         if addressList.flush:
            for address in addresses:
               codeList.append('clflush [R14 + ' + str(address) + ']; ' + afterEveryAcc)
         else:
            if len(addresses) == 1:
               codeList.append('mov RCX, [R14 + ' + str(addresses[0]) + ']; ')
            else:
               if not tuple(addresses) in alreadyAddedOneTimeInits:
                  oneTimeInit.append(getPointerChasingInit(addresses))
                  alreadyAddedOneTimeInits.add(tuple(addresses))

               codeList.append('lea RCX, [R14+' + str(addresses[0]) + ']; 1: mov RCX, [RCX]; ' + afterEveryAcc + 'jrcxz 2f; jmp 1b; 2: ')

      if not isInit and not pfcEnabled:
         codeList.append(PFC_START_ASM + '; ')

   return ExperimentCode(''.join(code), ''.join(init), ''.join(oneTimeInit))


def getClearHLAddresses(level, cacheSetList, cBox=1):
   lineSize = getCacheInfo(1).lineSize

   if level == 1:
      return []
   elif (level == 2) or (level == 3 and getCacheInfo(3).nSlices is None):
      nSets = getCacheInfo(level).nSets
      if not all(nSets > getCacheInfo(lLevel).nSets for lLevel in range(1, level)):
         raise ValueError('L' + str(level) + ' way size must be greater than lower level way sizes')

      nHLSets = getCacheInfo(level-1).nSets
      nClearAddresses = 2*sum(getCacheInfo(hLevel).assoc for hLevel in range(1, level))

      HLSets = set(cs % nHLSets for cs in cacheSetList)
      addrForClearingHL = []

      for HLSet in HLSets:
         possibleSets = [cs for cs in range(HLSet, nSets, nHLSets) if cs not in cacheSetList]
         if not possibleSets:
            raise ValueError("not enough cache sets available for clearing higher levels")

         addrForClearingHLSet = []

         for setIndex in count(HLSet, nHLSets):
            if not setIndex % nSets in possibleSets:
               continue
            addrForClearingHLSet.append(setIndex*lineSize)
            if len(addrForClearingHLSet) >= nClearAddresses:
               break

         addrForClearingHL += addrForClearingHLSet

      return addrForClearingHL
   elif level == 3:
      if not hasattr(getClearHLAddresses, 'clearL2Map'):
         getClearHLAddresses.clearL2Map = dict()
      clearL2Map = getClearHLAddresses.clearL2Map

      if not cBox in clearL2Map:
         clearL2Map[cBox] = dict()

      clearAddresses = []
      for L3Set in cacheSetList:
         if not L3Set in clearL2Map[cBox]:
            clearL2Map[cBox][L3Set] = getNewAddressesNotInCBox(2*(getCacheInfo(1).assoc+getCacheInfo(2).assoc), cBox, L3Set, [])
         clearAddresses += clearL2Map[cBox][L3Set]

      return clearAddresses

L3SetToWayIDMap = dict()
def getAddresses(level, wayID, cacheSetList, cBox=1, clearHL=True):
   lineSize = getCacheInfo(1).lineSize

   if level <= 2 or (level == 3 and getCacheInfo(3).nSlices is None):
      nSets = getCacheInfo(level).nSets
      waySize = getCacheInfo(level).waySize
      return [(wayID*waySize) + s*lineSize for s in cacheSetList]
   elif level == 3:
      if not cBox in L3SetToWayIDMap:
         L3SetToWayIDMap[cBox] = dict()

      addresses = []
      for L3Set in cacheSetList:
         if not L3Set in L3SetToWayIDMap[cBox]:
            L3SetToWayIDMap[cBox][L3Set] = dict()
            if getCacheInfo(3).nSlices != getNCBoxUnits():
               for i, addr in enumerate(findMinimalL3EvictionSet(L3Set, cBox)):
                  L3SetToWayIDMap[cBox][L3Set][i] = addr
         if not wayID in L3SetToWayIDMap[cBox][L3Set]:
            if getCacheInfo(3).nSlices == getNCBoxUnits():
               L3SetToWayIDMap[cBox][L3Set][wayID] = next(iter(getNewAddressesInCBox(1, cBox, L3Set, L3SetToWayIDMap[cBox][L3Set].values())))
            else:
               L3SetToWayIDMap[cBox][L3Set][wayID] = next(iter(findCongruentL3Addresses(1, L3Set, cBox, L3SetToWayIDMap[cBox][L3Set].values())))
         addresses.append(L3SetToWayIDMap[cBox][L3Set][wayID])

      return addresses

   raise ValueError('invalid level')


# removes ?s and !s, and returns the part before the first '_'
def getBlockName(blockStr):
   return re.sub('[?!]', '', blockStr.split('_')[0])


# removes ?s and !s, and returns the part after the last '_' (as int); returns None if there is no '_'
def getBlockSet(blockStr):
   if not '_' in blockStr:
      return None
   return int(re.match('\d+', blockStr.split('_')[-1]).group())


def parseCacheSetsStr(level, clearHL, cacheSetsStr):
   cacheSetList = []
   if cacheSetsStr is not None:
      for s in cacheSetsStr.split(','):
         if '-' in s:
            first, last = s.split('-')[:2]
            cacheSetList += range(int(first), int(last)+1)
         else:
            cacheSetList.append(int(s))
   else:
      nSets = getCacheInfo(level).nSets
      if level > 1 and clearHL and not (level == 3 and getCacheInfo(3).nSlices is not None):
         nHLSets = getCacheInfo(level-1).nSets
         cacheSetList = range(nHLSets, nSets)
      else:
         cacheSetList = range(0, nSets)
   return cacheSetList


def findCacheSetForCode(cacheSetList, level):
   nSets = getCacheInfo(level).nSets
   sortedCacheSetList = sorted(cacheSetList)
   sortedCacheSetList += [sortedCacheSetList[0] + nSets]

   maxDist = 1
   bestSet = 0
   for i in range(len(sortedCacheSetList)-1):
      dist = sortedCacheSetList[i+1] - sortedCacheSetList[i]
      if dist > maxDist:
         maxDist = dist
         bestSet = (sortedCacheSetList[i] + 1) % nSets

   return bestSet


def getAllUsedCacheSets(cacheSetList, seq, initSeq=''):
   cacheSetOverrideList = [s for s in set(map(getBlockSet, initSeq.split()+seq.split())) if s is not None]
   return sorted(set(cacheSetList + cacheSetOverrideList))

AddressList = namedtuple('AddressList', 'addresses exclude flush wbinvd')

def getCodeForCacheExperiment(level, seq, initSeq, cacheSetList, cBox, clearHL, wbinvd):
   allUsedSets = getAllUsedCacheSets(cacheSetList, seq, initSeq)

   clearHLAddrList = None
   if (clearHL and level > 1):
      clearHLAddrList = AddressList(getClearHLAddresses(level, allUsedSets, cBox), True, False, False)

   initAddressLists = []
   seqAddressLists = []
   nameToID = dict()

   for seqString, addrLists in [(initSeq, initAddressLists), (seq, seqAddressLists)]:
      for seqEl in seqString.split():
         name = getBlockName(seqEl)
         if name == '<wbinvd>':
            addrLists.append(AddressList([], True, False, True))
            continue

         overrideSet = getBlockSet(seqEl)

         wayID = nameToID.setdefault(name, len(nameToID))
         exclude = not '?' in seqEl
         flush = '!' in seqEl

         s = [overrideSet] if overrideSet is not None else cacheSetList
         addresses = getAddresses(level, wayID, s, cBox=cBox, clearHL=clearHL)

         if clearHLAddrList is not None and not flush:
            addrLists.append(clearHLAddrList)
         addrLists.append(AddressList(addresses, exclude, flush, False))

   log.debug('\nInitAddresses: ' + str(initAddressLists))
   log.debug('\nSeqAddresses: ' + str(seqAddressLists))

   return getCodeForAddressLists(seqAddressLists, initAddressLists, wbinvd)


def runCacheExperimentCode(code, initCode, oneTimeInitCode, loop, warmUpCount, codeOffset, nMeasurements, agg):
   resetNanoBench()
   setNanoBenchParameters(config=getDefaultCacheConfig(), msrConfig=getDefaultCacheMSRConfig(), nMeasurements=nMeasurements, unrollCount=1, loopCount=loop,
                          warmUpCount=warmUpCount, aggregateFunction=agg, basicMode=True, noMem=True, codeOffset=codeOffset, verbose=None)
   return runNanoBench(code=code, init=initCode, oneTimeInit=oneTimeInitCode)


# cacheSets=None means do access in all sets
# in this case, the first nL1Sets many sets of L2 will be reserved for clearing L1
# if wbinvd is set, wbinvd will be called before initSeq
def runCacheExperiment(level, seq, initSeq='', cacheSets=None, cBox=1, clearHL=True, loop=1, wbinvd=False, nMeasurements=10, warmUpCount=1, codeSet=None,
                       agg='avg'):
   cacheSetList = parseCacheSetsStr(level, clearHL, cacheSets)
   ec = getCodeForCacheExperiment(level, seq, initSeq=initSeq, cacheSetList=cacheSetList, cBox=cBox, clearHL=clearHL, wbinvd=wbinvd)

   log.debug('\nOneTimeInit: ' + ec.oneTimeInit)
   log.debug('\nInit: ' + ec.init)
   log.debug('\nCode: ' + ec.code)

   lineSize = getCacheInfo(1).lineSize
   allUsedSets = getAllUsedCacheSets(cacheSetList, seq, initSeq)
   codeOffset = lineSize * (codeSet if codeSet is not None else findCacheSetForCode(allUsedSets, level))

   return runCacheExperimentCode(ec.code, ec.init, ec.oneTimeInit, loop, warmUpCount, codeOffset, nMeasurements, agg)


def printNB(nb_result):
   for r in nb_result.items():
      print r[0] + ': ' + str(r[1])


def findMinimalL3EvictionSet(cacheSet, cBox):
   setNanoBenchParameters(config='\n'.join([getEventConfig('L3_HIT'), getEventConfig('L3_MISS')]), msrConfig=None, nMeasurements=10, unrollCount=1, loopCount=10,
                           warmUpCount=None, initialWarmUpCount=None, aggregateFunction='med', basicMode=True, noMem=True, verbose=None)
   if not hasattr(findMinimalL3EvictionSet, 'evSetForCacheSet'):
      findMinimalL3EvictionSet.evSetForCacheSet = dict()
   if not cBox in findMinimalL3EvictionSet.evSetForCacheSet:
      findMinimalL3EvictionSet.evSetForCacheSet[cBox] = dict()
   evSetForCacheSet = findMinimalL3EvictionSet.evSetForCacheSet[cBox]

   if cacheSet in evSetForCacheSet:
      return evSetForCacheSet[cacheSet]

   clearHLAddrList = AddressList(getClearHLAddresses(3, [cacheSet], cBox), True, False, False)
   addresses = []
   curAddress = cacheSet*getCacheInfo(3).lineSize

   while len(addresses) < getCacheInfo(3).assoc:
      curAddress += getCacheInfo(3).waySize
      if getCBoxOfAddress(curAddress) == cBox:
         addresses.append(curAddress)

   while True:
      curAddress += getCacheInfo(3).waySize
      if not getCBoxOfAddress(curAddress) == cBox: continue

      addresses += [curAddress]
      ec = getCodeForAddressLists([AddressList(addresses, False, False, False), clearHLAddrList])

      setNanoBenchParameters(config=getDefaultCacheConfig(), msrConfig='', nMeasurements=10, unrollCount=1, loopCount=100,
                             aggregateFunction='med', basicMode=True, noMem=True)
      nb = runNanoBench(code=ec.code, oneTimeInit=ec.oneTimeInit)

      if nb['L3_HIT'] < len(addresses) - .9:
         break

   for i in reversed(range(0, len(addresses))):
      tmpAddresses = addresses[:i] + addresses[(i+1):]

      ec = getCodeForAddressLists([AddressList(tmpAddresses, False, False, False), clearHLAddrList])
      nb = runNanoBench(code=ec.code, oneTimeInit=ec.oneTimeInit)

      if nb['L3_HIT'] < len(tmpAddresses) - 0.9:
         addresses = tmpAddresses

   evSetForCacheSet[cacheSet] = addresses
   return addresses


def findCongruentL3Addresses(n, cacheSet, cBox, L3EvictionSet):
   clearHLAddrList = AddressList(getClearHLAddresses(3, [cacheSet], cBox), True, False, False)

   congrAddresses = []
   L3WaySize = getCacheInfo(3).waySize

   for newAddr in count(max(L3EvictionSet)+L3WaySize, L3WaySize):
      if not getCBoxOfAddress(newAddr) == cBox: continue

      tmpAddresses = L3EvictionSet[:getCacheInfo(3).assoc] + [newAddr]
      ec = getCodeForAddressLists([AddressList(tmpAddresses, False, False, False), clearHLAddrList])

      setNanoBenchParameters(config=getEventConfig('L3_HIT'), msrConfig=None, nMeasurements=10, unrollCount=1, loopCount=100,
                             aggregateFunction='med', basicMode=True, noMem=True, verbose=None)
      nb = runNanoBench(code=ec.code, oneTimeInit=ec.oneTimeInit)

      if nb['L3_HIT'] < len(tmpAddresses) - 0.9:
         congrAddresses.append(newAddr)

      if len(congrAddresses) >= n: break

   return congrAddresses


def findMaximalNonEvictingL3SetInCBox(start, stride, L3Assoc, cBox):
   clearHLAddresses = []
   addresses = []

   curAddress = start
   while len(clearHLAddresses) < 2*(getCacheInfo(1).assoc+getCacheInfo(2).assoc):
      if getCBoxOfAddress(curAddress) != cBox:
         clearHLAddresses.append(curAddress)
      curAddress += stride
   clearHLAddrList = AddressList(clearHLAddresses, True, False, False)

   curAddress = start
   while len(addresses) < L3Assoc:
      if getCBoxOfAddress(curAddress) == cBox:
         addresses.append(curAddress)
      curAddress += stride

   notAdded = 0
   while notAdded < L3Assoc:
      curAddress += stride

      if not getCBoxOfAddress(curAddress) == cBox:
         continue

      newAddresses = addresses + [curAddress]
      ec = getCodeForAddressLists([AddressList(newAddresses, False, False, False), clearHLAddrList])

      setNanoBenchParameters(config=getEventConfig('L3_HIT'), msrConfig='', nMeasurements=10, unrollCount=1, loopCount=10,
                             aggregateFunction='med', basicMode=True, noMem=True)
      nb = runNanoBench(code=ec.code, oneTimeInit=ec.oneTimeInit)

      if nb['L3_HIT'] > len(newAddresses) - .9:
         addresses = newAddresses
         notAdded = 0
      else:
         notAdded += 1

   return addresses


def getUnusedBlockNames(n, usedBlockNames, prefix=''):
   newBlockNames = []
   i = 0
   while len(newBlockNames) < n:
      name = prefix + str(i)
      if not name in usedBlockNames: newBlockNames.append(name)
      i += 1
   return newBlockNames


# Returns a dict with the age of each block, i.e., how many fresh blocks need to be accessed until the block is evicted
# if returnNbResults is True, the function returns additionally all measurment results (as the second component of a tuple)
def getAgesOfBlocks(blocks, level, seq, initSeq='', maxAge=None, cacheSets=None, cBox=1, clearHL=True,  wbinvd=False, returnNbResults=False, nMeasurements=10, agg='avg'):
   ages = dict()
   if returnNbResults: nbResults = dict()

   if maxAge is None:
      maxAge = 2*getCacheInfo(level).assoc

   nSets = len(parseCacheSetsStr(level, clearHL, cacheSets))

   for block in blocks:
      if returnNbResults: nbResults[block] = []

      for nNewBlocks in range(0, maxAge+1):
         curSeq = seq.replace('?', '') + ' '
         newBlocks = getUnusedBlockNames(nNewBlocks, seq+initSeq, 'N')
         curSeq += ' '.join(newBlocks) + ' ' + block + '?'

         nb = runCacheExperiment(level, curSeq, initSeq=initSeq, cacheSets=cacheSets, cBox=cBox, clearHL=clearHL, loop=0, wbinvd=wbinvd, nMeasurements=nMeasurements, agg=agg)
         if returnNbResults: nbResults[block].append(nb)

         hitEvent = 'L' + str(level) + '_HIT'
         missEvent = 'L' + str(level) + '_MISS'

         if hitEvent in nb:
            if isClose(nb[hitEvent], 0.0, abs_tol=0.1):
               if not block in ages:
                  ages[block] = nNewBlocks
               #if not returnNbResults:
               #break
         elif missEvent in nb:
            if nb[missEvent] > nSets - 0.1:
               if not block in ages:
                  ages[block] = nNewBlocks
               #if not returnNbResults:
               #break
         else:
            raise ValueError('no cache results available')
      if not block in ages:
         ages[block] = -1

   if returnNbResults:
      return (ages, nbResults)
   else:
      return ages
