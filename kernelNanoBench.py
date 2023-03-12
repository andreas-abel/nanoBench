import atexit
import os
import re
import subprocess
import sys

from collections import OrderedDict
from shutil import copyfile

PFC_START_ASM = '.quad 0xE0B513B1C2813F04'
PFC_STOP_ASM = '.quad 0xF0B513B1C2813F04'

def writeFile(fileName, content):
   with open(fileName, 'w') as f:
      f.write(content)

def readFile(fileName):
   with open(fileName) as f:
      return f.read()


def assemble(code, objFile, asmFile='/tmp/ramdisk/asm.s'):
   try:
      if '|' in code:
         code = code.replace('|15', '.byte 0x66,0x66,0x66,0x66,0x66,0x66,0x2e,0x0f,0x1f,0x84,0x00,0x00,0x00,0x00,0x00;')
         code = code.replace('|14', '.byte 0x66,0x66,0x66,0x66,0x66,0x2e,0x0f,0x1f,0x84,0x00,0x00,0x00,0x00,0x00;')
         code = code.replace('|13', '.byte 0x66,0x66,0x66,0x66,0x2e,0x0f,0x1f,0x84,0x00,0x00,0x00,0x00,0x00;')
         code = code.replace('|12', '.byte 0x66,0x66,0x66,0x2e,0x0f,0x1f,0x84,0x00,0x00,0x00,0x00,0x00;')
         code = code.replace('|11', '.byte 0x66,0x66,0x2e,0x0f,0x1f,0x84,0x00,0x00,0x00,0x00,0x00;')
         code = code.replace('|10', '.byte 0x66,0x2e,0x0f,0x1f,0x84,0x00,0x00,0x00,0x00,0x00;')
         code = code.replace('|9',  '.byte 0x66,0x0f,0x1f,0x84,0x00,0x00,0x00,0x00,0x00;')
         code = code.replace('|8',  '.byte 0x0f,0x1f,0x84,0x00,0x00,0x00,0x00,0x00;')
         code = code.replace('|7',  '.byte 0x0f,0x1f,0x80,0x00,0x00,0x00,0x00;')
         code = code.replace('|6',  '.byte 0x66,0x0f,0x1f,0x44,0x00,0x00;')
         code = code.replace('|5',  '.byte 0x0f,0x1f,0x44,0x00,0x00;')
         code = code.replace('|4',  '.byte 0x0f,0x1f,0x40,0x00;')
         code = code.replace('|3',  '.byte 0x0f,0x1f,0x00;')
         code = code.replace('|2',  '.byte 0x66,0x90;')
         code = code.replace('|1',  'nop;')
         code = re.sub(r'(\d*)\*\|(.*?)\|', lambda m: int(m.group(1))*(m.group(2)+';'), code)
      code = '.intel_syntax noprefix;' + code + ';1:;.att_syntax prefix\n'
      with open(asmFile, 'w') as f:
         f.write(code);
      subprocess.check_call(['as', asmFile, '-o', objFile])
   except subprocess.CalledProcessError as e:
      sys.stderr.write("Error (assemble): " + str(e))
      sys.stderr.write(code)
      exit(1)


def objcopy(sourceFile, targetFile):
   try:
      subprocess.check_call(['objcopy', "-j", ".text", '-O', 'binary', sourceFile, targetFile])
   except subprocess.CalledProcessError as e:
      sys.stderr.write("Error (objcopy): " + str(e))
      exit(1)


def createBinaryFile(targetFile, asm=None, objFile=None, binFile=None):
   if asm:
      objFile = '/tmp/ramdisk/tmp.o'
      assemble(asm, objFile)
   if objFile is not None:
      objcopy(objFile, targetFile)
      return True
   if binFile is not None:
      copyfile(binFile, targetFile)
      return True
   return False


# Returns the size in bytes.
def getR14Size():
   if not hasattr(getR14Size, 'r14Size'):
      with open('/sys/nb/r14_size') as f:
         line = f.readline()
         mb = int(line.split()[2])
         getR14Size.r14Size = mb * 1024 * 1024
   return getR14Size.r14Size


# Returns the address that is stored in R14, RDI, RSI, RBP, or RSP as a hex string.
def getAddress(reg):
   with open('/sys/nb/addresses') as f:
      for line in f:
         lReg, addr = line.strip().split(': ')
         if reg.upper() == lReg:
            return addr
   raise ValueError('Address not found')


paramDict = dict()

# Assumes that no changes to the corresponding files in /sys/nb/ were made since the last call to setNanoBenchParameters().
# Otherwise, reset() needs to be called first.
def setNanoBenchParameters(config=None, configFile=None, msrConfig=None, msrConfigFile=None, fixedCounters=None, nMeasurements=None, unrollCount=None,
                           loopCount=None, warmUpCount=None, initialWarmUpCount=None, alignmentOffset=None, codeOffset=None, drainFrontend=None,
                           aggregateFunction=None, range=None, basicMode=None, noMem=None, noNormalization=None, verbose=None, endToEnd=None):
   if config is not None:
      if paramDict.get('config', None) != config:
         configFile = '/tmp/ramdisk/config'
         writeFile(configFile, config)
         paramDict['config'] = config
   if configFile is not None:
      writeFile('/sys/nb/config', configFile)

   if msrConfig is not None:
      if paramDict.get('msrConfig', None) != msrConfig:
         msrConfigFile = '/tmp/ramdisk/msr_config'
         writeFile(msrConfigFile, msrConfig)
         paramDict['msrConfig'] = msrConfig
   if msrConfigFile is not None:
      writeFile('/sys/nb/msr_config', msrConfigFile)

   if fixedCounters is not None:
      if paramDict.get('fixedCounters', None) != fixedCounters:
         writeFile('/sys/nb/fixed_counters', str(int(fixedCounters)))
         paramDict['fixedCounters'] = fixedCounters

   if nMeasurements is not None:
      if paramDict.get('nMeasurements', None) != nMeasurements:
         writeFile('/sys/nb/n_measurements', str(nMeasurements))
         paramDict['nMeasurements'] = nMeasurements

   if unrollCount is not None:
      if paramDict.get('unrollCount', None) != unrollCount:
         writeFile('/sys/nb/unroll_count', str(unrollCount))
         paramDict['unrollCount'] = unrollCount

   if loopCount is not None:
      if paramDict.get('loopCount', None) != loopCount:
         writeFile('/sys/nb/loop_count', str(loopCount))
         paramDict['loopCount'] = loopCount

   if warmUpCount is not None:
      if paramDict.get('warmUpCount', None) != warmUpCount:
         writeFile('/sys/nb/warm_up', str(warmUpCount))
         paramDict['warmUpCount'] = warmUpCount

   if initialWarmUpCount is not None:
      if paramDict.get('initialWarmUpCount', None) != initialWarmUpCount:
         writeFile('/sys/nb/initial_warm_up', str(initialWarmUpCount))
         paramDict['initialWarmUpCount'] = initialWarmUpCount

   if alignmentOffset is not None:
      if paramDict.get('alignmentOffset', None) != alignmentOffset:
         writeFile('/sys/nb/alignment_offset', str(alignmentOffset))
         paramDict['alignmentOffset'] = alignmentOffset

   if codeOffset is not None:
      if paramDict.get('codeOffset', None) != codeOffset:
         writeFile('/sys/nb/code_offset', str(codeOffset))
         paramDict['codeOffset'] = codeOffset

   if drainFrontend is not None:
      if paramDict.get('drainFrontend', None) != drainFrontend:
         writeFile('/sys/nb/drain_frontend', str(int(drainFrontend)))
         paramDict['drainFrontend'] = drainFrontend

   if aggregateFunction is not None:
      if paramDict.get('aggregateFunction', None) != aggregateFunction:
         writeFile('/sys/nb/agg', aggregateFunction)
         paramDict['aggregateFunction'] = aggregateFunction

   if range is not None:
      if paramDict.get('range', None) != range:
         writeFile('/sys/nb/output_range', str(int(range)))
         paramDict['range'] = range

   if basicMode is not None:
      if paramDict.get('basicMode', None) != basicMode:
         writeFile('/sys/nb/basic_mode', str(int(basicMode)))
         paramDict['basicMode'] = basicMode

   if noMem is not None:
      if paramDict.get('noMem', None) != noMem:
         writeFile('/sys/nb/no_mem', str(int(noMem)))
         paramDict['noMem'] = noMem

   if noNormalization is not None:
      if paramDict.get('noNormalization', None) != noNormalization:
         writeFile('/sys/nb/no_normalization', str(int(noNormalization)))
         paramDict['noNormalization'] = noNormalization

   if verbose is not None:
      if paramDict.get('verbose', None) != verbose:
         writeFile('/sys/nb/verbose', str(int(verbose)))
         paramDict['verbose'] = verbose

   if endToEnd is not None:
      if paramDict.get('endToEnd', None) != endToEnd:
         writeFile('/sys/nb/end_to_end', str(int(endToEnd)))
         paramDict['endToEnd'] = endToEnd


def resetNanoBench():
   with open('/sys/nb/reset') as resetFile: resetFile.read()
   paramDict.clear()


def _getNanoBenchOutput(procFile, code, codeObjFile, codeBinFile,
                                  init, initObjFile, initBinFile,
                                  lateInit, lateInitObjFile, lateInitBinFile,
                                  oneTimeInit, oneTimeInitObjFile, oneTimeInitBinFile, cpu, detP23):
   with open('/sys/nb/clear') as clearFile: clearFile.read()

   tmpCodeBinFile = '/tmp/ramdisk/code.bin'
   if createBinaryFile(tmpCodeBinFile, code, codeObjFile, codeBinFile):
      writeFile('/sys/nb/code', tmpCodeBinFile)

   tmpInitBinFiles = []
   if detP23:
      tmpP23BinFile = '/tmp/ramdisk/p23.bin'
      tmpInitBinFiles.append(tmpP23BinFile)
      createBinaryFile(tmpP23BinFile, asm=detP23Asm)
   tmpInitMainBinFile = '/tmp/ramdisk/init_main.bin'
   if createBinaryFile(tmpInitMainBinFile, init, initObjFile, initBinFile):
      tmpInitBinFiles.append(tmpInitMainBinFile)
   if tmpInitBinFiles:
      tmpInitBinFile = '/tmp/ramdisk/init.bin'
      with open(tmpInitBinFile, 'wb') as initBin:
         for filename in tmpInitBinFiles:
            with open(filename, 'rb') as f:
               initBin.write(f.read())
      writeFile('/sys/nb/init', tmpInitBinFile)

   tmpLateInitBinFile = '/tmp/ramdisk/late_init.bin'
   if createBinaryFile(tmpLateInitBinFile, lateInit, lateInitObjFile, lateInitBinFile):
      writeFile('/sys/nb/late_init', tmpLateInitBinFile)

   tmpOneTimeInitBinFile = '/tmp/ramdisk/one_time_init.bin'
   if createBinaryFile(tmpOneTimeInitBinFile, oneTimeInit, oneTimeInitObjFile, oneTimeInitBinFile):
      writeFile('/sys/nb/one_time_init', tmpOneTimeInitBinFile)

   try:
      if cpu is None:
         output = readFile(procFile)
      else:
         output = subprocess.check_output(['taskset', '-c', str(cpu), 'cat', procFile]).decode()
   except Exception as e:
      print('nanoBench failed; details might be available from dmesg', file=sys.stderr)
      sys.exit()

   return output


# code, codeObjFile, codeBinFile cannot be specified at the same time (same for init, initObjFile and initBinFile)
def runNanoBench(code='', codeObjFile=None, codeBinFile=None,
                 init='', initObjFile=None, initBinFile=None,
                 lateInit='', lateInitObjFile=None, lateInitBinFile=None,
                 oneTimeInit='', oneTimeInitObjFile=None, oneTimeInitBinFile=None, cpu=None, detP23=False):
   output = _getNanoBenchOutput('/proc/nanoBench', code, codeObjFile, codeBinFile,
                                                   init, initObjFile, initBinFile,
                                                   lateInit, lateInitObjFile, lateInitBinFile,
                                                   oneTimeInit, oneTimeInitObjFile, oneTimeInitBinFile, cpu, detP23)

   ret = OrderedDict()
   for line in output.split('\n'):
      if not ':' in line: continue
      lineSplit = line.split(':')
      counter = lineSplit[0].strip()
      if paramDict.get('range'):
         value = tuple(map(float, re.match(r' (.*) \[(.*);(.*)\]', lineSplit[1]).groups()))
      else:
         value = float(lineSplit[1].strip())
      ret[counter] = value
   return ret


# code, codeObjFile, codeBinFile cannot be specified at the same time (same for init, initObjFile and initBinFile)
def runNanoBenchCycleByCycle(code='', codeObjFile=None, codeBinFile=None,
                             init='', initObjFile=None, initBinFile=None,
                             lateInit='', lateInitObjFile=None, lateInitBinFile=None,
                             oneTimeInit='', oneTimeInitObjFile=None, oneTimeInitBinFile=None, cpu=None, detP23=False):
   prevConfig = paramDict.get('config', '')
   if not paramDict.get('endToEnd'):
      curConfig = prevConfig +  '\n'
      curConfig += '79.30 IDQ.MS_UOPS_internal\n'
      curConfig += 'C0.00 INST_RETIRED_internal\n'
      setNanoBenchParameters(config=curConfig)

   output = _getNanoBenchOutput('/proc/nanoBenchCycleByCycle', code, codeObjFile, codeBinFile,
                                                               init, initObjFile, initBinFile,
                                                               lateInit, lateInitObjFile, lateInitBinFile,
                                                               oneTimeInit, oneTimeInitObjFile, oneTimeInitBinFile, cpu, detP23)

   if not paramDict.get('endToEnd'):
      setNanoBenchParameters(config=prevConfig)

   nbDict = OrderedDict()
   for line in output.split('\n'):
      if not ',' in line: continue
      lineSplit = line.split(',')
      counter = lineSplit[0].strip()
      valueEmpty = int(lineSplit[1])
      valueEmptyWithLfence = int(lineSplit[2])
      minValues = []
      maxValues = []
      if paramDict.get('range'):
         values = list(map(int, lineSplit[3::3]))
         minValues = list(map(int, lineSplit[4::3]))
         maxValues = list(map(int, lineSplit[5::3]))
      else:
         values = list(map(int, lineSplit[3:]))
      nbDict[counter] = (valueEmpty, valueEmptyWithLfence, values, minValues, maxValues)

   if paramDict.get('verbose'):
      print('\n'.join((k + ': ' + str(v)) for k, v in nbDict.items()))

   if paramDict.get('endToEnd'):
      return OrderedDict((k, (v, vMin, vMax)) for k, (_, _, v, vMin, vMax) in nbDict.items() if "_internal" not in k)
   else:
      instRetired = nbDict['INST_RETIRED_internal'][2]
      if len(instRetired) < 3:
         return None
      if (instRetired[-1] == instRetired[-2]) or (instRetired[-2] != instRetired[-3]):
         return None
      cycleLastInstrRetired = min(i for i, v in enumerate(instRetired) if v == instRetired[-2])

      msUops = nbDict['IDQ.MS_UOPS_internal'][2]
      cycleOfLfenceUop = max((i for i, v in enumerate(msUops) if v < msUops[-1] and msUops[i] == msUops[i+1]), default=None)
      if cycleOfLfenceUop is None:
         return None

      result = OrderedDict()
      for k, (valueEmpty, valueEmptyWithLfence, values, minValues, maxValues) in nbDict.items():
         if "_internal" in k: continue

         leftMin = values[0]
         rightMax = values[-1]

         if any((x in k.upper()) for x in ['RETIRE']):
            leftMin = valueEmpty
            if 'UOP' in k.upper():
               rightMax = values[-1] - (valueEmptyWithLfence - valueEmpty)
            else:
               rightMax = values[cycleLastInstrRetired]
         elif any((x in k.upper()) for x in ['ISSUE']):
            rightMax = values[cycleLastInstrRetired-1] - (valueEmpty - values[0])
         elif 'IDQ' in k:
            rightMax = values[cycleOfLfenceUop - 1]

         result[k] = tuple([max(0, min(v, rightMax) - leftMin) for v in vx[:cycleLastInstrRetired + 1]] for vx in [values, minValues, maxValues])

      return result


detP23Asm = ("push rax; push rcx; push rdx;" # save registers
             "mov ecx, 0x186; rdmsr; push rax; push rdx;" # save IA32_PERFEVTSEL0
             "mov ecx, 0x0C1; rdmsr; push rax; push rdx;" # save IA32_PMC0
             "mov ecx, 0x38F; rdmsr; push rax; push rdx;" # save IA32_PERF_GLOBAL_CTRL
             "mov ecx, 0x38F; mov eax, 0; mov edx, 0; wrmsr;" # disable all counters
             "mov ecx, 0x186; mov eax, 0x4204A1; mov edx, 0; wrmsr;" # count UOPS_DISPATCHED_PORT.PORT_2 on counter 0
             "mov ecx, 0x0C1; mov eax, 0; mov edx, 0; wrmsr;" # clear counter 0
             "mov ecx, 0x38F; mov eax, 1; mov edx, 0; wrmsr;" # enable counter 0
             "mov eax, [rsp];" # perform one memory access
             "mov ecx, 0x38F; mov eax, 0; mov edx, 0; wrmsr;" # disable counter 0
             "mov ecx, 0; rdpmc;" # read counter 0
             "test eax, eax;"
             "lfence;"
             "jnz end;"
             "mov eax, [rsp];" # perform another access if first access was not on port 2
             "end:"
             "mov ecx, 0x38F; pop rdx; pop rax; wrmsr;" # restore IA32_PERF_GLOBAL_CTRL
             "mov ecx, 0x0C1; pop rdx; pop rax; wrmsr;" # restore IA32_PMC0
             "mov ecx, 0x186; pop rdx; pop rax; wrmsr;" # restore IA32_PERFEVTSEL0
             "pop rdx; pop rcx; pop rax;") # restore registers


def createRamdisk():
   try:
      subprocess.check_output('mkdir -p /tmp/ramdisk; mount -t tmpfs -o size=100M none /tmp/ramdisk/', shell=True)
   except subprocess.CalledProcessError as e:
      sys.exit('Could not create ramdisk ' + e.output)

def deleteRamdisk():
   try:
      subprocess.check_output('umount -l /tmp/ramdisk/', shell=True)
   except subprocess.CalledProcessError as e:
      sys.exit('Could not delete ramdisk ' + e.output)


def cleanup():
   if prevNMIWatchdogState != '0':
      writeFile('/proc/sys/kernel/nmi_watchdog', prevNMIWatchdogState)
   deleteRamdisk()


if os.geteuid() != 0:
   sys.exit('Error: nanoBench requires root privileges\nTry "sudo ' + sys.argv[0] + ' ..."')

if not os.path.exists('/sys/nb'):
   sys.exit('Error: nanoBench kernel module not loaded\nLoad with "sudo insmod kernel/nb.ko"')

if readFile('/sys/devices/system/cpu/smt/active').startswith('1'):
   print('Note: Hyper-threading is enabled; it can be disabled with "sudo ./disable-HT.sh"', file=sys.stderr)

prevNMIWatchdogState = readFile('/proc/sys/kernel/nmi_watchdog').strip()
if prevNMIWatchdogState != '0':
   writeFile('/proc/sys/kernel/nmi_watchdog', '0')

resetNanoBench()
createRamdisk()
atexit.register(cleanup)
