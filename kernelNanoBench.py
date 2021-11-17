import atexit
import collections
import os
import subprocess
import sys

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
         code = code.replace('|10',  'byte 0x66,0x2e,0x0f,0x1f,0x84,0x00,0x00,0x00,0x00,0x00;')
         code = code.replace('|9',  '.byte 0x66,0x0f,0x1f,0x84,0x00,0x00,0x00,0x00,0x00;')
         code = code.replace('|8',  '.byte 0x0f,0x1f,0x84,0x00,0x00,0x00,0x00,0x00;')
         code = code.replace('|7',  '.byte 0x0f,0x1f,0x80,0x00,0x00,0x00,0x00;')
         code = code.replace('|6',  '.byte 0x66,0x0f,0x1f,0x44,0x00,0x00;')
         code = code.replace('|5',  '.byte 0x0f,0x1f,0x44,0x00,0x00;')
         code = code.replace('|4',  '.byte 0x0f,0x1f,0x40,0x00;')
         code = code.replace('|3',  '.byte 0x0f,0x1f,0x00;')
         code = code.replace('|2',  '.byte 0x66,0x90;')
         code = code.replace('|1',  'nop;')
         code = code.replace('|',   '')
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


def filecopy(sourceFile, targetFile):
   try:
      subprocess.check_call(['cp', sourceFile, targetFile])
   except subprocess.CalledProcessError as e:
      sys.stderr.write("Error (cp): " + str(e))
      exit(1)


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
                           aggregateFunction=None, basicMode=None, noMem=None, noNormalization=None, verbose=None):
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


def resetNanoBench():
   with open('/sys/nb/reset') as resetFile: resetFile.read()
   paramDict.clear()


# code, codeObjFile, codeBinFile cannot be specified at the same time (same for init, initObjFile and initBinFile)
def runNanoBench(code='', codeObjFile=None, codeBinFile=None,
                 init='', initObjFile=None, initBinFile=None,
                 lateInit='', lateInitObjFile=None, lateInitBinFile=None,
                 oneTimeInit='', oneTimeInitObjFile=None, oneTimeInitBinFile=None,
                 cpu=None):
   with open('/sys/nb/clear') as clearFile: clearFile.read()

   if code:
      codeObjFile = '/tmp/ramdisk/code.o'
      assemble(code, codeObjFile)
   if codeObjFile is not None:
      objcopy(codeObjFile, '/tmp/ramdisk/code.bin')
      writeFile('/sys/nb/code', '/tmp/ramdisk/code.bin')
   elif codeBinFile is not None:
      writeFile('/sys/nb/code', codeBinFile)

   if init:
      initObjFile = '/tmp/ramdisk/init.o'
      assemble(init, initObjFile)
   if initObjFile is not None:
      objcopy(initObjFile, '/tmp/ramdisk/init.bin')
      writeFile('/sys/nb/init', '/tmp/ramdisk/init.bin')
   elif initBinFile is not None:
      writeFile('/sys/nb/init', initBinFile)

   if lateInit:
      lateInitObjFile = '/tmp/ramdisk/late_init.o'
      assemble(lateInit, lateInitObjFile)
   if lateInitObjFile is not None:
      objcopy(lateInitObjFile, '/tmp/ramdisk/late_init.bin')
      writeFile('/sys/nb/late_init', '/tmp/ramdisk/late_init.bin')
   elif lateInitBinFile is not None:
      writeFile('/sys/nb/late_init', lateInitBinFile)

   if oneTimeInit:
      oneTimeInitObjFile = '/tmp/ramdisk/one_time_init.o'
      assemble(oneTimeInit, oneTimeInitObjFile)
   if oneTimeInitObjFile is not None:
      objcopy(oneTimeInitObjFile, '/tmp/ramdisk/one_time_init.bin')
      writeFile('/sys/nb/one_time_init', '/tmp/ramdisk/one_time_init.bin')
   elif oneTimeInitBinFile is not None:
      writeFile('/sys/nb/one_time_init', oneTimeInitBinFile)

   if cpu is None:
      output = readFile('/proc/nanoBench')
   else:
      try:
         output = subprocess.check_output(['taskset', '-c', str(cpu), 'cat', '/proc/nanoBench']).decode()
      except subprocess.CalledProcessError as e:
         sys.exit(e)

   ret = collections.OrderedDict()
   for line in output.split('\n'):
      if not ':' in line: continue
      line_split = line.split(':')
      counter = line_split[0].strip()
      value = float(line_split[1].strip())
      ret[counter] = value

   return ret


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
   writeFile('/proc/sys/kernel/nmi_watchdog', prevNMIWatchdogState)
   deleteRamdisk()


if os.geteuid() != 0:
   sys.exit('Error: nanoBench requires root privileges\nTry "sudo ' + sys.argv[0] + ' ..."')

if not os.path.exists('/sys/nb'):
   sys.exit('Error: nanoBench kernel module not loaded\nLoad with "sudo insmod kernel/nb.ko"')

if readFile('/sys/devices/system/cpu/smt/active').startswith('1'):
   print('Note: Hyper-threading is enabled; it can be disabled with "sudo ./disable-HT.sh"', file=sys.stderr)

prevNMIWatchdogState = readFile('/proc/sys/kernel/nmi_watchdog')
writeFile('/proc/sys/kernel/nmi_watchdog', '0')

resetNanoBench()
createRamdisk()
atexit.register(cleanup)
