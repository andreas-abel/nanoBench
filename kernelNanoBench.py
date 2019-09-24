import atexit
import collections
import subprocess
import sys

PFC_START_ASM = '.quad 0xE0b513b1C2813F04'
PFC_STOP_ASM = '.quad 0xF0b513b1C2813F04'

def writeFile(fileName, content):
   with open(fileName, 'w') as f:
      f.write(content);

def assemble(code, objFile, asmFile='/tmp/ramdisk/asm.s'):
   try:
      code = '.intel_syntax noprefix;' + code + ';1:;.att_syntax prefix\n'
      with open(asmFile, 'w') as f: f.write(code);
      subprocess.check_call(['as', asmFile, '-o', objFile])
   except subprocess.CalledProcessError as e:
      sys.stderr.write("Error (assemble): " + str(e))
      sys.stderr.write(asm)
      exit(1)


def objcopy(sourceFile, targetFile):
   try:
      subprocess.check_call(['objcopy', sourceFile, '-O', 'binary', targetFile])
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


ramdiskCreated = False
paramDict = dict()

# Assumes that no changes to the corresponding files in /sys/nb/ were made since the last call to setNanoBenchParameters().
# Otherwise, reset() needs to be called first.
def setNanoBenchParameters(config=None, configFile=None, msrConfig=None, msrConfigFile=None, nMeasurements=None, unrollCount=None, loopCount=None,
                           warmUpCount=None, initialWarmUpCount=None, aggregateFunction=None, basicMode=None, noMem=None, verbose=None):
   if not ramdiskCreated: createRamdisk()

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
                 oneTimeInit='', oneTimeInitObjFile=None, oneTimeInitBinFile=None):
   if not ramdiskCreated: createRamdisk()
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

   if oneTimeInit:
      oneTimeInitObjFile = '/tmp/ramdisk/one_time_init.o'
      assemble(oneTimeInit, oneTimeInitObjFile)
   if oneTimeInitObjFile is not None:
      objcopy(oneTimeInitObjFile, '/tmp/ramdisk/one_time_init.bin')
      writeFile('/sys/nb/one_time_init', '/tmp/ramdisk/one_time_init.bin')
   elif oneTimeInitBinFile is not None:
      writeFile('/sys/nb/one_time_init', oneTimeInitBinFile)

   with open('/proc/nanoBench') as resultFile:
      output = resultFile.read().split('\n')

   ret = collections.OrderedDict()
   for line in output:
      if not ':' in line: continue
      line_split = line.split(':')
      counter = line_split[0].strip()
      value = float(line_split[1].strip())
      ret[counter] = value

   return ret


def createRamdisk():
   try:
      subprocess.check_output('mkdir -p /tmp/ramdisk; sudo mount -t tmpfs -o size=100M none /tmp/ramdisk/', shell=True)
      global ramdiskCreated
      ramdiskCreated = True
   except subprocess.CalledProcessError as e:
      sys.stderr.write('Could not create ramdisk ' + e.output + '\n')
      exit(1)

def deleteRamdisk():
   if ramdiskCreated:
      try:
         subprocess.check_output('umount -l /tmp/ramdisk/', shell=True)
      except subprocess.CalledProcessError as e:
         sys.stderr.write('Could not delete ramdisk ' + e.output + '\n')

atexit.register(deleteRamdisk)