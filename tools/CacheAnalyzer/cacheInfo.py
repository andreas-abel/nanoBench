#!/usr/bin/python
import argparse

from cacheLib import *

import logging
log = logging.getLogger(__name__)


def main():
   parser = argparse.ArgumentParser(description='Cache Information')
   parser.add_argument("-logLevel", help="Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)", default='INFO')
   args = parser.parse_args()

   logging.basicConfig(stream=sys.stdout, format='%(message)s', level=logging.getLevelName(args.logLevel))

   cpuidInfo = getCpuidCacheInfo()

   print ''
   print getCacheInfo(1)
   print getCacheInfo(2)
   if 'L3' in cpuidInfo:
      print getCacheInfo(3)


if __name__ == "__main__":
    main()
