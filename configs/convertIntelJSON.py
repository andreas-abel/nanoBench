#!/usr/bin/env python3

import argparse
import requests

parser = argparse.ArgumentParser(description='Converts JSON files from https://download.01.org/perfmon/')
parser.add_argument('url', help='URL of JSON file')
parser.add_argument('-offcore', help='Convert offcore events', action='store_true')
args = parser.parse_args()

print('# Based on ' + args.url)

mapFile = requests.get('https://download.01.org/perfmon/mapfile.csv')
famMod = []
for l in mapFile.iter_lines():
    fields = l.decode().split(',')
    if args.url.endswith(fields[2]):
        famMod.append(fields[0].replace('GenuineIntel-', ''))
if famMod:
    print('# Applies to processors with family-model in {' + str(famMod).replace("'", '')[1:-1] + '}')

json = requests.get(args.url).json()
allCtrs = max([ev['Counter'] for ev in json if not 'Fixed' in ev['Counter']], key=len)
if '0,1,2,3' in allCtrs:
    allCtrs = '0,1,2,3' # nanoBench does not use counters >= 4

evDescriptions = []
for ev in sorted(json, key=lambda x: (x['EventCode'].upper(), x['UMask'].upper())):
    if ('Fixed' in ev['Counter']) or (ev['Counter'] in ['32', '33', '34', '35']):
        continue
    if ev.get('Deprecated') == '1':
        continue
    if ev['EventName'] == 'OFFCORE_RESPONSE':
        continue
    if int(ev['Offcore']) != int(args.offcore):
        continue

    configList = []
    configList.append(ev['EventCode'][2:4].upper().zfill(2))
    configList.append(ev['UMask'][2:4].upper().zfill(2))
    if ev['CounterMask'] != '0':
        configList.append('CMSK=' + ev['CounterMask'])
    if ev.get('AnyThread') == '1':
        configList.append('AnyT')
    if ev['EdgeDetect'] == '1':
        configList.append('EDG')
    if ev['Invert'] == '1':
        configList.append('INV')

    if '3F6' in ev['MSRIndex'].upper():
        configList.append('MSR_3F6H=' + ev['MSRValue'].strip())
    if '1A6' in ev['MSRIndex'].upper():
        configList.append('MSR_RSP0=' + ev['MSRValue'].strip())

    if allCtrs not in ev['Counter']:
        configList.append('CTR=' + ev['Counter'].split(',')[0])

    if (ev.get('TakenAlone') == '1') or any(('MSR' in c) for c in configList):
        configList.append('TakenAlone')

    evDescriptions.append(('.'.join(configList), ev['EventName'], ev['BriefDescription']))

for evDesc in sorted(evDescriptions):
    print()
    print('# ' + evDesc[2])
    print(evDesc[0] + ' ' + evDesc[1])
