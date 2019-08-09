#!/bin/bash

if [ "$EUID" -ne 0 ]; then
    echo "This script must be run as root" 1>&2
    exit 1
fi

if [ $# -eq 0 ]; then
    echo "Usage: sudo ./set-R14-size.sh <size>"
    echo "Example: sudo ./enable-HugePages.sh 128M"
    exit 1
fi

size=$(echo $1 | sed 's/[^0-9]//g')
suffix=$(echo $1 | sed 's/[0-9]//g')
  
if [[ "$suffix" == "M" ]]; then
    :
elif [[ "$suffix" == "G" ]]; then
    size=$(($size*1024))
else
    echo "invalid suffix"
    exit 1
fi

echo "$size" > /sys/nb/r14_size
cat /sys/nb/r14_size
