#!/usr/bin/env bash

if [ "$EUID" -ne 0 ]; then
    echo "This script must be run as root" 1>&2
    exit 1
fi

for cpu in /sys/devices/system/cpu/cpu[1-9]*; do
    echo 0 > "$cpu/online"
done
