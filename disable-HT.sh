#!/usr/bin/env bash

if [ "$EUID" -ne 0 ]; then
    echo "This script must be run as root" 1>&2
    exit 1
fi

for cpu in /sys/devices/system/cpu/cpu[1-9]*; do
    if [ -e "$cpu/topology/thread_siblings_list" ]; then
        sibling=$(awk -F '[^0-9]' '{ print $2 }' $cpu/topology/thread_siblings_list)
        if [ ! -z $sibling ]; then
            echo 0 > "/sys/devices/system/cpu/cpu$sibling/online"
        fi
    fi
done
