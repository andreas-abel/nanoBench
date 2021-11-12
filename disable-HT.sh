#!/usr/bin/env bash

if [ "$EUID" -ne 0 ]; then
    echo "This script must be run as root" >&2
    echo "Try \"sudo ./disable-HT.sh\"" >&2
    exit 1
fi

echo off > /sys/devices/system/cpu/smt/control
