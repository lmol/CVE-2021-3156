#!/bin/bash
if [ "$EUID" -eq 0 ]
  then echo "Please do not run as root"
  exit
fi
#gdb tiene que tener suid para poder ejecutar gdb sudoedit sin ser root
sudo chmod +s /usr/bin/gdb
#echo 0|sudo tee /proc/sys/kernel/randomize_va_space
env -i gdb -q -x fengshui.py
sudo chmod -s /usr/bin/gdb
