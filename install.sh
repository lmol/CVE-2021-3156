#!/bin/bash
if [ "$EUID" -eq 0 ]
  then echo "Please do not run as root"
  exit
fi
sudo apt update -y
sudo apt install -y gdb gcc make python3-distro dpkg-dev
#python3-pip
#pip3 install distro
mkdir symbols
#Ubuntu 16
#curl https://bootstrap.pypa.io/pip/2.7/get-pip.py --output get-pip.py