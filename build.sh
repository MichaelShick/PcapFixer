#!/bin/bash
gcc -o output pcap_editor.c
sleep 1
sudo ./output
rm output