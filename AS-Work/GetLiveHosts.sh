#!/bin/bash
mkdir Outputs
nmap -iL targets.txt > Outputs/UpHosts
nmap -n -sn -iL targets.txt -oG - | awk '/Up$/{print $2}' > Outputs/LiveIPs
