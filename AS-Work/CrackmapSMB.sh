#!/bin/bash
mkdir Outputs
mkdir temp
crackmapexec smb Outputs/LiveIPs > temp/Crackmap
cat temp/Crackmap | awk '{print $2}' > temp/CrackIPs
cat temp/Crackmap | awk '{print $2, $12}' > Outputs/Domains
cat temp/Crackmap | awk '{print $2, $13, $14}' > Outputs/SMB-Details
crackmapexec smb temp/Crackips -u '' -p '' --local-auth |awk '/+/ {print}' > Outputs/SMBAuthBypass
