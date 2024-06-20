#!/bin/bash

mkdir Outputs
mkdir temp
echo 'Creating A List of Live Hosts'
nmap -iL targets.txt > Outputs/UpHosts
#create file called targets.txt for the scope
nmap -n -sn -iL targets.txt -oG - | awk '/Up$/{print $2}' > temp/Int_LH
crackmapexec smb Int_LH | awk '{print $2}' > temp/SMB-UsableIPs
#Run nmap command on targets.txt and output IPs to a file called Int_LH
echo 'Getting Domain and SMB Details'
cat temp/UsableIPS | awk '{print $2, $12}' > Outputs/Domains
#Creates a list of Domain names and the IPs under it
cat temp/UsableIPS | awk '{print $2, $13, $14}' > SMB-Details
#Prints SMBv1 and SMB signing information
echo 'Starting Authentication Bypass'
crackmapexec smb temp/SMB-UsableIPs -u '' -p '' --local-auth > temp/SMB-AuthBypass
#tests for smb authentication bypass 
cat temp/SMB-AuthBypass | awk '/SMB/{print $2}' > temp/Pre-SMB-IPs
sort temp/Pre-SMB-IPs | uniq > temp/SMB-IPs
#creates a list for test rechecks
cat temp/SMB-AuthBypass | awk '/+/{print}' > Outputs/SMB-AuthBypass
#makes a list of hosts that are vulnerable to authentication bypass
cat temp/SMB-AuthBypass | awk '/+/{print $4}' > temp/Name-Check
#creates a list of hosts names from the Authentication bypass test for later use
echo 'Enumerating Shares'
touch Outputs/Shares
echo '--------------------------------------------------    Shares        Permissions       Remark    -------------------------------------------' > Outputs/Shares
crackmapexec smb temp/SMB-IPs -u '' -p '' --shares | awk '!/[[*]]/{print}' | awk '!/[[-]]/{print}' | awk '!/[[+]]/{print}' | awk '!/-----/{print}' | awk '!/Share/{print}' | sort -n | tee -a Outputs/Shares
#sets up and organizes data for a list of Shares taken from hosts
          
#awk 'FNR==NR {a[$1]; next} $4 in a' file1 file2
#removes every line from file2 except lines that contain anything from file1
#$1 gets everything from the First collum in every line of file1
#$4 compares the input from file1 to the 4th collum of every line in file2
