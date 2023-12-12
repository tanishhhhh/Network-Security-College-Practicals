#Network Security College Practicals

#Ceaser Cipher
```
letters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
message = input("Enter Your Message")
key = int(input("Enter key"))
i = 0

while i < len(message):
    p = (letters.rfind(message[i]))
    print(letters[(p + key) % 26])
    i += 1

```

#monoaplhabetic
```
  def monoalpha():
    import random
    alphabets = "ABCDEFGHIJKLMOPQRTUVWXYZ"
    alphabets_list = list(alphabets)
    random.shuffle(alphabets_list)
    return "".join(alphabets_list)


def encrypt(message, key):
    alphabets = "ABCDEFGHIJKLMOPQRTUVWXYZ"
    message = message.upper()
    ciphertext = " "

    for char in message:
        if char in alphabets:
            index = alphabets.index(char)
            ciphertext += key[index]
        else:
            ciphertext += char

            return ciphertext


def main():
    key = monoalpha()
    message = "Tanu"
    encrypt_message = encrypt(message, key)
    print(encrypt_message)


if __name__ == "__main__":
    main()

```



#RSA
```
import math


def gcd(a, h):
    temp = 0
    while 1:
        temp = a % h
        if temp == 0:
            return h
        a = h
        h = temp


p = 3
q = 7
n = p * q
e = 2
phi = (p - 1) * (q - 1)

while e < phi:

    if gcd(e, phi) == 1:
        break
    else:
        e = e + 1

k = 2
d = (1 + (k * phi)) / e

msg = 12.0

print("Message data = ", msg)

c = pow(msg, e)
c = math.fmod(c, n)
print("Encrypted data = ", c)

m = pow(c, d)
m = math.fmod(m, n)
print("Original Message Sent = ", m)
```

#DES
```
import base32hex
import hashlib
from Crypto.Cipher import DES

password = "Password"
salt = '\x28\xAB\xBC\xCD\xDE\xEF\x00\x33'
key = password + salt
m = hashlib.md5(key)
key = m.digest()
(dk, iv) = (key[:8], key[8:])
crypter = DES.new(dk, DES.MODE_CBC, iv)

plain_text = "I see you"

print("The plain text is : ", plain_text)
plain_text += '\x00' * (8 - len(plain_text) % 8)
ciphertext = crypter.encrypt(plain_text)
encode_string = base32hex.b32encode(ciphertext)
print("The encoded string is : ", encode_string)
```

#Wilcard mask
```
Subnet mask: 255.255.255.224
Wildcard mask: 0.0.0.31

Subnet mask: 255.255.255.240
Wildcard mask: 0.0.0.15

Subnet mask: 255.255.255.192
Wildcard mask: 0.0.0.63
```

#Vernam Cipher
```

def stringEncryption(text, key):
	
	cipherText = ""

	
	cipher = []
	for i in range(len(key)):
		cipher.append(ord(text[i]) - ord('A') + ord(key[i])-ord('A'))


	for i in range(len(key)):
		if cipher[i] > 25:
			cipher[i] = cipher[i] - 26

	
	for i in range(len(key)):
		x = cipher[i] + ord('A')
		cipherText += chr(x)


	return cipherText



def stringDecryption(s, key):

	
	plainText = ""



	plain = []



	for i in range(len(key)):
		plain.append(ord(s[i]) - ord('A') - (ord(key[i]) - ord('A')))

	
	for i in range(len(key)):
		if (plain[i] < 0):
			plain[i] = plain[i] + 26



	for i in range(len(key)):
		x = plain[i] + ord('A')
		plainText += chr(x)


	return plainText


plainText = "Hello"


key = "MONEY"



encryptedText = stringEncryption(plainText.upper(), key.upper())


print("Cipher Text - " + encryptedText)


print("Message - " + stringDecryption(encryptedText, key.upper()))
```


# DES Algorithm 
```

import base32hex
import hashlib
from Crypto.Cipher import DES
password = "Password"
salt = '\x28\xAB\xBC\xCD\xDE\xEF\x00\x33'
key = password + salt
m = hashlib.md5(key)
key = m.digest()
(dk, iv) =(key[:8], key[8:])
crypter = DES.new(dk, DES.MODE_CBC, iv)

plain_text= "I see you"

print("The plain text is : ",plain_text)
plain_text += '\x00' * (8 - len(plain_text) % 8)
ciphertext = crypter.encrypt(plain_text)
encode_string= base32hex.b32encode(ciphertext)
print("The encoded string is : ",encode_string)
```


#Diffie-Hellman
```
import random

# Shared prime and base values (these should be agreed upon by both parties)
prime = 23
base = 5

# Generate a random private key for each party
private_key_A = random.randint(1, 100)
private_key_B = random.randint(1, 100)

# Calculate public keys for both parties
public_key_A = (base ** private_key_A) % prime
public_key_B = (base ** private_key_B) % prime

# Simulate the exchange of public keys (in a real-world scenario, this should be done securely)
shared_secret_key_A = (public_key_B ** private_key_A) % prime
shared_secret_key_B = (public_key_A ** private_key_B) % prime

# The shared_secret_key_A and shared_secret_key_B should be equal and can be used as a symmetric key
print("Shared Secret Key (Party A):", shared_secret_key_A)
print("Shared Secret Key (Party B):", shared_secret_key_B)
```



















#Cisco Packet Tracer
#Practical 01 
```
1]

R1(config)# router ospf 1
R1(config-router)# area 0 authentication message-digest
R2(config)# router ospf 1
R2(config-router)# area 0 authentication message-digest
R3(config)# router ospf 1
R3(config-router)# area 0 authentication message-digest

2] 

R1(config)# interface s0/0/0
R1(config-if)# ip ospf message-digest-key 1 md5 MD5pa55
R2(config)# interface s0/0/0
R2(config-if)# ip ospf message-digest-key 1 md5 MD5pa55
R2(config-if)# interface s0/0/1
R2(config-if)# ip ospf message-digest-key 1 md5 MD5pa55
R3(config)# interface s0/0/1
R3(config-if)# ip ospf message-digest-key 1 md5 MD5pa55

3] 
 
On PC-A, click NTP under the Services tab to verify NTP service is enabled.

To configure NTP authentication, click Enable under Authentication. Use key 1 and password NTPpa55 for authentication. 

R1(config)# ntp server 192.168.1.5
R2(config)# ntp server 192.168.1.5
R3(config)# ntp server 192.168.1.5

4] 

R1(config)# ntp update-calendar
R2(config)# ntp update-calendar
R3(config)# ntp update-calendar

5] 

R1(config)# ntp authenticate
R1(config)# ntp trusted-key 1
R1(config)# ntp authentication-key 1 md5 NTPpa55
R2(config)# ntp authenticate
R2(config)# ntp trusted-key 1
R2(config)# ntp authentication-key 1 md5 NTPpa55
R3(config)# ntp authenticate
R3(config)# ntp trusted-key 1
R3(config)# ntp authentication-key 1 md5 NTPpa55

6] 

R1(config)# service timestamps log datetime msec
R2(config)# service timestamps log datetime msec
R3(config)# service timestamps log datetime msec

7]

R1(config)# logging host 192.168.1.6
R2(config)# logging host 192.168.1.6
R3(config)# logging host 192.168.1.6

8] 

R3(config)# ip domain-name ccnasecurity.com
R3(config)# line vty 0 4
R3(config-line)# login local
R3(config-line)# transport input ssh

9] 

R3(config)# crypto key zeroize rsa
R3(config)# crypto key generate rsa

How many bits in the modulus [512]: 1024
% Generating 1024 bit RSA keys, keys will be non-exportable...[OK]

10] 

R3(config)# ip ssh time-out 90
R3(config)# ip ssh authentication-retries 2
R3(config)# ip ssh version 2

11] 

From PC-C:
PC> telnet 192.168.3.1
PC> ssh –l SSHadmin 192.168.3.1

R2# ssh –v 2 –l SSHadmin 10.2.2.1
```

#Practical 02 AAA 
```
1] 

R1(config)# username Admin1 secret admin1pa55
R1(config)# aaa new-model
R1(config)# aaa authentication login default local
R1(config)# line console 0 
R1(config-line)# login authentication default 
R1(config-line)# end
%SYS-5-CONFIG_I: Configured from console by console
R1# exit
User Access Verification
Username: Admin1
Password: admin1pa55 
R1>
R1(config)# ip domain-name ccnasecurity.com
R1(config)# crypto key generate rsa
R1(config)# aaa authentication login SSH-LOGIN local
R1(config)# line vty 0 4
R1(config-line)# login authentication SSH-LOGIN
R1(config-line)# transport input ssh 
R1(config-line)#end
PC> ssh –l Admin1 192.168.1.1
Open
Password: admin1pa55


2] 

R2(config)# username Admin2 secret admin2pa55
R2(config)# aaa new-model
R2(config)# aaa authentication login default group tacacs+ local
R2(config)# line console 0
R2(config-line)# login authentication default
R2(config-line)# end
R2# exit
Username: Admin2
Password: admin2pa55
R2>

3] 

R3(config)# username Admin3 secret admin3pa55
R3(config)# aaa new-model
R3(config)# aaa authentication login default group radius local
R3(config)# line console 0
R3(config-line)# login authentication default
R3(config-line)# end
R3# exit
Username: Admin3
Password: admin3pa55 
R3>
```

#Practical 04 Firewall
```
R3(config)# license boot module c1900 technology-package securityk9 
R3(config)# zone security IN-ZONE
R3(config-sec-zone) exit
R3(config-sec-zone)# zone security OUT-ZONE
 R3(config-seczone)# exit 
R3(config)# access-list 101 permit ip 192.168.3.0 0.0.0.255 any
R3(config)# class-map type inspect match-all IN-NET-CLASS-MAP R3(config-cmap)# match access-group 101 R3(config-cmap)# exit
R3(config)# policy-map type inspect IN-2-OUT-PMAP
R3(config-pmap)# class type inspect IN-NET-CLASS-MAP
R3(config-pmap-c)# inspect
R3(config-pmap-c)# exit
R3(config-pmap)# exit
R3(config)# zone-pair security IN-2-OUT-ZPAIR source IN-ZONE destination OUTZONE
R3(config-sec-zone-pair)# service-policy type inspect IN-2-OUT-PMAP
R3(config-sec-zone-pair)# exit
R3(config)# 
R3(config)# interface g0/1
R3(config-if)# zone-member security IN-ZONE
R3(config-if)# exit
R3(config)# interface s0/0/1
R3(config-if)# zone-member security OUT-ZONE 
R3(config-if)#exit
R3# show policy-map type inspect zone-pair sessions
```
