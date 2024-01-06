# CSA_23_Preseason
# CTF Writeups
## Writeups for the ADF Cyber Skills Association Pre-Season challenges.

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

### Pretty Okay Privacy
Description
The following PGP public key is associated with a dark net market user. We suspect that the user has not one, but two PGP keys. What is the email address associated with the second PGP key? Write the answer like “email@domain.com”.

Flag format: FLAG{email@domain.com}

The PGP public key block is in the attachment. [Zip_File](https://github.com/gnarkill78/CSA_23_Preseason/blob/main/public_key_block76yfkgTiy.zip)

Solution: Putting the public key details into CyberChef reveals that the assocated email address is "samwhiskey@elude.in"
```
-----BEGIN PGP PUBLIC KEY BLOCK-----

mQENBF8OTz4BCAC6K+SGfZC8QsEhFOdZoZT3i1BtbBo6F0iNxFg7O644yDoDuu5K
Jd5fh+sOcAvad2JAC3Oqrkz+Fs4IroyNjnj2Nm1tZRYuMCFHK58bR3WN0BYCGjHI
UXTISnjwdw3DtZm1JnsJ2GbqQjptoPICazbrcyjHtxtFIjHwgfgIgqDJCfRB3Lts
5PuOGaGYQJOGsfZmqyTQUAtKbT7t252UgWvWRYwOPUj83PPF8JoJLwKe6t3Whogi
0YL1qILLOCFKjFc3udcjrRSr4A1fkFAObeheimOXFNuqA3III16L8nx6EXp8LEbz
Nn7YchtxUk8LMTc7ezt26cfCk1ATHLDfnvrrABEBAAG0IHNhbXdoaXNrZXkgPHNh
bXdoaXNrZXlAZWx1ZGUuaW4+iQFOBBMBCAA4FiEE/cFQy0FTq/ZiWLhjJbhKQf5S
qK4FAl8OTz4CGwMFCwkIBwIGFQoJCAsCBBYCAwECHgECF4AACgkQJbhKQf5SqK4k
3gf9GXv1iWJ2T7LElFhcXvkH97BFApVJYX4/4BDDL5nEMxghu95wFZXEKHt7tS9/
9EuBsyDseWW8ytRij3cn/ExXd6AoZtyWMssfE3VimwH7tjhiDXS2b4ci8L+rGnib
ie0OOBaa5IQg3GE2V9KfhZFlBbiSAIf1BKrUs4JmkabqulANCCV+uqavy8+tbgqk
MiP8uQQB0jQUPZ8y3azr2Xc7mPx4n8F6GOwQyUXKl4ZVBzpZ/Xj3POLAfWafkr9N
szfWrXuibWs7wBmmAYPu3wJYhUR7f70I4J6Kp5G2a0ptY7B9B2w7C2OpUaPGFbvD
f7t3XY/YcHgK+9kJYi+x8qvZ/rkBDQRfDk8+AQgAzSYftS+c3uIZ5r/BwGH3XXdH
oYCuyVXI61NGAMQMhvwTdSX/1tbUdPsV+P/6dBr7F4w+IdYgP5yYWKa4iygSWwAu
NwK9xhR7BCvtJMGRv5KDlrMUdCvSrbCfOJblAcm/h1fcjxd+k5VVrAxuc/OxP0zL
+qlp8idaFKvZfPPYnvacs29G0OMGYQ3z/RDCI638SjknqkkSzj7kvV/CI5DyX6wH
b9NNK8xi6Ruj+fgVvmCCe19jCMNY+TFiUFI2TmVbanzhtYbiBMZtdKIBu14v3n+a
wPjYgP7rLaSz+gnQBDNp90KYQdRM5HNJp4YquMpncAfvergOLFomcI1d0P9mHwAR
AQABiQE2BBgBCAAgFiEE/cFQy0FTq/ZiWLhjJbhKQf5SqK4FAl8OTz4CGwwACgkQ
JbhKQf5SqK69gwf/Whw0H2TM8CGQyI7sETarTxrMTRxE5osNQVnOD+rRD3hTPgSt
5noHJfcVdnmssC9GubaqQu7YCwSk+fQ+j/vMDVEzmB0k6WXQC+7bcsGUwdfuuJ3W
lzej3xYD8s4HvShJ2Ili+BiIptHMh9zUFUpGJ1N6bW7gzffRwXl8D89gfFq7ZMWL
uACUuy1Lr2zXkvd2c5BRtSXIWQyZUom8c73y7ixA6Z1xeVh4PI0B0aEbxQykSmBq
PMbdb8AwOOwSPn1nE7eo39UkB+frMPiNAQ7ZCxxY7zTSLnMQ0ZTgzBzvCIdNexYW
Eeh64qMxh+d1FIamp6ZbBzfRdBIpR3HhB/cS+Q==
=uJ72
-----END PGP PUBLIC KEY BLOCK-----
```

```
samwhiskey <samwhiskey@elude.in>
```
Jumping on to the OSINT Framework and searching the MIT PGP Key Server (Username > Specific Sites > MIT PGP Key Server), two results are returned:
```
Search results for 'samwhiskey'
Type bits/keyID     Date       User ID
pub  2048R/FE52A8AE 2020-07-15 samwhiskey <samwhiskey@elude.in>
pub  4096R/1F0376CA 2019-03-16 samwhiskey <samwhiskey@torbox3uiot6wch.onion>
```

:+1: FLAG{samwhiskey@torbox3uiot6wch.onion}
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

### PythonFlaskDefender
Description - I wrote my own blog framework! I just learned python flask recently, it's super easy to get started.

But apparently some kiddies thought it would be funny to hack my website and leak my files...

So I've had to implement some self-defense measures. Take that, skids!

URL port: 5000

Flag format: FLAG{you_have_found_the_flag}

Solution:
Heading to the URL, and testing for LFI, you can check for things such as /etc/passwd and /etc/shadow

I happened to try /proc/self/environ and got this
```
/proc/self/environ
HOSTNAME=ip-172-31-24-42.ap-southeast-2.compute.internalFLASK_RUN_APP=appPYTHON_PIP_VERSION=22.0.4SHLVL=2HOME=/rootGPG_KEY=E3FF2839C048B25C084DEBE9B26995E310250568AWS_EXECUTION_ENV=AWS_ECS_FARGATEECS_AGENT_URI=http://169.254.170.2/api/d26781c5276b4b8ebceaa40e94539429-792494206AWS_DEFAULT_REGION=ap-southeast-2PYTHON_GET_PIP_URL=https://github.com/pypa/get-pip/raw/5eaac1050023df1f5c98b173b248c260023f2278/public/get-pip.pyECS_CONTAINER_METADATA_URI_V4=http://169.254.170.2/v4/d26781c5276b4b8ebceaa40e94539429-792494206ECS_CONTAINER_METADATA_URI=http://169.254.170.2/v3/d26781c5276b4b8ebceaa40e94539429-792494206FLASK_RUN_HOST=0.0.0.0PATH=/usr/local/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/binLANG=C.UTF-8PYTHON_VERSION=3.9.14PYTHON_SETUPTOOLS_VERSION=58.1.0AWS_REGION=ap-southeast-2PWD=/PYTHON_GET_PIP_SHA256=5aefe6ade911d997af080b315ebcb7f882212d070465df544e1175ac2be519b4FLAG=FLAG{some_files_are_not_files}
```
Low and behold, the flag was sitting at the end

:+1: FLAG{some_files_are_not_files}
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

### Website Prank Paradox
Description - Played a prank on a friend a while ago, and it did not go well for me.. Apparently, she defaced my website.

Can you help me get it back?

Docker Port: 1234
Site: http://platfo-loadb-vt7qhzmmuv60-5dc2d77df490e76f.elb.ap-southeast-2.amazonaws.com:1234/
Flag format: FLAG{flag_found_for_this_website_get_itback}

Solution:
Using netcat, connect to the remote docker container for a very basic shell
```
nc platfo-loadb-vt7qhzmmuv60-5dc2d77df490e76f.elb.ap-southeast-2.amazonaws.com 1234
```
I fumbled around for a while until I decided to look at the nginx configuration, moreso, the config in /etc/nginx/conf.d/default which showed me where the webpage was being served from.
```
cat default.conf
server {
    listen       80;
    server_name  localhost;

    #access_log  /var/log/nginx/host.access.log  main;

    location / {
        root   /usr/share/nginx/html;
        index  index.html index.htm;
    }

    #error_page  404              /404.html;

    # redirect server error pages to the static page /50x.html
    #
    error_page   500 502 503 504  /50x.html;
    location = /50x.html {
        root   /usr/share/nginx/html;
    }

    # proxy the PHP scripts to Apache listening on 127.0.0.1:80
    #
    #location ~ \.php$ {
    #    proxy_pass   http://127.0.0.1;
    #}

    # pass the PHP scripts to FastCGI server listening on 127.0.0.1:9000
    #
    #location ~ \.php$ {
    #    root           html;
    #    fastcgi_pass   127.0.0.1:9000;
    #    fastcgi_index  index.php;
    #    fastcgi_param  SCRIPT_FILENAME  /scripts$fastcgi_script_name;
    #    include        fastcgi_params;
    #}

    # deny access to .htaccess files, if Apache's document root
    # concurs with nginx's one
    #
    #location ~ /\.ht {
    #    deny  all;
    #}
}
```
Heading over to /usr/share/nginx/html, I ran a ls
```
ls -la
total 20
drwxrwxrwx 1 root root 4096 Mar 22  2023 .
drwxr-xr-x 1 root root 4096 Feb  9  2023 ..
-rwxrwxrwx 1 root root 1864 May 28  2022 .lol_skid
-rwxrwxrwx 1 root root  497 Dec 13  2022 50x.html
-rwxrwxrwx 1 root root 3260 May 28  2022 index.html
```
Obviously 2 interesting ones here, index.html and .lol_skid

Looking at index.html and you can see this was causing the error
```
cat index.html
Lol hacked
Told you not to mess with me, buddy. Good luck getting your website back :)

⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠟⠛⠛⠛⠋⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠙⠛⠛⠛⠿⠻⠿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⡿⠋⠀⠀⠀⠀⠀⡀⠠⠤⠒⢂⣉⣉⣉⣑⣒⣒⠒⠒⠒⠒⠒⠒⠒⠀⠀⠐⠒⠚⠻⠿⠿⣿⣿⣿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⠏⠀⠀⠀⠀⡠⠔⠉⣀⠔⠒⠉⣀⣀⠀⠀⠀⣀⡀⠈⠉⠑⠒⠒⠒⠒⠒⠈⠉⠉⠉⠁⠂⠀⠈⠙⢿⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⠇⠀⠀⠀⠔⠁⠠⠖⠡⠔⠊⠀⠀⠀⠀⠀⠀⠀⠐⡄⠀⠀⠀⠀⠀⠀⡄⠀⠀⠀⠀⠉⠲⢄⠀⠀⠀⠈⣿⣿⣿⣿⣿
⣿⣿⣿⣿⣿⣿⠋⠀⠀⠀⠀⠀⠀⠀⠊⠀⢀⣀⣤⣤⣤⣤⣀⠀⠀⠀⢸⠀⠀⠀⠀⠀⠜⠀⠀⠀⠀⣀⡀⠀⠈⠃⠀⠀⠀⠸⣿⣿⣿⣿
⣿⣿⣿⣿⡿⠥⠐⠂⠀⠀⠀⠀⡄⠀⠰⢺⣿⣿⣿⣿⣿⣟⠀⠈⠐⢤⠀⠀⠀⠀⠀⠀⢀⣠⣶⣾⣯⠀⠀⠉⠂⠀⠠⠤⢄⣀⠙⢿⣿⣿
⣿⡿⠋⠡⠐⠈⣉⠭⠤⠤⢄⡀⠈⠀⠈⠁⠉⠁⡠⠀⠀⠀⠉⠐⠠⠔⠀⠀⠀⠀⠀⠲⣿⠿⠛⠛⠓⠒⠂⠀⠀⠀⠀⠀⠀⠠⡉⢢⠙⣿
⣿⠀⢀⠁⠀⠊⠀⠀⠀⠀⠀⠈⠁⠒⠂⠀⠒⠊⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⡇⠀⠀⠀⠀⠀⢀⣀⡠⠔⠒⠒⠂⠀⠈⠀⡇⣿
⣿⠀⢸⠀⠀⠀⢀⣀⡠⠋⠓⠤⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠄⠀⠀⠀⠀⠀⠀⠈⠢⠤⡀⠀⠀⠀⠀⠀⠀⢠⠀⠀⠀⡠⠀⡇⣿
⣿⡀⠘⠀⠀⠀⠀⠀⠘⡄⠀⠀⠀⠈⠑⡦⢄⣀⠀⠀⠐⠒⠁⢸⠀⠀⠠⠒⠄⠀⠀⠀⠀⠀⢀⠇⠀⣀⡀⠀⠀⢀⢾⡆⠀⠈⡀⠎⣸⣿
⣿⣿⣄⡈⠢⠀⠀⠀⠀⠘⣶⣄⡀⠀⠀⡇⠀⠀⠈⠉⠒⠢⡤⣀⡀⠀⠀⠀⠀⠀⠐⠦⠤⠒⠁⠀⠀⠀⠀⣀⢴⠁⠀⢷⠀⠀⠀⢰⣿⣿
⣿⣿⣿⣿⣇⠂⠀⠀⠀⠀⠈⢂⠀⠈⠹⡧⣀⠀⠀⠀⠀⠀⡇⠀⠀⠉⠉⠉⢱⠒⠒⠒⠒⢖⠒⠒⠂⠙⠏⠀⠘⡀⠀⢸⠀⠀⠀⣿⣿⣿
⣿⣿⣿⣿⣿⣧⠀⠀⠀⠀⠀⠀⠑⠄⠰⠀⠀⠁⠐⠲⣤⣴⣄⡀⠀⠀⠀⠀⢸⠀⠀⠀⠀⢸⠀⠀⠀⠀⢠⠀⣠⣷⣶⣿⠀⠀⢰⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣧⠀⠀⠀⠀⠀⠀⠀⠁⢀⠀⠀⠀⠀⠀⡙⠋⠙⠓⠲⢤⣤⣷⣤⣤⣤⣤⣾⣦⣤⣤⣶⣿⣿⣿⣿⡟⢹⠀⠀⢸⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣧⡀⠀⠀⠀⠀⠀⠀⠀⠑⠀⢄⠀⡰⠁⠀⠀⠀⠀⠀⠈⠉⠁⠈⠉⠻⠋⠉⠛⢛⠉⠉⢹⠁⢀⢇⠎⠀⠀⢸⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⣀⠈⠢⢄⡉⠂⠄⡀⠀⠈⠒⠢⠄⠀⢀⣀⣀⣰⠀⠀⠀⠀⠀⠀⠀⠀⡀⠀⢀⣎⠀⠼⠊⠀⠀⠀⠘⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣄⡀⠉⠢⢄⡈⠑⠢⢄⡀⠀⠀⠀⠀⠀⠀⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠁⠀⠀⢀⠀⠀⠀⠀⠀⢻⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣦⣀⡈⠑⠢⢄⡀⠈⠑⠒⠤⠄⣀⣀⠀⠉⠉⠉⠉⠀⠀⠀⣀⡀⠤⠂⠁⠀⢀⠆⠀⠀⢸⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣦⣄⡀⠁⠉⠒⠂⠤⠤⣀⣀⣉⡉⠉⠉⠉⠉⢀⣀⣀⡠⠤⠒⠈⠀⠀⠀⠀⣸⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣷⣶⣤⣄⣀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣰⣿⣿⣿
⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣶⣶⣶⣤⣤⣤⣤⣀⣀⣤⣤⣤⣶⣾⣿⣿⣿⣿⣿
```
Checked out .lol_skid
```
cat .lol_skid
<html>

	<title>Beautiful flags website</title>

	<pre>
	
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣠⣤⣔⠒⠀⠉⠉⠢⡀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⣀⣀⠠⠄⠒⠘⢿⣿⣿⣿⣿⣆⠀⠀⠀⠀⠱⡀⠀⠀⠀⠀⠀⠀
⢺⣦⢻⣿⣿⣿⣿⣄⠀⠀⠀⠀⠈⢿⡿⠿⠛⠛⠐⣶⣿⣿⣿⣧⡀⠀⠀⠀⠀⠀
⠈⢿⣧⢻⣿⣿⣿⣿⣆⣀⣠⣴⣶⣿⡄⠀⠀⠀⠀⠘⣿⣿⣿⣿⣧⠀⠀⠀⠀I swear I put the flag somewhere... maybe in /tmp? ⠀
⠀⠀⢿⣧⢋⠉⠀⠀⠀⠹⣿⣿⣿⣿⣿⡆⣀⣤⣤⣶⣮⠀⠀⠀⠀⠣⠀⠀⠀⠀
⠀⠀⠈⢿⣧⢂⠀⠀⠀⠀⢘⠟⠛⠉⠁⠀⠹⣿⣿⣿⣿⣷⡀⠀⠀⠀⢣⠀⠀If will only appear if my website works tho! But who am I kidding,
⠀⠀⠀⠈⢿⣧⢲⣶⣾⣿⣿⣧⡀⠀⠀⠀⢀⣹⠛⠋⠉⠉⠉⢿⣿⣿⣿⣧⠀⠀ no one will ever hack my website..
⠀⠀⠀⠀⠀⢿⣧⢻⣿⣿⣿⡿⠷⢤⣶⣿⣿⣿⣧⡀⠀⠀⠀⠈⢻⣿⣿⣿⣧⠀
⠀⠀⠀⠀⠀⠈⢿⣧⢛⠉⠁⠀⠀⠀⢻⣿⣿⣿⡿⠗⠒⠒⠈⠉⠉⠉⠙⡉⠛⡃
⠀⠀⠀⠀⠀⠀⠈⢿⣯⢂⠀⠀⠀⡀⠤⠋⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠈⢿⣯⠐⠈⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⣇⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀

	</pre>

</html>
```
I copied this file over index.html then went a checked out /tmp
```
cp .lol_skid index.html
cd /tmp
ls -la
total 36
drwxrwxrwt 1 root  root 4096 Oct 29 07:00 .
drwxr-xr-x 1 root  root 4096 Oct 29 06:51 ..
drwx------ 2 nginx root 4096 Oct 29 06:51 client_temp
drwx------ 2 nginx root 4096 Oct 29 06:51 fastcgi_temp
-rw-r--r-- 1 root  root   51 Oct 29 07:00 flag
-rw-r--r-- 1 root  root    3 Oct 29 06:51 nginx.pid
drwx------ 2 nginx root 4096 Oct 29 06:51 proxy_temp_path
drwx------ 2 nginx root 4096 Oct 29 06:51 scgi_temp
drwx------ 2 nginx root 4096 Oct 29 06:51 uwsgi_temp
```
Then ran cat flag for the flag

:+1: FLAG{s0met1mes_d3f4c3d_is_n0t_r3ally_THAT_defaced}
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

### Words Arithmetic
Description - Can you make a calculator, but in English? Docker URL PORT:1234 
Flag format: FLAG{777__goodw0rkd0ne__999}

Solution:
When testing this, used netcat to connect to the remote session. This presented the following:
```
Welcome to the english calculator challenge! Please give integer answers (rounded up) to all 200 questions within 15 seconds
twenty three minus thirty = ?
```
The script below connects via netcat, then reads the equation and converts it numbers and calculates the equation.

```
import subprocess
from word2number import w2n
import math

# Define the IP and port to connect to
ip = "3.104.131.180"
port = 1234

# Number of times to repeat the process
iterations = 200

# Define translation for arithmetic symbols
arithmetic_translation = {
    "plus": "+",
    "minus": "-",
    "times": "*",
    "dividedby": "/"
}

# Custom function to handle the conversion of words to numbers
def convert_word_to_number(word):
    try:
        # Use word2number to convert words to numbers
        return w2n.word_to_num(word)
    except ValueError:
        # Handle specific cases like "forty one"
        if "forty" in word:
            return w2n.word_to_num(word.replace(" ", "-"))
        return None

def process_equation(equation_line):
    equation_line = equation_line.lower()  # Convert to lowercase for case-insensitivity

    # Check if "divided by" is present and replace it with "/"
    if "divided" in equation_line and "by" in equation_line:
        equation_line = equation_line.replace("divided by", "dividedby")
        
    # Split the equation into components
    equation_parts = equation_line.split()
    parsed_equation = ""

    i = 0
    while i < len(equation_parts):
        if equation_parts[i] in arithmetic_translation:
            operator = equation_parts[i]
            left = equation_parts[:i]
            right = equation_parts[i+1:]

            # Identify and concatenate multi-word numbers in left and right parts
            left, right = concatenate_multi_word_numbers(left), concatenate_multi_word_numbers(right)

            # Convert the left and right parts to numbers
            left_numbers = [convert_word_to_number(word) for word in left]
            right_numbers = [convert_word_to_number(word) for word in right]

            # Check if there are any invalid words in left or right parts
            if None in left_numbers or None in right_numbers:
                print("Invalid word in equation.")
                return None

            # Determine the operator
            if operator in arithmetic_translation:
                parsed_operator = arithmetic_translation[operator]
            else:
                # Treat any operator other than "plus," "minus," or "times" as "divided by"
                parsed_operator = "/"

            # Combine the left and right parts with the operator
            parsed_equation = " ".join(map(str, left_numbers)) + " " + arithmetic_translation[operator] + " " + " ".join(map(str, right_numbers))
            break  # We've processed the equation, so we can exit the loop
        i += 1

    if not parsed_equation:
        print("Operator not found in equation. Skipping.")
        return None

    return parsed_equation

def concatenate_multi_word_numbers(words):
    concatenated_words = []
    i = 0
    while i < len(words):
        number = convert_word_to_number(words[i])
        if number is not None:
            concatenated_word = words[i]
            i += 1
            while i < len(words) and convert_word_to_number(words[i]) is not None:
                concatenated_word += " " + words[i]
                i += 1
            concatenated_words.append(concatenated_word)
        else:
            concatenated_words.append(words[i])
            i += 1
    return concatenated_words

for i in range(iterations):
    # Connect to the IP using Netcat
    nc_process = subprocess.Popen(['nc', ip, str(port)], stdout=subprocess.PIPE, stdin=subprocess.PIPE, text=True)

    # Read and print the first line
    welcome_message = nc_process.stdout.readline().strip()
    print(welcome_message)

    # Read and print the second line
    equation_line = nc_process.stdout.readline().strip()
    print(equation_line)

    # Remove the equal sign (=) at the end of the equation
    equation_line = equation_line.rsplit("=", 1)[0].strip()

    if not equation_line:
        print("Empty equation. Skipping.")
        nc_process.stdin.write("\n")
        nc_process.stdin.flush()
        continue

    # Process the equation and get the parsed equation
    parsed_equation = process_equation(equation_line)

    if parsed_equation is not None:
        # Evaluate the parsed equation
        answer = math.ceil(eval(parsed_equation))
        # Round the answer to the nearest integer
        answer = round(answer)
        # Print just the answer
        print(answer)

        # Send the answer to the Netcat connection
        nc_process.stdin.write(str(answer) + "\n")
        nc_process.stdin.flush()

        # Check if the answer is correct and print the "Correct! Next" message
        response = nc_process.stdout.readline().strip()
        if response.startswith("Correct"):
            print(response)
    else:
        print("Invalid equation. Skipping.")

    # Close the Netcat connection
    nc_process.stdin.close()
    nc_process.stdout.close()
    nc_process.terminate()
```
The downside is that it doesn't always run quick enough to answer 200 questions in 15 seconds.

:+1: FLAG{000__N1ceM4thsMyFr13nd__000}
<hr>

### VBScript is dead, Long Live VBScript
Description
VBS is dead? Naaah vbscript will live on! Uncover hidden secrets by decoding a mysterious VBScript code snippet and reveal the concealed flag. 
Flag format: FLAG{your_f14g}

Solution:
ChatGTP rewrote the vbs to print from python using the script:

```
result = (
    chr(6157853 // int("121cf", 16)) +
    chr(-6851 + int("1b28", 16)) +
    chr(int("10735", 16) - 67265) +
    chr(-88922 + int("15b7a", 16)) +
    chr(4723161 // int("a637", 16)) +
    chr(-20918 + int("5209", 16)) +
    chr(int("5f7e", 16) - 24342) +
    chr(int("4622", 16) - 17853) +
    chr(int("155e9", 16) - 87421) +
    chr(-87944 + int("157f4", 16)) +
    chr(-89565 + int("15dfd", 16)) +
    chr(-65506 + int("1001f", 16)) +
    chr(199584 // int("185d", 16)) +
    chr(int("3eb2", 16) - 15963) +
    chr(-8285 + int("20b0", 16)) +
    chr(427977 // int("10e3", 16)) +
    chr(-21714 + int("5544", 16)) +
    chr(5789280 // int("d760", 16)) +
    chr(int("8dd3", 16) - 36195) +
    chr(int("baba", 16) - 47686) +
    chr(int("14ef3", 16) - 85701) +
    chr(-12746 + int("320d", 16)) +
    chr(827640 // int("1c5c", 16)) +
    chr(-41171 + int("a138", 16)) +
    chr(int("bb24", 16) - 47811) +
    chr(-78745 + int("1340d", 16)) +
    chr(2079792 // int("5070", 16)) +
    chr(int("16880", 16) - 92209) +
    chr(4733694 // int("bcaf", 16)) +
    chr(-56885 + int("de9f", 16)) +
    chr(-87876 + int("157a9", 16)) +
    chr(int("8a2b", 16) - 35272) +
    chr(2010048 // int("43b0", 16)) +
    chr(int("160f", 16) - 5607) +
    chr(3095802 // int("163ad", 16)) +
    chr(-95228 + int("17453", 16)) +
    chr(2875203 // int("8751", 16)) +
    chr(-1788 + int("73f", 16)) +
    chr(int("33b7", 16) - 13125) +
    chr(int("759a", 16) - 30001) +
    chr(-36954 + int("90ca", 16)) +
    chr(-74244 + int("12278", 16)) +
    chr(int("1a7b", 16) - 6733) +
    chr(int("c25", 16) - 2994) +
    chr(8885240 // int("14dbb", 16)) +
    chr(int("91b1", 16) - 37196) +
    chr(int("13097", 16) - 77867) +
    chr(-35813 + int("8c51", 16)) +
    chr(1708330 // int("c445", 16)) +
    chr(-81985 + int("1406a", 16)) +
    chr(int("15c73", 16) - 89193) +
    chr(-86900 + int("153e3", 16)) +
    chr(1682991 // int("4f35", 16)) +
    chr(4516824 // int("a9a7", 16)) +
    chr(-30039 + int("75bc", 16)) +
    chr(-41278 + int("a1aa", 16)) +
    chr(916488 // int("2126", 16)) +
    chr(704030 // int("3bc9", 16)) +
    chr(-45519 + int("b241", 16)) +
    chr(5722704 // int("bf10", 16)) +
    chr(int("bb0b", 16) - 47773) +
    chr(int("1059", 16) - 4153) +
    chr(-52796 + int("ce5e", 16)) +
    chr(6946434 // int("11216", 16)) +
    chr(916036 // int("20d4", 16)) +
    chr(854000 // int("215c", 16)) +
    chr(2012640 // int("f5af", 16)) +
    chr(3190454 // int("1092a", 16)) +
    chr(-4855 + int("135a", 16)) +
    chr(-84718 + int("14b0e", 16)) +
    chr(int("624f", 16) - 25128) +
    chr(-22115 + int("56c8", 16)) +
    chr(int("a699", 16) - 42550) +
    chr(4718064 // int("b136", 16)) +
    chr(-47461 + int("b9d4", 16)) +
    chr(int("5d04", 16) - 23780) +
    chr(int("a300", 16) - 41658) +
    chr(-44179 + int("acdf", 16)) +
    chr(677170 // int("28b2", 16)) +
    chr(int("153f0", 16) - 86953) +
    chr(689784 // int("15e8", 16)) +
    chr(-10789 + int("2a9b", 16)) +
    chr(int("c02a", 16) - 49096) +
    chr(1608512 // int("c45a", 16)) +
    chr(2497930 // int("100c7", 16)) +
    chr(234004 // int("180e", 16)) +
    chr(465248 // int("38cb", 16)) +
    chr(8788070 // int("12a82", 16)) +
    chr(int("13a63", 16) - 80382) +
    chr(2702336 // int("5b00", 16)) +
    chr(1658528 // int("ca75", 16)) +
    chr(-10133 + int("27db", 16)) +
    chr(2190266 // int("8c42", 16)) +
    chr(int("11422", 16) - 70575) +
    chr(int("12b08", 16) - 76457) +
    chr(int("83cb", 16) - 33637) +
    chr(-76326 + int("12a56", 16)) +
    chr(int("123ab", 16) - 74553) +
    chr(2017254 // int("9a82", 16)) +
    chr(6092222 // int("c9ad", 16)) +
    chr(-66322 + int("10345", 16)) +
    chr(int("10e47", 16) - 69077) +
    chr(2096750 // int("4186", 16)) +
    chr(-46818 + int("b709", 16)) +
    chr(-7337 + int("1ccb", 16)) +
    "\n"
)

print(result)
```

When run, the output is
```
Set oShell = WScript.CreateObject("WSCript.shell")
oShell.run "cmd /c 'echo FLAG{vb && set F=s_f0r3v3r}'"
```
:+1: FLAG{vbs_f0r3v3r}
<hr>
