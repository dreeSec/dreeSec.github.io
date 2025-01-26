+++
author = "dree"
title = "UMD CTF 2023"
date = "2023-05-04"
tags = [
    "forensics", "OSINT, HW-RF"
]
+++

This past weekend my team WolvSec competed in fellow big-10 University of Maryland's CTF and placed 20th! This had a crazy amount of challenges, almost all of which had some pokemon theme, and overall was a lot of fun! 

I solved 16 challenges totaling 4914 points, including all the OSINT, most of the forensics, most of the HW+RF (Hardware and Radio Frequency), and one crypto.
<!--more-->

---

[**forensics/Mirror Unknown**](https://dree.blog/posts/umd-ctf-2023#forensicsmirror-unknown) [298 solves]

[**forensics/No. 352**](https://dree.blog/posts/umd-ctf-2023#forensicsno-352) [142 solves]

[**forensics/Fire Type Pokemon Only**](https://dree.blog/posts/umd-ctf-2023#forensicsfire-type-pokemon-only) [128 solves]

[**forensics/YARA Trainer Gym**](https://dree.blog/posts/umd-ctf-2023#forensicsyara-trainer-gym) [82 solves]

[**forensics/Telekinetic Warfare**](https://dree.blog/posts/umd-ctf-2023#telekinetic-warfare) [73 solves]

[**HW+RF/Bleep1**](https://dree.blog/posts/umd-ctf-2023#hwrfbleep1) [91 solves]

[**HW+RF/Clutter**](https://dree.blog/posts/umd-ctf-2023#hwrfclutter) [53 solves]

[**HW+RF/beep-boop**](https://dree.blog/posts/umd-ctf-2023#hwrfbeep-boop) [50 solves]

[**OSINT/Gone Missing 1**](https://dree.blog/posts/umd-ctf-2023#osintgone-missing-1) [357 solves]

[**OSINT/Gone Missing 2**](https://dree.blog/posts/umd-ctf-2023#osintgone-missing-2) [256 solves]

[**OSINT/Gone Missing 3**](https://dree.blog/posts/umd-ctf-2023#osintgone-missing-3) [83 solves]

[**OSINT/tcc1**](https://dree.blog/posts/umd-ctf-2023#osinttcc1) [221 solves]

[**OSINT/tcc2**](https://dree.blog/posts/umd-ctf-2023#osinttcc2) [67 solves]

[**OSINT/tcc3**](https://dree.blog/posts/umd-ctf-2023#osinttcc3) [57 solves]

[**OSINT/tcc4**](https://dree.blog/posts/umd-ctf-2023#osinttcc4) [31 solves]

[**crypto/hidden-message**](https://dree.blog/posts/umd-ctf-2023#cryptohidden-message) [67 solves]

---

## forensics/Mirror Unknown

Authors: `Ishaan514`  
Points: **50**  
Solves: **298**

### Challenge Description:
I found some unknown symbols in a nearby collapsed cave. Can you figure out what they mean?

(Note: Ancient civilizations didn't believe in whitespace of lowercase)

{{< img src="Mirror_Unkown.png" >}}

### Approach

We can translate the above message, and mirror it, to get the flag
{{< img50 src="ukown.png" >}}

Flag:  `UMDCTF{sinjoh_ruins}`
<br/><br/><br/><br/>

---

## forensics/No. 352

Authors: `Angela`  
Points: **410**  
Solves: **142**

### Challenge Description:
password 1: the name of pokemon #352 in lowercase
password 2: timetofindwhatkecleonishiding

{{< img src="hide-n-seek.png" >}}

### Approach

My teammate Catgut6675 got the first image of keckeon via [this stego decoder](http://futureboy.us/stegano/decinput.html)

I then saved the image as `img.jpg`, then ran the following command:
```
stegcracker img.jpg wordlist
```
where `wordlist` contains `timetofindwhatkecleonishiding` and got the flag!

Flag: `UMDCTF{KECLE0NNNNN}`
<br/><br/><br/><br/>

---

## forensics/Fire Type Pokemon Only

Authors: `birch`  
Points: **50**  
Solves: **128**

### Challenge Description:
Some wannabe trainer with no pokemon left their PC connected to the internet. Watch as I hack this nerd lol.

### Approach

We are given a pcap. Dumping the FTP objects, we get a password-protected zip file `secret`

Filtering the packets for the FTP stream, we can see the following:
```
220 (vsFTPd 3.0.5)
USER pokemonfan1
331 Please specify the password.
PASS pika
```

We can then use the password `pika` on the zip file to get the secret (audio warning):

{{< video50 src="wisdom.mp4" type="video/mp4" preload="auto" >}}

Flag: `UMDCTF{its_n0t_p1kachu!!!}`
<br/><br/><br/><br/>

---

## forensics/YARA Trainer Gym

Authors: `birch`  
Points: **427**  
Solves: **82**

### Challenge Description:
My pokemon aren't very strong yet so I need to slip past the sigs written by the 8 YARA gym leaders! Can you help me!!!

Note: you can run the yara rules locally with yara yara_rules.yar $file

```python
import "elf"
import "math"

rule rule1 {
    condition:
        uint32(0) == 0x464c457f
}

rule rule2 {
    strings:
        $rocket1 = "jessie"
        $rocket2 = "james"
        $rocket3 = "meowth"

    condition:
        all of ($rocket*)
}

rule rule3 {
    meta:
        description = "Number of sections in a binary"
     condition:
        elf.number_of_sections == 40
}

rule rule4 {
    strings:
        $hex1 = {73 6f 6d 65 74 68 69 6e 67 73 6f 6d 65 74 68 69 6e 67 6d 61 6c 77 61 72 65}
        $hex2 = {5445414d524f434b4554}
        $hex3 = {696d20736f207469726564}
        $hex4 = {736c656570792074696d65}

    condition:
        ($hex1 and $hex2) or ($hex3 and $hex4)
}

rule rule5 {
    condition:
        math.entropy(0, filesize) >= 6
}

rule rule6 {
    strings:
        $xor = "aqvkpjmdofazwf{lqjm1310<" xor
    condition:
        $xor
}

rule rule7 {
    condition:
        for any section in elf.sections : (section.name == "poophaha")
}

rule rule8 {
    condition:
        filesize < 2MB and filesize > 1MB
}
```

### Approach

To solve this challenge, we need to create a file that satisfies all of these conditions.

**Rule 1**
Create a c++ program that does nothing, and compile
```console
echo -n 'int main(){}' > empty.cpp;
g++ -o file.elf empty.cpp
```
**Rule 2 & 7**
Add section `poophaha` which contains the three strings
```console
echo -n "jessiejamesmeowth" > temp.bin
objcopy --add-section poophaha=temp.bin file.elf
```
**Rule 4**
Add hex strings 3 & 4 to the elf
```console
perl -e 'print pack "H*", "696d20736f207469726564736c656570792074696d65"' > temp.bin
objcopy --add-section hex=temp.bin file.elf
```
**Rule 6**
We can simply just add this string to another section in the elf
```console
echo -n 'aqvkpjmdofazwf{lqjm1310<' > temp.bin
objcopy --add-section xor=temp.bin file.elf
```
**Rule 5 & 8**
We need this elf to be a size between 1-2 MB, and have sufficient entropy. We can add a section that fulfills this
```console
dd if=/dev/urandom of=temp.bin bs=1024 count=1024
objcopy --add-section random=temp.bin file.elf
```
**Rule 3**
Add the remaining empty X sections
```console
for i in {1..X}; do
  objcopy --add-section empty$i=/dev/null file.elf
done
```

Combining everything, we can create the file with the following commands:
```console
echo -n 'int main(){}' > empty.cpp;
g++ -o file.elf empty.cpp;
echo -n "jessiejamesmeowth" > total.bin;
perl -e 'print pack "H*", "696d20736f207469726564736c656570792074696d65"' >> total.bin;
echo -n 'aqvkpjmdofazwf{lqjm1310<' >> total.bin;
dd if=/dev/urandom bs=1024 count=1024 >> total.bin;
objcopy --add-section poophaha=total.bin file.elf;
for i in {1..9}; do
  objcopy --add-section empty$i=/dev/null file.elf
done
```

Then we can submit the file and take down all the gym leaders!
{{< img src="yara.png" >}}

Flag: `UMDCTF{Y0ur3_4_r34l_y4r4_m4573r!}`
<br/><br/><br/><br/>

---

## forensics/Telekinetic Warfare

Authors: `birch`  
Points: **442**  
Solves: **73**

### Challenge Description:
Someone was able to exfil a top secret document from our airgapped network! How???

{{< img50 src="bruhh.gif" >}}

### Approach
We can extract each frame of the GIF, read the QR code data, and convert from b64 with the following script:

```python
import imageio
from pyzbar.pyzbar import decode
from PIL import Image
import base64

# get image frames
gif_file = "bruh.gif"
reader = imageio.get_reader(gif_file)

# create string for data
qr_data = b""

# iterate through each frame and extract the QR code data
for frame in reader:
    decocdeQR = decode(frame)
    qr_data += base64.b64decode(decocdeQR[0].data.decode('ascii'))

# write the bytes to a file
with open("output", "wb") as f:
    f.write(qr_data)
```

From this, we get the following document
{{< img50 src="tele_doc.png" >}}

Flag: `UMDCTF{wh0_n33d5_k1net1c_w4rfar3_anyw4ys}`

<br/><br/><br/><br/>

---

## HW+RF/Bleep1

Authors: `gary`  
Points: **409**  
Solves: **91**

### Challenge Description:
Toss the flag.enc contents into the ROM and press play :)

### Approach
All we have to do for this is open up logisim-evolution (not logisim!), fill in the rom with the hex given, and run the program!

{{< img src="logisim.gif" >}}

Flag: `UMDCTF{w3lc0me_t0_l0g1s1m_yeet}`

<br/><br/><br/><br/>

---

## HW+RF/Clutter

Authors: `busescanfly`  
Points: **470**  
Solves: **53**

### Challenge Description:
I wrote this machine code but Giovanni wiped my memory! I'm all scatter-brained and can't remember where I wrote the flag to :(

[vesp](https://user.eng.umd.edu//~yavuz/teaching/courses/enee350/vesp-source-code/vesp1.1X/main.cpp)

### Approach

When we run `clutter.vsp` on verbose output, we can see the output looks something like this:

```console
*************Begin[Machine Level]*****************

A = 0052, B = 0003, Z = 0, S = 0, C = 0, F = 0
MAR = 0008, PC = 000A, IR = 2000, reset = 0
add = 0 complement = 0

Memory[0000] = 0052

*************End[Machine Level]*****************Machine Cycle 0005: PC = 000A, 
FETCH SUBCYCLE
MAR = 000A, IR = 0000, 
Clock cycle = E
DECODE SUBCYCLE
Decoded instruction is: ADD
Clock cycle = E
EXECUTE SUBCYCLE
Clock cycle = F

*************Begin[Machine Level]*****************

A = 0055, B = 0003, Z = 0, S = 0, C = 0, F = 0
MAR = 000A, PC = 000B, IR = 0000, reset = 0
add = 1 complement = 0

Machine Cycle 0006: PC = 000B, 
FETCH SUBCYCLE
MAR = 000B, IR = 315B, 
Clock cycle = 11
DECODE SUBCYCLE
Decoded instruction is: MOV
Clock cycle = 11
EXECUTE SUBCYCLE
Clock cycle = 13

*************Begin[Machine Level]*****************

A = 0055, B = 0003, Z = 0, S = 0, C = 0, F = 0
MAR = 000B, PC = 000D, IR = 315B, reset = 0
add = 0 complement = 0

Memory[015B] = 0055

*************End[Machine Level]*****************Machine Cycle 0007: PC = 000D, 
```

With the first few memory writes looking as such:
```
Memory[0000] = 0000
Memory[0001] = 0000
Memory[0001] = 0003
Memory[0000] = 0052
Memory[015B] = 0055
Memory[0001] = 0008
Memory[0000] = 0045
Memory[0285] = 004D
Memory[0001] = 0003
Memory[0000] = 0041
Memory[0185] = 0044
Memory[0001] = 0006
Memory[0000] = 003D
Memory[022A] = 0043
Memory[0001] = 0009
```

From the challenge description, we know the program is writing the flag to random memory addresses. We can see that pattern in the above memory writes.

So we can write a command to obtain all the memory writes, exclude `Memory[0000]` and `Memory[0001]` writes, get the last two bytes of hex on each line, and convert to ASCII!

```console
cat output | grep 'Memory' | awk '!/Memory\[000[01]\]/' | sed 's/.*= 00//' | xxd -r -p
```

Flag: `UMDCTF{Ux13-us3-m3m0ry-w1p3!}`

<br/><br/><br/><br/>

---

## HW+RF/beep-boop

Authors: `Assgent`  
Points: **473**  
Solves: **50**

### Challenge Description:
"Oh why didn't I just choose Computer Science??" -Every Computer Engineering major
```m
%Build script to beep-boop (UMDCTF2023, author: Assgent)

%{
A flag was encoded into a sound file using the script below. 
Analyze the script and reverse-engineer the flag!
%}

close
clear all

flag = fileread("flag.txt");

Fs = 8192;
sound = string_to_sound(flag, Fs, 1, 0.5);

sound_normalized = sound / (max(abs(sound)));
audiowrite("sound.wav", sound_normalized, Fs);

function freq = get_frequency_1(char)
    freq = char * 13;
end

function freq = get_frequency_2(char)
    freq = (char - 50) * 11;
end


% Fs is the samples/sec.
% T is the duration of each key. (in seconds)
% Tpause is the pause between keys. (in seconds)
function x = string_to_sound(keys,Fs,T,Tpause)
    t = (0:fix(T*Fs)).'/Fs ;
    zp = zeros(fix(Tpause*Fs/2),1) ;
    x = [];
    for r = 1:length(keys(:))
        char = keys(r);
        x = [x ; zp ; cos(2*pi*get_frequency_1(char)*t) + cos(2*pi*get_frequency_2(char)*t) ; zp];
    end
end
```
{{< audio src="sound.wav">}}

### Approach

This solution will present a bit of a cheese. We can build a MATLAB solution using a fast fourier transform with the help of GPT as such:

```m
% read in file
[sound, Fs] = audioread('sound.wav');

% parameters
T = 1.1;  
Tpause = .4; 

% loop over keys and write char to array
i = 1;
flag = '';
while i <= length(sound) - 60
    % Extract the current key
    key = sound(i:i+round(T*Fs));
    i = i + round((T+Tpause)*Fs);
    
    % compute spectrum of the key
    N = length(key);
    Y = fft(key)/N;
    f = Fs*(0:(N/2))/N;
    P = abs(Y(1:(N/2+1)));
    
    % find two frequencies
    [~, idx1] = max(P);
    f1 = f(idx1);
    P(idx1) = 0;
    [~, idx2] = max(P);
    f2 = f(idx2);
    
    % decode char and add to flag
    char = round(((f1/13) + (f2/11 + 50))/2);
    flag = [flag, char];
end

% Display the decoded message
disp(flag);
```

This results in the following string, whose length we know is accurate:
```
UMICTK{it_ tz_ahtzaqq _jsjt _sigsaq_prthjssisg_???}
```
Messing with the parameters, we can also get this string
```
UUMIICYYK{{ioo_yyouu_aacyyuaaqqqy__essoooy__siigssaqq_uuwooceesssissg__????}}
```
Therefore the solution is pretty easy to figure out even if we didn't decode it right 100%

Flag: `UMDCTF{do_you_actually_enjoy_signal_processing_???}`

<br/><br/><br/><br/>

---

## OSINT/Gone Missing 1

Authors: `gary`  
Points: **50**  
Solves: **357**

### Challenge Description:
A fire type Pokemon has gone missing. Can you find it?

{{< google_maps/royal_palace>}}

### Approach
For these challenges, we are given a 360 degree view of a google street view location, and asked to identify it

Performing a reverse image search on google images, we can see immediately that this is Oslo Royal Palace, Norway

[Location](https://goo.gl/maps/1Av1ZFTM1ZvRqsjt5)

Flag: `idk_rn_infra_taken_down`

<br/><br/><br/><br/>

---

## OSINT/Gone Missing 2

Authors: `gary`  
Points: **50**  
Solves: **256**

### Challenge Description:
A grass type Pokemon has gone missing. Can you find it?

{{< google_maps/castle_rock>}}

### Approach
This challenge was not as straightforward. It appeared at first glance to be somewhere in the US based on the flag, landscape, and large parking lots.

Eventually, via reverse image searching the landscape through google images, and checking locations it presents, we find that the location is Castle Rock, CO

[Location](https://goo.gl/maps/6MYXfyEyrnzYHfyg7)

Flag: `idk_rn_infra_taken_down`

<br/><br/><br/><br/>

---

## OSINT/Gone Missing 3

Authors: `gary`  
Points: **425**  
Solves: **83**

### Challenge Description:
A water type Pokemon has gone missing. Can you find it?

{{< google_maps/taiwan>}}

### Approach
The first step for these OSINTs for me is identifying the country, since there's a lot of clues that can help with that.

For this, we can see a striped pole extended all the way down, which is very common to Taiwan. This plus the rice paddy fields helped confirm this.
{{< img50 src="pole.png">}}

My next step was using the poster to somehow zero us in on the location or region within Taiwan. 

Translating the image we can see "Unlin"

{{< img src="unlin.png">}}

I spent a while prior to this trying to car-meta by looking for locations in Taiwan where the car, when pointing the camera straight down, was the same. One of these locations I found where the car was very, very similar was in Yunlin County.

From there, I figured it was enough to find the location. Other people used poles to narrow it down exactly. 

What I did was this this:
- Align the compass exactly north
- Get the approximate orientation of the road in my head to match for on google maps
- Look for where there is a straight line with a bend to the same direction as seen in the panorama
- Look for rural areas where terrain is very flat, since there are no hills in the panorama

From this, the location became much easier to find a match from above:

{{< img50 src="overview.png">}}

[Location](https://goo.gl/maps/d2MEhZkpdKT3s5L28)

Flag: `idk_rn_infra_taken_down`

<br/><br/><br/><br/>

---
## OSINT/TCC1

Authors: `gary`  
Points: **50**  
Solves: **221**

### Challenge Description:
I found this hacker group and they're acting kinda strange. Let's do some diggin'. Maybe we can find their discord server? I thought they linked it on their website before...

https://tcc.lol

### Approach
We can use the [Wayback Machine](https://web.archive.org/web/20230419213033/https://tcc.lol/) to get the [discord link](https://discord.com/invite/dDgydkTq9t)

From there, the flag is in #general

Flag: `UMDCTF{w3lc0me_t0_th3_b35t_d!sc0rd_982364}`

<br/><br/><br/><br/>

---

## OSINT/TCC2

Authors: `gary`  
Points: **451**  
Solves: **67**

### Challenge Description:
What is that secret page on their website?

tcc.lol

### Approach
There is a page titled `secret` which asks 4 questions

__**Question 1:** What place did TCC get in their most recent CTF competition?__

Searching for "the charizard collective" we can find their [CTF team](https://ctftime.org/team/223777) and see that they placed **145** in DawgCTF 2023

__**Question 2:** Which company is p1ku currently working for?__

I initially found [p1ku's twitter](https://twitter.com/captainoftcc) when searching for TCC. We can see this tweet made by them:

{{< img src="p1ku_twitter.png">}}

Looking up their email on Google, a link to their resume shows up:

{{< img src="google_p1ku.png">}}

In this resume we can see their prior work experience is **Leidos**:

```
Professional Experience
Security Analyst, Leidos (August 2020 - Present)
```

__**Question 3:** What is bree’s favorite CTF category?__

From the discord we know they like **misc** challenges
{{< img75 src="misc.png">}}

__**Question 4:** What is the brand name of the gift that blub is going to buy?__

{{< img75 src="discord_list.png">}}

In discord there is a debate about what to get Bulberina and p1ku mentions there being a list.

{{< img src="epios.png">}}

Via reverse email search on epios, we know bulb has an amazon account with that email. I started looking at lists for bulberina but found no results. 

Then I discovered there is a separate [listing for weddings](https://www.amazon.com/wedding/search), and there we find a result for [Bulberina Asaur](https://www.amazon.com/wedding/registry/EV0PKO2KIUYU?ref=wr_search_page_result_1)

From bulb's message on discord, we know they got bulberina a storage container

{{< img50 src="discord_storage.png">}}

On the list we can see **Shazo** storage:

{{< img src="storage.png">}}

With all those answers, we can access the secret page to get the flag

Flag: `UMDCTF{y0u_sur3_kn0w_h0w_t0_d0_y0ur_r3s3@rch_289723}`

<br/><br/><br/><br/>

---

## OSINT/TCC3

Authors: `gary`  
Points: **465**  
Solves: **57**

### Challenge Description:
I'm missing contact information for one of the members. They said they were Out of Office (OOO) on vacation.

### Approach
Out Of Office (OOO) means that someone is away for a while, and most people configure their emails to automatically respond when they're OOO.

From the past formats of the emails it is reasonable to think mach0, who is the only one without an email listed, would also have an email in the format name.umdctf2023@gmail.com

Emailing mach0.umdctf2023@gmail.com results in the following response:

{{< img src="mach0_email.png">}}

Calling the number 281-698-0109 gives the flag (after trying to painfully transcribe it -_-)

{{< audio src="phone.wav">}}

Flag: `UMDCTF{y0u_h4v3_r3ach3d_mach0_v01cema1l_333}`

<br/><br/><br/><br/>

---

## OSINT/TCC4

Authors: `gary`  
Points: **490**  
Solves: **31**

### Challenge Description:
mach0 told me he has been tweeting a lot and might expose TCC secrets!

### Approach
In discord, mach0 signs all their messages with ` - macho`

{{< img50 src="mach0_msg.png">}}

Most of the messages from mach0 were edited, and I figure this was the challenge author creating the last challenge and appending ` - macho` to each message. 

Twitter does not allow including the dash in the advanced search, so the only string for sure was macho. I tried including other terms but those yielded no results.

I ended up having to search 'macho' and scroll through many...questionable results to find [mach0's account](https://twitter.com/beefed_out).

One of mach0's tweets has a [pastebin](https://pastebin.com/th4KWMup) which contains the flag
{{< img src="mach0_tweet.png">}}

Flag: `UMDCTF{tw1tt3r_adv4nc3d_s3arch_y0ink}`

<br/><br/><br/><br/>

---


## crypto/Hidden Message

Authors: `SillyLily`  
Points: **451**  
Solves: **67**

### Challenge Description:
Can you find the hidden message?

***HINT:*** The delimiter is a space

***NOTE:*** Wrap the result in UMDCTF{}

```
GO CATCH tHe bug parAS! AbRa LIKES His speED! GO catCH zubaT Or not! like paraS cutE zUBAT Is FUn! hes GREAT! GO CATch RoCk onix! onIx LOVes My new mATTE rocKS lol!
```

### Approach
Since the delimiter is a space, each section of the text prior to the `!` is a word, unless the flag is 7 characters but that seemed unlikely

I then figured each word must be a character, and attempted to translate the text into morse code where uppercase is `-` lowercase is `.` and ! is `/`

{{< img src="morse.png">}}

Flag: `UMDCTF{M0RS3_C0D3_M34NS_H4V1NG_S0_M8CH_F8NS13S}`

<br/><br/><br/><br/>

---

Hope you enjoyed the writeups :D and thanks to UMD for hosting a great CTF!!