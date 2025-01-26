+++
author = "dree"
title = "Nahamcon CTF 2022"
date = "2022-05-01"
tags = [
    "OSINT",
]
+++

Keeber OSINT Complete 1-8
<!--more-->

## Challenge: Keeber
Category: **OSINT**  
Difficulty: **Medium**  
Authors: `@matlac#2291, @Gary#4657`  
Points: **1842**  

---

[**Keeber 1**](https://dree.blog/posts/nahamcon-ctf-2022#keeber-1) [1246 solves]

[**Keeber 2**](https://dree.blog/posts/nahamcon-ctf-2022#keeber-2) [890 solves]

[**Keeber 3**](https://dree.blog/posts/nahamcon-ctf-2022#keeber-3) [377 solves]

[**Keeber 4**](https://dree.blog/posts/nahamcon-ctf-2022#keeber-4) [192 solves]

[**Keeber 5**](https://dree.blog/posts/nahamcon-ctf-2022#keeber-5) [573 solves]

[**Keeber 6**](https://dree.blog/posts/nahamcon-ctf-2022#keeber-6) [164 solves]

[**Keeber 7**](https://dree.blog/posts/nahamcon-ctf-2022#keeber-7) [74 solves]

[**Keeber 8**](https://dree.blog/posts/nahamcon-ctf-2022#keeber-8) [62 solves]

---

### Keeber 1
Points: **50**  
Solves: **1246**

Challenge Description: 
You have been applying to entry-level cybersecurity jobs focused on reconnaissance and open source intelligence (OSINT). Great news! You got an interview with a small cybersecurity company; the Keeber Security Group. Before interviewing, they want to test your skills through a series of challenges oriented around investigating the Keeber Security Group.

The first step in your investigation is to find more information about the company itself. All we know is that the company is named Keeber Security Group and they are a cybersecurity startup. To start, help us find the person who registered their domain. The flag is in regular format.

#### Approach
Starting off we get this prompt that the Keeber Security Group about them wanting us to perform an investigation on them using our OSINT knowledge. We see that someone registered a domain, so step 1 should be finding this website. Not too hard after a quick google search for Keeber Security Group.

{{< img src="1.png" >}}

We can use external websites to find out who registered the domain, such as [whois.com](https://www.whois.com).

{{< img src="2.png" >}}

flag: `flag{ef67b2243b195eba43c7dc797b75d75b}`

---

### Keeber 2
Points: **50**  
Solves: **890**

Challenge Description: 
The Keeber Security Group is a new startup in its infant stages. The team is always changing and some people have left the company. The Keeber Security Group has been quick with changing their website to reflect these changes, but there must be some way to find ex-employees. Find an ex-employee through the group's website. The flag is in regular format.

#### Approach
I started off looking at the Github for this one, and found a contributor named `Tiffany Douglas` who wasn’t on the team section of the website. However, I couldn't find the flag there. I then pivoted to the [Wayback Machine](https://web.archive.org/web/20220419212259/https://keebersecuritygroup.com/team/) and noticed a snapshot was taken prior to the competition starting.

{{< img src="3.png" >}}

Looking at this, we can find the flag under Tiffany's name in the team section.

{{< img src="4.png" >}}

flag: `flag{cddb59d78a6d50905340a62852e315c9}`

---

### Keeber 3
Points: **50**  
Solves: **377**

Challenge Description: 
The ex-employee you found was fired for "committing a secret to public github repositories". Find the committed secret, and use that to find confidential company information. The flag is in regular format.

#### Approach
To find the committed secret, I turned to github to see if there were any commits by Tiffany that were undone. Under the `.gitignore` in `security-evaluation-workflow` we see a secret that Tiffany must have added by mistake. 

{{< img src="5.png" >}}

I wasn’t sure what asana was at first, but after googling it seems that it’s some software that Keeber uses. I went to the [asana documentation](https://developers.asana.com/docs) to see what we could do with this and came across a way to access the api: 

```
curl https://app.asana.com/api/1.0/users/me \  
  -H "Authorization: Bearer 0/a7f89e98g007e0s07da763a"
```

Replacing the string with the one in the github, we get the flag.

{{< img src="6.png" >}}

flag: `flag{49305a2a9dcc503cb2b1fdeef8a7ac04}`

---

### Keeber 4
Points: **318**  
Solves: **192**

Challenge Description: 
The ex-employee also left the company password database exposed to the public through GitHub. Since the password is shared throughout the company, it must be easy for employees to remember. The password used to encrypt the database is a single lowercase word somehow relating to the company. Make a custom word list using the Keeber Security Groups public facing information, and use it to open the password database The flag is in regular format.

(Hint: John the Ripper may have support for cracking .kdbx password hashes!)

#### Approach
Finding the password database wasn't hard, as it's under `password-manager` in the github. After some research, we find that the `.kdbx` extension is a Keepass database hash. Following the steps in [this github](https://github.com/patecm/cracking_keepass) we can crack this keepass using John the Ripper and Hashcat together. With `keepass2john` in John the Ripper we can get a hash file that is readable by hashcat. You must remove the file name from the start of the hash file by editing it or with `| grep -o "$keepass$.*"`.

The hardest part for me in this challenge was creating a good word list to use. I initially used [CeWL](https://github.com/digininja/CeWL) to compile a list of words on the website and github, then turned them to lowercase and removed duplicates. The correct password was in here, but the wordlist was 30k+ words and hashcat would not have finished in time.

I looked closer at the `security-evaluation-workflow` in the github and found a lot of strange words that did not exist like in “We strive to achieve *minivivi* and *clainebookahl* through this”. I figured one of these made up words would be the password, and compiled a wordlist of the 72 of them. Using hashcat, we get the password is `craccurrelss` in 4 mins, 35 seconds.

{{< img src="7.png" >}}
{{< img src="8.png" >}}

Using Keepass, we can open the .kdbx file with `craccurrelss` and get access to the passwords. After messing around for a bit I found that performing auto-type on an entry outputs the flag.

flag: `flag{9a59bc85ebf02d5694d4b517143efba6}`

---

### Keeber 5
Points: **50**  
Solves: **573**

Challenge Description: 
The ex-employee in focus made other mistakes while using the company's GitHub. All employees were supposed to commit code using the keeber-@protonmail.com email assigned to them. They made some commits without following this practice. Find the personal email of this employee through GitHub. The flag is in regular format.

#### Approach
The challenge description tells us that we should look in the company’s GitHub to find the email of Tiffany. My initial thought is that she may have made a commit on another public GitHub repo. However, the Keeber repository is the only public one she has made commits to. 

I then did some research to see if there was a way to get the email of an account through GitHub and came across [this article](https://www.nymeria.io/blog/how-to-manually-find-email-addresses-for-github-users). Following these steps, I went through each of Tiffany’s commits in the GitHub repo adding `.patch` to all of the urls. Eventually, we get to [this commit](https://github.com/keebersecuritygroup/security-evaluation-workflow/commit/b25ed7f5aa72f88c0145a3832012546360c2ffc2) and get the following output when adding `.patch`:

```
From b25ed7f5aa72f88c0145a3832012546360c2ffc2 Mon Sep 17 00:00:00 2001
From: flag{2c90416c24a91a9e1eb18168697e8ff5} <tif.hearts.science@gmail.com>
Date: Wed, 20 Apr 2022 22:46:09 -0400
Subject: [PATCH] started code_reviews.txt

---
 code_reviews.txt | 16 ++++++++++++++++
 1 file changed, 16 insertions(+)
...
```

flag: `flag{2c90416c24a91a9e1eb18168697e8ff5}`

---

### Keeber 6
Points: **368**  
Solves: **164**

Challenge Description: 
After all of the damage the ex-employee's mistakes caused to the company, the Keeber Security Group is suing them for negligence! In order to file a proper lawsuit, we need to know where they are so someone can go and serve them. Can you find the ex-employee’s new workplace? The flag is in regular format, and can be found in a recent yelp review of their new workplace.

(Hint: You will need to pivot off of the email found in the past challenge!)

#### Approach
The hint tells us that we need to use `tif.hearts.science@gmail.com` to eventually find this new workplace. I tried to use [epieos](https://epieos.com/) to get more information. This only gives us her name and that she has a GitHub account, which we already knew. Since we are trying to find their new workplace, I figured they may have a social media account that would allow us to find this place (similar to a recent [OSINT](https://github.com/dree314/WolvSec-CTF-2022-Writeups/blob/main/OSINT/Where%20in%20the%20world.md) I made for WolvSecCon). Linkedin produced no results, and I thought Instagram was not either. None of the Tiffany Douglas accounts on instagram seemed to be her, but searching `tif.hearts.science` we find an account that is hers. 

{{< img src="10.png" >}}
{{< img src="11.png" >}}

I started with this first post to find her work location. We can see a Google watermark on it, so I set out to find where this could be on Google Maps. On Tiffany's GitHub profile, she states that she is from Maine. This can also be deduced from the 207 area code on Keeber's website. Searching on the coast of Google Maps, we can easily see ferry routes denoted by blue dashed lines. I eliminated the minor cities in Maine and figured it must be Portland, which would also be why she called it “the city.”

{{< img src="12.png" >}}

After scanning these ports I eventually came across [this one](https://www.google.com/maps/@43.6568766,-70.2480553,3a,75y,178.19h,87.69t/data=!3m7!1e1!3m5!1seNEkVm0dTjxhVTHSt2B5Qw!2e0!5s20151101T000000!7i16384!8i8192) that looked like the image, and sure enough if we turn the date back to 2015 we see the same image that was on her instagram.

{{< img src="13.png" >}}

From her first instagram post I see that there is a courtyard at the place she works at, so I start scanning for courtyards in Portland on Google Maps to see if any of them had similar photospheres. This was not getting me anywhere, so I looked more at her Instagram and figured she works at a hotel from the “but the pool is indoors” meme. In hindsight, the bedding Instagram posts were also indications of this. I searched for hotels in Portland and found one with a courtyard in satellite mode.

{{< img src="14.png" >}}

Searching [this hotel on yelp](https://www.yelp.com/biz/residence-inn-by-marriott-portland-downtown-waterfront-portland), we find Tiffany’s review with the flag in it.

{{< img src="15.png" >}}

flag: `flag{0d707179f4c993c5eb3ba9becfb046034}`

---

### Keeber 7
Points: **474**  
Solves: **74**

Challenge Description: 
Multiple employees have gotten strange phishing emails from the same phishing scheme. Use the email corresponding to the phishing email to find the true identity of the scammer. The flag is in regular format.

(Note: This challenge can be solved without paying for anything!)

[keeber_7.pdf](https://github.com/dree314/Nahamcon-CTF-2022-Keeeber-OSINT-Writeups/files/8599678/keeber_7.pdf)


#### Approach
Thankfully, Princess of the Ugbo Kingdom Ayofemi Akinruntan’s valiant attempt to get Keeber to donate to him and Sir. Beiber did not trick them. However, they did leave their email `cheerios.fanatic1941@gmail.com` which we may be able to use to figure out whoever sent this. 

{{< img src="16.png" >}}

I thought about doing forensics work on the pdf, but since this was an OSINT challenge and the description said *use the email* I didn’t bother doing anything past looking at the metadata, to which there was nothing. The note saying we did not need to pay for any OSINT tool hinted that we should be able to use a public one, so I went back to [epieos](https://epieos.com/). This gave us the information that this gmail is registered with the name `Issac Anderson` and with [holehe](https://github.com/megadose/holehe) we know that they have a Myspace account created with this email. 

{{< img src="17.png" >}}

I looked for a while to see if there was a way to find a Myspace account with just an email, but could not find anything. I then searched for Issac Anderson on Myspace and checked the ones that showed up but did not see a flag. I thought for a bit that maybe holehe was wrong or someone else registered an account with that email, but looking at the pdf again I figured the mention of Justin Bieber was a hint that we should in fact be looking for a Myspace account, since people like to share music there. I then realized I did not look through all the Issac Andersons, of which many, many results showed up.

{{< img src="18.png" >}}

I went through opening all of them and quickly looked through to see if I found the right one. Sure enough, the flag showed up on one of them.

{{< img src="19.png" >}}

flag: `flag{4a7e2fcd7f85a315a3914197c8a20f0d}`

---

### Keeber 8
Points: **482**  
Solves: **62**

Challenge Description: 
Despite all of the time we spend teaching people about phishing, someone at Keeber fell for one! Maria responded to the email and sent some of her personal information. Pivot off of what you found in the previous challenge to find where Maria's personal information was posted. The flag is in regular format.

#### Approach
From the Myspace account in `Keeber 7` the url leaves us with their username `cereal_lover1990`. The [Sherlock tool](https://github.com/sherlock-project/sherlock) is great for finding accounts connected to usernames. 

{{< img src="20.png" >}}

A lot of the results that showed up like CapFriendly show up for most searches but don’t actually have an account linked to that username. However, Pastebin doesn’t normally show up, and that seems like a great place to post personal information. Going to the *Chump list* on [their pastebin](https://pastebin.com/u/cereal_lover1990), we can find the flag in Maria’s personal information.

{{< img src="21.png" >}}

flag: `flag{70b5a5d461d8a9c5529a66fa018ba0d0}`

---

Seems like we’re ready for that interview now ;)