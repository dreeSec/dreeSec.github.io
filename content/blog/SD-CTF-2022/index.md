+++
author = "dree"
title = "SD CTF 2022"
date = "2022-05-10"
tags = [
    "OSINT",
]
+++

Complete OSINT Solves from University of San Diego's CTF
<!--more-->



---

## Part of the ship...
Difficulty: **Easy**  
Authors: `Blarthogg`  
Points: **150**  
Solves: **76**

Challenge Description:  
Sometimes I worry about my friend... he's way too into memes, he's always smiling, and he's always spouting nonsense about some "forbidden app." I don't know what he's talking about, but maybe you can help me figure it out! All I know is a username he used way back in the day. Good luck! Flag format is sdctf{flag}  
**Username**  
DanFlashes

### Approach

I started off this challenge by looking up the username `DanFlashes` on different social media platforms to see if one was linked to SDCTF. I found one on Instagram, but it seemed unrelated to the competition. I went back to the prompt to see what other clues could lead us to this account. I decided to google “forbidden app” and found [urban dictionary definitions](https://www.urbandictionary.com/define.php?term=The%20Forbidden%20App) that this app is iFunny, and the definitions also mentioned being “part of the ship” (like the challenge name) so I figured this was the right social media.

{{< img src="forbidden_app.png" >}}

Looking at DanFlashes [on iFunny](https://ifunny.co/user/DanFlashes), we see that this page does not exist. However, the challenge description states that this was “‘way back’ in the day” which hints that we should use the [Wayback Machine](https://web.archive.org/web/20220128003432/https://ifunny.co/user/DanFlashes) (always look for hints like these in OSINT challenges!). From this we can see a snapshot was taken January 28th of this year, which gives us the flag on DanFlashes' profile.

{{< img src="wayback_ifunny.png" >}}

flag: `sdctf{morning_noon_and_night_I_meme}`

---

## Google Ransom
Difficulty: **Easy**  
Authors: `KNOXDEV`  
Points: **100**  
Solves: **155**

Challenge Description:  
Oh no! A hacker has stolen a flag from us and is holding it ransom. Can you help us figure out who created this document? Find their email address and demand they return the flag!  
**Attachments**  
[ransom letter](https://docs.google.com/document/d/1MbY-aT4WY6jcfTugUEpLTjPQyIL9pnZgX_jP8d8G2Uo/edit)  

### Approach  
From the ransom letter, we see a cryptic note about someone threatening to sign their email up for an annoying newsletter. As threatening as this is, it doesn’t give us any information about who made this google doc. However, since it’s google there is likely a way to view the email of this account owner. I went to the “shared with me” section on google drive to get more information about the random letter. Looking at `Details`, we can see that the owner of the document is `Amy SDCTF`. 

{{< img src="ransom_details.png" >}}

I could have used [GHunt](https://github.com/mxrch/GHunt) to get the exact email, but from the Turing Test challenge I assumed the email was in the same format as `jack.sdctf@gmail.com` and confirmed this on [epieos](https://epieos.com/). After sending `amy.sdctf@gmail.com` an email demanding the flag, we get a response giving it to us.

{{< img src="email_flag.png" >}}

flag: `sdctf{0p3n_S0uRCE_1S_aMaz1NG}`

## Samuel
Difficulty: **Medium**  
Authors: `k3v1n`  
Points: **88**  
Solves: **160**

Challenge Description:  
Where is this?
https://www.youtube.com/watch?v=fDGVF1fK1cA

Flag format: sdctf{latitude,longitude} using decimal degrees and 3 decimal places rounded toward zero (Ex. 4.1239 → 4.123, -4.0009 → -4.000)

Example: If the location were https://goo.gl/maps/TnhzfxXKg9TDYDfR9 the flag would be sdctf{38.889,-77.035}  
**Note**  
The youtube channel/account is not relevant to this challenge. Only the video content is relevant.

### Approach  
The video linked shows us a blinking beacon at night, with a plane flying by in the distance. I initially thought this was an [Aviation OSINT](https://www.osintessentials.com/aviation) since the plane in the background was the only other thing in the video. I had no idea how to use the beacon or distant plane.

As the competition progressed, I saw that the challenge had a lot of solves and I figured it likely wasn’t some insanely hard Aviation OSINT. I then realized the blinking beacon was likely morse code. `.-- .... .- - / .... .- - .... / --. --- -.. / .-- .-. --- ..- --. .... -` translated to **WHAT HATH GOD WROUGHT**. After googling what that means, we learn it was [the official first Morse code message transmitted in the US](https://en.wikipedia.org/wiki/What_hath_God_wrought#:~:text=%22What%20hath%20God%20wrought%22%20is,the%20Baltimore%E2%80%93Washington%20telegraph%20line).

I thought then the location may be where the message was originally transferred or received, but couldn’t find anything there. I then just searched “What hath god wrought” on Google Maps and found a sculpture at the University of California San Diego. Seeing that the competition is hosted by San Diego State University, I assumed this was the right spot. From this we can get the coordinates on [Google Maps](https://www.google.com/maps/place/What+Hath+God+Wrought/@32.8751745,-117.2408527,21z/data=!4m5!3m4!1s0x80dc07e0d30e81a7:0x69087278617d6b1d!8m2!3d32.8752134!4d-117.2407749) in the url, and truncating 32.8751745,-117.2408527 to get the flag.

{{< img src="google_maps.png" >}}

flag: `sdctf{32.875,-117.240}`

---

## Turing Test
Difficulty: **Medium**  
Authors: `Blarthogg, KNOXDEV`  
Points: **200**  
Solves: **49**

Challenge Description:  
My friend has been locked out of his account! Can you help him recover it?  
**Email**  
`jack.sdctf@gmail.com`  
**Website**  
https://vault.sdc.tf/  
**Note**  
Twitter does not need to be used for this challenge.

### Approach  
My first step in this challenge was going to the website, and started spamming random passwords to see what would happen. After 5 incorrect guesses, an `Account Support` window is prompted. We are then asked security questions to get back into our account (as well as bread puns).

{{< img src="flag_vault.png" >}}

For the first prompt, we are asked our name. We can use [epieos](https://epieos.com/) on Jack’s email to find his name is Jack Banner.

{{< img src="epios_jack.png" >}}

Next we are prompted with “What month were you born in?” I wasn't sure if you were supposed to brute force this but figured since it was an OSINT challenge thre would be a social media account. Epieos showed Jack’s email as being connected to a Twitter, but luckily the challenge admin noticed this as well and added a disclaimer that twitter does not need to be used. What could have happened is someone else registered an account with that email, which admins have to be prepared to fix for these kinds of challenges. I tried other social media platforms, and specifically ones that I did not explore yet. OSINT categories usually try to avoid using the same platform twice. Looking up “Jack Banner” on Facebook, we see [the account](https://www.facebook.com/profile.php?id=100077609021228) we are looking for.

{{< img src="jack_banner_facebook.png" >}}

The first post we can use to find his birthday by a quick google search of “99 days before april 19” giving us their birthday of January 10th.

{{< img src="jack_banner_birthday.png" >}}

The next prompt is “What is the name of your dog?” Looking around more on their facebook, we see an instagram for their dog linked in the Intro section. Something I learned from this challenge is that this can **only be seen if you are logged into Facebook**, so for some OSINT challenges you may need to be logged in. Although for regular OSINT gathering usually you don’t want to alert the person you are looking at, such as on LinkedIn. On the Instagram account we see that the dog’s name is Ravioli.

{{< img src="intro.png" >}}

{{< img src="pastadoggy.png" >}}


The final prompt is “What are the first six characters of your flag?” which is `sdctf{` for this CTF. This lets us access the flag vault and get the flag.

{{< img src="flag_vault_flag.png" >}}


flag: `sdctf{7he_1m1747i0n_94m3}`

---

## Paypal Playboy
Difficulty: **Hard**  
Authors: `Blarthogg`  
Points: **300**  
Solves: **23**

Challenge Description:  
We've apprehended somebody suspected of purchasing SDCTF flags off an underground market. That said, this guy is small fry. We need to find the leaker and bring them to brutal justice!

Attached is an email we retrieved from his inbox. See if you can't figure out the boss of their operation.  
Flag format is sdctf{...}  
**mbox**  
[Click here to download](https://github.com/drewd314/SD-CTF-2022-Writeups/blob/main/mbox)  
**Note**  
You should not have to spend any money to solve this challenge  
**Note**  
If you encounter an email not in the format of `[name].sdctf@gmail.com` it is not in the challenge scope.

### Approach  
The [mbox](https://github.com/drewd314/SD-CTF-2022-Writeups/blob/main/mbox) file contains an email from `flag.peddler@wehate.sdc.tf` about "cheap sdctf banners". I used [epieos](https://epieos.com/) to see more information about that email, but it doesn't exist. I then wanted to see what `支付.png` (payment.png) was. Using a [base64 to image converter](https://codebeautify.org/base64-to-image-converter), we get a qr code that leads to [this Cash App](https://cash.app/$limosheen?qr=1).

{{< img src="b64.png" >}}

The username on Cash App is
 `limosheen`. I first used [Sherlock](https://github.com/sherlock-project/sherlock) to look for accounts connected to that username but couldn’t find anything. I looked back at the email for more information that we could use to find limosheen. 

I decoded the plaintext section of the email with base64 and utf-8, then ran it through Google Translate:

``
Cheap banner for the San Diego Cybersecurity Games. Be the winner of SDCTF. fast and convenient. Click below. Cheap banner for the San Diego Cybersecurity Games. Be the winner of SDCTF. fast and convenient. Click below. Cheap banner for the San Diego Cybersecurity Games. Be the winner of SDCTF. fast and convenient. Click below. You can also find us on PayPal or on the blockchain. 0xbad ... A43B ..... SDCTF {Forgery_bana} 3️⃣ ✳ ✳️ 👟 📙 👈 🔠 🖖 🐾 🃏 🕕 ❇ ❇ ❇️ ⬇ 🈷️ 🕜 ↘️ 🍕 👨 🌏 ◾️ 🌎 😸 🍄 ✳️ 🕡 🚛 👧 🔻 ♓️ 🔠 😭
``

This note says we also find them on PayPal. When searching for limosheen on PayPal, we can see that there exists an account with the SDCTF logo. The challenge description said "You should not have to spend any money to solve this challenge", although some people still sent the account money but received nothing :(. After some research I learned about paypal.me accounts which give more information about a user. Going to [limosheen’s profile](https://www.paypal.com/limosheen), we find this:

{{< img src="paypal.png" >}}

I saw a string on this that started with 0x and incorrectly thought it was a hex string by default, and decoding it gave nothing. I eventually learned it was an Ethereum address by just googling and inputting the address into crypto websites. In hindsight I should have definitely realized this sooner with the plaintext saying we can also find them on the blockchain, and the ropETH comment on the PayPal. When looking up the address on [Etherscan](https://etherscan.io/address/0xBAd914D292CBFEe9d93A6A7a16400Cb53319A43B) we find that the address is valid, but no entries are found.

{{< img src="etherscan.png" >}}

I thought that this was a dead end at first and started doing reverse image searches and forensics on the PayPal banner, but did not get any results. I looked back at the Ethereum address and figured there must be a reason that it’s there. On Etherscan there is a notification saying that the address can be found on other chains, and sure enough we see that it’s on the Ropsten Testnet. 

{{< img src="ropsten.png" >}}

I tried googling the “ropETH” hint from the PayPal prior but must have done so poorly since I could not find Ropsten Testnet, but it at least confirmed we were in the right place now. We see Ethereum was transferred to ` 0x949213139D202115c8b878E8Af1F1D8949459f3f`, and this address has only inbound transfers, so it can be assumed that this is the boss we are looking for. 

{{< img src="transactions.png" >}}

The PayPal account said we could find the boss on Twitter, so I put this address into twitter and found the account [Jon Fakeflag](https://twitter.com/wrestling_wave_). 

{{< img src="jonfakeflag1.png" >}}

{{< img src="jonfakeflag2.png" >}}

From this account we get a base64 string that gives us the flag.

{{< img src="cyberchef.png" >}}

flag: `sdctf{You_Ever_Dance_With_the_Devil_In_the_Pale_Moonlight}`

---

## Mann Hunt
Difficulty: **Hard**  
Authors: `KNOXDEV`  
Points: **400**  
Solves: **96**

Challenge Description:  
We were on the trail of a notorious hacker earlier this week, but they suddenly went dark, taking down all of their internet presence...All we have is a username. We need you to track down their personal email address! It will be in the form `****.sdctf@gmail.com`. Once you find it, send them an email to demand the flag!   
**Username**  
`mann5549`  

### Approach 
After a quick search for mann5549 we find that they have a Twitter.

{{< img src="mann_twitter.png" >}}

I tried using the [Wayback Machine](https://archive.org/web/) on this Twitter but could not find anything useful. I went to the website linked on Twitter where we find this message stating that we will never find this user.

{{< img src="mann_codes.png" >}}

Wayback Machine does not prove to be useful here either, so I looked at the source code of the website and found a link to a [GitHub repository](https://github.com/manncyber/manncodes.github.io) for the website.

```
…name="description" content="Contribute to the blog at https://github.com/manncyber/manncodes.github.io"/><meta data-react-helmet="true" property="og:title"...
```

In this repository we can see a commit that manncyber made removing certain data because he was being tracked. My first thought was maybe they used their email in this commit, so I added `.patch` to the end of the commit url but they used a standard GitHub email for this. 

{{< img src="mann_git.png" >}}


Here is where I started overthinking the challenge and tried a couple of dead end routes. I saw an image called `salty_egg` was removed in this commit, and when reverse image searvching it I was lead to this [Wikipedia article](https://en.wikipedia.org/wiki/Salted_duck_egg). I spent a long time looking through the editing history profiles and IPs before realizing the image was a [stock template](https://github.com/gatsbyjs/gatsby-starter-blog/blob/master/content/blog/hello-world/index.md) for Gatsby. 

In this commit history we can also see that the blog author’s name `Emanuel Hunt` was removed. I initially looked on [epieos](https://epieos.com/) to see if `emmanuel.sdctf@gmail.com` or `hunt.sdctf@gmail.com` were valid emails, but they were not. I finally just googled “Emanuel Hunt” (which I should have done initially) and was immediatley shown a search result for an Emanuel Hunt from San Diego on [LinkedIn](https://www.linkedin.com/in/emanuel-hunt-34749a207/).

{{< img src="linkedin.png" >}}

If we go to the resume that is linked, the email is unfortunately blanked out. However, if we hover over Emanuel Hunt’s profile picture on the right hand side the email `mann.sdctf@gmail.com` is shown.

{{< img src="hunt_resume.png" >}}

This email is fairly simple to guess and some people may have done that initially. Sending them an email demanding the flag we get this response:

{{< img src="hunt_email_flag.png" >}}

flag:`sdctf{MaNN_tH@t_w@s_Ann0YinG}`

