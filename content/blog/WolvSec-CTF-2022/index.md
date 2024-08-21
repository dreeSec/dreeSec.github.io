+++
author = "dree"
title = "WolvSec CTF 2022"
date = "2022-03-29"
tags = [
    "OSINT",
]
+++

Author writeups for my 4 challenges in Crypto, Forensics, and OSINT

<!--more-->

---

[**ANYTHING**](https://dree.blog/posts/wolvsec-ctf-2022#anything) [Crypto] [241 solves]

[**RSA Frustration**](https://dree.blog/posts/wolvsec-ctf-2022#rsa-frustration) [Crypto] [12 solves]

[**Noise**](https://dree.blog/posts/wolvsec-ctf-2022#noise) [Forensics] [18 solves]

[**Where in the world?**](https://dree.blog/posts/wolvsec-ctf-2022#where-in-the-world) [OSINT] [39 solves]

---

# ANYTHING
Category: **Crypto**  
Difficulty: **Easy**  
Points: **100**  
Solves: **241**

Challenge Description: 
This could be encrypted with ANYTHING!
`wfa{oporteec_gvb_ogd}`

### Approach

1.The flag seems to be encrypted by some 1:1 cipher, since there are still 3 letters before the flag. The challenge name and description imply that the word “Anything” might be useful to help decrypt this msg. Since the first letter is not encrypted, and the first letter of anything is an A, one might be able to deduce that this is a vigenere cipher. Putting it through a vigenere cipher on [dcode](https://www.dcode.fr/vigenere-cipher) yields the following results: 

{{< img src="1.png" >}}

flag: `wsc{vigenere_not_bad}`

---

# RSA Frustration
Category: **Crypto**  
Difficulty: **Hard**  
Points: **499**  
Solves: **12**

Challenge Description: 
My friend encrypted the flag but realized they can’t decrypt it. Frustrated, they decided to keep encrypting the flag hoping this will somehow fix it. How are we going to recover it now? An efficient solution would probably be useful here.

### Files
```python
from Crypto.Util.number import getPrime, bytes_to_long, long_to_bytes

def encrypt(numToEncrypt):
    def getPrimeCustom(bitLength, e):
        while True:
            i = getPrime(bitLength)
            if (i-1) % e**2 == 0:
                return i

    global e
    global C
    bitLength = ((len(bin(numToEncrypt)) - 2) // 2) + 9
    e = 113
    p = getPrimeCustom(bitLength, e)
    q = getPrimeCustom(bitLength, e)
    N = p * q
    print(f"N = {N}")
    C = pow(numToEncrypt, e, N)
    return C

msg = b"wsc{????????????????????}"
numToEncrypt = bytes_to_long(msg)

# maybe if I keep encrypting it will fix itself???
# surely it won't make it worse
encryptedNum = encrypt(numToEncrypt)
for x in range(26):
    encryptedNum = encrypt(encryptedNum)
  
print(f"e = {e}")
print(f"C = {C}")
```

[RSA_Frustration output](https://github.com/drewd314/WolvSec-CTF-2022-Writeups/files/8358502/RSA_Frustration_-_output.2.txt)

### Approach
The idea for this challenge stemmed from [Dice CTF's](https://ctftime.org/writeup/32264) recent RSA challenge!

Based off the description, the person is having trouble decrypting their flag. This means something is broken with the algorithm. We can see that the encryption script is choosing primes that are divisible by the second power of e, meaning phi is not coprime to e!. This will cause a decryption using the inverse mod of the ciphertext to not be useful.

Therefore, we have to use a solution similar to [Dice CTF's](https://ctftime.org/writeup/32264) where we take all candidate decryptions using the nth root algorithm in sage.



**Step 1:**
We need all p and q values of the Ns. This can take a long time to generate since the largest N is 199 digits long. To accommodate for this, I uploaded the factors to [FactorDB](http://factordb.com/). An algorithm that fetches the primes from factor DB can be used, or just manually doing it since there are only 27 Ns to factor.

**Step 2:**
We are given the encrypted ciphertext after 27 encryptions, so we have to start by using the largest N's p and q values and the nth root algorithm to get possible p and q roots. We use the Chinese remainder theorem with the p and q roots to give us possible candidate decryptions, for which there will be e^2 of (12769 in this case). 

**Step 3:**
We are then going to have to construct an algorithm to keep recursing through the possible candidate decryptions, using the correct p and q values based on the depth of the recursion. A depth first search (DFS) is most useful here to get the flag quicker. Using [OPz qt's](https://github.com/christheyankee) DFS Sage Script we can get the flag!

```python
from Crypto.Util.number import long_to_bytes
from sage.all import *
e = 113
cipher = 289223688898876062358163081273625341952297233921219593553513840208424403509027574309712966219651401244239931354412620786106157789544225699742107659898527749034941786967678022482729534370307963310016
N_list = [1134876149917575363176366704410565158549594427794901202977560677131703617, 68506321231437453734007374706367120760326482177047006099953454136095248103663, 7783503593765446343363083302704731608384677185199537317445372251030064778965500447, 1070135687488356161164202697449500843725645617129661751744246979913699130211505096520493, 84012402115704505952834528733063574032699054524475028392540927197962976150657887637275643641, 4497278582433699034700211877087309784829036823057043402314297478185216205338241432310114079123771, 222438508972972285373674471797570608108219830357859030918870564627162064662598790037437036093579139489, 19116847751264029874551971240684579996570601026679560309305369168779130317938356692609176166515369250878437, 1549903986709797721131070830901667744892392382636347158789834851868638863292232718716074359148785900673192362699, 62387766690725996279968636478698222263235233511074646032501495855928095611796694112573478405813305623307157261619643, 1496134688150941811618178638810353297864345150241986530472328508974364124440160181353848429438725939837967063441528305921, 128744123633657656499069966444992201456797762973822340505291131642660343436783413140023509983315177426811890315424928661125061, 6917342652058596217869122177298094984415751234677039849514181349685079073411591975537016273056773954075238307918266361998553646469, 1999306851167477770905800721615579416365273707414308684419794311809177595829473632853128686208533753019224536487399393397120864878000113, 138594056023048386926766329537127538558164718841925506735112367176642328352257472034381662493666299220910783237918231719166519833124529218331, 8397272388904583425531462714999219642572091279898695377838194583995214737828538895164195817973441184775814069396690436662985593377966417476040659, 83372889332166088651413254885376085265561130214754686361784964744744711092668473281132249352040520639092871294276293287744276919265091479681667169671, 10684953914628370830889219903654707140968094024767031366624595731918523435466123514094659595357231410471738736952266383928737163485550013190959149252435167, 428359134899960532964729749713513106760306719712194950954567619156985067322564731294653991204666853689688900339268764469280769569535109069729404621290809120793, 24491413133428851306933688733518898516890217803647806829002775935975741568422047344206442746983871735723486865901743352102305801200224958166496937663406627341150101, 2247517335600310176909964109060502815240207684510918447209767597511414934626668616704865548059751008841620288545344598917362752622130186820039265603312354963258673860579, 157978379942536176944325875241196121764116712487226808271002140500926678942090491383544034591205964958130852055691446362753906164711087278555153881606839791499207025307202087, 43938571869497484913682975192955012614794498816057204091016374302341854100775132924321569876797699342959191646206571444845883942305710956894334106963321644724361549027630634869933, 2609065298534470914730686454716224905333131812890643378630636043224255484662185236061585264231004975072801053316107165770342161619265243081616632312934742288262985830181883449780965531, 222235907202454132555071455958700740228567465616560859711214102245461514428187391909176054661864893645713338391509536653547350134615807194339839952004333949540567943568810413945779642106201, 44890472824427626252451120059527486677662371033945481542195354255473403815853320591468917295474578271680865394304946847791535710766947049195816261224382109115684638995528332538466194474846836399, 1062789633774349417938788353001516763303743389381120380522262327123099728631034935663418832664265833959487018276693680850987382421521055508477988016246558095545925414048663082368488342633334571240563]
p_list = [1189933229053113361422958527792232151, 295185057334340451492588650872876746227, 88380889077762105057154017276462714444697, 43974782968656404951924524450501283426052127, 7832299017937880395583715032476962329929226581, 1656848589754467667368312855929759764100120657831, 385788223643735590500185001710758495904528462058461, 135813272566456906193934636644217527100917542578856697, 41680117092754807988080699273322244961911189757589699867, 9419832152875820180139633405089278278408407453522978357309, 1567597041534155679238655992215022394597376421096298363211067, 350121371461894793578110243222665782247737840410076591434903787, 103424977238409568447978495499643051307907366367259219393937014631, 43449898447639409732732812916430042263570178747794530133229640125923, 12445294229358634680867170058509842935273054334385354032543323581223253, 3200631836176555526009533059891690177091538103904679780020639896015937897, 317277895959173163347650321012213555955385929418622006880521870012130207557, 102366458668689911004027849640392002821642295855327735994412634235696717329671, 26984206512970181742033712455904984758134288864531714209886622060356697128804201, 4479430800690915874719403516331677127806963529247809966024777708496270901092401687, 1328165608715012145707239303399129070657427496129541416861187541092152796676371237057, 368461902207817023013078031477042541053987571003677386333567043030477451518424731838173, 206721456778089912780641186795393376537372828449722520397829606593267585681448641482345737, 59471978701477648587546053450213894562580907285714122639903144859545186463681183925646967041, 15115713372931874518523751684548940147062395364112500028355694776530968944848166318295947674571, 5952590790902091635268726673538951527433355660839816621733964706901441977862333411532558667717227, 1086686910531802445146659484012613083647370307628438760118376029969836222533970554565751069314622539]
q_list = [953730950786751671162019537171974567, 232079231415308325450092906880606082069, 88067722275537586769787599991567203589751, 24335212484189159197840692460327461505035059, 10726403821316775206273675267109184566904426261, 2714357008989072105081411295741540337141142641741, 576581905150085393327734090419529952232186498060949, 140758317578347635848563045232314610161039815135897421, 37185691759470013533730603170661686570987787098353146897, 6623023178993627032758350846838617937710601663528839184727, 954412804126450754097808991490470782833291028309980575506163, 367712839396521757736384350030802803477965822058616833553305103, 66882708962198932251728043152245270662769508317424500666902658099, 46014074200352892806829193743016415423205917845271691428043440245531, 11136261905010083405430254612464029672882837025885682392810368001188527, 2623629589005115152329094552749299711026240699896424120660145647226563547, 262775599542220820608778738911414710660835549772895468394761119434220071003, 104379442774418262390337411577160146519860415840398189010112686742489182665577, 15874438801602936764330936047390981280096007684699625987478211613419079727910193, 5467527956822382309398095704409409074818664888285375307055715842283183939297839923, 1692196606246085729483398884059069884182535824953762329164855466589577530953493347747, 428750921047556327595864876619292414694543668237320723518704707914310601565770504401619, 212549643149353357950643557614966235999942509894271006476145929120541407503538644651435909, 43870497594014737833600078975099212558645315030912084285417550950854483979406797450479252891, 14702310219802004876082313481498680940324963613770096574742182597840558294030859405666549879531, 7541333580839789645678699855290145212677767915429008863004397257213367753100058966625356835737037, 978009050697262759337388871320370165458800566798280419667959552859180906066907114053826258140106617]
def factorize(p,q,N,depth,cip):
    assert p * q == N
    p_roots = mod(cip, p).nth_root(e, all=True)
    q_roots = mod(cip, q).nth_root(e, all=True)
    for xp in p_roots:
        for xq in q_roots:
            x = crt([Integer(xp), Integer(xq)], [p,q])
            x = int(x)
            flag = long_to_bytes(x)
            #print(flag)
            if flag.startswith(b"wsc"):
                print(flag.decode())
            if depth != 26:
                factorize(p_list[len(p_list) - 1 - (depth + 1)], q_list[len(q_list) - 1 - (depth + 1)], N_list[len(q_list) - 1 - (depth + 1)], (depth + 1), x)           

if __name__ == "__main__":
    factorize(p_list[len(p_list) - 1], q_list[len(q_list)-1], N_list[len(q_list)-1], 0, cipher)
```

flag: `wsc{s4g3m4th_i5_5up3r_co0l!}`


***The Optimization:***
The above solution was able to find the flag, however, we can make this even faster. Since the encryption added 9 more bits to the minimum size p and q could be `bitLength = ((len(bin(numToEncrypt)) - 2) // 2) + 9`, this means we don't have to DFS through 12769 candidate decryptions each time but actually just a couple or even sometimes 1! The algorithm below gets all candidate decryptions, and only chooses the smallest one for ciphers > 400 bits, smallest 5 for ciphers > 350 bits and smallest 10 for the rest. This will save about a minute's time (on my machine) when trying to find the flag.


```python
from Crypto.Util.number import long_to_bytes
from sage.all import *

e = 113
cipher = 289223688898876062358163081273625341952297233921219593553513840208424403509027574309712966219651401244239931354412620786106157789544225699742107659898527749034941786967678022482729534370307963310016
N_list = [1134876149917575363176366704410565158549594427794901202977560677131703617, 68506321231437453734007374706367120760326482177047006099953454136095248103663, 7783503593765446343363083302704731608384677185199537317445372251030064778965500447, 1070135687488356161164202697449500843725645617129661751744246979913699130211505096520493, 84012402115704505952834528733063574032699054524475028392540927197962976150657887637275643641, 4497278582433699034700211877087309784829036823057043402314297478185216205338241432310114079123771, 222438508972972285373674471797570608108219830357859030918870564627162064662598790037437036093579139489, 19116847751264029874551971240684579996570601026679560309305369168779130317938356692609176166515369250878437, 1549903986709797721131070830901667744892392382636347158789834851868638863292232718716074359148785900673192362699, 62387766690725996279968636478698222263235233511074646032501495855928095611796694112573478405813305623307157261619643, 1496134688150941811618178638810353297864345150241986530472328508974364124440160181353848429438725939837967063441528305921, 128744123633657656499069966444992201456797762973822340505291131642660343436783413140023509983315177426811890315424928661125061, 6917342652058596217869122177298094984415751234677039849514181349685079073411591975537016273056773954075238307918266361998553646469, 1999306851167477770905800721615579416365273707414308684419794311809177595829473632853128686208533753019224536487399393397120864878000113, 138594056023048386926766329537127538558164718841925506735112367176642328352257472034381662493666299220910783237918231719166519833124529218331, 8397272388904583425531462714999219642572091279898695377838194583995214737828538895164195817973441184775814069396690436662985593377966417476040659, 83372889332166088651413254885376085265561130214754686361784964744744711092668473281132249352040520639092871294276293287744276919265091479681667169671, 10684953914628370830889219903654707140968094024767031366624595731918523435466123514094659595357231410471738736952266383928737163485550013190959149252435167, 428359134899960532964729749713513106760306719712194950954567619156985067322564731294653991204666853689688900339268764469280769569535109069729404621290809120793, 24491413133428851306933688733518898516890217803647806829002775935975741568422047344206442746983871735723486865901743352102305801200224958166496937663406627341150101, 2247517335600310176909964109060502815240207684510918447209767597511414934626668616704865548059751008841620288545344598917362752622130186820039265603312354963258673860579, 157978379942536176944325875241196121764116712487226808271002140500926678942090491383544034591205964958130852055691446362753906164711087278555153881606839791499207025307202087, 43938571869497484913682975192955012614794498816057204091016374302341854100775132924321569876797699342959191646206571444845883942305710956894334106963321644724361549027630634869933, 2609065298534470914730686454716224905333131812890643378630636043224255484662185236061585264231004975072801053316107165770342161619265243081616632312934742288262985830181883449780965531, 222235907202454132555071455958700740228567465616560859711214102245461514428187391909176054661864893645713338391509536653547350134615807194339839952004333949540567943568810413945779642106201, 44890472824427626252451120059527486677662371033945481542195354255473403815853320591468917295474578271680865394304946847791535710766947049195816261224382109115684638995528332538466194474846836399, 1062789633774349417938788353001516763303743389381120380522262327123099728631034935663418832664265833959487018276693680850987382421521055508477988016246558095545925414048663082368488342633334571240563]
p_list = [1189933229053113361422958527792232151, 295185057334340451492588650872876746227, 88380889077762105057154017276462714444697, 43974782968656404951924524450501283426052127, 7832299017937880395583715032476962329929226581, 1656848589754467667368312855929759764100120657831, 385788223643735590500185001710758495904528462058461, 135813272566456906193934636644217527100917542578856697, 41680117092754807988080699273322244961911189757589699867, 9419832152875820180139633405089278278408407453522978357309, 1567597041534155679238655992215022394597376421096298363211067, 350121371461894793578110243222665782247737840410076591434903787, 103424977238409568447978495499643051307907366367259219393937014631, 43449898447639409732732812916430042263570178747794530133229640125923, 12445294229358634680867170058509842935273054334385354032543323581223253, 3200631836176555526009533059891690177091538103904679780020639896015937897, 317277895959173163347650321012213555955385929418622006880521870012130207557, 102366458668689911004027849640392002821642295855327735994412634235696717329671, 26984206512970181742033712455904984758134288864531714209886622060356697128804201, 4479430800690915874719403516331677127806963529247809966024777708496270901092401687, 1328165608715012145707239303399129070657427496129541416861187541092152796676371237057, 368461902207817023013078031477042541053987571003677386333567043030477451518424731838173, 206721456778089912780641186795393376537372828449722520397829606593267585681448641482345737, 59471978701477648587546053450213894562580907285714122639903144859545186463681183925646967041, 15115713372931874518523751684548940147062395364112500028355694776530968944848166318295947674571, 5952590790902091635268726673538951527433355660839816621733964706901441977862333411532558667717227, 1086686910531802445146659484012613083647370307628438760118376029969836222533970554565751069314622539]
q_list = [953730950786751671162019537171974567, 232079231415308325450092906880606082069, 88067722275537586769787599991567203589751, 24335212484189159197840692460327461505035059, 10726403821316775206273675267109184566904426261, 2714357008989072105081411295741540337141142641741, 576581905150085393327734090419529952232186498060949, 140758317578347635848563045232314610161039815135897421, 37185691759470013533730603170661686570987787098353146897, 6623023178993627032758350846838617937710601663528839184727, 954412804126450754097808991490470782833291028309980575506163, 367712839396521757736384350030802803477965822058616833553305103, 66882708962198932251728043152245270662769508317424500666902658099, 46014074200352892806829193743016415423205917845271691428043440245531, 11136261905010083405430254612464029672882837025885682392810368001188527, 2623629589005115152329094552749299711026240699896424120660145647226563547, 262775599542220820608778738911414710660835549772895468394761119434220071003, 104379442774418262390337411577160146519860415840398189010112686742489182665577, 15874438801602936764330936047390981280096007684699625987478211613419079727910193, 5467527956822382309398095704409409074818664888285375307055715842283183939297839923, 1692196606246085729483398884059069884182535824953762329164855466589577530953493347747, 428750921047556327595864876619292414694543668237320723518704707914310601565770504401619, 212549643149353357950643557614966235999942509894271006476145929120541407503538644651435909, 43870497594014737833600078975099212558645315030912084285417550950854483979406797450479252891, 14702310219802004876082313481498680940324963613770096574742182597840558294030859405666549879531, 7541333580839789645678699855290145212677767915429008863004397257213367753100058966625356835737037, 978009050697262759337388871320370165458800566798280419667959552859180906066907114053826258140106617]
def lenTable(cip):
    bitLen = len(bin(cip)) - 2
    if bitLen > 400:
        return 1
    elif bitLen > 350:
        return 5
    else:
        return 10

def factorize(p,q,N,depth,cip):
    assert p * q == N
    p_roots = mod(cip, p).nth_root(e, all=True)
    q_roots = mod(cip, q).nth_root(e, all=True)
    s1 = list()
    for xp in p_roots:
        for xq in q_roots:
            x = crt([Integer(xp), Integer(xq)], [p,q])
            x = int(x)
            if len(s1) < lenTable(cip):
                s1.append(x)
            elif x < s1[0]:
                s1[lenTable(cip) - 1] = x
            s1.sort()
            flag = long_to_bytes(x)
            if flag.startswith(b"wsc"):
                print(flag.decode())
    if depth != 26:
        for num in s1:
            factorize(p_list[len(p_list) - 1 - (depth + 1)], q_list[len(q_list) - 1 - (depth + 1)], N_list[len(q_list) - 1 - (depth + 1)], (depth + 1), num)


if __name__ == "__main__":
    factorize(p_list[len(p_list) - 1], q_list[len(q_list)-1], N_list[len(q_list)-1], 0, cipher)
```
### Notes

The initial idea was to make the optimization needed to find the flag, however this would likely lead to people with very great computing power to be able to still use the sole DFS algorithm without the e optimization. Therefore, the optimization is just a bonus idea. It is most useful when trying to replicate the results of the challenge. Sage remembers factors, so when running the scripts a second time the non-optimized one takes a minute whereas the optimized one takes 5 seconds on my machine. Maybe someone could force this optimization in a challenge of their own! If 10 bits were added instead of 9 then we would not even need a DFS, and could do it linear with the smallest candidate decryption each time. However, the idea for this challenge was to incorporate a DFS but to be able to use the optimization as assistance.

---

# Noise
Category: **Forensics**  
Difficulty: **Medium**  
Points: **498**  
Solves: **18**

Challenge Description: 
My buddy sent me this totally RAW clip of them playing guitar. Doesn’t sound quite right to me, something might be off. Also don’t listen with headphones at the end!

### Approach
This challenge was based off of [Joshua Casper's](https://youtu.be/tU8WbB9vhDg) steganography idea!

While listening to the audio file, you can hear the audio has gotten corrupted towards the end of the recording. 
  
If you run strings on the file, it will output hidden comments:

{{< img src="2.png" >}}

This is hinting that you will need to view this as a raw file in photoshop. This is also hinted in the description with RAW being capitalized. To convert it to a raw file, change the file extension from ".wav" to ".raw". Then, when trying to open the file in photoshop you are presented with the following options:

{{< img src="3.png" >}}

From the hint, we are given that the channels should be set to 1 and the depth should be set to 8 bits. These are also the default settings, so the hint was not necessarily needed.

{{< img src="4.png" >}}

flag: `wsc{t0t4lly_w1ck3d_dud3}`
  
### Note
At least one team was able to do this without the use of photoshop, and just online tools.

---

# Where in the world?
Category: **OSINT**  
Difficulty: **Medium**  
Points: **486**  
Solves: **39**

Challenge Description: 
User Vividpineconepig claims on to live next to a street that's above some train tracks. Where are they? Maybe finding their social media could help. We’ll give you a flag for tracking them down. Give us this elevated STREETNAME preceding the St/Rd/Ave/Lane to prove it.

Format: wsc{STREETNAME}

### Approach

Vividpineconepig appears to be the name of some unique user. The description tells us we might want to find their social media account. Using tools like [Sherlock](https://github.com/sherlock-project/sherlock) we can find possible social media accounts of unique users. Once we try instagram, we find the following account and picture:

{{< img src="5.png" >}}
{{< img src="6.png" >}}

One might initially think that we are going to need to brute force search the location, but we can actually narrow down this location using the two main clues in the picture. After doing research, one would find that the **Adopt a Highway sign** on the right is exclusive to the state on Montana. The other major clue is the **Mile 280** mile marker. Since we know the state is Montana, one might find this [Montana's DOT Mile Marker map](https://gis-mdt.opendata.arcgis.com/datasets/eaa5f283dd7f4a33bd30f8a392925e7f_0/explore?location=47.504619%2C-108.692992%2C7.94) to be useful. There are now very little locations you would have to check on programs such as google maps.

Once we find that the town is **Shelby, MT**, the next step is finding the streetname. From the picture, we might consider this elevated street over the traintracks to be the street the description is referring to.

{{< img src="7.png" >}}

Looking on google maps, we can find the most updated street name (NOTE: If you check on google street view, it will give you an older name of the street, which is incorrect):

{{< img src="8.png" >}}

Here, we can see the street is Oilfield Ave.

flag: `wsc{OILFIELD}`

Shoutout to the [USA Geoguessr community](https://discord.gg/wx7CUMAxJQ)! would not have all adopt a highway signs memorized without them :)