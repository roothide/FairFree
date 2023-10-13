# FairFree

jailbreak any ipa and run on apple silicon M1/M2 macOS without decrypted.


## Initial thought

when Apple released an ARM-based Mac and announced that it could allow iOS apps, everyone was excited. but soon after, apple prevented users from installing IPA at will through macos updates. and only a small number of iOS apps are available on macos appstore.

so everyone began to look for other methods, such as decrypting all mach-o in the ipa and repackaging it in jailbroken iOS. however, this method has many limitations, such as some apps prevent you from decrypting, and some apps will detect whether they are decrypted when running, even checks whether its own signature is the stock version.

and running decrypted ipa in macos usually requires disabling SIP and re-signing the ipa with a valid certificate, which undoubtedly adds a lot of trouble. many people also use PlayCover to run decrypted apps without re-signing the ipa, but it is convert ios app to catalysts app, some apps may not run properly.

<img width="699" alt="image" src="https://github.com/RootHide/FairFree/assets/134120506/f6c1887d-790e-4f76-8773-decfbd2d783e">

## Investigate

we started thinking about the way apple implements this restriction. is it in the code of the macOS system itself or in the ipa package? after some investigation we came to the following facts:

1: the originally released macos11.0 system can still install any ipa without restrictions.

2: some ipa downloaded in macos 11.0 can still be installed in the new macos, even if the latest version of ipa is restricted.

so the conclusion is that apple implemented the flags and restrictions in both the new version of macos and the new version of ipa.

## Start journey

since we didn't have a device on hand that could run macos11.0, we first started analyzing the restrictions and flags in the ipa. after some testing and analysis, we quickly found some useful clues, the installation log showed that the restriction flags in the ipa seemed From the SINF file:
```
19:25:24.665931+0800	appinstalld	0x16d5c3000 -[MIExecutableBundle validateSinfWithError:]: 1487: 
The SINF provided for the bundle at /private/var/containers/Temp/Bundle/Application/8EC2AA9C-9688-49E0-B9B8-C4E4FE3DD987/maps.app is not valid on this platform.
```

it is easy to see some interesting things when looking at the SC_Info/*.sinf file: "mode". we compared the two ipas and found that their modes are indeed different. 

<img width="1561" alt="image" src="https://github.com/RootHide/FairFree/assets/134120506/45e9b23f-542d-4dd6-bc2f-81ceea4fb471">


we tried to modify the mode value, but when installing, it prompted that the ipa was damaged. then we replaced the sinf file of one ipa with another ipa and found that the restricted ipa could indeed be installed, but it could not be run, we guessed that the sinf file contained some key information of mach-o in for the runtime decryption.
```
 19:35:14.863265+0800	kernel	proc 53276: set_code_unprotect() error 7 for file "maps"
```

the only feasible way is to find the correct way to modify the mode value. after some testing and analysis, we found that the second half of the sinf file seems to contain a piece of encrypted data called priv.

<img width="565" alt="image" src="https://github.com/RootHide/FairFree/assets/134120506/a7100f3a-5e6d-47dd-853c-aa8357cc74c6">


## Into the hell

after further analysis and testing, we finally found the protagonist: FairPlay

there is very little information about FairPlay on the Internet. we can only know that it is a system used by apple to protect ipa from unauthorized installation and use. it includes the user-mode fairplayd daemon and the kernel iokit extension.

when we started analyzing the fairplayd binary, we realized that it was an ollvm hell, all functions and instructions highly obfuscated, no any symbolic information, no logs, even no any useful strings. fortunately we were donated an advanced tool to analyze obfuscated code. 

![image](https://github.com/RootHide/FairFree/assets/134120506/93a15761-f29d-4a25-adb2-552830dc2793)

![image](https://github.com/RootHide/FairFree/assets/134120506/b888d78c-5d07-4acb-87fb-68f965640ef8)


## Death and reborn

after a whole month of analysis and debugging, we finally successfully decrypted the priv field and could freely modify the sinf file. 

<img width="1607" alt="image" src="https://github.com/RootHide/FairFree/assets/134120506/32f7b76d-afe4-486f-b18d-0822ce7873cb">

the priv field is almost the encrypted backup of the first half of sinf. so we only have to modify the plaintext mode and the encrypted mode at the same time to install and run any iOS app on macos without restrictions.

the decryption function seemed to be a variant of AES128, with all cryptographic loops fully expanded, and had almost 8000 local variables after obfuscated. so we wrote a script to hack it on specific device and ios version.

## Enjoy it

how to use:

1. device iphone X & ios13.5.1
2. jailbreak & install frida-server
3. login apple id in appstore & install the app
4. ```chmod -R 777 /path/to/*.app/SC_Info/``` on ios
5. run ```python3 fairfree.py``` on computer
6. launch the app in home screen
7. check the "mode" in SC_Info/*.sinf
8. zip the *.app to a ipa file
9. copy ipa file to macos and install
10. login the apple id in macos appstore
11. launch the app in macos

## Does it safe?

Yes, we only modify sinf to re-authorize the ipa, and the sandbox will prevent the app from accessing the sinf file (which contains the private information of the appleid), so the app cannot find out that it has been modified.

