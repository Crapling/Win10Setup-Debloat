# win10script
This is the Ultimate Windows 10 Script from a creation from multiple debloat scripts and gists from github.
I also added various programs for my default Windows 10 Installation.

I forked ChrisTitusTech's scripts (https://github.com/ChrisTitusTech/win10script) and made some minor adjustments to fit my liking.

## My Additions

- 

## Modifications
Just like ChrisTitusTech I encourage people to fork this project and comment out things they don't like! Here is a list of normal things people change:
- Installing Adobe, Chocolatey, Notepad++ and 7-Zip

Comment any thing you don't want out... Example:

```
########## NOTE THE # SIGNS! These disable lines This example shows UACLow being set and Disabling SMB1
### Security Tweaks ###
	"SetUACLow",                  # "SetUACHigh",
	"DisableSMB1",                # "EnableSMB1",

########## NOW LETS SWAP THESE VALUES AND ENABLE SMB1 and Set UAC to HIGH
### Security Tweaks ###
	"SetUACHigh",
	"EnableSMB1",
```
