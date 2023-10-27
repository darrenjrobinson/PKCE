# PKCE Code Verifier and Challenge Generator PowerShell Module
Generate OAuth 2.0 Proof Key for Code Exchange (PKCE) 'code_challenge' and 'code_verifier' for use with an OAuth2 Authorization Code Grant flow. 

[![PSGallery Version](https://img.shields.io/powershellgallery/v/PKCE.svg?style=flat&logo=powershell&label=PSGallery%20Version)](https://www.powershellgallery.com/packages/PKCE) [![PSGallery Downloads](https://img.shields.io/powershellgallery/dt/PKCE.svg?style=flat&logo=powershell&label=PSGallery%20Downloads)](https://www.powershellgallery.com/packages/PKCE)

It contains one cmdlet (New-PKCE) that does a number of key things;
* Generate both the code_verifier and the associated code_challenge
* Generate the code_challenge for a valid code_verifier
* Generate a code_verifier of a specified length [as per RFC 7636](https://datatracker.ietf.org/doc/html/rfc7636)

[Available in the PowerShell Gallery](https://www.powershellgallery.com/packages/PKCE)

[Associated Blogpost](https://blog.darrenjrobinson.com/generating-pkce-codes-with-powershell)

## Install
Install direct from the PowerShell Gallery (Powershell 5.1 and above).


```powershell
install-module -name PKCE
```

## Import
Import the Module. 

```powershell
import-module PKCE
```

## Example 
Generate a code_verifier and code_challenge using the default 127 character length. 

```powershell
New-PKCE | FL
```

### Output 
```
code_verifier  : WoBOriV4tDoK61KVPbWM71sk5maozuSXjxRUO2fu9zIQCoH0ExenrT7clYznp15CKLy8HnnXENGBw3SuZjM0T2vaUvVJBD7ThpD2XqkjdPyekAkYFs8b4cCFaxHgFOhO
code_challenge : dKk5vCznfP9dqr7PPugOfq/cmyX1hEMzvdVT/x0ZRg0
```

## Example 
Generate a code_verifier and code_challenge with a length of 99 for the code_verifier.

```powershell 
New-PKCE -length 99 | FL
```

### Output

```
code_verifier  : yf82tm6q0Q9mgkFfxPXfRNyN4dhlDHrI9kKKsX5vAVhMLeW80LyutH3wx9bPh82wisluIBOsaR6Z7P0z5LMcqoOfJRayn7ZpTkD
code_challenge : YOamaHC/iqRrIkSusU2FEMahO2BVJz1KZzEQ9o6j5kE
```

## Example 
Generate a code_challenge for a specified code_verifier.

```powershell 
New-PKCE -codeVerifier '0_EUVyNBjAFIAKg7xqw-3WC5xAZkx..~~xqndi4WRc1NCCEdXUScvCfDsVygmDQQ~eIZiVamZsQp3XhqL9TuH5~9U-BRBvI3KeOtalT.~uByhfTcGhnd9gHySopRaeLN' | FL
```

### Output

```
code_verifier  : 0_EUVyNBjAFIAKg7xqw-3WC5xAZkx..~~xqndi4WRc1NCCEdXUScvCfDsVygmDQQ~eIZiVamZsQp3XhqL9TuH5~9U-BRBvI3KeOtalT.~uByhfTcGhnd9gHySopRaeLN
code_challenge : gewJaAUliqSe-nMhl48sutkX4ayfCtcPc-72jRnAPMA
```

## Example 
Generate a code_challenge and code_verifier and assign to variables for use in an OAuth2 Authorization Code Grant flow

```powershell 
$pkceCodes = New-PKCE 
$codeChallenge = $pkceCodes.code_challenge
$codeVerifier = $pkceCodes.code_verifier

$pkceCodes | FL
$codeVerifier
$codeChallenge
```

### Output

```
code_verifier  : n8bOz65bchiqsu5dW1JTRWBGWlkbmKUCXR5CRiUqrdqIBeSvTlOjS8i9xsgpVVMBXEgjNKDBKhFNDnzFa4yp87v3fZNgPA2MtFEIrtdjoRkvtmAwrj3uCcyf1A4h7ZGY
code_challenge : T1nH0TteC6QN7p4upQ4GPT/x0nWCfKMrtTi5+mptrvg

n8bOz65bchiqsu5dW1JTRWBGWlkbmKUCXR5CRiUqrdqIBeSvTlOjS8i9xsgpVVMBXEgjNKDBKhFNDnzFa4yp87v3fZNgPA2MtFEIrtdjoRkvtmAwrj3uCcyf1A4h7ZGY
T1nH0TteC6QN7p4upQ4GPT/x0nWCfKMrtTi5+mptrvg
```

## Keep up to date
* [Visit my blog](http://darrenjrobinson.com/)
* ![](http://twitter.com/favicon.ico) [Follow on Twitter](https://twitter.com/darrenjrobinson)
