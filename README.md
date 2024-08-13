# Azure2FA TOTP
Azure Two factor Authentication code generator

## Overview

This repository contains NeoLoad Advanced Actions that allows performance testers using NeoLoad to generate TOTP Code.

| Property           | Value                                                                         |
|--------------------|-------------------------------------------------------------------------------|
| Maturity           | Experimental                                                                  |
| Support            | Supported by Neotys                                                           |
| Author             | Neotys                                                                        |
| License            | [BSD Simplified](https://www.neotys.com/documents/legal/bsd-neotys.txt)       |
| NeoLoad            | 2024.2 (Enterprise or Professional Edition w/ Integration & Advanced Usage)    |
| Bundled in NeoLoad | No                                                                          |
| Download Binaries  | See the [latest release]() |


## Installation

### Setting up the TOTP Advance action for Azure/Google Autheticator

1. Download the latest Advance Action jar [latest release](https://github.com/Neotys-Labs/Azure2FA/releases/tag/Azure2FA_TOTPFinal).
   Keept the Jar file in the extlib folder of yor Neoload Project

4. Reopen Neoload project
## Advanced Actions definitions
### TOTP
##1. TOTP codegeneartors parameter - Parameters

| Name                     | Description       |
| ---------------          | ----------------- |
| Secret                   | Secret generated at the time of registration of user/password reset in the applictaion    |

Status Codes:
* NL-TOTP_ERROR :  Any error while genearting code 
Example:
<p align="center"><img src="/screenshot/TOTP.png" alt="TOTP" /></p>

## ChangeLog

* Version 0.0.2 (Aug 1 2024): 


