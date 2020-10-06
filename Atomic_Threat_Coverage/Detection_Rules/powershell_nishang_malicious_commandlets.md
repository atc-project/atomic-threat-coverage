| Title                    | Malicious Nishang PowerShell Commandlets       |
|:-------------------------|:------------------|
| **Description**          | Detects Commandlet names and arguments from the Nishang exploitation framework |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1059.001: PowerShell](https://attack.mitre.org/techniques/T1059/001)</li><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0036_4104_windows_powershell_script_block](../Data_Needed/DN_0036_4104_windows_powershell_script_block.md)</li><li>[DN_0037_4103_windows_powershell_executing_pipeline](../Data_Needed/DN_0037_4103_windows_powershell_executing_pipeline.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1059.001: PowerShell](../Triggers/T1059.001.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Penetration testing</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/samratashok/nishang](https://github.com/samratashok/nishang)</li></ul>  |
| **Author**               | Alec Costello |


## Detection Rules

### Sigma rule

```
title: Malicious Nishang PowerShell Commandlets
id: f772cee9-b7c2-4cb2-8f07-49870adc02e0
status: experimental
description: Detects Commandlet names and arguments from the Nishang exploitation framework
date: 2019/05/16
references:
    - https://github.com/samratashok/nishang
tags:
    - attack.execution
    - attack.t1059.001
    - attack.t1086  #an old one
author: Alec Costello
logsource:
    product: windows
    service: powershell
    definition: It is recommanded to use the new "Script Block Logging" of PowerShell v5 https://adsecurity.org/?p=2277
detection:
    keywords:
        - Add-ConstrainedDelegationBackdoor
        - Set-DCShadowPermissions
        - DNS_TXT_Pwnage
        - Execute-OnTime
        - HTTP-Backdoor
        - Set-RemotePSRemoting
        - Set-RemoteWMI
        - Invoke-AmsiBypass
        - Out-CHM
        - Out-HTA
        - Out-SCF
        - Out-SCT
        - Out-Shortcut
        - Out-WebQuery
        - Out-Word
        - Enable-Duplication
        - Remove-Update
        - Download-Execute-PS
        - Download_Execute
        - Execute-Command-MSSQL
        - Execute-DNSTXT-Code
        - Out-RundllCommand
        - Copy-VSS
        - FireBuster
        - FireListener
        - Get-Information
        - Get-PassHints
        - Get-WLAN-Keys
        - Get-Web-Credentials
        - Invoke-CredentialsPhish
        - Invoke-MimikatzWDigestDowngrade
        - Invoke-SSIDExfil
        - Invoke-SessionGopher
        - Keylogger
        - Invoke-Interceptor
        - Create-MultipleSessions
        - Invoke-NetworkRelay
        - Run-EXEonRemote
        - Invoke-Prasadhak
        - Invoke-BruteForce
        - Password-List
        - Invoke-JSRatRegsvr
        - Invoke-JSRatRundll
        - Invoke-PoshRatHttps
        - Invoke-PowerShellIcmp
        - Invoke-PowerShellUdp
        - Invoke-PSGcat
        - Invoke-PsGcatAgent
        - Remove-PoshRat
        - Add-Persistance
        - ExetoText
        - Invoke-Decode
        - Invoke-Encode
        - Parse_Keys
        - Remove-Persistence
        - StringtoBase64
        - TexttoExe
        - Powerpreter
        - Nishang
        - EncodedData
        - DataToEncode
        - LoggedKeys
        - OUT-DNSTXT
        - Jitter
        - ExfilOption
        - Tamper
        - DumpCerts
        - DumpCreds
        - Shellcode32
        - Shellcode64
        - NotAllNameSpaces
        - exfill
        - FakeDC
        - Exploit
    condition: keywords
falsepositives:
    - Penetration testing
level: high

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | where {(($_.message -match "Add-ConstrainedDelegationBackdoor" -or $_.message -match "Set-DCShadowPermissions" -or $_.message -match "DNS_TXT_Pwnage" -or $_.message -match "Execute-OnTime" -or $_.message -match "HTTP-Backdoor" -or $_.message -match "Set-RemotePSRemoting" -or $_.message -match "Set-RemoteWMI" -or $_.message -match "Invoke-AmsiBypass" -or $_.message -match "Out-CHM" -or $_.message -match "Out-HTA" -or $_.message -match "Out-SCF" -or $_.message -match "Out-SCT" -or $_.message -match "Out-Shortcut" -or $_.message -match "Out-WebQuery" -or $_.message -match "Out-Word" -or $_.message -match "Enable-Duplication" -or $_.message -match "Remove-Update" -or $_.message -match "Download-Execute-PS" -or $_.message -match "Download_Execute" -or $_.message -match "Execute-Command-MSSQL" -or $_.message -match "Execute-DNSTXT-Code" -or $_.message -match "Out-RundllCommand" -or $_.message -match "Copy-VSS" -or $_.message -match "FireBuster" -or $_.message -match "FireListener" -or $_.message -match "Get-Information" -or $_.message -match "Get-PassHints" -or $_.message -match "Get-WLAN-Keys" -or $_.message -match "Get-Web-Credentials" -or $_.message -match "Invoke-CredentialsPhish" -or $_.message -match "Invoke-MimikatzWDigestDowngrade" -or $_.message -match "Invoke-SSIDExfil" -or $_.message -match "Invoke-SessionGopher" -or $_.message -match "Keylogger" -or $_.message -match "Invoke-Interceptor" -or $_.message -match "Create-MultipleSessions" -or $_.message -match "Invoke-NetworkRelay" -or $_.message -match "Run-EXEonRemote" -or $_.message -match "Invoke-Prasadhak" -or $_.message -match "Invoke-BruteForce" -or $_.message -match "Password-List" -or $_.message -match "Invoke-JSRatRegsvr" -or $_.message -match "Invoke-JSRatRundll" -or $_.message -match "Invoke-PoshRatHttps" -or $_.message -match "Invoke-PowerShellIcmp" -or $_.message -match "Invoke-PowerShellUdp" -or $_.message -match "Invoke-PSGcat" -or $_.message -match "Invoke-PsGcatAgent" -or $_.message -match "Remove-PoshRat" -or $_.message -match "Add-Persistance" -or $_.message -match "ExetoText" -or $_.message -match "Invoke-Decode" -or $_.message -match "Invoke-Encode" -or $_.message -match "Parse_Keys" -or $_.message -match "Remove-Persistence" -or $_.message -match "StringtoBase64" -or $_.message -match "TexttoExe" -or $_.message -match "Powerpreter" -or $_.message -match "Nishang" -or $_.message -match "EncodedData" -or $_.message -match "DataToEncode" -or $_.message -match "LoggedKeys" -or $_.message -match "OUT-DNSTXT" -or $_.message -match "Jitter" -or $_.message -match "ExfilOption" -or $_.message -match "Tamper" -or $_.message -match "DumpCerts" -or $_.message -match "DumpCreds" -or $_.message -match "Shellcode32" -or $_.message -match "Shellcode64" -or $_.message -match "NotAllNameSpaces" -or $_.message -match "exfill" -or $_.message -match "FakeDC" -or $_.message -match "Exploit")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
\\*.keyword:(*Add\\-ConstrainedDelegationBackdoor* OR *Set\\-DCShadowPermissions* OR *DNS_TXT_Pwnage* OR *Execute\\-OnTime* OR *HTTP\\-Backdoor* OR *Set\\-RemotePSRemoting* OR *Set\\-RemoteWMI* OR *Invoke\\-AmsiBypass* OR *Out\\-CHM* OR *Out\\-HTA* OR *Out\\-SCF* OR *Out\\-SCT* OR *Out\\-Shortcut* OR *Out\\-WebQuery* OR *Out\\-Word* OR *Enable\\-Duplication* OR *Remove\\-Update* OR *Download\\-Execute\\-PS* OR *Download_Execute* OR *Execute\\-Command\\-MSSQL* OR *Execute\\-DNSTXT\\-Code* OR *Out\\-RundllCommand* OR *Copy\\-VSS* OR *FireBuster* OR *FireListener* OR *Get\\-Information* OR *Get\\-PassHints* OR *Get\\-WLAN\\-Keys* OR *Get\\-Web\\-Credentials* OR *Invoke\\-CredentialsPhish* OR *Invoke\\-MimikatzWDigestDowngrade* OR *Invoke\\-SSIDExfil* OR *Invoke\\-SessionGopher* OR *Keylogger* OR *Invoke\\-Interceptor* OR *Create\\-MultipleSessions* OR *Invoke\\-NetworkRelay* OR *Run\\-EXEonRemote* OR *Invoke\\-Prasadhak* OR *Invoke\\-BruteForce* OR *Password\\-List* OR *Invoke\\-JSRatRegsvr* OR *Invoke\\-JSRatRundll* OR *Invoke\\-PoshRatHttps* OR *Invoke\\-PowerShellIcmp* OR *Invoke\\-PowerShellUdp* OR *Invoke\\-PSGcat* OR *Invoke\\-PsGcatAgent* OR *Remove\\-PoshRat* OR *Add\\-Persistance* OR *ExetoText* OR *Invoke\\-Decode* OR *Invoke\\-Encode* OR *Parse_Keys* OR *Remove\\-Persistence* OR *StringtoBase64* OR *TexttoExe* OR *Powerpreter* OR *Nishang* OR *EncodedData* OR *DataToEncode* OR *LoggedKeys* OR *OUT\\-DNSTXT* OR *Jitter* OR *ExfilOption* OR *Tamper* OR *DumpCerts* OR *DumpCreds* OR *Shellcode32* OR *Shellcode64* OR *NotAllNameSpaces* OR *exfill* OR *FakeDC* OR *Exploit*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/f772cee9-b7c2-4cb2-8f07-49870adc02e0 <<EOF\n{\n  "metadata": {\n    "title": "Malicious Nishang PowerShell Commandlets",\n    "description": "Detects Commandlet names and arguments from the Nishang exploitation framework",\n    "tags": [\n      "attack.execution",\n      "attack.t1059.001",\n      "attack.t1086"\n    ],\n    "query": "\\\\*.keyword:(*Add\\\\-ConstrainedDelegationBackdoor* OR *Set\\\\-DCShadowPermissions* OR *DNS_TXT_Pwnage* OR *Execute\\\\-OnTime* OR *HTTP\\\\-Backdoor* OR *Set\\\\-RemotePSRemoting* OR *Set\\\\-RemoteWMI* OR *Invoke\\\\-AmsiBypass* OR *Out\\\\-CHM* OR *Out\\\\-HTA* OR *Out\\\\-SCF* OR *Out\\\\-SCT* OR *Out\\\\-Shortcut* OR *Out\\\\-WebQuery* OR *Out\\\\-Word* OR *Enable\\\\-Duplication* OR *Remove\\\\-Update* OR *Download\\\\-Execute\\\\-PS* OR *Download_Execute* OR *Execute\\\\-Command\\\\-MSSQL* OR *Execute\\\\-DNSTXT\\\\-Code* OR *Out\\\\-RundllCommand* OR *Copy\\\\-VSS* OR *FireBuster* OR *FireListener* OR *Get\\\\-Information* OR *Get\\\\-PassHints* OR *Get\\\\-WLAN\\\\-Keys* OR *Get\\\\-Web\\\\-Credentials* OR *Invoke\\\\-CredentialsPhish* OR *Invoke\\\\-MimikatzWDigestDowngrade* OR *Invoke\\\\-SSIDExfil* OR *Invoke\\\\-SessionGopher* OR *Keylogger* OR *Invoke\\\\-Interceptor* OR *Create\\\\-MultipleSessions* OR *Invoke\\\\-NetworkRelay* OR *Run\\\\-EXEonRemote* OR *Invoke\\\\-Prasadhak* OR *Invoke\\\\-BruteForce* OR *Password\\\\-List* OR *Invoke\\\\-JSRatRegsvr* OR *Invoke\\\\-JSRatRundll* OR *Invoke\\\\-PoshRatHttps* OR *Invoke\\\\-PowerShellIcmp* OR *Invoke\\\\-PowerShellUdp* OR *Invoke\\\\-PSGcat* OR *Invoke\\\\-PsGcatAgent* OR *Remove\\\\-PoshRat* OR *Add\\\\-Persistance* OR *ExetoText* OR *Invoke\\\\-Decode* OR *Invoke\\\\-Encode* OR *Parse_Keys* OR *Remove\\\\-Persistence* OR *StringtoBase64* OR *TexttoExe* OR *Powerpreter* OR *Nishang* OR *EncodedData* OR *DataToEncode* OR *LoggedKeys* OR *OUT\\\\-DNSTXT* OR *Jitter* OR *ExfilOption* OR *Tamper* OR *DumpCerts* OR *DumpCreds* OR *Shellcode32* OR *Shellcode64* OR *NotAllNameSpaces* OR *exfill* OR *FakeDC* OR *Exploit*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "\\\\*.keyword:(*Add\\\\-ConstrainedDelegationBackdoor* OR *Set\\\\-DCShadowPermissions* OR *DNS_TXT_Pwnage* OR *Execute\\\\-OnTime* OR *HTTP\\\\-Backdoor* OR *Set\\\\-RemotePSRemoting* OR *Set\\\\-RemoteWMI* OR *Invoke\\\\-AmsiBypass* OR *Out\\\\-CHM* OR *Out\\\\-HTA* OR *Out\\\\-SCF* OR *Out\\\\-SCT* OR *Out\\\\-Shortcut* OR *Out\\\\-WebQuery* OR *Out\\\\-Word* OR *Enable\\\\-Duplication* OR *Remove\\\\-Update* OR *Download\\\\-Execute\\\\-PS* OR *Download_Execute* OR *Execute\\\\-Command\\\\-MSSQL* OR *Execute\\\\-DNSTXT\\\\-Code* OR *Out\\\\-RundllCommand* OR *Copy\\\\-VSS* OR *FireBuster* OR *FireListener* OR *Get\\\\-Information* OR *Get\\\\-PassHints* OR *Get\\\\-WLAN\\\\-Keys* OR *Get\\\\-Web\\\\-Credentials* OR *Invoke\\\\-CredentialsPhish* OR *Invoke\\\\-MimikatzWDigestDowngrade* OR *Invoke\\\\-SSIDExfil* OR *Invoke\\\\-SessionGopher* OR *Keylogger* OR *Invoke\\\\-Interceptor* OR *Create\\\\-MultipleSessions* OR *Invoke\\\\-NetworkRelay* OR *Run\\\\-EXEonRemote* OR *Invoke\\\\-Prasadhak* OR *Invoke\\\\-BruteForce* OR *Password\\\\-List* OR *Invoke\\\\-JSRatRegsvr* OR *Invoke\\\\-JSRatRundll* OR *Invoke\\\\-PoshRatHttps* OR *Invoke\\\\-PowerShellIcmp* OR *Invoke\\\\-PowerShellUdp* OR *Invoke\\\\-PSGcat* OR *Invoke\\\\-PsGcatAgent* OR *Remove\\\\-PoshRat* OR *Add\\\\-Persistance* OR *ExetoText* OR *Invoke\\\\-Decode* OR *Invoke\\\\-Encode* OR *Parse_Keys* OR *Remove\\\\-Persistence* OR *StringtoBase64* OR *TexttoExe* OR *Powerpreter* OR *Nishang* OR *EncodedData* OR *DataToEncode* OR *LoggedKeys* OR *OUT\\\\-DNSTXT* OR *Jitter* OR *ExfilOption* OR *Tamper* OR *DumpCerts* OR *DumpCreds* OR *Shellcode32* OR *Shellcode64* OR *NotAllNameSpaces* OR *exfill* OR *FakeDC* OR *Exploit*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Malicious Nishang PowerShell Commandlets\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
\\*.keyword:(*Add\\-ConstrainedDelegationBackdoor* OR *Set\\-DCShadowPermissions* OR *DNS_TXT_Pwnage* OR *Execute\\-OnTime* OR *HTTP\\-Backdoor* OR *Set\\-RemotePSRemoting* OR *Set\\-RemoteWMI* OR *Invoke\\-AmsiBypass* OR *Out\\-CHM* OR *Out\\-HTA* OR *Out\\-SCF* OR *Out\\-SCT* OR *Out\\-Shortcut* OR *Out\\-WebQuery* OR *Out\\-Word* OR *Enable\\-Duplication* OR *Remove\\-Update* OR *Download\\-Execute\\-PS* OR *Download_Execute* OR *Execute\\-Command\\-MSSQL* OR *Execute\\-DNSTXT\\-Code* OR *Out\\-RundllCommand* OR *Copy\\-VSS* OR *FireBuster* OR *FireListener* OR *Get\\-Information* OR *Get\\-PassHints* OR *Get\\-WLAN\\-Keys* OR *Get\\-Web\\-Credentials* OR *Invoke\\-CredentialsPhish* OR *Invoke\\-MimikatzWDigestDowngrade* OR *Invoke\\-SSIDExfil* OR *Invoke\\-SessionGopher* OR *Keylogger* OR *Invoke\\-Interceptor* OR *Create\\-MultipleSessions* OR *Invoke\\-NetworkRelay* OR *Run\\-EXEonRemote* OR *Invoke\\-Prasadhak* OR *Invoke\\-BruteForce* OR *Password\\-List* OR *Invoke\\-JSRatRegsvr* OR *Invoke\\-JSRatRundll* OR *Invoke\\-PoshRatHttps* OR *Invoke\\-PowerShellIcmp* OR *Invoke\\-PowerShellUdp* OR *Invoke\\-PSGcat* OR *Invoke\\-PsGcatAgent* OR *Remove\\-PoshRat* OR *Add\\-Persistance* OR *ExetoText* OR *Invoke\\-Decode* OR *Invoke\\-Encode* OR *Parse_Keys* OR *Remove\\-Persistence* OR *StringtoBase64* OR *TexttoExe* OR *Powerpreter* OR *Nishang* OR *EncodedData* OR *DataToEncode* OR *LoggedKeys* OR *OUT\\-DNSTXT* OR *Jitter* OR *ExfilOption* OR *Tamper* OR *DumpCerts* OR *DumpCreds* OR *Shellcode32* OR *Shellcode64* OR *NotAllNameSpaces* OR *exfill* OR *FakeDC* OR *Exploit*)
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-PowerShell/Operational" ("Add-ConstrainedDelegationBackdoor" OR "Set-DCShadowPermissions" OR "DNS_TXT_Pwnage" OR "Execute-OnTime" OR "HTTP-Backdoor" OR "Set-RemotePSRemoting" OR "Set-RemoteWMI" OR "Invoke-AmsiBypass" OR "Out-CHM" OR "Out-HTA" OR "Out-SCF" OR "Out-SCT" OR "Out-Shortcut" OR "Out-WebQuery" OR "Out-Word" OR "Enable-Duplication" OR "Remove-Update" OR "Download-Execute-PS" OR "Download_Execute" OR "Execute-Command-MSSQL" OR "Execute-DNSTXT-Code" OR "Out-RundllCommand" OR "Copy-VSS" OR "FireBuster" OR "FireListener" OR "Get-Information" OR "Get-PassHints" OR "Get-WLAN-Keys" OR "Get-Web-Credentials" OR "Invoke-CredentialsPhish" OR "Invoke-MimikatzWDigestDowngrade" OR "Invoke-SSIDExfil" OR "Invoke-SessionGopher" OR "Keylogger" OR "Invoke-Interceptor" OR "Create-MultipleSessions" OR "Invoke-NetworkRelay" OR "Run-EXEonRemote" OR "Invoke-Prasadhak" OR "Invoke-BruteForce" OR "Password-List" OR "Invoke-JSRatRegsvr" OR "Invoke-JSRatRundll" OR "Invoke-PoshRatHttps" OR "Invoke-PowerShellIcmp" OR "Invoke-PowerShellUdp" OR "Invoke-PSGcat" OR "Invoke-PsGcatAgent" OR "Remove-PoshRat" OR "Add-Persistance" OR "ExetoText" OR "Invoke-Decode" OR "Invoke-Encode" OR "Parse_Keys" OR "Remove-Persistence" OR "StringtoBase64" OR "TexttoExe" OR "Powerpreter" OR "Nishang" OR "EncodedData" OR "DataToEncode" OR "LoggedKeys" OR "OUT-DNSTXT" OR "Jitter" OR "ExfilOption" OR "Tamper" OR "DumpCerts" OR "DumpCreds" OR "Shellcode32" OR "Shellcode64" OR "NotAllNameSpaces" OR "exfill" OR "FakeDC" OR "Exploit"))
```


### logpoint
    
```
("Add-ConstrainedDelegationBackdoor" OR "Set-DCShadowPermissions" OR "DNS_TXT_Pwnage" OR "Execute-OnTime" OR "HTTP-Backdoor" OR "Set-RemotePSRemoting" OR "Set-RemoteWMI" OR "Invoke-AmsiBypass" OR "Out-CHM" OR "Out-HTA" OR "Out-SCF" OR "Out-SCT" OR "Out-Shortcut" OR "Out-WebQuery" OR "Out-Word" OR "Enable-Duplication" OR "Remove-Update" OR "Download-Execute-PS" OR "Download_Execute" OR "Execute-Command-MSSQL" OR "Execute-DNSTXT-Code" OR "Out-RundllCommand" OR "Copy-VSS" OR "FireBuster" OR "FireListener" OR "Get-Information" OR "Get-PassHints" OR "Get-WLAN-Keys" OR "Get-Web-Credentials" OR "Invoke-CredentialsPhish" OR "Invoke-MimikatzWDigestDowngrade" OR "Invoke-SSIDExfil" OR "Invoke-SessionGopher" OR "Keylogger" OR "Invoke-Interceptor" OR "Create-MultipleSessions" OR "Invoke-NetworkRelay" OR "Run-EXEonRemote" OR "Invoke-Prasadhak" OR "Invoke-BruteForce" OR "Password-List" OR "Invoke-JSRatRegsvr" OR "Invoke-JSRatRundll" OR "Invoke-PoshRatHttps" OR "Invoke-PowerShellIcmp" OR "Invoke-PowerShellUdp" OR "Invoke-PSGcat" OR "Invoke-PsGcatAgent" OR "Remove-PoshRat" OR "Add-Persistance" OR "ExetoText" OR "Invoke-Decode" OR "Invoke-Encode" OR "Parse_Keys" OR "Remove-Persistence" OR "StringtoBase64" OR "TexttoExe" OR "Powerpreter" OR "Nishang" OR "EncodedData" OR "DataToEncode" OR "LoggedKeys" OR "OUT-DNSTXT" OR "Jitter" OR "ExfilOption" OR "Tamper" OR "DumpCerts" OR "DumpCreds" OR "Shellcode32" OR "Shellcode64" OR "NotAllNameSpaces" OR "exfill" OR "FakeDC" OR "Exploit")
```


### grep
    
```
grep -P '^(?:.*(?:.*Add-ConstrainedDelegationBackdoor|.*Set-DCShadowPermissions|.*DNS_TXT_Pwnage|.*Execute-OnTime|.*HTTP-Backdoor|.*Set-RemotePSRemoting|.*Set-RemoteWMI|.*Invoke-AmsiBypass|.*Out-CHM|.*Out-HTA|.*Out-SCF|.*Out-SCT|.*Out-Shortcut|.*Out-WebQuery|.*Out-Word|.*Enable-Duplication|.*Remove-Update|.*Download-Execute-PS|.*Download_Execute|.*Execute-Command-MSSQL|.*Execute-DNSTXT-Code|.*Out-RundllCommand|.*Copy-VSS|.*FireBuster|.*FireListener|.*Get-Information|.*Get-PassHints|.*Get-WLAN-Keys|.*Get-Web-Credentials|.*Invoke-CredentialsPhish|.*Invoke-MimikatzWDigestDowngrade|.*Invoke-SSIDExfil|.*Invoke-SessionGopher|.*Keylogger|.*Invoke-Interceptor|.*Create-MultipleSessions|.*Invoke-NetworkRelay|.*Run-EXEonRemote|.*Invoke-Prasadhak|.*Invoke-BruteForce|.*Password-List|.*Invoke-JSRatRegsvr|.*Invoke-JSRatRundll|.*Invoke-PoshRatHttps|.*Invoke-PowerShellIcmp|.*Invoke-PowerShellUdp|.*Invoke-PSGcat|.*Invoke-PsGcatAgent|.*Remove-PoshRat|.*Add-Persistance|.*ExetoText|.*Invoke-Decode|.*Invoke-Encode|.*Parse_Keys|.*Remove-Persistence|.*StringtoBase64|.*TexttoExe|.*Powerpreter|.*Nishang|.*EncodedData|.*DataToEncode|.*LoggedKeys|.*OUT-DNSTXT|.*Jitter|.*ExfilOption|.*Tamper|.*DumpCerts|.*DumpCreds|.*Shellcode32|.*Shellcode64|.*NotAllNameSpaces|.*exfill|.*FakeDC|.*Exploit))'
```



