| Title                | MSHTA Suspicious Execution 01                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detection for mshta.exe suspicious execution patterns sometimes involving file polyglotism                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1140: Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1140: Deobfuscate/Decode Files or Information](../Triggers/T1140.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>False positives depend on scripts and administrative tools used in the monitored environment</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[http://blog.sevagas.com/?Hacking-around-HTA-files](http://blog.sevagas.com/?Hacking-around-HTA-files)</li><li>[https://0x00sec.org/t/clientside-exploitation-in-2018-how-pentesting-has-changed/7356](https://0x00sec.org/t/clientside-exploitation-in-2018-how-pentesting-has-changed/7356)</li><li>[https://docs.microsoft.com/en-us/dotnet/standard/data/xml/xslt-stylesheet-scripting-using-msxsl-script](https://docs.microsoft.com/en-us/dotnet/standard/data/xml/xslt-stylesheet-scripting-using-msxsl-script)</li><li>[https://medium.com/tsscyber/pentesting-and-hta-bypassing-powershell-constrained-language-mode-53a42856c997](https://medium.com/tsscyber/pentesting-and-hta-bypassing-powershell-constrained-language-mode-53a42856c997)</li></ul>  |
| Author               | Diego Perez (@darkquassar) |


## Detection Rules

### Sigma rule

```
title: MSHTA Suspicious Execution 01
id: cc7abbd0-762b-41e3-8a26-57ad50d2eea3
status: experimental
description: Detection for mshta.exe suspicious execution patterns sometimes involving file polyglotism
date: 22/02/2019
modified: 22/02/2019
author: Diego Perez (@darkquassar)
references:
    - http://blog.sevagas.com/?Hacking-around-HTA-files
    - https://0x00sec.org/t/clientside-exploitation-in-2018-how-pentesting-has-changed/7356
    - https://docs.microsoft.com/en-us/dotnet/standard/data/xml/xslt-stylesheet-scripting-using-msxsl-script
    - https://medium.com/tsscyber/pentesting-and-hta-bypassing-powershell-constrained-language-mode-53a42856c997
tags:
    - attack.defense_evasion
    - attack.t1140
logsource:
    category: process_creation
    product: windows
falsepositives: 
    - False positives depend on scripts and administrative tools used in the monitored environment
level: high
detection:
    selection1:
        CommandLine: 
            - '*mshta vbscript:CreateObject("Wscript.Shell")*'
            - '*mshta vbscript:Execute("Execute*'
            - '*mshta vbscript:CreateObject("Wscript.Shell").Run("mshta.exe*'
    selection2:
        Image:
            - 'C:\Windows\system32\mshta.exe'
        CommandLine: 
            - '*.jpg*'
            - '*.png*'
            - '*.lnk*'
            # - '*.chm*'  # could be prone to false positives
            - '*.xls*'
            - '*.doc*'
            - '*.zip*'
    condition:
        selection1 or selection2

```





### splunk
    
```
((CommandLine="*mshta vbscript:CreateObject(\\"Wscript.Shell\\")*" OR CommandLine="*mshta vbscript:Execute(\\"Execute*" OR CommandLine="*mshta vbscript:CreateObject(\\"Wscript.Shell\\").Run(\\"mshta.exe*") OR ((Image="C:\\\\Windows\\\\system32\\\\mshta.exe") (CommandLine="*.jpg*" OR CommandLine="*.png*" OR CommandLine="*.lnk*" OR CommandLine="*.xls*" OR CommandLine="*.doc*" OR CommandLine="*.zip*")))
```






### Saved Search for Splunk

```
b'# Generated with Sigma2SplunkAlert\n[MSHTA Suspicious Execution 01]\naction.email = 1\naction.email.subject.alert = Splunk Alert: $name$\naction.email.to = test@test.de\naction.email.message.alert = Splunk Alert $name$ triggered \\\nList of interesting fields:   \\\ntitle: MSHTA Suspicious Execution 01 status: experimental \\\ndescription: Detection for mshta.exe suspicious execution patterns sometimes involving file polyglotism \\\nreferences: [\'http://blog.sevagas.com/?Hacking-around-HTA-files\', \'https://0x00sec.org/t/clientside-exploitation-in-2018-how-pentesting-has-changed/7356\', \'https://docs.microsoft.com/en-us/dotnet/standard/data/xml/xslt-stylesheet-scripting-using-msxsl-script\', \'https://medium.com/tsscyber/pentesting-and-hta-bypassing-powershell-constrained-language-mode-53a42856c997\'] \\\ntags: [\'attack.defense_evasion\', \'attack.t1140\'] \\\nauthor: Diego Perez (@darkquassar) \\\ndate:  \\\nfalsepositives: [\'False positives depend on scripts and administrative tools used in the monitored environment\'] \\\nlevel: high\naction.email.useNSSubject = 1\nalert.severity = 1\nalert.suppress = 0\nalert.track = 1\nalert.expires = 24h\ncounttype = number of events\ncron_schedule = */10 * * * *\nallow_skew = 50%\nschedule_window = auto\ndescription = Detection for mshta.exe suspicious execution patterns sometimes involving file polyglotism\ndispatch.earliest_time = -10m\ndispatch.latest_time = now\nenableSched = 1\nquantity = 0\nrelation = greater than\nrequest.ui_dispatch_app = sigma_hunting_app\nrequest.ui_dispatch_view = search\nsearch = ((CommandLine="*mshta vbscript:CreateObject(\\"Wscript.Shell\\")*" OR CommandLine="*mshta vbscript:Execute(\\"Execute*" OR CommandLine="*mshta vbscript:CreateObject(\\"Wscript.Shell\\").Run(\\"mshta.exe*") OR ((Image="C:\\\\Windows\\\\system32\\\\mshta.exe") (CommandLine="*.jpg*" OR CommandLine="*.png*" OR CommandLine="*.lnk*" OR CommandLine="*.xls*" OR CommandLine="*.doc*" OR CommandLine="*.zip*"))) | stats values(*) AS * by _time | search NOT [| inputlookup MSHTA_Suspicious_Execution_01_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.defense_evasion,sigma_tag=attack.t1140,level=high"\n\n\n'
```
