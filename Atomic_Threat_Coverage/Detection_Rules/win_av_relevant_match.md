| Title                | Relevant Anti-Virus Event                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | This detection method points out highly relevant Antivirus events                                                                                                                                           |
| ATT&amp;CK Tactic    |   This Detection Rule wasn't mapped to ATT&amp;CK Tactic yet  |
| ATT&amp;CK Technique |  This Detection Rule wasn't mapped to ATT&amp;CK Technique yet  |
| Data Needed          |  There is no documented Data Needed for this Detection Rule yet  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              |  There is no documented Trigger for this Detection Rule yet  |
| Severity Level       | high |
| False Positives      | <ul><li>Some software piracy tools (key generators, cracks) are classified as hack tools</li></ul>  |
| Development Status   |  Development Status wasn't defined for this Detection Rule yet  |
| References           |  There are no documented References for this Detection Rule yet  |
| Author               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Relevant Anti-Virus Event
id: 78bc5783-81d9-4d73-ac97-59f6db4f72a8
description: This detection method points out highly relevant Antivirus events
author: Florian Roth
logsource:
    product: windows
    service: application
detection:
    keywords:
        Message:
            - "*HTool*"
            - "*Hacktool*"
            - "*ASP/Backdoor*"
            - "*JSP/Backdoor*"
            - "*PHP/Backdoor*"
            - "*Backdoor.ASP*"
            - "*Backdoor.JSP*"
            - "*Backdoor.PHP*"
            - "*Webshell*"
            - "*Portscan*"
            - "*Mimikatz*"
            - "*WinCred*"
            - "*PlugX*"
            - "*Korplug*"
            - "*Pwdump*"
            - "*Chopper*"
            - "*WmiExec*"
            - "*Xscan*"
            - "*Clearlog*"
            - "*ASPXSpy*"
    filters:
        Message:
            - "*Keygen*"
            - "*Crack*"
    condition: keywords and not 1 of filters
falsepositives:
    - Some software piracy tools (key generators, cracks) are classified as hack tools
level: high

```





### splunk
    
```
((Message="*HTool*" OR Message="*Hacktool*" OR Message="*ASP/Backdoor*" OR Message="*JSP/Backdoor*" OR Message="*PHP/Backdoor*" OR Message="*Backdoor.ASP*" OR Message="*Backdoor.JSP*" OR Message="*Backdoor.PHP*" OR Message="*Webshell*" OR Message="*Portscan*" OR Message="*Mimikatz*" OR Message="*WinCred*" OR Message="*PlugX*" OR Message="*Korplug*" OR Message="*Pwdump*" OR Message="*Chopper*" OR Message="*WmiExec*" OR Message="*Xscan*" OR Message="*Clearlog*" OR Message="*ASPXSpy*") NOT ((Message="*Keygen*" OR Message="*Crack*")))
```






### Saved Search for Splunk

```
b'# Generated with Sigma2SplunkAlert\n[Relevant Anti-Virus Event]\naction.email = 1\naction.email.subject.alert = Splunk Alert: $name$\naction.email.to = test@test.de\naction.email.message.alert = Splunk Alert $name$ triggered \\\nList of interesting fields:   \\\ntitle: Relevant Anti-Virus Event status:  \\\ndescription: This detection method points out highly relevant Antivirus events \\\nreferences:  \\\ntags:  \\\nauthor: Florian Roth \\\ndate:  \\\nfalsepositives: [\'Some software piracy tools (key generators, cracks) are classified as hack tools\'] \\\nlevel: high\naction.email.useNSSubject = 1\nalert.severity = 1\nalert.suppress = 0\nalert.track = 1\nalert.expires = 24h\ncounttype = number of events\ncron_schedule = */10 * * * *\nallow_skew = 50%\nschedule_window = auto\ndescription = This detection method points out highly relevant Antivirus events\ndispatch.earliest_time = -10m\ndispatch.latest_time = now\nenableSched = 1\nquantity = 0\nrelation = greater than\nrequest.ui_dispatch_app = sigma_hunting_app\nrequest.ui_dispatch_view = search\nsearch = ((Message="*HTool*" OR Message="*Hacktool*" OR Message="*ASP/Backdoor*" OR Message="*JSP/Backdoor*" OR Message="*PHP/Backdoor*" OR Message="*Backdoor.ASP*" OR Message="*Backdoor.JSP*" OR Message="*Backdoor.PHP*" OR Message="*Webshell*" OR Message="*Portscan*" OR Message="*Mimikatz*" OR Message="*WinCred*" OR Message="*PlugX*" OR Message="*Korplug*" OR Message="*Pwdump*" OR Message="*Chopper*" OR Message="*WmiExec*" OR Message="*Xscan*" OR Message="*Clearlog*" OR Message="*ASPXSpy*") NOT ((Message="*Keygen*" OR Message="*Crack*"))) | stats values(*) AS * by _time | search NOT [| inputlookup Relevant_Anti-Virus_Event_whitelist.csv] \n\n\n'
```
