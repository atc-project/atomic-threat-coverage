| Title                | Successful Overpass the Hash Attempt                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects successful logon with logon type 9 (NewCredentials) which matches the Overpass the Hash behavior of e.g Mimikatz's sekurlsa::pth module.                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1075: Pass the Hash](https://attack.mitre.org/techniques/T1075)</li></ul>  |
| Data Needed          | <ul><li>[DN_0004_4624_windows_account_logon](../Data_Needed/DN_0004_4624_windows_account_logon.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1075: Pass the Hash](../Triggers/T1075.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Runas command-line tool using /netonly parameter</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://cyberwardog.blogspot.de/2017/04/chronicles-of-threat-hunter-hunting-for.html](https://cyberwardog.blogspot.de/2017/04/chronicles-of-threat-hunter-hunting-for.html)</li></ul>  |
| Author               | Roberto Rodriguez (source), Dominik Schaudel (rule) |
| Other Tags           | <ul><li>attack.s0002</li><li>attack.s0002</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Successful Overpass the Hash Attempt
id: 192a0330-c20b-4356-90b6-7b7049ae0b87
status: experimental
description: Detects successful logon with logon type 9 (NewCredentials) which matches the Overpass the Hash behavior of e.g Mimikatz's sekurlsa::pth module.
references:
    - https://cyberwardog.blogspot.de/2017/04/chronicles-of-threat-hunter-hunting-for.html
author: Roberto Rodriguez (source), Dominik Schaudel (rule)
date: 2018/02/12
tags:
    - attack.lateral_movement
    - attack.t1075
    - attack.s0002
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        LogonType: 9
        LogonProcessName: seclogo
        AuthenticationPackageName: Negotiate
    condition: selection
falsepositives:
    - Runas command-line tool using /netonly parameter
level: high

```





### splunk
    
```
(EventID="4624" LogonType="9" LogonProcessName="seclogo" AuthenticationPackageName="Negotiate")
```






### Saved Search for Splunk

```
b'# Generated with Sigma2SplunkAlert\n[Successful Overpass the Hash Attempt]\naction.email = 1\naction.email.subject.alert = Splunk Alert: $name$\naction.email.to = test@test.de\naction.email.message.alert = Splunk Alert $name$ triggered \\\nList of interesting fields:   \\\ntitle: Successful Overpass the Hash Attempt status: experimental \\\ndescription: Detects successful logon with logon type 9 (NewCredentials) which matches the Overpass the Hash behavior of e.g Mimikatz\'s sekurlsa::pth module. \\\nreferences: [\'https://cyberwardog.blogspot.de/2017/04/chronicles-of-threat-hunter-hunting-for.html\'] \\\ntags: [\'attack.lateral_movement\', \'attack.t1075\', \'attack.s0002\'] \\\nauthor: Roberto Rodriguez (source), Dominik Schaudel (rule) \\\ndate:  \\\nfalsepositives: [\'Runas command-line tool using /netonly parameter\'] \\\nlevel: high\naction.email.useNSSubject = 1\nalert.severity = 1\nalert.suppress = 0\nalert.track = 1\nalert.expires = 24h\ncounttype = number of events\ncron_schedule = */10 * * * *\nallow_skew = 50%\nschedule_window = auto\ndescription = Detects successful logon with logon type 9 (NewCredentials) which matches the Overpass the Hash behavior of e.g Mimikatz\'s sekurlsa::pth module.\ndispatch.earliest_time = -10m\ndispatch.latest_time = now\nenableSched = 1\nquantity = 0\nrelation = greater than\nrequest.ui_dispatch_app = sigma_hunting_app\nrequest.ui_dispatch_view = search\nsearch = (EventID="4624" LogonType="9" LogonProcessName="seclogo" AuthenticationPackageName="Negotiate") | stats values(*) AS * by _time | search NOT [| inputlookup Successful_Overpass_the_Hash_Attempt_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.lateral_movement,sigma_tag=attack.t1075,sigma_tag=attack.s0002,level=high"\n\n\n'
```
