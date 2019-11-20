| Title                | Possible Application Whitelisting Bypass via WinDbg/CDB as a shellcode runner                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Launch 64-bit shellcode from the x64_calc.wds file using cdb.exe.                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1218: Signed Binary Proxy Execution](https://attack.mitre.org/techniques/T1218)</li></ul>  |
| Data Needed          |  There is no documented Data Needed for this Detection Rule yet  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1218: Signed Binary Proxy Execution](../Triggers/T1218.md)</li></ul>  |
| Severity Level       | medium |
| False Positives      | <ul><li>Legitimate use of debugging tools</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Cdb.yml](https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Cdb.yml)</li><li>[http://www.exploit-monday.com/2016/08/windbg-cdb-shellcode-runner.html](http://www.exploit-monday.com/2016/08/windbg-cdb-shellcode-runner.html)</li></ul>  |
| Author               | Beyu Denis, oscd.community |


## Detection Rules

### Sigma rule

```
title: Possible Application Whitelisting Bypass via WinDbg/CDB as a shellcode runner
id: b5c7395f-e501-4a08-94d4-57fe7a9da9d2
status: experimental
description: Launch 64-bit shellcode from the x64_calc.wds file using cdb.exe.
references:
    - https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Cdb.yml
    - http://www.exploit-monday.com/2016/08/windbg-cdb-shellcode-runner.html
author: Beyu Denis, oscd.community
date: 2019/10/26
modified: 2019/11/04
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1218
level: medium
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\cdb.exe'
        CommandLine|contains: '-cf'
    condition: selection
falsepositives:
    - Legitimate use of debugging tools

```





### splunk
    
```
(Image="*\\\\cdb.exe" CommandLine="*-cf*")
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Possible Application Whitelisting Bypass via WinDbg/CDB as a shellcode runner]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:   \
title: Possible Application Whitelisting Bypass via WinDbg/CDB as a shellcode runner status: experimental \
description: Launch 64-bit shellcode from the x64_calc.wds file using cdb.exe. \
references: ['https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Cdb.yml', 'http://www.exploit-monday.com/2016/08/windbg-cdb-shellcode-runner.html'] \
tags: ['attack.defense_evasion', 'attack.execution', 'attack.t1218'] \
author: Beyu Denis, oscd.community \
date:  \
falsepositives: ['Legitimate use of debugging tools'] \
level: medium
action.email.useNSSubject = 1
alert.severity = 1
alert.suppress = 0
alert.track = 1
alert.expires = 24h
counttype = number of events
cron_schedule = */10 * * * *
allow_skew = 50%
schedule_window = auto
description = Launch 64-bit shellcode from the x64_calc.wds file using cdb.exe.
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = (Image="*\\cdb.exe" CommandLine="*-cf*") | stats values(*) AS * by _time | search NOT [| inputlookup Possible_Application_Whitelisting_Bypass_via_WinDbg_CDB_as_a_shellcode_runner_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.defense_evasion,sigma_tag=attack.execution,sigma_tag=attack.t1218,level=medium"
```
