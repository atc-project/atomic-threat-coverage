| Title                    | Credentials Dumping Tools Accessing LSASS Memory       |
|:-------------------------|:------------------|
| **Description**          | Detects process access LSASS memory which is typical for credentials dumping tools |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1003: Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0014_10_windows_sysmon_ProcessAccess](../Data_Needed/DN_0014_10_windows_sysmon_ProcessAccess.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1003: Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Legitimate software accessing LSASS process for legitimate reason; update the whitelist with it</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://onedrive.live.com/view.aspx?resid=D026B4699190F1E6!2843&ithint=file%2cpptx&app=PowerPoint&authkey=!AMvCRTKB_V1J5ow](https://onedrive.live.com/view.aspx?resid=D026B4699190F1E6!2843&ithint=file%2cpptx&app=PowerPoint&authkey=!AMvCRTKB_V1J5ow)</li><li>[https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for_22.html](https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for_22.html)</li><li>[https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment](https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment)</li><li>[http://security-research.dyndns.org/pub/slides/FIRST2017/FIRST-2017_Tom-Ueltschi_Sysmon_FINAL_notes.pdf](http://security-research.dyndns.org/pub/slides/FIRST2017/FIRST-2017_Tom-Ueltschi_Sysmon_FINAL_notes.pdf)</li></ul>  |
| **Author**               | Florian Roth, Roberto Rodriguez, Dimitrios Slamaris, Mark Russinovich, Thomas Patzke, Teymur Kheirkhabarov, Sherif Eldeeb, James Dickenson, Aleksey Potapov, oscd.community (update) |
| Other Tags           | <ul><li>attack.s0002</li><li>car.2019-04-004</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Credentials Dumping Tools Accessing LSASS Memory
id: 32d0d3e2-e58d-4d41-926b-18b520b2b32d
status: experimental
description: Detects process access LSASS memory which is typical for credentials dumping tools
author: Florian Roth, Roberto Rodriguez, Dimitrios Slamaris, Mark Russinovich, Thomas Patzke, Teymur Kheirkhabarov, Sherif Eldeeb, James Dickenson, Aleksey Potapov,
    oscd.community (update)
date: 2017/02/16
modified: 2019/11/08
references:
    - https://onedrive.live.com/view.aspx?resid=D026B4699190F1E6!2843&ithint=file%2cpptx&app=PowerPoint&authkey=!AMvCRTKB_V1J5ow
    - https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for_22.html
    - https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment
    - http://security-research.dyndns.org/pub/slides/FIRST2017/FIRST-2017_Tom-Ueltschi_Sysmon_FINAL_notes.pdf
tags:
    - attack.t1003
    - attack.s0002
    - attack.credential_access
    - car.2019-04-004
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 10
        TargetImage|endswith: '\lsass.exe'
        GrantedAccess|contains:
            - '0x40'
            - '0x1000'
            - '0x1400'
            - '0x100000'
            - '0x1410'    # car.2019-04-004
            - '0x1010'    # car.2019-04-004
            - '0x1438'    # car.2019-04-004
            - '0x143a'    # car.2019-04-004
            - '0x1418'    # car.2019-04-004
            - '0x1f0fff'
            - '0x1f1fff'
            - '0x1f2fff'
            - '0x1f3fff'
    filter:
        ProcessName|endswith: # easy to bypass. need to implement supportive rule to detect bypass attempts
            - '\wmiprvse.exe'
            - '\taskmgr.exe'
            - '\procexp64.exe'
            - '\procexp.exe'
            - '\lsm.exe'
            - '\csrss.exe'
            - '\wininit.exe'
            - '\vmtoolsd.exe'
    condition: selection and not filter
fields:
    - ComputerName
    - User
    - SourceImage
falsepositives:
    - Legitimate software accessing LSASS process for legitimate reason; update the whitelist with it
level: high

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "10" -and $_.message -match "TargetImage.*.*\\\\lsass.exe" -and ($_.message -match "GrantedAccess.*.*0x40.*" -or $_.message -match "GrantedAccess.*.*0x1000.*" -or $_.message -match "GrantedAccess.*.*0x1400.*" -or $_.message -match "GrantedAccess.*.*0x100000.*" -or $_.message -match "GrantedAccess.*.*0x1410.*" -or $_.message -match "GrantedAccess.*.*0x1010.*" -or $_.message -match "GrantedAccess.*.*0x1438.*" -or $_.message -match "GrantedAccess.*.*0x143a.*" -or $_.message -match "GrantedAccess.*.*0x1418.*" -or $_.message -match "GrantedAccess.*.*0x1f0fff.*" -or $_.message -match "GrantedAccess.*.*0x1f1fff.*" -or $_.message -match "GrantedAccess.*.*0x1f2fff.*" -or $_.message -match "GrantedAccess.*.*0x1f3fff.*")) -and  -not (($_.message -match "ProcessName.*.*\\\\wmiprvse.exe" -or $_.message -match "ProcessName.*.*\\\\taskmgr.exe" -or $_.message -match "ProcessName.*.*\\\\procexp64.exe" -or $_.message -match "ProcessName.*.*\\\\procexp.exe" -or $_.message -match "ProcessName.*.*\\\\lsm.exe" -or $_.message -match "ProcessName.*.*\\\\csrss.exe" -or $_.message -match "ProcessName.*.*\\\\wininit.exe" -or $_.message -match "ProcessName.*.*\\\\vmtoolsd.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\\-Windows\\-Sysmon\\/Operational" AND (winlog.event_id:"10" AND winlog.event_data.TargetImage.keyword:*\\\\lsass.exe AND winlog.event_data.GrantedAccess.keyword:(*0x40* OR *0x1000* OR *0x1400* OR *0x100000* OR *0x1410* OR *0x1010* OR *0x1438* OR *0x143a* OR *0x1418* OR *0x1f0fff* OR *0x1f1fff* OR *0x1f2fff* OR *0x1f3fff*)) AND (NOT (winlog.event_data.ProcessName.keyword:(*\\\\wmiprvse.exe OR *\\\\taskmgr.exe OR *\\\\procexp64.exe OR *\\\\procexp.exe OR *\\\\lsm.exe OR *\\\\csrss.exe OR *\\\\wininit.exe OR *\\\\vmtoolsd.exe))))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/32d0d3e2-e58d-4d41-926b-18b520b2b32d <<EOF\n{\n  "metadata": {\n    "title": "Credentials Dumping Tools Accessing LSASS Memory",\n    "description": "Detects process access LSASS memory which is typical for credentials dumping tools",\n    "tags": [\n      "attack.t1003",\n      "attack.s0002",\n      "attack.credential_access",\n      "car.2019-04-004"\n    ],\n    "query": "(winlog.channel:\\"Microsoft\\\\-Windows\\\\-Sysmon\\\\/Operational\\" AND (winlog.event_id:\\"10\\" AND winlog.event_data.TargetImage.keyword:*\\\\\\\\lsass.exe AND winlog.event_data.GrantedAccess.keyword:(*0x40* OR *0x1000* OR *0x1400* OR *0x100000* OR *0x1410* OR *0x1010* OR *0x1438* OR *0x143a* OR *0x1418* OR *0x1f0fff* OR *0x1f1fff* OR *0x1f2fff* OR *0x1f3fff*)) AND (NOT (winlog.event_data.ProcessName.keyword:(*\\\\\\\\wmiprvse.exe OR *\\\\\\\\taskmgr.exe OR *\\\\\\\\procexp64.exe OR *\\\\\\\\procexp.exe OR *\\\\\\\\lsm.exe OR *\\\\\\\\csrss.exe OR *\\\\\\\\wininit.exe OR *\\\\\\\\vmtoolsd.exe))))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.channel:\\"Microsoft\\\\-Windows\\\\-Sysmon\\\\/Operational\\" AND (winlog.event_id:\\"10\\" AND winlog.event_data.TargetImage.keyword:*\\\\\\\\lsass.exe AND winlog.event_data.GrantedAccess.keyword:(*0x40* OR *0x1000* OR *0x1400* OR *0x100000* OR *0x1410* OR *0x1010* OR *0x1438* OR *0x143a* OR *0x1418* OR *0x1f0fff* OR *0x1f1fff* OR *0x1f2fff* OR *0x1f3fff*)) AND (NOT (winlog.event_data.ProcessName.keyword:(*\\\\\\\\wmiprvse.exe OR *\\\\\\\\taskmgr.exe OR *\\\\\\\\procexp64.exe OR *\\\\\\\\procexp.exe OR *\\\\\\\\lsm.exe OR *\\\\\\\\csrss.exe OR *\\\\\\\\wininit.exe OR *\\\\\\\\vmtoolsd.exe))))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Credentials Dumping Tools Accessing LSASS Memory\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\nComputerName = {{_source.ComputerName}}\\n        User = {{_source.User}}\\n SourceImage = {{_source.SourceImage}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((EventID:"10" AND TargetImage.keyword:*\\\\lsass.exe AND GrantedAccess.keyword:(*0x40* *0x1000* *0x1400* *0x100000* *0x1410* *0x1010* *0x1438* *0x143a* *0x1418* *0x1f0fff* *0x1f1fff* *0x1f2fff* *0x1f3fff*)) AND (NOT (ProcessName.keyword:(*\\\\wmiprvse.exe *\\\\taskmgr.exe *\\\\procexp64.exe *\\\\procexp.exe *\\\\lsm.exe *\\\\csrss.exe *\\\\wininit.exe *\\\\vmtoolsd.exe))))
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" (EventCode="10" TargetImage="*\\\\lsass.exe" (GrantedAccess="*0x40*" OR GrantedAccess="*0x1000*" OR GrantedAccess="*0x1400*" OR GrantedAccess="*0x100000*" OR GrantedAccess="*0x1410*" OR GrantedAccess="*0x1010*" OR GrantedAccess="*0x1438*" OR GrantedAccess="*0x143a*" OR GrantedAccess="*0x1418*" OR GrantedAccess="*0x1f0fff*" OR GrantedAccess="*0x1f1fff*" OR GrantedAccess="*0x1f2fff*" OR GrantedAccess="*0x1f3fff*")) NOT ((ProcessName="*\\\\wmiprvse.exe" OR ProcessName="*\\\\taskmgr.exe" OR ProcessName="*\\\\procexp64.exe" OR ProcessName="*\\\\procexp.exe" OR ProcessName="*\\\\lsm.exe" OR ProcessName="*\\\\csrss.exe" OR ProcessName="*\\\\wininit.exe" OR ProcessName="*\\\\vmtoolsd.exe"))) | table ComputerName,User,SourceImage
```


### logpoint
    
```
((event_id="10" TargetImage="*\\\\lsass.exe" GrantedAccess IN ["*0x40*", "*0x1000*", "*0x1400*", "*0x100000*", "*0x1410*", "*0x1010*", "*0x1438*", "*0x143a*", "*0x1418*", "*0x1f0fff*", "*0x1f1fff*", "*0x1f2fff*", "*0x1f3fff*"])  -(ProcessName IN ["*\\\\wmiprvse.exe", "*\\\\taskmgr.exe", "*\\\\procexp64.exe", "*\\\\procexp.exe", "*\\\\lsm.exe", "*\\\\csrss.exe", "*\\\\wininit.exe", "*\\\\vmtoolsd.exe"]))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*10)(?=.*.*\\lsass\\.exe)(?=.*(?:.*.*0x40.*|.*.*0x1000.*|.*.*0x1400.*|.*.*0x100000.*|.*.*0x1410.*|.*.*0x1010.*|.*.*0x1438.*|.*.*0x143a.*|.*.*0x1418.*|.*.*0x1f0fff.*|.*.*0x1f1fff.*|.*.*0x1f2fff.*|.*.*0x1f3fff.*))))(?=.*(?!.*(?:.*(?=.*(?:.*.*\\wmiprvse\\.exe|.*.*\\taskmgr\\.exe|.*.*\\procexp64\\.exe|.*.*\\procexp\\.exe|.*.*\\lsm\\.exe|.*.*\\csrss\\.exe|.*.*\\wininit\\.exe|.*.*\\vmtoolsd\\.exe))))))'
```



