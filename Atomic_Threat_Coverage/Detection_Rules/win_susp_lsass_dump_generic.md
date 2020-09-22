| Title                    | Generic Password Dumper Activity on LSASS       |
|:-------------------------|:------------------|
| **Description**          | Detects process handle on LSASS process with certain access mask |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1003: OS Credential Dumping](https://attack.mitre.org/techniques/T1003)</li><li>[T1003.001: LSASS Memory](https://attack.mitre.org/techniques/T1003.001)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0058_4656_handle_to_an_object_was_requested](../Data_Needed/DN_0058_4656_handle_to_an_object_was_requested.md)</li><li>[DN_0062_4663_attempt_was_made_to_access_an_object](../Data_Needed/DN_0062_4663_attempt_was_made_to_access_an_object.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1003: OS Credential Dumping](../Triggers/T1003.md)</li><li>[T1003.001: LSASS Memory](../Triggers/T1003.001.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Legitimate software accessing LSASS process for legitimate reason; update the whitelist with it</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for_22.html](https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for_22.html)</li><li>[https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment](https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment)</li></ul>  |
| **Author**               | Roberto Rodriguez, Teymur Kheirkhabarov, Dimitrios Slamaris, Mark Russinovich, Aleksey Potapov, oscd.community (update) |
| Other Tags           | <ul><li>car.2019-04-004</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Generic Password Dumper Activity on LSASS
id: 4a1b6da0-d94f-4fc3-98fc-2d9cb9e5ee76
description: Detects process handle on LSASS process with certain access mask
status: experimental
author: Roberto Rodriguez, Teymur Kheirkhabarov, Dimitrios Slamaris, Mark Russinovich, Aleksey Potapov, oscd.community (update)
date: 2019/11/01
modified: 2019/11/07
references:
    - https://cyberwardog.blogspot.com/2017/03/chronicles-of-threat-hunter-hunting-for_22.html
    - https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment
tags:
    - attack.credential_access
    - attack.t1003          # an old one
    - car.2019-04-004
    - attack.t1003.001
logsource:
    product: windows
    service: security
detection:
    selection_1:
        EventID: 4656
        ObjectName|endswith: '\lsass.exe'
        AccessMask|contains:
            - '0x40'
            - '0x1400'
            - '0x1000'
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
    selection_2:
        EventID: 4663
        ObjectName|endswith: '\lsass.exe'
        AccessList|contains:
            - '4484'
            - '4416'
    filter:
        ProcessName|endswith:
            - '\wmiprvse.exe'
            - '\taskmgr.exe'
            - '\procexp64.exe'
            - '\procexp.exe'
            - '\lsm.exe'
            - '\csrss.exe'
            - '\wininit.exe'
            - '\vmtoolsd.exe'
            - '\minionhost.exe'  # Cyberreason
            - '\VsTskMgr.exe'  # McAfee Enterprise
    condition: selection_1 or selection_2 and not filter
fields:
    - ComputerName
    - SubjectDomainName
    - SubjectUserName
    - ProcessName
    - ProcessID
falsepositives:
    - Legitimate software accessing LSASS process for legitimate reason; update the whitelist with it
level: high

```





### powershell
    
```
Get-WinEvent -LogName Security | where {((($_.ID -eq "4656" -and $_.message -match "ObjectName.*.*\\\\lsass.exe" -and ($_.message -match "AccessMask.*.*0x40.*" -or $_.message -match "AccessMask.*.*0x1400.*" -or $_.message -match "AccessMask.*.*0x1000.*" -or $_.message -match "AccessMask.*.*0x100000.*" -or $_.message -match "AccessMask.*.*0x1410.*" -or $_.message -match "AccessMask.*.*0x1010.*" -or $_.message -match "AccessMask.*.*0x1438.*" -or $_.message -match "AccessMask.*.*0x143a.*" -or $_.message -match "AccessMask.*.*0x1418.*" -or $_.message -match "AccessMask.*.*0x1f0fff.*" -or $_.message -match "AccessMask.*.*0x1f1fff.*" -or $_.message -match "AccessMask.*.*0x1f2fff.*" -or $_.message -match "AccessMask.*.*0x1f3fff.*")) -or (($_.ID -eq "4663" -and $_.message -match "ObjectName.*.*\\\\lsass.exe" -and ($_.message -match "AccessList.*.*4484.*" -or $_.message -match "AccessList.*.*4416.*")) -and  -not (($_.message -match "ProcessName.*.*\\\\wmiprvse.exe" -or $_.message -match "ProcessName.*.*\\\\taskmgr.exe" -or $_.message -match "ProcessName.*.*\\\\procexp64.exe" -or $_.message -match "ProcessName.*.*\\\\procexp.exe" -or $_.message -match "ProcessName.*.*\\\\lsm.exe" -or $_.message -match "ProcessName.*.*\\\\csrss.exe" -or $_.message -match "ProcessName.*.*\\\\wininit.exe" -or $_.message -match "ProcessName.*.*\\\\vmtoolsd.exe" -or $_.message -match "ProcessName.*.*\\\\minionhost.exe" -or $_.message -match "ProcessName.*.*\\\\VsTskMgr.exe"))))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Security" AND ((winlog.event_id:"4656" AND winlog.event_data.ObjectName.keyword:*\\\\lsass.exe AND winlog.event_data.AccessMask.keyword:(*0x40* OR *0x1400* OR *0x1000* OR *0x100000* OR *0x1410* OR *0x1010* OR *0x1438* OR *0x143a* OR *0x1418* OR *0x1f0fff* OR *0x1f1fff* OR *0x1f2fff* OR *0x1f3fff*)) OR ((winlog.event_id:"4663" AND winlog.event_data.ObjectName.keyword:*\\\\lsass.exe AND AccessList.keyword:(*4484* OR *4416*)) AND (NOT (winlog.event_data.ProcessName.keyword:(*\\\\wmiprvse.exe OR *\\\\taskmgr.exe OR *\\\\procexp64.exe OR *\\\\procexp.exe OR *\\\\lsm.exe OR *\\\\csrss.exe OR *\\\\wininit.exe OR *\\\\vmtoolsd.exe OR *\\\\minionhost.exe OR *\\\\VsTskMgr.exe))))))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/4a1b6da0-d94f-4fc3-98fc-2d9cb9e5ee76 <<EOF\n{\n  "metadata": {\n    "title": "Generic Password Dumper Activity on LSASS",\n    "description": "Detects process handle on LSASS process with certain access mask",\n    "tags": [\n      "attack.credential_access",\n      "attack.t1003",\n      "car.2019-04-004",\n      "attack.t1003.001"\n    ],\n    "query": "(winlog.channel:\\"Security\\" AND ((winlog.event_id:\\"4656\\" AND winlog.event_data.ObjectName.keyword:*\\\\\\\\lsass.exe AND winlog.event_data.AccessMask.keyword:(*0x40* OR *0x1400* OR *0x1000* OR *0x100000* OR *0x1410* OR *0x1010* OR *0x1438* OR *0x143a* OR *0x1418* OR *0x1f0fff* OR *0x1f1fff* OR *0x1f2fff* OR *0x1f3fff*)) OR ((winlog.event_id:\\"4663\\" AND winlog.event_data.ObjectName.keyword:*\\\\\\\\lsass.exe AND AccessList.keyword:(*4484* OR *4416*)) AND (NOT (winlog.event_data.ProcessName.keyword:(*\\\\\\\\wmiprvse.exe OR *\\\\\\\\taskmgr.exe OR *\\\\\\\\procexp64.exe OR *\\\\\\\\procexp.exe OR *\\\\\\\\lsm.exe OR *\\\\\\\\csrss.exe OR *\\\\\\\\wininit.exe OR *\\\\\\\\vmtoolsd.exe OR *\\\\\\\\minionhost.exe OR *\\\\\\\\VsTskMgr.exe))))))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.channel:\\"Security\\" AND ((winlog.event_id:\\"4656\\" AND winlog.event_data.ObjectName.keyword:*\\\\\\\\lsass.exe AND winlog.event_data.AccessMask.keyword:(*0x40* OR *0x1400* OR *0x1000* OR *0x100000* OR *0x1410* OR *0x1010* OR *0x1438* OR *0x143a* OR *0x1418* OR *0x1f0fff* OR *0x1f1fff* OR *0x1f2fff* OR *0x1f3fff*)) OR ((winlog.event_id:\\"4663\\" AND winlog.event_data.ObjectName.keyword:*\\\\\\\\lsass.exe AND AccessList.keyword:(*4484* OR *4416*)) AND (NOT (winlog.event_data.ProcessName.keyword:(*\\\\\\\\wmiprvse.exe OR *\\\\\\\\taskmgr.exe OR *\\\\\\\\procexp64.exe OR *\\\\\\\\procexp.exe OR *\\\\\\\\lsm.exe OR *\\\\\\\\csrss.exe OR *\\\\\\\\wininit.exe OR *\\\\\\\\vmtoolsd.exe OR *\\\\\\\\minionhost.exe OR *\\\\\\\\VsTskMgr.exe))))))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Generic Password Dumper Activity on LSASS\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n     ComputerName = {{_source.ComputerName}}\\nSubjectDomainName = {{_source.SubjectDomainName}}\\n  SubjectUserName = {{_source.SubjectUserName}}\\n      ProcessName = {{_source.ProcessName}}\\n        ProcessID = {{_source.ProcessID}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((EventID:"4656" AND ObjectName.keyword:*\\\\lsass.exe AND AccessMask.keyword:(*0x40* *0x1400* *0x1000* *0x100000* *0x1410* *0x1010* *0x1438* *0x143a* *0x1418* *0x1f0fff* *0x1f1fff* *0x1f2fff* *0x1f3fff*)) OR ((EventID:"4663" AND ObjectName.keyword:*\\\\lsass.exe AND AccessList.keyword:(*4484* *4416*)) AND (NOT (ProcessName.keyword:(*\\\\wmiprvse.exe *\\\\taskmgr.exe *\\\\procexp64.exe *\\\\procexp.exe *\\\\lsm.exe *\\\\csrss.exe *\\\\wininit.exe *\\\\vmtoolsd.exe *\\\\minionhost.exe *\\\\VsTskMgr.exe)))))
```


### splunk
    
```
(source="WinEventLog:Security" ((EventCode="4656" ObjectName="*\\\\lsass.exe" (AccessMask="*0x40*" OR AccessMask="*0x1400*" OR AccessMask="*0x1000*" OR AccessMask="*0x100000*" OR AccessMask="*0x1410*" OR AccessMask="*0x1010*" OR AccessMask="*0x1438*" OR AccessMask="*0x143a*" OR AccessMask="*0x1418*" OR AccessMask="*0x1f0fff*" OR AccessMask="*0x1f1fff*" OR AccessMask="*0x1f2fff*" OR AccessMask="*0x1f3fff*")) OR ((EventCode="4663" ObjectName="*\\\\lsass.exe" (AccessList="*4484*" OR AccessList="*4416*")) NOT ((ProcessName="*\\\\wmiprvse.exe" OR ProcessName="*\\\\taskmgr.exe" OR ProcessName="*\\\\procexp64.exe" OR ProcessName="*\\\\procexp.exe" OR ProcessName="*\\\\lsm.exe" OR ProcessName="*\\\\csrss.exe" OR ProcessName="*\\\\wininit.exe" OR ProcessName="*\\\\vmtoolsd.exe" OR ProcessName="*\\\\minionhost.exe" OR ProcessName="*\\\\VsTskMgr.exe"))))) | table ComputerName,SubjectDomainName,SubjectUserName,ProcessName,ProcessID
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" ((event_id="4656" ObjectName="*\\\\lsass.exe" AccessMask IN ["*0x40*", "*0x1400*", "*0x1000*", "*0x100000*", "*0x1410*", "*0x1010*", "*0x1438*", "*0x143a*", "*0x1418*", "*0x1f0fff*", "*0x1f1fff*", "*0x1f2fff*", "*0x1f3fff*"]) OR ((event_id="4663" ObjectName="*\\\\lsass.exe" AccessList IN ["*4484*", "*4416*"])  -(ProcessName IN ["*\\\\wmiprvse.exe", "*\\\\taskmgr.exe", "*\\\\procexp64.exe", "*\\\\procexp.exe", "*\\\\lsm.exe", "*\\\\csrss.exe", "*\\\\wininit.exe", "*\\\\vmtoolsd.exe", "*\\\\minionhost.exe", "*\\\\VsTskMgr.exe"]))))
```


### grep
    
```
grep -P '^(?:.*(?:.*(?:.*(?=.*4656)(?=.*.*\\lsass\\.exe)(?=.*(?:.*.*0x40.*|.*.*0x1400.*|.*.*0x1000.*|.*.*0x100000.*|.*.*0x1410.*|.*.*0x1010.*|.*.*0x1438.*|.*.*0x143a.*|.*.*0x1418.*|.*.*0x1f0fff.*|.*.*0x1f1fff.*|.*.*0x1f2fff.*|.*.*0x1f3fff.*)))|.*(?:.*(?=.*(?:.*(?=.*4663)(?=.*.*\\lsass\\.exe)(?=.*(?:.*.*4484.*|.*.*4416.*))))(?=.*(?!.*(?:.*(?=.*(?:.*.*\\wmiprvse\\.exe|.*.*\\taskmgr\\.exe|.*.*\\procexp64\\.exe|.*.*\\procexp\\.exe|.*.*\\lsm\\.exe|.*.*\\csrss\\.exe|.*.*\\wininit\\.exe|.*.*\\vmtoolsd\\.exe|.*.*\\minionhost\\.exe|.*.*\\VsTskMgr\\.exe))))))))'
```



