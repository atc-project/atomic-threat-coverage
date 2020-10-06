| Title                    | Mimikatz DC Sync       |
|:-------------------------|:------------------|
| **Description**          | Detects Mimikatz DC sync security events |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1003: OS Credential Dumping](https://attack.mitre.org/techniques/T1003)</li><li>[T1003.006: DCSync](https://attack.mitre.org/techniques/T1003/006)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0030_4662_operation_was_performed_on_an_object](../Data_Needed/DN_0030_4662_operation_was_performed_on_an_object.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1003: OS Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Valid DC Sync that is not covered by the filters; please report</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://twitter.com/gentilkiwi/status/1003236624925413376](https://twitter.com/gentilkiwi/status/1003236624925413376)</li><li>[https://gist.github.com/gentilkiwi/dcc132457408cf11ad2061340dcb53c2](https://gist.github.com/gentilkiwi/dcc132457408cf11ad2061340dcb53c2)</li></ul>  |
| **Author**               | Benjamin Delpy, Florian Roth, Scott Dermott |
| Other Tags           | <ul><li>attack.s0002</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Mimikatz DC Sync
id: 611eab06-a145-4dfa-a295-3ccc5c20f59a
description: Detects Mimikatz DC sync security events
status: experimental
date: 2018/06/03
modified: 2020/09/11
author: Benjamin Delpy, Florian Roth, Scott Dermott
references:
    - https://twitter.com/gentilkiwi/status/1003236624925413376
    - https://gist.github.com/gentilkiwi/dcc132457408cf11ad2061340dcb53c2
tags:
    - attack.credential_access
    - attack.s0002
    - attack.t1003          # an old one
    - attack.t1003.006
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4662
        Properties:
            - '*Replicating Directory Changes All*'
            - '*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*'
    filter1:
        SubjectDomainName: 'Window Manager'
    filter2:
        SubjectUserName:
            - 'NT AUTHORITY*'
            - '*$'
            - 'MSOL_*'
    condition: selection and not filter1 and not filter2
falsepositives:
    - Valid DC Sync that is not covered by the filters; please report
level: high


```





### powershell
    
```
Get-WinEvent -LogName Security | where {((($_.ID -eq "4662" -and ($_.message -match "Properties.*.*Replicating Directory Changes All.*" -or $_.message -match "Properties.*.*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2.*")) -and  -not ($_.message -match "SubjectDomainName.*Window Manager")) -and  -not (($_.message -match "SubjectUserName.*NT AUTHORITY.*" -or $_.message -match "SubjectUserName.*.*$" -or $_.message -match "SubjectUserName.*MSOL_.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Security" AND ((winlog.event_id:"4662" AND winlog.event_data.Properties.keyword:(*Replicating\\ Directory\\ Changes\\ All* OR *1131f6ad\\-9c07\\-11d1\\-f79f\\-00c04fc2dcd2*)) AND (NOT (SubjectDomainName:"Window\\ Manager"))) AND (NOT (winlog.event_data.SubjectUserName.keyword:(NT\\ AUTHORITY* OR *$ OR MSOL_*))))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/611eab06-a145-4dfa-a295-3ccc5c20f59a <<EOF\n{\n  "metadata": {\n    "title": "Mimikatz DC Sync",\n    "description": "Detects Mimikatz DC sync security events",\n    "tags": [\n      "attack.credential_access",\n      "attack.s0002",\n      "attack.t1003",\n      "attack.t1003.006"\n    ],\n    "query": "(winlog.channel:\\"Security\\" AND ((winlog.event_id:\\"4662\\" AND winlog.event_data.Properties.keyword:(*Replicating\\\\ Directory\\\\ Changes\\\\ All* OR *1131f6ad\\\\-9c07\\\\-11d1\\\\-f79f\\\\-00c04fc2dcd2*)) AND (NOT (SubjectDomainName:\\"Window\\\\ Manager\\"))) AND (NOT (winlog.event_data.SubjectUserName.keyword:(NT\\\\ AUTHORITY* OR *$ OR MSOL_*))))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.channel:\\"Security\\" AND ((winlog.event_id:\\"4662\\" AND winlog.event_data.Properties.keyword:(*Replicating\\\\ Directory\\\\ Changes\\\\ All* OR *1131f6ad\\\\-9c07\\\\-11d1\\\\-f79f\\\\-00c04fc2dcd2*)) AND (NOT (SubjectDomainName:\\"Window\\\\ Manager\\"))) AND (NOT (winlog.event_data.SubjectUserName.keyword:(NT\\\\ AUTHORITY* OR *$ OR MSOL_*))))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Mimikatz DC Sync\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(((EventID:"4662" AND Properties.keyword:(*Replicating Directory Changes All* *1131f6ad\\-9c07\\-11d1\\-f79f\\-00c04fc2dcd2*)) AND (NOT (SubjectDomainName:"Window Manager"))) AND (NOT (SubjectUserName.keyword:(NT AUTHORITY* *$ MSOL_*))))
```


### splunk
    
```
(source="WinEventLog:Security" ((EventCode="4662" (Properties="*Replicating Directory Changes All*" OR Properties="*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*")) NOT (SubjectDomainName="Window Manager")) NOT ((SubjectUserName="NT AUTHORITY*" OR SubjectUserName="*$" OR SubjectUserName="MSOL_*")))
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" ((event_id="4662" Properties IN ["*Replicating Directory Changes All*", "*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*"])  -(SubjectDomainName="Window Manager"))  -(SubjectUserName IN ["NT AUTHORITY*", "*$", "MSOL_*"]))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*(?:.*(?=.*4662)(?=.*(?:.*.*Replicating Directory Changes All.*|.*.*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2.*))))(?=.*(?!.*(?:.*(?=.*Window Manager))))))(?=.*(?!.*(?:.*(?=.*(?:.*NT AUTHORITY.*|.*.*\\$|.*MSOL_.*))))))'
```



