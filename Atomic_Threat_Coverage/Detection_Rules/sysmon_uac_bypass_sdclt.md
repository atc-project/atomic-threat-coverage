| Title                | UAC Bypass via sdclt                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects changes to HKCU:\Software\Classes\exefile\shell\runas\command\isolatedCommand                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1088: Bypass User Account Control](https://attack.mitre.org/techniques/T1088)</li></ul>  |
| Data Needed          | <ul><li>[DN_0017_13_windows_sysmon_RegistryEvent](../Data_Needed/DN_0017_13_windows_sysmon_RegistryEvent.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1088: Bypass User Account Control](../Triggers/T1088.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://enigma0x3.net/2017/03/17/fileless-uac-bypass-using-sdclt-exe/](https://enigma0x3.net/2017/03/17/fileless-uac-bypass-using-sdclt-exe/)</li></ul>  |
| Author               | Omer Yampel |
| Other Tags           | <ul><li>car.2019-04-001</li><li>car.2019-04-001</li></ul> | 

## Detection Rules

### Sigma rule

```
title: UAC Bypass via sdclt
status: experimental
description: Detects changes to HKCU:\Software\Classes\exefile\shell\runas\command\isolatedCommand
references:
    - https://enigma0x3.net/2017/03/17/fileless-uac-bypass-using-sdclt-exe/
author: Omer Yampel
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 13 
        TargetObject: 'HKEY_USERS\\*\Classes\exefile\shell\runas\command\isolatedCommand'
    condition: selection
tags:
    - attack.defense_evasion
    - attack.privilege_escalation
    - attack.t1088
    - car.2019-04-001
falsepositives:
    - unknown
level: high


```





### es-qs
    
```
(EventID:"13" AND TargetObject:"HKEY_USERS\\\\*\\\\Classes\\\\exefile\\\\shell\\\\runas\\\\command\\\\isolatedCommand")
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/UAC-Bypass-via-sdclt <<EOF\n{\n  "metadata": {\n    "title": "UAC Bypass via sdclt",\n    "description": "Detects changes to HKCU:\\\\Software\\\\Classes\\\\exefile\\\\shell\\\\runas\\\\command\\\\isolatedCommand",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.privilege_escalation",\n      "attack.t1088",\n      "car.2019-04-001"\n    ],\n    "query": "(EventID:\\"13\\" AND TargetObject:\\"HKEY_USERS\\\\\\\\*\\\\\\\\Classes\\\\\\\\exefile\\\\\\\\shell\\\\\\\\runas\\\\\\\\command\\\\\\\\isolatedCommand\\")"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:\\"13\\" AND TargetObject:\\"HKEY_USERS\\\\\\\\*\\\\\\\\Classes\\\\\\\\exefile\\\\\\\\shell\\\\\\\\runas\\\\\\\\command\\\\\\\\isolatedCommand\\")",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'UAC Bypass via sdclt\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"13" AND TargetObject:"HKEY_USERS\\\\*\\\\Classes\\\\exefile\\\\shell\\\\runas\\\\command\\\\isolatedCommand")
```


### splunk
    
```
(EventID="13" TargetObject="HKEY_USERS\\\\*\\\\Classes\\\\exefile\\\\shell\\\\runas\\\\command\\\\isolatedCommand")
```


### logpoint
    
```
(EventID="13" TargetObject="HKEY_USERS\\\\*\\\\Classes\\\\exefile\\\\shell\\\\runas\\\\command\\\\isolatedCommand")
```


### grep
    
```
grep -P '^(?:.*(?=.*13)(?=.*HKEY_USERS\\\\.*\\Classes\\exefile\\shell\\runas\\command\\isolatedCommand))'
```



