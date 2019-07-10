| Title                | Default PowerSploit Schtasks Persistence                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects the creation of a schtask via PowerSploit Default Configuration                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1053: Scheduled Task](https://attack.mitre.org/techniques/T1053)</li><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1053: Scheduled Task](../Triggers/T1053.md)</li><li>[T1086: PowerShell](../Triggers/T1086.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>False positives are possible, depends on organisation and processes</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://github.com/0xdeadbeefJERKY/PowerSploit/blob/8690399ef70d2cad10213575ac67e8fa90ddf7c3/Persistence/Persistence.psm1](https://github.com/0xdeadbeefJERKY/PowerSploit/blob/8690399ef70d2cad10213575ac67e8fa90ddf7c3/Persistence/Persistence.psm1)</li></ul>  |
| Author               | Markus Neis |
| Other Tags           | <ul><li>attack.s0111</li><li>attack.s0111</li><li>attack.g0022</li><li>attack.g0022</li><li>attack.g0060</li><li>attack.g0060</li><li>car.2013-08-001</li><li>car.2013-08-001</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Default PowerSploit Schtasks Persistence 
status: experimental
description: Detects the creation of a schtask via PowerSploit Default Configuration 
references:
    - https://github.com/0xdeadbeefJERKY/PowerSploit/blob/8690399ef70d2cad10213575ac67e8fa90ddf7c3/Persistence/Persistence.psm1
author: Markus Neis
date: 2018/03/06
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        ParentImage:
            - '*\Powershell.exe'
        CommandLine:
            - '*\schtasks.exe*/Create*/RU*system*/SC*ONLOGON*'
            - '*\schtasks.exe*/Create*/RU*system*/SC*DAILY*'
            - '*\schtasks.exe*/Create*/RU*system*/SC*ONIDLE*'
            - '*\schtasks.exe*/Create*/RU*system*/SC*HOURLY*'
    condition: selection
tags:
    - attack.execution
    - attack.persistence
    - attack.privilege_escalation
    - attack.t1053
    - attack.t1086
    - attack.s0111
    - attack.g0022
    - attack.g0060
    - car.2013-08-001
falsepositives:
    - False positives are possible, depends on organisation and processes
level: high

```





### es-qs
    
```
(ParentImage.keyword:(*\\\\Powershell.exe) AND CommandLine.keyword:(*\\\\schtasks.exe*\\/Create*\\/RU*system*\\/SC*ONLOGON* *\\\\schtasks.exe*\\/Create*\\/RU*system*\\/SC*DAILY* *\\\\schtasks.exe*\\/Create*\\/RU*system*\\/SC*ONIDLE* *\\\\schtasks.exe*\\/Create*\\/RU*system*\\/SC*HOURLY*))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Default-PowerSploit-Schtasks-Persistence <<EOF\n{\n  "metadata": {\n    "title": "Default PowerSploit Schtasks Persistence",\n    "description": "Detects the creation of a schtask via PowerSploit Default Configuration",\n    "tags": [\n      "attack.execution",\n      "attack.persistence",\n      "attack.privilege_escalation",\n      "attack.t1053",\n      "attack.t1086",\n      "attack.s0111",\n      "attack.g0022",\n      "attack.g0060",\n      "car.2013-08-001"\n    ],\n    "query": "(ParentImage.keyword:(*\\\\\\\\Powershell.exe) AND CommandLine.keyword:(*\\\\\\\\schtasks.exe*\\\\/Create*\\\\/RU*system*\\\\/SC*ONLOGON* *\\\\\\\\schtasks.exe*\\\\/Create*\\\\/RU*system*\\\\/SC*DAILY* *\\\\\\\\schtasks.exe*\\\\/Create*\\\\/RU*system*\\\\/SC*ONIDLE* *\\\\\\\\schtasks.exe*\\\\/Create*\\\\/RU*system*\\\\/SC*HOURLY*))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(ParentImage.keyword:(*\\\\\\\\Powershell.exe) AND CommandLine.keyword:(*\\\\\\\\schtasks.exe*\\\\/Create*\\\\/RU*system*\\\\/SC*ONLOGON* *\\\\\\\\schtasks.exe*\\\\/Create*\\\\/RU*system*\\\\/SC*DAILY* *\\\\\\\\schtasks.exe*\\\\/Create*\\\\/RU*system*\\\\/SC*ONIDLE* *\\\\\\\\schtasks.exe*\\\\/Create*\\\\/RU*system*\\\\/SC*HOURLY*))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Default PowerSploit Schtasks Persistence\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(ParentImage:("*\\\\Powershell.exe") AND CommandLine:("*\\\\schtasks.exe*\\/Create*\\/RU*system*\\/SC*ONLOGON*" "*\\\\schtasks.exe*\\/Create*\\/RU*system*\\/SC*DAILY*" "*\\\\schtasks.exe*\\/Create*\\/RU*system*\\/SC*ONIDLE*" "*\\\\schtasks.exe*\\/Create*\\/RU*system*\\/SC*HOURLY*"))
```


### splunk
    
```
((ParentImage="*\\\\Powershell.exe") (CommandLine="*\\\\schtasks.exe*/Create*/RU*system*/SC*ONLOGON*" OR CommandLine="*\\\\schtasks.exe*/Create*/RU*system*/SC*DAILY*" OR CommandLine="*\\\\schtasks.exe*/Create*/RU*system*/SC*ONIDLE*" OR CommandLine="*\\\\schtasks.exe*/Create*/RU*system*/SC*HOURLY*"))
```


### logpoint
    
```
(ParentImage IN ["*\\\\Powershell.exe"] CommandLine IN ["*\\\\schtasks.exe*/Create*/RU*system*/SC*ONLOGON*", "*\\\\schtasks.exe*/Create*/RU*system*/SC*DAILY*", "*\\\\schtasks.exe*/Create*/RU*system*/SC*ONIDLE*", "*\\\\schtasks.exe*/Create*/RU*system*/SC*HOURLY*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*.*\\Powershell\\.exe))(?=.*(?:.*.*\\schtasks\\.exe.*/Create.*/RU.*system.*/SC.*ONLOGON.*|.*.*\\schtasks\\.exe.*/Create.*/RU.*system.*/SC.*DAILY.*|.*.*\\schtasks\\.exe.*/Create.*/RU.*system.*/SC.*ONIDLE.*|.*.*\\schtasks\\.exe.*/Create.*/RU.*system.*/SC.*HOURLY.*)))'
```



