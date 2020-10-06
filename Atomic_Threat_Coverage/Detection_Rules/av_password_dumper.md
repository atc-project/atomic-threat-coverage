| Title                    | Antivirus Password Dumper Detection       |
|:-------------------------|:------------------|
| **Description**          | Detects a highly relevant Antivirus alert that reports a password dumper |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1003: OS Credential Dumping](https://attack.mitre.org/techniques/T1003)</li><li>[T1558: Steal or Forge Kerberos Tickets](https://attack.mitre.org/techniques/T1558)</li><li>[T1003.001: LSASS Memory](https://attack.mitre.org/techniques/T1003/001)</li><li>[T1003.002: Security Account Manager](https://attack.mitre.org/techniques/T1003/002)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0084_av_alert](../Data_Needed/DN_0084_av_alert.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1003: OS Credential Dumping](../Triggers/T1003.md)</li><li>[T1003.001: LSASS Memory](../Triggers/T1003.001.md)</li><li>[T1003.002: Security Account Manager](../Triggers/T1003.002.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Unlikely</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           | <ul><li>[https://www.nextron-systems.com/2018/09/08/antivirus-event-analysis-cheat-sheet-v1-4/](https://www.nextron-systems.com/2018/09/08/antivirus-event-analysis-cheat-sheet-v1-4/)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Antivirus Password Dumper Detection
id: 78cc2dd2-7d20-4d32-93ff-057084c38b93
description: Detects a highly relevant Antivirus alert that reports a password dumper
date: 2018/09/09
modified: 2019/10/04
author: Florian Roth
references:
    - https://www.nextron-systems.com/2018/09/08/antivirus-event-analysis-cheat-sheet-v1-4/
tags:
    - attack.credential_access
    - attack.t1003
    - attack.t1558
    - attack.t1003.001
    - attack.t1003.002
logsource:
    product: antivirus
detection:
    selection:
        Signature:
            - "*DumpCreds*"
            - "*Mimikatz*"
            - "*PWCrack*"
            - "HTool/WCE"
            - "*PSWtool*"
            - "*PWDump*"
            - "*SecurityTool*"
            - "*PShlSpy*"
    condition: selection
fields:
    - FileName
    - User
falsepositives:
    - Unlikely
level: critical

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "Signature.*.*DumpCreds.*" -or $_.message -match "Signature.*.*Mimikatz.*" -or $_.message -match "Signature.*.*PWCrack.*" -or $_.message -match "HTool/WCE" -or $_.message -match "Signature.*.*PSWtool.*" -or $_.message -match "Signature.*.*PWDump.*" -or $_.message -match "Signature.*.*SecurityTool.*" -or $_.message -match "Signature.*.*PShlSpy.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.Signature.keyword:(*DumpCreds* OR *Mimikatz* OR *PWCrack* OR HTool\\/WCE OR *PSWtool* OR *PWDump* OR *SecurityTool* OR *PShlSpy*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/78cc2dd2-7d20-4d32-93ff-057084c38b93 <<EOF\n{\n  "metadata": {\n    "title": "Antivirus Password Dumper Detection",\n    "description": "Detects a highly relevant Antivirus alert that reports a password dumper",\n    "tags": [\n      "attack.credential_access",\n      "attack.t1003",\n      "attack.t1558",\n      "attack.t1003.001",\n      "attack.t1003.002"\n    ],\n    "query": "winlog.event_data.Signature.keyword:(*DumpCreds* OR *Mimikatz* OR *PWCrack* OR HTool\\\\/WCE OR *PSWtool* OR *PWDump* OR *SecurityTool* OR *PShlSpy*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "winlog.event_data.Signature.keyword:(*DumpCreds* OR *Mimikatz* OR *PWCrack* OR HTool\\\\/WCE OR *PSWtool* OR *PWDump* OR *SecurityTool* OR *PShlSpy*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Antivirus Password Dumper Detection\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\nFileName = {{_source.FileName}}\\n    User = {{_source.User}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
Signature.keyword:(*DumpCreds* *Mimikatz* *PWCrack* HTool\\/WCE *PSWtool* *PWDump* *SecurityTool* *PShlSpy*)
```


### splunk
    
```
(Signature="*DumpCreds*" OR Signature="*Mimikatz*" OR Signature="*PWCrack*" OR Signature="HTool/WCE" OR Signature="*PSWtool*" OR Signature="*PWDump*" OR Signature="*SecurityTool*" OR Signature="*PShlSpy*") | table FileName,User
```


### logpoint
    
```
Signature IN ["*DumpCreds*", "*Mimikatz*", "*PWCrack*", "HTool/WCE", "*PSWtool*", "*PWDump*", "*SecurityTool*", "*PShlSpy*"]
```


### grep
    
```
grep -P '^(?:.*.*DumpCreds.*|.*.*Mimikatz.*|.*.*PWCrack.*|.*HTool/WCE|.*.*PSWtool.*|.*.*PWDump.*|.*.*SecurityTool.*|.*.*PShlSpy.*)'
```



