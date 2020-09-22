| Title                    | File Was Not Allowed To Run       |
|:-------------------------|:------------------|
| **Description**          | Detect run not allowed files. Applocker is a very useful tool, especially on servers where unprivileged users have access. For example terminal servers. You need configure applocker and log collect to receive these events. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li><li>[T1064: Scripting](https://attack.mitre.org/techniques/T1064)</li><li>[T1204: User Execution](https://attack.mitre.org/techniques/T1204)</li><li>[T1035: Service Execution](https://attack.mitre.org/techniques/T1035)</li><li>[T1204.002: Malicious File](https://attack.mitre.org/techniques/T1204.002)</li><li>[T1059.001: PowerShell](https://attack.mitre.org/techniques/T1059.001)</li><li>[T1059.003: Windows Command Shell](https://attack.mitre.org/techniques/T1059.003)</li><li>[T1059.005: Visual Basic](https://attack.mitre.org/techniques/T1059.005)</li><li>[T1059.006: Python](https://attack.mitre.org/techniques/T1059.006)</li><li>[T1059.007: JavaScript/JScript](https://attack.mitre.org/techniques/T1059.007)</li></ul>  |
| **Data Needed**          |  There is no documented Data Needed for this Detection Rule yet  |
| **Trigger**              | <ul><li>[T1204.002: Malicious File](../Triggers/T1204.002.md)</li><li>[T1059.001: PowerShell](../Triggers/T1059.001.md)</li><li>[T1059.003: Windows Command Shell](../Triggers/T1059.003.md)</li><li>[T1059.005: Visual Basic](../Triggers/T1059.005.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>need tuning applocker or add exceptions in SIEM</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker)</li><li>[https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/using-event-viewer-with-applocker](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/using-event-viewer-with-applocker)</li><li>[https://nxlog.co/documentation/nxlog-user-guide/applocker.html](https://nxlog.co/documentation/nxlog-user-guide/applocker.html)</li></ul>  |
| **Author**               | Pushkarev Dmitry |


## Detection Rules

### Sigma rule

```
title: File Was Not Allowed To Run 
id: 401e5d00-b944-11ea-8f9a-00163ecd60ae
description: Detect run not allowed files. Applocker is a very useful tool, especially on servers where unprivileged users have access. For example terminal servers. You need configure applocker and log collect to receive these events.
status: experimental
tags:
    - attack.execution
    - attack.t1086          # an old one
    - attack.t1064          # an old one
    - attack.t1204          # an old one
    - attack.t1035          # an old one
    - attack.t1204.002
    - attack.t1059.001
    - attack.t1059.003
    - attack.t1059.005
    - attack.t1059.006
    - attack.t1059.007
references:
    - https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/what-is-applocker
    - https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-application-control/applocker/using-event-viewer-with-applocker
    - https://nxlog.co/documentation/nxlog-user-guide/applocker.html
author: Pushkarev Dmitry
date: 2020/06/28
modified: 2020/08/23
logsource:
    product: windows
    service: applocker
detection:
    selection:
        EventID:
          - 8004
          - 8007
    condition: selection
fields:
    - PolicyName
    - RuleId
    - RuleName
    - TargetUser
    - TargetProcessId
    - FilePath
    - FileHash
    - Fqbn
falsepositives:
    - need tuning applocker or add exceptions in SIEM
level: medium

```





### powershell
    
```
Get-WinEvent | where {(($_.message -match "Microsoft-Windows-AppLocker/MSI and Script" -or $_.message -match "Microsoft-Windows-AppLocker/EXE and DLL" -or $_.message -match "Microsoft-Windows-AppLocker/Packaged app-Deployment" -or $_.message -match "Microsoft-Windows-AppLocker/Packaged app-Execution") -and ($_.ID -eq "8004" -or $_.ID -eq "8007")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:("Microsoft\\-Windows\\-AppLocker\\/MSI\\ and\\ Script" OR "Microsoft\\-Windows\\-AppLocker\\/EXE\\ and\\ DLL" OR "Microsoft\\-Windows\\-AppLocker\\/Packaged\\ app\\-Deployment" OR "Microsoft\\-Windows\\-AppLocker\\/Packaged\\ app\\-Execution") AND winlog.event_id:("8004" OR "8007"))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/401e5d00-b944-11ea-8f9a-00163ecd60ae <<EOF\n{\n  "metadata": {\n    "title": "File Was Not Allowed To Run",\n    "description": "Detect run not allowed files. Applocker is a very useful tool, especially on servers where unprivileged users have access. For example terminal servers. You need configure applocker and log collect to receive these events.",\n    "tags": [\n      "attack.execution",\n      "attack.t1086",\n      "attack.t1064",\n      "attack.t1204",\n      "attack.t1035",\n      "attack.t1204.002",\n      "attack.t1059.001",\n      "attack.t1059.003",\n      "attack.t1059.005",\n      "attack.t1059.006",\n      "attack.t1059.007"\n    ],\n    "query": "(winlog.channel:(\\"Microsoft\\\\-Windows\\\\-AppLocker\\\\/MSI\\\\ and\\\\ Script\\" OR \\"Microsoft\\\\-Windows\\\\-AppLocker\\\\/EXE\\\\ and\\\\ DLL\\" OR \\"Microsoft\\\\-Windows\\\\-AppLocker\\\\/Packaged\\\\ app\\\\-Deployment\\" OR \\"Microsoft\\\\-Windows\\\\-AppLocker\\\\/Packaged\\\\ app\\\\-Execution\\") AND winlog.event_id:(\\"8004\\" OR \\"8007\\"))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.channel:(\\"Microsoft\\\\-Windows\\\\-AppLocker\\\\/MSI\\\\ and\\\\ Script\\" OR \\"Microsoft\\\\-Windows\\\\-AppLocker\\\\/EXE\\\\ and\\\\ DLL\\" OR \\"Microsoft\\\\-Windows\\\\-AppLocker\\\\/Packaged\\\\ app\\\\-Deployment\\" OR \\"Microsoft\\\\-Windows\\\\-AppLocker\\\\/Packaged\\\\ app\\\\-Execution\\") AND winlog.event_id:(\\"8004\\" OR \\"8007\\"))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "throttle_period": "15m",\n      "email": {\n        "profile": "standard",\n        "from": "root@localhost",\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'File Was Not Allowed To Run\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n     PolicyName = {{_source.PolicyName}}\\n         RuleId = {{_source.RuleId}}\\n       RuleName = {{_source.RuleName}}\\n     TargetUser = {{_source.TargetUser}}\\nTargetProcessId = {{_source.TargetProcessId}}\\n       FilePath = {{_source.FilePath}}\\n       FileHash = {{_source.FileHash}}\\n           Fqbn = {{_source.Fqbn}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
EventID:("8004" "8007")
```


### splunk
    
```
((source="Microsoft-Windows-AppLocker/MSI and Script" OR source="Microsoft-Windows-AppLocker/EXE and DLL" OR source="Microsoft-Windows-AppLocker/Packaged app-Deployment" OR source="Microsoft-Windows-AppLocker/Packaged app-Execution") (EventCode="8004" OR EventCode="8007")) | table PolicyName,RuleId,RuleName,TargetUser,TargetProcessId,FilePath,FileHash,Fqbn
```


### logpoint
    
```
(event_source IN ["Microsoft-Windows-AppLocker/MSI and Script", "Microsoft-Windows-AppLocker/EXE and DLL", "Microsoft-Windows-AppLocker/Packaged app-Deployment", "Microsoft-Windows-AppLocker/Packaged app-Execution"] event_id IN ["8004", "8007"])
```


### grep
    
```
grep -P '^(?:.*8004|.*8007)'
```



