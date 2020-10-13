| Title                    | File Was Not Allowed To Run       |
|:-------------------------|:------------------|
| **Description**          | Detect run not allowed files. Applocker is a very useful tool, especially on servers where unprivileged users have access. For example terminal servers. You need configure applocker and log collect to receive these events. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li><li>[T1064: Scripting](https://attack.mitre.org/techniques/T1064)</li><li>[T1204: User Execution](https://attack.mitre.org/techniques/T1204)</li><li>[T1035: Service Execution](https://attack.mitre.org/techniques/T1035)</li><li>[T1204.002: Malicious File](https://attack.mitre.org/techniques/T1204/002)</li><li>[T1059.001: PowerShell](https://attack.mitre.org/techniques/T1059/001)</li><li>[T1059.003: Windows Command Shell](https://attack.mitre.org/techniques/T1059/003)</li><li>[T1059.005: Visual Basic](https://attack.mitre.org/techniques/T1059/005)</li><li>[T1059.006: Python](https://attack.mitre.org/techniques/T1059/006)</li><li>[T1059.007: JavaScript/JScript](https://attack.mitre.org/techniques/T1059/007)</li></ul>  |
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
(winlog.channel:("Microsoft\-Windows\-AppLocker\/MSI\ and\ Script" OR "Microsoft\-Windows\-AppLocker\/EXE\ and\ DLL" OR "Microsoft\-Windows\-AppLocker\/Packaged\ app\-Deployment" OR "Microsoft\-Windows\-AppLocker\/Packaged\ app\-Execution") AND winlog.event_id:("8004" OR "8007"))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/401e5d00-b944-11ea-8f9a-00163ecd60ae <<EOF
{
  "metadata": {
    "title": "File Was Not Allowed To Run",
    "description": "Detect run not allowed files. Applocker is a very useful tool, especially on servers where unprivileged users have access. For example terminal servers. You need configure applocker and log collect to receive these events.",
    "tags": [
      "attack.execution",
      "attack.t1086",
      "attack.t1064",
      "attack.t1204",
      "attack.t1035",
      "attack.t1204.002",
      "attack.t1059.001",
      "attack.t1059.003",
      "attack.t1059.005",
      "attack.t1059.006",
      "attack.t1059.007"
    ],
    "query": "(winlog.channel:(\"Microsoft\\-Windows\\-AppLocker\\/MSI\\ and\\ Script\" OR \"Microsoft\\-Windows\\-AppLocker\\/EXE\\ and\\ DLL\" OR \"Microsoft\\-Windows\\-AppLocker\\/Packaged\\ app\\-Deployment\" OR \"Microsoft\\-Windows\\-AppLocker\\/Packaged\\ app\\-Execution\") AND winlog.event_id:(\"8004\" OR \"8007\"))"
  },
  "trigger": {
    "schedule": {
      "interval": "30m"
    }
  },
  "input": {
    "search": {
      "request": {
        "body": {
          "size": 0,
          "query": {
            "bool": {
              "must": [
                {
                  "query_string": {
                    "query": "(winlog.channel:(\"Microsoft\\-Windows\\-AppLocker\\/MSI\\ and\\ Script\" OR \"Microsoft\\-Windows\\-AppLocker\\/EXE\\ and\\ DLL\" OR \"Microsoft\\-Windows\\-AppLocker\\/Packaged\\ app\\-Deployment\" OR \"Microsoft\\-Windows\\-AppLocker\\/Packaged\\ app\\-Execution\") AND winlog.event_id:(\"8004\" OR \"8007\"))",
                    "analyze_wildcard": true
                  }
                }
              ],
              "filter": {
                "range": {
                  "timestamp": {
                    "gte": "now-30m/m"
                  }
                }
              }
            }
          }
        },
        "indices": [
          "winlogbeat-*"
        ]
      }
    }
  },
  "condition": {
    "compare": {
      "ctx.payload.hits.total": {
        "not_eq": 0
      }
    }
  },
  "actions": {
    "send_email": {
      "throttle_period": "15m",
      "email": {
        "profile": "standard",
        "from": "root@localhost",
        "to": "root@localhost",
        "subject": "Sigma Rule 'File Was Not Allowed To Run'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\n     PolicyName = {{_source.PolicyName}}\n         RuleId = {{_source.RuleId}}\n       RuleName = {{_source.RuleName}}\n     TargetUser = {{_source.TargetUser}}\nTargetProcessId = {{_source.TargetProcessId}}\n       FilePath = {{_source.FilePath}}\n       FileHash = {{_source.FileHash}}\n           Fqbn = {{_source.Fqbn}}================================================================================\n{{/ctx.payload.hits.hits}}",
        "attachments": {
          "data.json": {
            "data": {
              "format": "json"
            }
          }
        }
      }
    }
  }
}
EOF

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



