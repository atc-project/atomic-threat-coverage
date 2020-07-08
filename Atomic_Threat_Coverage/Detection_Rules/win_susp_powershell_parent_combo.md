| Title                    | Suspicious PowerShell Invocation Based on Parent Process       |
|:-------------------------|:------------------|
| **Description**          | Detects suspicious powershell invocations from interpreters or unusual programs |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| **Data Needed**          | <ul><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Microsoft Operations Manager (MOM)</li><li>Other scripts</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://www.carbonblack.com/2017/03/15/attackers-leverage-excel-powershell-dns-latest-non-malware-attack/](https://www.carbonblack.com/2017/03/15/attackers-leverage-excel-powershell-dns-latest-non-malware-attack/)</li></ul>  |
| **Author**               | Florian Roth |
| Other Tags           | <ul><li>attack.t1059.001</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Suspicious PowerShell Invocation Based on Parent Process
id: 95eadcb2-92e4-4ed1-9031-92547773a6db
status: experimental
description: Detects suspicious powershell invocations from interpreters or unusual programs
author: Florian Roth
date: 2019/01/16
references:
    - https://www.carbonblack.com/2017/03/15/attackers-leverage-excel-powershell-dns-latest-non-malware-attack/
tags:
    - attack.execution
    - attack.t1086
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage:
            - '*\wscript.exe'
            - '*\cscript.exe'
        Image:
            - '*\powershell.exe'
    falsepositive:
        CurrentDirectory: '*\Health Service State\\*'
    condition: selection and not falsepositive
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Microsoft Operations Manager (MOM)
    - Other scripts
level: medium

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and (($_.message -match "ParentImage.*.*\\wscript.exe" -or $_.message -match "ParentImage.*.*\\cscript.exe") -and ($_.message -match "Image.*.*\\powershell.exe")) -and  -not ($_.message -match "CurrentDirectory.*.*\\Health Service State\\.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
((winlog.event_data.ParentImage.keyword:(*\\wscript.exe OR *\\cscript.exe) AND winlog.event_data.Image.keyword:(*\\powershell.exe)) AND (NOT (winlog.event_data.CurrentDirectory.keyword:*\\Health\ Service\ State\\*)))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/95eadcb2-92e4-4ed1-9031-92547773a6db <<EOF
{
  "metadata": {
    "title": "Suspicious PowerShell Invocation Based on Parent Process",
    "description": "Detects suspicious powershell invocations from interpreters or unusual programs",
    "tags": [
      "attack.execution",
      "attack.t1086",
      "attack.t1059.001"
    ],
    "query": "((winlog.event_data.ParentImage.keyword:(*\\\\wscript.exe OR *\\\\cscript.exe) AND winlog.event_data.Image.keyword:(*\\\\powershell.exe)) AND (NOT (winlog.event_data.CurrentDirectory.keyword:*\\\\Health\\ Service\\ State\\\\*)))"
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
                    "query": "((winlog.event_data.ParentImage.keyword:(*\\\\wscript.exe OR *\\\\cscript.exe) AND winlog.event_data.Image.keyword:(*\\\\powershell.exe)) AND (NOT (winlog.event_data.CurrentDirectory.keyword:*\\\\Health\\ Service\\ State\\\\*)))",
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
        "subject": "Sigma Rule 'Suspicious PowerShell Invocation Based on Parent Process'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\n      CommandLine = {{_source.CommandLine}}\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\n{{/ctx.payload.hits.hits}}",
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
((ParentImage.keyword:(*\\wscript.exe *\\cscript.exe) AND Image.keyword:(*\\powershell.exe)) AND (NOT (CurrentDirectory.keyword:*\\Health Service State\\*)))
```


### splunk
    
```
(((ParentImage="*\\wscript.exe" OR ParentImage="*\\cscript.exe") (Image="*\\powershell.exe")) NOT (CurrentDirectory="*\\Health Service State\\*")) | table CommandLine,ParentCommandLine
```


### logpoint
    
```
(event_id="1" (ParentImage IN ["*\\wscript.exe", "*\\cscript.exe"] Image IN ["*\\powershell.exe"])  -(CurrentDirectory="*\\Health Service State\\*"))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*(?:.*.*\wscript\.exe|.*.*\cscript\.exe))(?=.*(?:.*.*\powershell\.exe))))(?=.*(?!.*(?:.*(?=.*.*\Health Service State\\.*)))))'
```



