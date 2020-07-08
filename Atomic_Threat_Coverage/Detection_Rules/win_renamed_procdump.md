| Title                    | Renamed ProcDump       |
|:-------------------------|:------------------|
| **Description**          | Detects the execution of a renamed ProcDump executable often used by attackers or malware |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1036: Masquerading](https://attack.mitre.org/techniques/T1036)</li></ul>  |
| **Data Needed**          | <ul><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Procdump illegaly bundled with legitimate software</li><li>Weird admins who renamed binaries</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://docs.microsoft.com/en-us/sysinternals/downloads/procdump](https://docs.microsoft.com/en-us/sysinternals/downloads/procdump)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Renamed ProcDump
id: 4a0b2c7e-7cb2-495d-8b63-5f268e7bfd67
status: experimental
description: Detects the execution of a renamed ProcDump executable often used by attackers or malware
references:
    - https://docs.microsoft.com/en-us/sysinternals/downloads/procdump
author: Florian Roth
date: 2019/11/18
tags:
    - attack.defense_evasion
    - attack.t1036
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        OriginalFileName: 'procdump'
    filter:
        Image: 
            - '*\procdump.exe'
            - '*\procdump64.exe'
    condition: selection and not filter
falsepositives:
    - Procdump illegaly bundled with legitimate software
    - Weird admins who renamed binaries
level: critical

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "OriginalFileName.*procdump" -and  -not (($_.message -match "Image.*.*\\procdump.exe" -or $_.message -match "Image.*.*\\procdump64.exe"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(OriginalFileName:"procdump" AND (NOT (winlog.event_data.Image.keyword:(*\\procdump.exe OR *\\procdump64.exe))))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/4a0b2c7e-7cb2-495d-8b63-5f268e7bfd67 <<EOF
{
  "metadata": {
    "title": "Renamed ProcDump",
    "description": "Detects the execution of a renamed ProcDump executable often used by attackers or malware",
    "tags": [
      "attack.defense_evasion",
      "attack.t1036"
    ],
    "query": "(OriginalFileName:\"procdump\" AND (NOT (winlog.event_data.Image.keyword:(*\\\\procdump.exe OR *\\\\procdump64.exe))))"
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
                    "query": "(OriginalFileName:\"procdump\" AND (NOT (winlog.event_data.Image.keyword:(*\\\\procdump.exe OR *\\\\procdump64.exe))))",
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
        "subject": "Sigma Rule 'Renamed ProcDump'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}{{_source}}\n================================================================================\n{{/ctx.payload.hits.hits}}",
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
(OriginalFileName:"procdump" AND (NOT (Image.keyword:(*\\procdump.exe *\\procdump64.exe))))
```


### splunk
    
```
(OriginalFileName="procdump" NOT ((Image="*\\procdump.exe" OR Image="*\\procdump64.exe")))
```


### logpoint
    
```
(event_id="1" OriginalFileName="procdump"  -(Image IN ["*\\procdump.exe", "*\\procdump64.exe"]))
```


### grep
    
```
grep -P '^(?:.*(?=.*procdump)(?=.*(?!.*(?:.*(?=.*(?:.*.*\procdump\.exe|.*.*\procdump64\.exe))))))'
```



