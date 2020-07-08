| Title                    | Application Whitelisting Bypass via Dxcap.exe       |
|:-------------------------|:------------------|
| **Description**          | Detects execution of of Dxcap.exe |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1218: Signed Binary Proxy Execution](https://attack.mitre.org/techniques/T1218)</li></ul>  |
| **Data Needed**          | <ul><li>[DN0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1218: Signed Binary Proxy Execution](../Triggers/T1218.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Legitimate execution of dxcap.exe by legitimate user</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Dxcap.yml](https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Dxcap.yml)</li><li>[https://twitter.com/harr0ey/status/992008180904419328](https://twitter.com/harr0ey/status/992008180904419328)</li></ul>  |
| **Author**               | Beyu Denis, oscd.community |


## Detection Rules

### Sigma rule

```
title: Application Whitelisting Bypass via Dxcap.exe
id: 60f16a96-db70-42eb-8f76-16763e333590
status: experimental
description: Detects execution of of Dxcap.exe
references:
    - https://github.com/LOLBAS-Project/LOLBAS/blob/master/yml/OtherMSBinaries/Dxcap.yml
    - https://twitter.com/harr0ey/status/992008180904419328
author: Beyu Denis, oscd.community
date: 2019/10/26
modified: 2019/11/04
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1218
level: medium
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\dxcap.exe'
        CommandLine|contains|all:
            - '-c'
            - '.exe'
    condition: selection
falsepositives:
    - Legitimate execution of dxcap.exe by legitimate user

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and $_.message -match "Image.*.*\\dxcap.exe" -and $_.message -match "CommandLine.*.*-c.*" -and $_.message -match "CommandLine.*.*.exe.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.Image.keyword:*\\dxcap.exe AND winlog.event_data.CommandLine.keyword:*\-c* AND winlog.event_data.CommandLine.keyword:*.exe*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/60f16a96-db70-42eb-8f76-16763e333590 <<EOF
{
  "metadata": {
    "title": "Application Whitelisting Bypass via Dxcap.exe",
    "description": "Detects execution of of Dxcap.exe",
    "tags": [
      "attack.defense_evasion",
      "attack.execution",
      "attack.t1218"
    ],
    "query": "(winlog.event_data.Image.keyword:*\\\\dxcap.exe AND winlog.event_data.CommandLine.keyword:*\\-c* AND winlog.event_data.CommandLine.keyword:*.exe*)"
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
                    "query": "(winlog.event_data.Image.keyword:*\\\\dxcap.exe AND winlog.event_data.CommandLine.keyword:*\\-c* AND winlog.event_data.CommandLine.keyword:*.exe*)",
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
        "subject": "Sigma Rule 'Application Whitelisting Bypass via Dxcap.exe'",
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
(Image.keyword:*\\dxcap.exe AND CommandLine.keyword:*\-c* AND CommandLine.keyword:*.exe*)
```


### splunk
    
```
(Image="*\\dxcap.exe" CommandLine="*-c*" CommandLine="*.exe*")
```


### logpoint
    
```
(event_id="1" Image="*\\dxcap.exe" CommandLine="*-c*" CommandLine="*.exe*")
```


### grep
    
```
grep -P '^(?:.*(?=.*.*\dxcap\.exe)(?=.*.*-c.*)(?=.*.*\.exe.*))'
```



