| Title                    | Domain Trust Discovery       |
|:-------------------------|:------------------|
| **Description**          | Detects a discovery of domain trusts |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0007: Discovery](https://attack.mitre.org/tactics/TA0007)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1482: Domain Trust Discovery](https://attack.mitre.org/techniques/T1482)</li></ul>  |
| **Data Needed**          | <ul><li>[DN0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1482: Domain Trust Discovery](../Triggers/T1482.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Administration of systems</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1482/T1482.yaml](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1482/T1482.yaml)</li></ul>  |
| **Author**               | Jakob Weinzettl, oscd.community |


## Detection Rules

### Sigma rule

```
title: Domain Trust Discovery
id: 77815820-246c-47b8-9741-e0def3f57308
status: experimental
description: Detects a discovery of domain trusts
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1482/T1482.yaml
author: Jakob Weinzettl, oscd.community
date: 2019/10/23
modified: 2019/11/08
tags:
    - attack.discovery
    - attack.t1482
logsource:
    category: process_creation
    product: windows
detection:
    selection:
      - Image|endswith: '\dsquery.exe'
        CommandLine|contains|all:
            - '-filter'
            - 'trustedDomain'
      - Image|endswith: '\nltest.exe'
        CommandLine|contains: 'domain_trusts'
    condition: selection
falsepositives:
    - Administration of systems
level: medium

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "Image.*.*\\dsquery.exe" -and $_.message -match "CommandLine.*.*-filter.*" -and $_.message -match "CommandLine.*.*trustedDomain.*") -or ($_.message -match "Image.*.*\\nltest.exe" -and $_.message -match "CommandLine.*.*domain_trusts.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
((winlog.event_data.Image.keyword:*\\dsquery.exe AND winlog.event_data.CommandLine.keyword:*\-filter* AND winlog.event_data.CommandLine.keyword:*trustedDomain*) OR (winlog.event_data.Image.keyword:*\\nltest.exe AND winlog.event_data.CommandLine.keyword:*domain_trusts*))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/77815820-246c-47b8-9741-e0def3f57308 <<EOF
{
  "metadata": {
    "title": "Domain Trust Discovery",
    "description": "Detects a discovery of domain trusts",
    "tags": [
      "attack.discovery",
      "attack.t1482"
    ],
    "query": "((winlog.event_data.Image.keyword:*\\\\dsquery.exe AND winlog.event_data.CommandLine.keyword:*\\-filter* AND winlog.event_data.CommandLine.keyword:*trustedDomain*) OR (winlog.event_data.Image.keyword:*\\\\nltest.exe AND winlog.event_data.CommandLine.keyword:*domain_trusts*))"
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
                    "query": "((winlog.event_data.Image.keyword:*\\\\dsquery.exe AND winlog.event_data.CommandLine.keyword:*\\-filter* AND winlog.event_data.CommandLine.keyword:*trustedDomain*) OR (winlog.event_data.Image.keyword:*\\\\nltest.exe AND winlog.event_data.CommandLine.keyword:*domain_trusts*))",
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
        "subject": "Sigma Rule 'Domain Trust Discovery'",
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
((Image.keyword:*\\dsquery.exe AND CommandLine.keyword:*\-filter* AND CommandLine.keyword:*trustedDomain*) OR (Image.keyword:*\\nltest.exe AND CommandLine.keyword:*domain_trusts*))
```


### splunk
    
```
((Image="*\\dsquery.exe" CommandLine="*-filter*" CommandLine="*trustedDomain*") OR (Image="*\\nltest.exe" CommandLine="*domain_trusts*"))
```


### logpoint
    
```
(event_id="1" ((Image="*\\dsquery.exe" CommandLine="*-filter*" CommandLine="*trustedDomain*") OR (Image="*\\nltest.exe" CommandLine="*domain_trusts*")))
```


### grep
    
```
grep -P '^(?:.*(?:.*(?:.*(?=.*.*\dsquery\.exe)(?=.*.*-filter.*)(?=.*.*trustedDomain.*))|.*(?:.*(?=.*.*\nltest\.exe)(?=.*.*domain_trusts.*))))'
```



