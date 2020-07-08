| Title                    | Harvesting of Wifi Credentials Using netsh.exe       |
|:-------------------------|:------------------|
| **Description**          | Detect the harvesting of wifi credentials using netsh.exe |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0007: Discovery](https://attack.mitre.org/tactics/TA0007)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1040: Network Sniffing](https://attack.mitre.org/techniques/T1040)</li></ul>  |
| **Data Needed**          | <ul><li>[DN0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1040: Network Sniffing](../Triggers/T1040.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Legitimate administrator or user uses netsh.exe wlan functionality for legitimate reason</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://blog.malwarebytes.com/threat-analysis/2020/04/new-agenttesla-variant-steals-wifi-credentials/](https://blog.malwarebytes.com/threat-analysis/2020/04/new-agenttesla-variant-steals-wifi-credentials/)</li></ul>  |
| **Author**               | Andreas Hunkeler (@Karneades) |


## Detection Rules

### Sigma rule

```
title: Harvesting of Wifi Credentials Using netsh.exe
id: 42b1a5b8-353f-4f10-b256-39de4467faff
status: experimental
description: Detect the harvesting of wifi credentials using netsh.exe
references:
    - https://blog.malwarebytes.com/threat-analysis/2020/04/new-agenttesla-variant-steals-wifi-credentials/
author: Andreas Hunkeler (@Karneades)
date: 2020/04/20
tags:
    - attack.discovery
    - attack.t1040
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - 'netsh wlan s* p* k*=clear'
    condition: selection
falsepositives:
    - Legitimate administrator or user uses netsh.exe wlan functionality for legitimate reason
level: medium

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "CommandLine.*netsh wlan s.* p.* k.*=clear")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.CommandLine.keyword:(netsh\ wlan\ s*\ p*\ k*\=clear)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/42b1a5b8-353f-4f10-b256-39de4467faff <<EOF
{
  "metadata": {
    "title": "Harvesting of Wifi Credentials Using netsh.exe",
    "description": "Detect the harvesting of wifi credentials using netsh.exe",
    "tags": [
      "attack.discovery",
      "attack.t1040"
    ],
    "query": "winlog.event_data.CommandLine.keyword:(netsh\\ wlan\\ s*\\ p*\\ k*\\=clear)"
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
                    "query": "winlog.event_data.CommandLine.keyword:(netsh\\ wlan\\ s*\\ p*\\ k*\\=clear)",
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
        "subject": "Sigma Rule 'Harvesting of Wifi Credentials Using netsh.exe'",
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
CommandLine.keyword:(netsh wlan s* p* k*=clear)
```


### splunk
    
```
(CommandLine="netsh wlan s* p* k*=clear")
```


### logpoint
    
```
(event_id="1" CommandLine IN ["netsh wlan s* p* k*=clear"])
```


### grep
    
```
grep -P '^(?:.*netsh wlan s.* p.* k.*=clear)'
```



