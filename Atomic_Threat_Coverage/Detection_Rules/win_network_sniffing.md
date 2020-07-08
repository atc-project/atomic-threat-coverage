| Title                    | Network Sniffing       |
|:-------------------------|:------------------|
| **Description**          | Network sniffing refers to using the network interface on a system to monitor or capture information sent over a wired or wireless connection. An adversary may place a network interface into promiscuous mode to passively access data in transit over the network, or use span ports to capture a larger amount of data. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li><li>[TA0007: Discovery](https://attack.mitre.org/tactics/TA0007)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1040: Network Sniffing](https://attack.mitre.org/techniques/T1040)</li></ul>  |
| **Data Needed**          | <ul><li>[DN0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1040: Network Sniffing](../Triggers/T1040.md)</li></ul>  |
| **Severity Level**       | low |
| **False Positives**      | <ul><li>Admin activity</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1040/T1040.yaml](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1040/T1040.yaml)</li></ul>  |
| **Author**               | Timur Zinniatullin, oscd.community |


## Detection Rules

### Sigma rule

```
title: Network Sniffing
id: ba1f7802-adc7-48b4-9ecb-81e227fddfd5
status: experimental
description: Network sniffing refers to using the network interface on a system to monitor or capture information sent over a wired or wireless connection. An adversary
    may place a network interface into promiscuous mode to passively access data in transit over the network, or use span ports to capture a larger amount of data.
author: Timur Zinniatullin, oscd.community
date: 2019/10/21
modified: 2019/11/04
references:
    - https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1040/T1040.yaml
logsource:
    category: process_creation
    product: windows
detection:
    selection:
      - Image|endswith: '\tshark.exe'
        CommandLine|contains: '-i'
      - Image|endswith: '\windump.exe'
    condition: selection
falsepositives:
    - Admin activity
fields:
    - Image
    - CommandLine
    - User
    - LogonGuid
    - Hashes
    - ParentProcessGuid
    - ParentCommandLine
level: low
tags:
    - attack.credential_access
    - attack.discovery
    - attack.t1040

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "Image.*.*\\tshark.exe" -and $_.message -match "CommandLine.*.*-i.*") -or $_.message -match "Image.*.*\\windump.exe")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
((winlog.event_data.Image.keyword:*\\tshark.exe AND winlog.event_data.CommandLine.keyword:*\-i*) OR winlog.event_data.Image.keyword:*\\windump.exe)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/ba1f7802-adc7-48b4-9ecb-81e227fddfd5 <<EOF
{
  "metadata": {
    "title": "Network Sniffing",
    "description": "Network sniffing refers to using the network interface on a system to monitor or capture information sent over a wired or wireless connection. An adversary may place a network interface into promiscuous mode to passively access data in transit over the network, or use span ports to capture a larger amount of data.",
    "tags": [
      "attack.credential_access",
      "attack.discovery",
      "attack.t1040"
    ],
    "query": "((winlog.event_data.Image.keyword:*\\\\tshark.exe AND winlog.event_data.CommandLine.keyword:*\\-i*) OR winlog.event_data.Image.keyword:*\\\\windump.exe)"
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
                    "query": "((winlog.event_data.Image.keyword:*\\\\tshark.exe AND winlog.event_data.CommandLine.keyword:*\\-i*) OR winlog.event_data.Image.keyword:*\\\\windump.exe)",
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
        "subject": "Sigma Rule 'Network Sniffing'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\n            Image = {{_source.Image}}\n      CommandLine = {{_source.CommandLine}}\n             User = {{_source.User}}\n        LogonGuid = {{_source.LogonGuid}}\n           Hashes = {{_source.Hashes}}\nParentProcessGuid = {{_source.ParentProcessGuid}}\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\n{{/ctx.payload.hits.hits}}",
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
((Image.keyword:*\\tshark.exe AND CommandLine.keyword:*\-i*) OR Image.keyword:*\\windump.exe)
```


### splunk
    
```
((Image="*\\tshark.exe" CommandLine="*-i*") OR Image="*\\windump.exe") | table Image,CommandLine,User,LogonGuid,Hashes,ParentProcessGuid,ParentCommandLine
```


### logpoint
    
```
(event_id="1" ((Image="*\\tshark.exe" CommandLine="*-i*") OR Image="*\\windump.exe"))
```


### grep
    
```
grep -P '^(?:.*(?:.*(?:.*(?=.*.*\tshark\.exe)(?=.*.*-i.*))|.*.*\windump\.exe))'
```



