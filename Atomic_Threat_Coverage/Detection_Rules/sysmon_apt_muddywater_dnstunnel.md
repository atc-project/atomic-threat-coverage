| Title                    | DNS Tunnel Technique from MuddyWater       |
|:-------------------------|:------------------|
| **Description**          | Detecting DNS tunnel activity for Muddywater actor |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0011: Command and Control](https://attack.mitre.org/tactics/TA0011)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1071: Application Layer Protocol](https://attack.mitre.org/techniques/T1071)</li><li>[T1071.004: DNS](https://attack.mitre.org/techniques/T1071/004)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1071.004: DNS](../Triggers/T1071.004.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://www.virustotal.com/gui/file/5ad401c3a568bd87dd13f8a9ddc4e450ece61cd9ce4d1b23f68ce0b1f3c190b7/](https://www.virustotal.com/gui/file/5ad401c3a568bd87dd13f8a9ddc4e450ece61cd9ce4d1b23f68ce0b1f3c190b7/)</li><li>[https://www.vmray.com/analyses/5ad401c3a568/report/overview.html](https://www.vmray.com/analyses/5ad401c3a568/report/overview.html)</li></ul>  |
| **Author**               | @caliskanfurkan_ |


## Detection Rules

### Sigma rule

```
title: DNS Tunnel Technique from MuddyWater
id: 36222790-0d43-4fe8-86e4-674b27809543
description: Detecting DNS tunnel activity for Muddywater actor
author: '@caliskanfurkan_'
status: experimental
date: 2020/06/04
references:
    - https://www.virustotal.com/gui/file/5ad401c3a568bd87dd13f8a9ddc4e450ece61cd9ce4d1b23f68ce0b1f3c190b7/
    - https://www.vmray.com/analyses/5ad401c3a568/report/overview.html
tags:
    - attack.command_and_control
    - attack.t1071 # an old one
    - attack.t1071.004
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\powershell.exe'
        ParentImage|endswith:
            - '\excel.exe'
        CommandLine|contains:
            - 'DataExchange.dll'
    condition: selection
falsepositives:
    - Unknown
level: critical

```





### powershell
    
```
Get-WinEvent | where {(($_.message -match "Image.*.*\\powershell.exe") -and ($_.message -match "ParentImage.*.*\\excel.exe") -and ($_.message -match "CommandLine.*.*DataExchange.dll.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.Image.keyword:(*\\powershell.exe) AND winlog.event_data.ParentImage.keyword:(*\\excel.exe) AND winlog.event_data.CommandLine.keyword:(*DataExchange.dll*))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/36222790-0d43-4fe8-86e4-674b27809543 <<EOF
{
  "metadata": {
    "title": "DNS Tunnel Technique from MuddyWater",
    "description": "Detecting DNS tunnel activity for Muddywater actor",
    "tags": [
      "attack.command_and_control",
      "attack.t1071",
      "attack.t1071.004"
    ],
    "query": "(winlog.event_data.Image.keyword:(*\\\\powershell.exe) AND winlog.event_data.ParentImage.keyword:(*\\\\excel.exe) AND winlog.event_data.CommandLine.keyword:(*DataExchange.dll*))"
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
                    "query": "(winlog.event_data.Image.keyword:(*\\\\powershell.exe) AND winlog.event_data.ParentImage.keyword:(*\\\\excel.exe) AND winlog.event_data.CommandLine.keyword:(*DataExchange.dll*))",
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
        "subject": "Sigma Rule 'DNS Tunnel Technique from MuddyWater'",
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
(Image.keyword:(*\\powershell.exe) AND ParentImage.keyword:(*\\excel.exe) AND CommandLine.keyword:(*DataExchange.dll*))
```


### splunk
    
```
((Image="*\\powershell.exe") (ParentImage="*\\excel.exe") (CommandLine="*DataExchange.dll*"))
```


### logpoint
    
```
(Image IN ["*\\powershell.exe"] ParentImage IN ["*\\excel.exe"] CommandLine IN ["*DataExchange.dll*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*.*\powershell\.exe))(?=.*(?:.*.*\excel\.exe))(?=.*(?:.*.*DataExchange\.dll.*)))'
```



