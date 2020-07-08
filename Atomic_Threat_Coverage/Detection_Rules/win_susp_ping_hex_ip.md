| Title                    | Ping Hex IP       |
|:-------------------------|:------------------|
| **Description**          | Detects a ping command that uses a hex encoded IP address |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1140: Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140)</li><li>[T1027: Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027)</li></ul>  |
| **Data Needed**          | <ul><li>[DN0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1140: Deobfuscate/Decode Files or Information](../Triggers/T1140.md)</li><li>[T1027: Obfuscated Files or Information](../Triggers/T1027.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unlikely, because no sane admin pings IP addresses in a hexadecimal form</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           | <ul><li>[https://github.com/vysec/Aggressor-VYSEC/blob/master/ping.cna](https://github.com/vysec/Aggressor-VYSEC/blob/master/ping.cna)</li><li>[https://twitter.com/vysecurity/status/977198418354491392](https://twitter.com/vysecurity/status/977198418354491392)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Ping Hex IP
id: 1a0d4aba-7668-4365-9ce4-6d79ab088dfd
description: Detects a ping command that uses a hex encoded IP address
references:
    - https://github.com/vysec/Aggressor-VYSEC/blob/master/ping.cna
    - https://twitter.com/vysecurity/status/977198418354491392
author: Florian Roth
date: 2018/03/23
tags:
    - attack.defense_evasion
    - attack.t1140
    - attack.t1027
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - '*\ping.exe 0x*'
            - '*\ping 0x*'
    condition: selection
fields:
    - ParentCommandLine
falsepositives:
    - Unlikely, because no sane admin pings IP addresses in a hexadecimal form
level: high

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*\\ping.exe 0x.*" -or $_.message -match "CommandLine.*.*\\ping 0x.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.CommandLine.keyword:(*\\ping.exe\ 0x* OR *\\ping\ 0x*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/1a0d4aba-7668-4365-9ce4-6d79ab088dfd <<EOF
{
  "metadata": {
    "title": "Ping Hex IP",
    "description": "Detects a ping command that uses a hex encoded IP address",
    "tags": [
      "attack.defense_evasion",
      "attack.t1140",
      "attack.t1027"
    ],
    "query": "winlog.event_data.CommandLine.keyword:(*\\\\ping.exe\\ 0x* OR *\\\\ping\\ 0x*)"
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
                    "query": "winlog.event_data.CommandLine.keyword:(*\\\\ping.exe\\ 0x* OR *\\\\ping\\ 0x*)",
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
        "subject": "Sigma Rule 'Ping Hex IP'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\n{{/ctx.payload.hits.hits}}",
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
CommandLine.keyword:(*\\ping.exe 0x* *\\ping 0x*)
```


### splunk
    
```
(CommandLine="*\\ping.exe 0x*" OR CommandLine="*\\ping 0x*") | table ParentCommandLine
```


### logpoint
    
```
(event_id="1" CommandLine IN ["*\\ping.exe 0x*", "*\\ping 0x*"])
```


### grep
    
```
grep -P '^(?:.*.*\ping\.exe 0x.*|.*.*\ping 0x.*)'
```



