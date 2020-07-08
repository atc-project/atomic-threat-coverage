| Title                    | Suspicious Commandline Escape       |
|:-------------------------|:------------------|
| **Description**          | Detects suspicious process that use escape characters |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1140: Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140)</li></ul>  |
| **Data Needed**          | <ul><li>[DN0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1140: Deobfuscate/Decode Files or Information](../Triggers/T1140.md)</li></ul>  |
| **Severity Level**       | low |
| **False Positives**      | <ul><li>False positives depend on scripts and administrative tools used in the monitored environment</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://twitter.com/vysecurity/status/885545634958385153](https://twitter.com/vysecurity/status/885545634958385153)</li><li>[https://twitter.com/Hexacorn/status/885553465417756673](https://twitter.com/Hexacorn/status/885553465417756673)</li><li>[https://twitter.com/Hexacorn/status/885570278637678592](https://twitter.com/Hexacorn/status/885570278637678592)</li><li>[https://www.fireeye.com/blog/threat-research/2017/06/obfuscation-in-the-wild.html](https://www.fireeye.com/blog/threat-research/2017/06/obfuscation-in-the-wild.html)</li><li>[http://www.windowsinspired.com/understanding-the-command-line-string-and-arguments-received-by-a-windows-program/](http://www.windowsinspired.com/understanding-the-command-line-string-and-arguments-received-by-a-windows-program/)</li></ul>  |
| **Author**               | juju4 |


## Detection Rules

### Sigma rule

```
title: Suspicious Commandline Escape
id: f0cdd048-82dc-4f7a-8a7a-b87a52b6d0fd
description: Detects suspicious process that use escape characters
status: experimental
references:
    - https://twitter.com/vysecurity/status/885545634958385153
    - https://twitter.com/Hexacorn/status/885553465417756673
    - https://twitter.com/Hexacorn/status/885570278637678592
    - https://www.fireeye.com/blog/threat-research/2017/06/obfuscation-in-the-wild.html
    - http://www.windowsinspired.com/understanding-the-command-line-string-and-arguments-received-by-a-windows-program/
author: juju4
date: 2018/12/11
modified: 2020/03/14
tags:
    - attack.defense_evasion
    - attack.t1140
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            # - <TAB>   # no TAB modifier in sigmac yet, so this matches <TAB> (or TAB in elasticsearch backends without DSL queries)
            - '*h^t^t^p*'
            - '*h"t"t"p*'
    condition: selection
falsepositives:
    - False positives depend on scripts and administrative tools used in the monitored environment
level: low

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*h^t^t^p.*" -or $_.message -match "CommandLine.*.*h\"t\"t\"p.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.CommandLine.keyword:(*h\^t\^t\^p* OR *h\"t\"t\"p*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/f0cdd048-82dc-4f7a-8a7a-b87a52b6d0fd <<EOF
{
  "metadata": {
    "title": "Suspicious Commandline Escape",
    "description": "Detects suspicious process that use escape characters",
    "tags": [
      "attack.defense_evasion",
      "attack.t1140"
    ],
    "query": "winlog.event_data.CommandLine.keyword:(*h\\^t\\^t\\^p* OR *h\\\"t\\\"t\\\"p*)"
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
                    "query": "winlog.event_data.CommandLine.keyword:(*h\\^t\\^t\\^p* OR *h\\\"t\\\"t\\\"p*)",
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
        "subject": "Sigma Rule 'Suspicious Commandline Escape'",
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
CommandLine.keyword:(*h\^t\^t\^p* *h\"t\"t\"p*)
```


### splunk
    
```
(CommandLine="*h^t^t^p*" OR CommandLine="*h\"t\"t\"p*")
```


### logpoint
    
```
(event_id="1" CommandLine IN ["*h^t^t^p*", "*h\"t\"t\"p*"])
```


### grep
    
```
grep -P '^(?:.*.*h\^t\^t\^p.*|.*.*h"t"t"p.*)'
```



