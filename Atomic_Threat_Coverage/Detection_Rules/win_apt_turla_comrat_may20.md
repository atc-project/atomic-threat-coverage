| Title                    | Turla Group Commands May 2020       |
|:-------------------------|:------------------|
| **Description**          | Detects commands used by Turla group as reported by ESET in May 2020 |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li><li>[TA0007: Discovery](https://attack.mitre.org/tactics/TA0007)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li><li>[T1053: Scheduled Task/Job](https://attack.mitre.org/techniques/T1053)</li><li>[T1027: Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027)</li><li>[T1016: System Network Configuration Discovery](https://attack.mitre.org/techniques/T1016)</li></ul>  |
| **Data Needed**          | <ul><li>[DN0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1027: Obfuscated Files or Information](../Triggers/T1027.md)</li><li>[T1016: System Network Configuration Discovery](../Triggers/T1016.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://www.welivesecurity.com/wp-content/uploads/2020/05/ESET_Turla_ComRAT.pdf](https://www.welivesecurity.com/wp-content/uploads/2020/05/ESET_Turla_ComRAT.pdf)</li></ul>  |
| **Author**               | Florian Roth |
| Other Tags           | <ul><li>attack.g0010</li><li>attack.t1059.001</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Turla Group Commands May 2020
id: 9e2e51c5-c699-4794-ba5a-29f5da40ac0c
status: experimental
description: Detects commands used by Turla group as reported by ESET in May 2020
references:
    - https://www.welivesecurity.com/wp-content/uploads/2020/05/ESET_Turla_ComRAT.pdf
tags:
    - attack.g0010
    - attack.execution
    - attack.t1086
    - attack.t1053
    - attack.t1027
    - attack.discovery
    - attack.t1016
    - attack.t1059.001
author: Florian Roth
date: 2020/05/26
logsource:
    category: process_creation
    product: windows
falsepositives:
    - Unknown
detection:
    selection1:
        CommandLine|contains:
            - 'tracert -h 10 yahoo.com'
            - '.WSqmCons))|iex;'
            - 'Fr`omBa`se6`4Str`ing'
    selection2:
        CommandLine|contains|all:
            - 'net use https://docs.live.net'
            - '@aol.co.uk'
    condition: 1 of them
level: critical

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "CommandLine.*.*tracert -h 10 yahoo.com.*" -or $_.message -match "CommandLine.*.*.WSqmCons))|iex;.*" -or $_.message -match "CommandLine.*.*Fr`omBa`se6`4Str`ing.*") -or ($_.message -match "CommandLine.*.*net use https://docs.live.net.*" -and $_.message -match "CommandLine.*.*@aol.co.uk.*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.CommandLine.keyword:(*tracert\ \-h\ 10\ yahoo.com* OR *.WSqmCons\)\)|iex;* OR *Fr`omBa`se6`4Str`ing*) OR (winlog.event_data.CommandLine.keyword:*net\ use\ https\:\/\/docs.live.net* AND winlog.event_data.CommandLine.keyword:*@aol.co.uk*))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/9e2e51c5-c699-4794-ba5a-29f5da40ac0c <<EOF
{
  "metadata": {
    "title": "Turla Group Commands May 2020",
    "description": "Detects commands used by Turla group as reported by ESET in May 2020",
    "tags": [
      "attack.g0010",
      "attack.execution",
      "attack.t1086",
      "attack.t1053",
      "attack.t1027",
      "attack.discovery",
      "attack.t1016",
      "attack.t1059.001"
    ],
    "query": "(winlog.event_data.CommandLine.keyword:(*tracert\\ \\-h\\ 10\\ yahoo.com* OR *.WSqmCons\\)\\)|iex;* OR *Fr`omBa`se6`4Str`ing*) OR (winlog.event_data.CommandLine.keyword:*net\\ use\\ https\\:\\/\\/docs.live.net* AND winlog.event_data.CommandLine.keyword:*@aol.co.uk*))"
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
                    "query": "(winlog.event_data.CommandLine.keyword:(*tracert\\ \\-h\\ 10\\ yahoo.com* OR *.WSqmCons\\)\\)|iex;* OR *Fr`omBa`se6`4Str`ing*) OR (winlog.event_data.CommandLine.keyword:*net\\ use\\ https\\:\\/\\/docs.live.net* AND winlog.event_data.CommandLine.keyword:*@aol.co.uk*))",
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
        "subject": "Sigma Rule 'Turla Group Commands May 2020'",
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
(CommandLine.keyword:(*tracert \-h 10 yahoo.com* *.WSqmCons\)\)|iex;* *Fr`omBa`se6`4Str`ing*) OR (CommandLine.keyword:*net use https\:\/\/docs.live.net* AND CommandLine.keyword:*@aol.co.uk*))
```


### splunk
    
```
((CommandLine="*tracert -h 10 yahoo.com*" OR CommandLine="*.WSqmCons))|iex;*" OR CommandLine="*Fr`omBa`se6`4Str`ing*") OR (CommandLine="*net use https://docs.live.net*" CommandLine="*@aol.co.uk*"))
```


### logpoint
    
```
(event_id="1" (CommandLine IN ["*tracert -h 10 yahoo.com*", "*.WSqmCons))|iex;*", "*Fr`omBa`se6`4Str`ing*"] OR (CommandLine="*net use https://docs.live.net*" CommandLine="*@aol.co.uk*")))
```


### grep
    
```
grep -P '^(?:.*(?:.*(?:.*.*tracert -h 10 yahoo\.com.*|.*.*\.WSqmCons\)\)\|iex;.*|.*.*Fr`omBa`se6`4Str`ing.*)|.*(?:.*(?=.*.*net use https://docs\.live\.net.*)(?=.*.*@aol\.co\.uk.*))))'
```



