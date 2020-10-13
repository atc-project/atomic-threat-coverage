| Title                    | Regsvr32 Flags Anomaly       |
|:-------------------------|:------------------|
| **Description**          | Detects a flag anomaly in which regsvr32.exe uses a /i flag without using a /n flag at the same time |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1218.010: Regsvr32](https://attack.mitre.org/techniques/T1218/010)</li><li>[T1117: Regsvr32](https://attack.mitre.org/techniques/T1117)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1218.010: Regsvr32](../Triggers/T1218.010.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://twitter.com/sbousseaden/status/1282441816986484737?s=12](https://twitter.com/sbousseaden/status/1282441816986484737?s=12)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Regsvr32 Flags Anomaly
id: b236190c-1c61-41e9-84b3-3fe03f6d76b0
status: experimental
description: Detects a flag anomaly in which regsvr32.exe uses a /i flag without using a /n flag at the same time
author: Florian Roth
date: 2019/07/13
references:
    - https://twitter.com/sbousseaden/status/1282441816986484737?s=12
tags:
    - attack.defense_evasion
    - attack.t1218.010
    - attack.t1117      # an old one 
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\regsvr32.exe'
        CommandLine|contains: ' /i:'
    filter:
        CommandLine|contains: ' /n '
    condition: selection and not filter
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Unknown
level: high

```





### powershell
    
```
Get-WinEvent | where {(($_.message -match "Image.*.*\\regsvr32.exe" -and $_.message -match "CommandLine.*.* /i:.*") -and  -not ($_.message -match "CommandLine.*.* /n .*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
((winlog.event_data.Image.keyword:*\\regsvr32.exe AND winlog.event_data.CommandLine.keyword:*\ \/i\:*) AND (NOT (winlog.event_data.CommandLine.keyword:*\ \/n\ *)))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/b236190c-1c61-41e9-84b3-3fe03f6d76b0 <<EOF
{
  "metadata": {
    "title": "Regsvr32 Flags Anomaly",
    "description": "Detects a flag anomaly in which regsvr32.exe uses a /i flag without using a /n flag at the same time",
    "tags": [
      "attack.defense_evasion",
      "attack.t1218.010",
      "attack.t1117"
    ],
    "query": "((winlog.event_data.Image.keyword:*\\\\regsvr32.exe AND winlog.event_data.CommandLine.keyword:*\\ \\/i\\:*) AND (NOT (winlog.event_data.CommandLine.keyword:*\\ \\/n\\ *)))"
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
                    "query": "((winlog.event_data.Image.keyword:*\\\\regsvr32.exe AND winlog.event_data.CommandLine.keyword:*\\ \\/i\\:*) AND (NOT (winlog.event_data.CommandLine.keyword:*\\ \\/n\\ *)))",
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
        "subject": "Sigma Rule 'Regsvr32 Flags Anomaly'",
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
((Image.keyword:*\\regsvr32.exe AND CommandLine.keyword:* \/i\:*) AND (NOT (CommandLine.keyword:* \/n *)))
```


### splunk
    
```
((Image="*\\regsvr32.exe" CommandLine="* /i:*") NOT (CommandLine="* /n *")) | table CommandLine,ParentCommandLine
```


### logpoint
    
```
((Image="*\\regsvr32.exe" CommandLine="* /i:*")  -(CommandLine="* /n *"))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*(?=.*.*\regsvr32\.exe)(?=.*.* /i:.*)))(?=.*(?!.*(?:.*(?=.*.* /n .*)))))'
```



