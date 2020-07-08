| Title                    | Suspicious Encoded PowerShell Command Line       |
|:-------------------------|:------------------|
| **Description**          | Detects suspicious powershell process starts with base64 encoded commands (e.g. Emotet) |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1086: PowerShell](https://attack.mitre.org/techniques/T1086)</li></ul>  |
| **Data Needed**          | <ul><li>[DN0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | high |
| **False Positives**      |  There are no documented False Positives for this Detection Rule yet  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://app.any.run/tasks/6217d77d-3189-4db2-a957-8ab239f3e01e](https://app.any.run/tasks/6217d77d-3189-4db2-a957-8ab239f3e01e)</li></ul>  |
| **Author**               | Florian Roth, Markus Neis |
| Other Tags           | <ul><li>attack.t1059.001</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Suspicious Encoded PowerShell Command Line
id: ca2092a1-c273-4878-9b4b-0d60115bf5ea
description: Detects suspicious powershell process starts with base64 encoded commands (e.g. Emotet)
status: experimental
references:
    - https://app.any.run/tasks/6217d77d-3189-4db2-a957-8ab239f3e01e
author: Florian Roth, Markus Neis
date: 2018/09/03
modified: 2019/12/16
tags:
    - attack.execution
    - attack.t1086
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - '* -e JAB*'
            - '* -e  JAB*'
            - '* -e   JAB*'
            - '* -e    JAB*'
            - '* -e     JAB*'
            - '* -e      JAB*'
            - '* -en JAB*'
            - '* -enc JAB*'
            - '* -enc* JAB*'
            - '* -w hidden -e* JAB*'
            - '* BA^J e-'
            - '* -e SUVYI*'
            - '* -e aWV4I*'
            - '* -e SQBFAFgA*'
            - '* -e aQBlAHgA*'
            - '* -enc SUVYI*'
            - '* -enc aWV4I*'
            - '* -enc SQBFAFgA*'
            - '* -enc aQBlAHgA*'
    falsepositive1:
        CommandLine: '* -ExecutionPolicy remotesigned *'
    condition: selection and not falsepositive1
level: high

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "CommandLine.*.* -e JAB.*" -or $_.message -match "CommandLine.*.* -e  JAB.*" -or $_.message -match "CommandLine.*.* -e   JAB.*" -or $_.message -match "CommandLine.*.* -e    JAB.*" -or $_.message -match "CommandLine.*.* -e     JAB.*" -or $_.message -match "CommandLine.*.* -e      JAB.*" -or $_.message -match "CommandLine.*.* -en JAB.*" -or $_.message -match "CommandLine.*.* -enc JAB.*" -or $_.message -match "CommandLine.*.* -enc.* JAB.*" -or $_.message -match "CommandLine.*.* -w hidden -e.* JAB.*" -or $_.message -match "CommandLine.*.* BA^J e-" -or $_.message -match "CommandLine.*.* -e SUVYI.*" -or $_.message -match "CommandLine.*.* -e aWV4I.*" -or $_.message -match "CommandLine.*.* -e SQBFAFgA.*" -or $_.message -match "CommandLine.*.* -e aQBlAHgA.*" -or $_.message -match "CommandLine.*.* -enc SUVYI.*" -or $_.message -match "CommandLine.*.* -enc aWV4I.*" -or $_.message -match "CommandLine.*.* -enc SQBFAFgA.*" -or $_.message -match "CommandLine.*.* -enc aQBlAHgA.*") -and  -not ($_.message -match "CommandLine.*.* -ExecutionPolicy remotesigned .*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.CommandLine.keyword:(*\ \-e\ JAB* OR *\ \-e\ \ JAB* OR *\ \-e\ \ \ JAB* OR *\ \-e\ \ \ \ JAB* OR *\ \-e\ \ \ \ \ JAB* OR *\ \-e\ \ \ \ \ \ JAB* OR *\ \-en\ JAB* OR *\ \-enc\ JAB* OR *\ \-enc*\ JAB* OR *\ \-w\ hidden\ \-e*\ JAB* OR *\ BA\^J\ e\- OR *\ \-e\ SUVYI* OR *\ \-e\ aWV4I* OR *\ \-e\ SQBFAFgA* OR *\ \-e\ aQBlAHgA* OR *\ \-enc\ SUVYI* OR *\ \-enc\ aWV4I* OR *\ \-enc\ SQBFAFgA* OR *\ \-enc\ aQBlAHgA*) AND (NOT (winlog.event_data.CommandLine.keyword:*\ \-ExecutionPolicy\ remotesigned\ *)))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/ca2092a1-c273-4878-9b4b-0d60115bf5ea <<EOF
{
  "metadata": {
    "title": "Suspicious Encoded PowerShell Command Line",
    "description": "Detects suspicious powershell process starts with base64 encoded commands (e.g. Emotet)",
    "tags": [
      "attack.execution",
      "attack.t1086",
      "attack.t1059.001"
    ],
    "query": "(winlog.event_data.CommandLine.keyword:(*\\ \\-e\\ JAB* OR *\\ \\-e\\ \\ JAB* OR *\\ \\-e\\ \\ \\ JAB* OR *\\ \\-e\\ \\ \\ \\ JAB* OR *\\ \\-e\\ \\ \\ \\ \\ JAB* OR *\\ \\-e\\ \\ \\ \\ \\ \\ JAB* OR *\\ \\-en\\ JAB* OR *\\ \\-enc\\ JAB* OR *\\ \\-enc*\\ JAB* OR *\\ \\-w\\ hidden\\ \\-e*\\ JAB* OR *\\ BA\\^J\\ e\\- OR *\\ \\-e\\ SUVYI* OR *\\ \\-e\\ aWV4I* OR *\\ \\-e\\ SQBFAFgA* OR *\\ \\-e\\ aQBlAHgA* OR *\\ \\-enc\\ SUVYI* OR *\\ \\-enc\\ aWV4I* OR *\\ \\-enc\\ SQBFAFgA* OR *\\ \\-enc\\ aQBlAHgA*) AND (NOT (winlog.event_data.CommandLine.keyword:*\\ \\-ExecutionPolicy\\ remotesigned\\ *)))"
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
                    "query": "(winlog.event_data.CommandLine.keyword:(*\\ \\-e\\ JAB* OR *\\ \\-e\\ \\ JAB* OR *\\ \\-e\\ \\ \\ JAB* OR *\\ \\-e\\ \\ \\ \\ JAB* OR *\\ \\-e\\ \\ \\ \\ \\ JAB* OR *\\ \\-e\\ \\ \\ \\ \\ \\ JAB* OR *\\ \\-en\\ JAB* OR *\\ \\-enc\\ JAB* OR *\\ \\-enc*\\ JAB* OR *\\ \\-w\\ hidden\\ \\-e*\\ JAB* OR *\\ BA\\^J\\ e\\- OR *\\ \\-e\\ SUVYI* OR *\\ \\-e\\ aWV4I* OR *\\ \\-e\\ SQBFAFgA* OR *\\ \\-e\\ aQBlAHgA* OR *\\ \\-enc\\ SUVYI* OR *\\ \\-enc\\ aWV4I* OR *\\ \\-enc\\ SQBFAFgA* OR *\\ \\-enc\\ aQBlAHgA*) AND (NOT (winlog.event_data.CommandLine.keyword:*\\ \\-ExecutionPolicy\\ remotesigned\\ *)))",
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
        "subject": "Sigma Rule 'Suspicious Encoded PowerShell Command Line'",
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
(CommandLine.keyword:(* \-e JAB* * \-e  JAB* * \-e   JAB* * \-e    JAB* * \-e     JAB* * \-e      JAB* * \-en JAB* * \-enc JAB* * \-enc* JAB* * \-w hidden \-e* JAB* * BA\^J e\- * \-e SUVYI* * \-e aWV4I* * \-e SQBFAFgA* * \-e aQBlAHgA* * \-enc SUVYI* * \-enc aWV4I* * \-enc SQBFAFgA* * \-enc aQBlAHgA*) AND (NOT (CommandLine.keyword:* \-ExecutionPolicy remotesigned *)))
```


### splunk
    
```
((CommandLine="* -e JAB*" OR CommandLine="* -e  JAB*" OR CommandLine="* -e   JAB*" OR CommandLine="* -e    JAB*" OR CommandLine="* -e     JAB*" OR CommandLine="* -e      JAB*" OR CommandLine="* -en JAB*" OR CommandLine="* -enc JAB*" OR CommandLine="* -enc* JAB*" OR CommandLine="* -w hidden -e* JAB*" OR CommandLine="* BA^J e-" OR CommandLine="* -e SUVYI*" OR CommandLine="* -e aWV4I*" OR CommandLine="* -e SQBFAFgA*" OR CommandLine="* -e aQBlAHgA*" OR CommandLine="* -enc SUVYI*" OR CommandLine="* -enc aWV4I*" OR CommandLine="* -enc SQBFAFgA*" OR CommandLine="* -enc aQBlAHgA*") NOT (CommandLine="* -ExecutionPolicy remotesigned *"))
```


### logpoint
    
```
(event_id="1" CommandLine IN ["* -e JAB*", "* -e  JAB*", "* -e   JAB*", "* -e    JAB*", "* -e     JAB*", "* -e      JAB*", "* -en JAB*", "* -enc JAB*", "* -enc* JAB*", "* -w hidden -e* JAB*", "* BA^J e-", "* -e SUVYI*", "* -e aWV4I*", "* -e SQBFAFgA*", "* -e aQBlAHgA*", "* -enc SUVYI*", "* -enc aWV4I*", "* -enc SQBFAFgA*", "* -enc aQBlAHgA*"]  -(CommandLine="* -ExecutionPolicy remotesigned *"))
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*.* -e JAB.*|.*.* -e  JAB.*|.*.* -e   JAB.*|.*.* -e    JAB.*|.*.* -e     JAB.*|.*.* -e      JAB.*|.*.* -en JAB.*|.*.* -enc JAB.*|.*.* -enc.* JAB.*|.*.* -w hidden -e.* JAB.*|.*.* BA\^J e-|.*.* -e SUVYI.*|.*.* -e aWV4I.*|.*.* -e SQBFAFgA.*|.*.* -e aQBlAHgA.*|.*.* -enc SUVYI.*|.*.* -enc aWV4I.*|.*.* -enc SQBFAFgA.*|.*.* -enc aQBlAHgA.*))(?=.*(?!.*(?:.*(?=.*.* -ExecutionPolicy remotesigned .*)))))'
```



