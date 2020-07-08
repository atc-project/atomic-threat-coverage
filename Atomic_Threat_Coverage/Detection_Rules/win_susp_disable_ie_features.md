| Title                    | Disabled IE Security Features       |
|:-------------------------|:------------------|
| **Description**          | Detects command lines that indicate unwanted modifications to registry keys that disable important Internet Explorer security features |
| **ATT&amp;CK Tactic**    |   This Detection Rule wasn't mapped to ATT&amp;CK Tactic yet  |
| **ATT&amp;CK Technique** | <ul><li>[T1089: Disabling Security Tools](https://attack.mitre.org/techniques/T1089)</li></ul>  |
| **Data Needed**          | <ul><li>[DN0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown, maybe some security software installer disables these features temporarily</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://unit42.paloaltonetworks.com/operation-ke3chang-resurfaces-with-new-tidepool-malware/](https://unit42.paloaltonetworks.com/operation-ke3chang-resurfaces-with-new-tidepool-malware/)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: Disabled IE Security Features
id: fb50eb7a-5ab1-43ae-bcc9-091818cb8424
status: experimental
description: Detects command lines that indicate unwanted modifications to registry keys that disable important Internet Explorer security features
references:
    - https://unit42.paloaltonetworks.com/operation-ke3chang-resurfaces-with-new-tidepool-malware/
tags:
    - attack.t1089
author: Florian Roth 
date: 2020/06/19
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        CommandLine|contains|all:
            - ' -name IEHarden '
            - ' -value 0 '        
    selection2:
        CommandLine|contains|all:
            - ' -name DEPOff '
            - ' -value 1 '
    selection3:
        CommandLine|contains|all:
            - ' -name DisableFirstRunCustomize '
            - ' -value 2 '
    condition: 1 of them
falsepositives:
    - Unknown, maybe some security software installer disables these features temporarily
level: high

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {(($_.ID -eq "1") -and (($_.message -match "CommandLine.*.* -name IEHarden .*" -and $_.message -match "CommandLine.*.* -value 0 .*") -or ($_.message -match "CommandLine.*.* -name DEPOff .*" -and $_.message -match "CommandLine.*.* -value 1 .*") -or ($_.message -match "CommandLine.*.* -name DisableFirstRunCustomize .*" -and $_.message -match "CommandLine.*.* -value 2 .*"))) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
((winlog.event_data.CommandLine.keyword:*\ \-name\ IEHarden\ * AND winlog.event_data.CommandLine.keyword:*\ \-value\ 0\ *) OR (winlog.event_data.CommandLine.keyword:*\ \-name\ DEPOff\ * AND winlog.event_data.CommandLine.keyword:*\ \-value\ 1\ *) OR (winlog.event_data.CommandLine.keyword:*\ \-name\ DisableFirstRunCustomize\ * AND winlog.event_data.CommandLine.keyword:*\ \-value\ 2\ *))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/fb50eb7a-5ab1-43ae-bcc9-091818cb8424 <<EOF
{
  "metadata": {
    "title": "Disabled IE Security Features",
    "description": "Detects command lines that indicate unwanted modifications to registry keys that disable important Internet Explorer security features",
    "tags": [
      "attack.t1089"
    ],
    "query": "((winlog.event_data.CommandLine.keyword:*\\ \\-name\\ IEHarden\\ * AND winlog.event_data.CommandLine.keyword:*\\ \\-value\\ 0\\ *) OR (winlog.event_data.CommandLine.keyword:*\\ \\-name\\ DEPOff\\ * AND winlog.event_data.CommandLine.keyword:*\\ \\-value\\ 1\\ *) OR (winlog.event_data.CommandLine.keyword:*\\ \\-name\\ DisableFirstRunCustomize\\ * AND winlog.event_data.CommandLine.keyword:*\\ \\-value\\ 2\\ *))"
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
                    "query": "((winlog.event_data.CommandLine.keyword:*\\ \\-name\\ IEHarden\\ * AND winlog.event_data.CommandLine.keyword:*\\ \\-value\\ 0\\ *) OR (winlog.event_data.CommandLine.keyword:*\\ \\-name\\ DEPOff\\ * AND winlog.event_data.CommandLine.keyword:*\\ \\-value\\ 1\\ *) OR (winlog.event_data.CommandLine.keyword:*\\ \\-name\\ DisableFirstRunCustomize\\ * AND winlog.event_data.CommandLine.keyword:*\\ \\-value\\ 2\\ *))",
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
        "subject": "Sigma Rule 'Disabled IE Security Features'",
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
((CommandLine.keyword:* \-name IEHarden * AND CommandLine.keyword:* \-value 0 *) OR (CommandLine.keyword:* \-name DEPOff * AND CommandLine.keyword:* \-value 1 *) OR (CommandLine.keyword:* \-name DisableFirstRunCustomize * AND CommandLine.keyword:* \-value 2 *))
```


### splunk
    
```
((CommandLine="* -name IEHarden *" CommandLine="* -value 0 *") OR (CommandLine="* -name DEPOff *" CommandLine="* -value 1 *") OR (CommandLine="* -name DisableFirstRunCustomize *" CommandLine="* -value 2 *"))
```


### logpoint
    
```
(event_id="1" ((CommandLine="* -name IEHarden *" CommandLine="* -value 0 *") OR (CommandLine="* -name DEPOff *" CommandLine="* -value 1 *") OR (CommandLine="* -name DisableFirstRunCustomize *" CommandLine="* -value 2 *")))
```


### grep
    
```
grep -P '^(?:.*(?:.*(?:.*(?=.*.* -name IEHarden .*)(?=.*.* -value 0 .*))|.*(?:.*(?=.*.* -name DEPOff .*)(?=.*.* -value 1 .*))|.*(?:.*(?=.*.* -name DisableFirstRunCustomize .*)(?=.*.* -value 2 .*))))'
```



