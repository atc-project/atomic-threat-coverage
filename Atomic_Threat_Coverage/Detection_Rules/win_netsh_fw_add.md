| Title                    | Netsh Port or Application Allowed       |
|:-------------------------|:------------------|
| **Description**          | Allow Incoming Connections by Port or Application on Windows Firewall |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li><li>[TA0011: Command and Control](https://attack.mitre.org/tactics/TA0011)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1090: Proxy](https://attack.mitre.org/techniques/T1090)</li></ul>  |
| **Data Needed**          | <ul><li>[DN0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Legitimate administration</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://attack.mitre.org/software/S0246/ (Lazarus HARDRAIN)](https://attack.mitre.org/software/S0246/ (Lazarus HARDRAIN))</li><li>[https://www.operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-RAT-and-Staging-Report.pdf](https://www.operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-RAT-and-Staging-Report.pdf)</li></ul>  |
| **Author**               | Markus Neis, Sander Wiebing |


## Detection Rules

### Sigma rule

```
title: Netsh Port or Application Allowed
id: cd5cfd80-aa5f-44c0-9c20-108c4ae12e3c
description: Allow Incoming Connections by Port or Application on Windows Firewall
references:
    - https://attack.mitre.org/software/S0246/ (Lazarus HARDRAIN)
    - https://www.operationblockbuster.com/wp-content/uploads/2016/02/Operation-Blockbuster-RAT-and-Staging-Report.pdf
date: 2019/01/29
tags:
    - attack.lateral_movement
    - attack.command_and_control
    - attack.t1090 
status: experimental
author: Markus Neis, Sander Wiebing
logsource:
    category: process_creation
    product: windows
detection:
    selection1:
        CommandLine:
            - '*netsh*'
    selection2:
        CommandLine:
            - '*firewall add*'
    condition: selection1 and selection2
falsepositives:
    - Legitimate administration
level: medium

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "1" -and ($_.message -match "CommandLine.*.*netsh.*") -and ($_.message -match "CommandLine.*.*firewall add.*")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.CommandLine.keyword:(*netsh*) AND winlog.event_data.CommandLine.keyword:(*firewall\ add*))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/cd5cfd80-aa5f-44c0-9c20-108c4ae12e3c <<EOF
{
  "metadata": {
    "title": "Netsh Port or Application Allowed",
    "description": "Allow Incoming Connections by Port or Application on Windows Firewall",
    "tags": [
      "attack.lateral_movement",
      "attack.command_and_control",
      "attack.t1090"
    ],
    "query": "(winlog.event_data.CommandLine.keyword:(*netsh*) AND winlog.event_data.CommandLine.keyword:(*firewall\\ add*))"
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
                    "query": "(winlog.event_data.CommandLine.keyword:(*netsh*) AND winlog.event_data.CommandLine.keyword:(*firewall\\ add*))",
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
        "subject": "Sigma Rule 'Netsh Port or Application Allowed'",
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
(CommandLine.keyword:(*netsh*) AND CommandLine.keyword:(*firewall add*))
```


### splunk
    
```
((CommandLine="*netsh*") (CommandLine="*firewall add*"))
```


### logpoint
    
```
(event_id="1" CommandLine IN ["*netsh*"] CommandLine IN ["*firewall add*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*.*netsh.*))(?=.*(?:.*.*firewall add.*)))'
```



