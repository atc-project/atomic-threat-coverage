| Title                    | MavInject Process Injection       |
|:-------------------------|:------------------|
| **Description**          | Detects process injection using the signed Windows tool Mavinject32.exe |
| **ATT&amp;CK Tactic**    |   This Detection Rule wasn't mapped to ATT&amp;CK Tactic yet  |
| **ATT&amp;CK Technique** | <ul><li>[T1055: Process Injection](https://attack.mitre.org/techniques/T1055)</li><li>[T1218: Signed Binary Proxy Execution](https://attack.mitre.org/techniques/T1218)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1055: Process Injection](../Triggers/T1055.md)</li><li>[T1218: Signed Binary Proxy Execution](../Triggers/T1218.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://twitter.com/gN3mes1s/status/941315826107510784](https://twitter.com/gN3mes1s/status/941315826107510784)</li><li>[https://reaqta.com/2017/12/mavinject-microsoft-injector/](https://reaqta.com/2017/12/mavinject-microsoft-injector/)</li><li>[https://twitter.com/Hexacorn/status/776122138063409152](https://twitter.com/Hexacorn/status/776122138063409152)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: MavInject Process Injection
id: 17eb8e57-9983-420d-ad8a-2c4976c22eb8
status: experimental
description: Detects process injection using the signed Windows tool Mavinject32.exe
references:
    - https://twitter.com/gN3mes1s/status/941315826107510784
    - https://reaqta.com/2017/12/mavinject-microsoft-injector/
    - https://twitter.com/Hexacorn/status/776122138063409152
author: Florian Roth
date: 2018/12/12
tags:
    - attack.t1055
    - attack.t1218
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine: '* /INJECTRUNNING *'
    condition: selection
falsepositives:
    - unknown
level: critical

```





### powershell
    
```
Get-WinEvent | where {$_.message -match "CommandLine.*.* /INJECTRUNNING .*" } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.CommandLine.keyword:*\ \/INJECTRUNNING\ *
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/17eb8e57-9983-420d-ad8a-2c4976c22eb8 <<EOF
{
  "metadata": {
    "title": "MavInject Process Injection",
    "description": "Detects process injection using the signed Windows tool Mavinject32.exe",
    "tags": [
      "attack.t1055",
      "attack.t1218"
    ],
    "query": "winlog.event_data.CommandLine.keyword:*\\ \\/INJECTRUNNING\\ *"
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
                    "query": "winlog.event_data.CommandLine.keyword:*\\ \\/INJECTRUNNING\\ *",
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
      "email": {
        "to": "root@localhost",
        "subject": "Sigma Rule 'MavInject Process Injection'",
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
CommandLine.keyword:* \/INJECTRUNNING *
```


### splunk
    
```
CommandLine="* /INJECTRUNNING *"
```


### logpoint
    
```
CommandLine="* /INJECTRUNNING *"
```


### grep
    
```
grep -P '^.* /INJECTRUNNING .*'
```



