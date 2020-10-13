| Title                    | IIS Native-Code Module Command Line Installation       |
|:-------------------------|:------------------|
| **Description**          | Detects suspicious IIS native-code module installations via command line |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1505.003: Web Shell](https://attack.mitre.org/techniques/T1505/003)</li><li>[T1100: Web Shell](https://attack.mitre.org/techniques/T1100)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1505.003: Web Shell](../Triggers/T1505.003.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Unknown as it may vary from organisation to arganisation how admins use to install IIS modules</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://researchcenter.paloaltonetworks.com/2018/01/unit42-oilrig-uses-rgdoor-iis-backdoor-targets-middle-east/](https://researchcenter.paloaltonetworks.com/2018/01/unit42-oilrig-uses-rgdoor-iis-backdoor-targets-middle-east/)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
title: IIS Native-Code Module Command Line Installation
id: 9465ddf4-f9e4-4ebd-8d98-702df3a93239
description: Detects suspicious IIS native-code module installations via command line
status: experimental
references:
    - https://researchcenter.paloaltonetworks.com/2018/01/unit42-oilrig-uses-rgdoor-iis-backdoor-targets-middle-east/
author: Florian Roth
date: 2012/12/11
tags:
    - attack.persistence
    - attack.t1505.003
    - attack.t1100      # an old one
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - '*\APPCMD.EXE install module /name:*'
    condition: selection
falsepositives:
    - Unknown as it may vary from organisation to arganisation how admins use to install IIS modules
level: medium

```





### powershell
    
```
Get-WinEvent | where {($_.message -match "CommandLine.*.*\\APPCMD.EXE install module /name:.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
winlog.event_data.CommandLine.keyword:(*\\APPCMD.EXE\ install\ module\ \/name\:*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/9465ddf4-f9e4-4ebd-8d98-702df3a93239 <<EOF
{
  "metadata": {
    "title": "IIS Native-Code Module Command Line Installation",
    "description": "Detects suspicious IIS native-code module installations via command line",
    "tags": [
      "attack.persistence",
      "attack.t1505.003",
      "attack.t1100"
    ],
    "query": "winlog.event_data.CommandLine.keyword:(*\\\\APPCMD.EXE\\ install\\ module\\ \\/name\\:*)"
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
                    "query": "winlog.event_data.CommandLine.keyword:(*\\\\APPCMD.EXE\\ install\\ module\\ \\/name\\:*)",
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
        "subject": "Sigma Rule 'IIS Native-Code Module Command Line Installation'",
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
CommandLine.keyword:(*\\APPCMD.EXE install module \/name\:*)
```


### splunk
    
```
(CommandLine="*\\APPCMD.EXE install module /name:*")
```


### logpoint
    
```
CommandLine IN ["*\\APPCMD.EXE install module /name:*"]
```


### grep
    
```
grep -P '^(?:.*.*\APPCMD\.EXE install module /name:.*)'
```



