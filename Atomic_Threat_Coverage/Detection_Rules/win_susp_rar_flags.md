| Title                    | Rar with Password or Compression Level       |
|:-------------------------|:------------------|
| **Description**          | Detects the use of rar.exe, on the command line, to create an archive with password protection or with a specific compression level. This is pretty indicative of malicious actions. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0009: Collection](https://attack.mitre.org/tactics/TA0009)</li><li>[TA0010: Exfiltration](https://attack.mitre.org/tactics/TA0010)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1560.001: Archive via Utility](https://attack.mitre.org/techniques/T1560/001)</li><li>[T1002: Data Compressed](https://attack.mitre.org/techniques/T1002)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1560.001: Archive via Utility](../Triggers/T1560.001.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Legitimate use of Winrar command line version</li><li>Other command line tools, that use these flags</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://labs.sentinelone.com/the-anatomy-of-an-apt-attack-and-cobaltstrike-beacons-encoded-configuration/](https://labs.sentinelone.com/the-anatomy-of-an-apt-attack-and-cobaltstrike-beacons-encoded-configuration/)</li></ul>  |
| **Author**               | @ROxPinTeddy |


## Detection Rules

### Sigma rule

```
title: Rar with Password or Compression Level 
id: faa48cae-6b25-4f00-a094-08947fef582f
status: experimental
description: Detects the use of rar.exe, on the command line, to create an archive with password protection or with a specific compression level. This is pretty indicative of malicious actions. 
references:
    - https://labs.sentinelone.com/the-anatomy-of-an-apt-attack-and-cobaltstrike-beacons-encoded-configuration/
author: '@ROxPinTeddy'
date: 2020/05/12
modified: 2020/08/28
tags:
    - attack.collection
    - attack.t1560.001
    - attack.exfiltration # an old one  
    - attack.t1002        # an old one  

logsource:
    category: process_creation
    product: windows
detection:
    selection:
       CommandLine|contains|all:
               - ' -hp'
               - ' -m'
    condition: selection
falsepositives:
    - Legitimate use of Winrar command line version
    - Other command line tools, that use these flags
level: medium
```





### powershell
    
```
Get-WinEvent | where {($_.message -match "CommandLine.*.* -hp.*" -and $_.message -match "CommandLine.*.* -m.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_data.CommandLine.keyword:*\ \-hp* AND winlog.event_data.CommandLine.keyword:*\ \-m*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/faa48cae-6b25-4f00-a094-08947fef582f <<EOF
{
  "metadata": {
    "title": "Rar with Password or Compression Level",
    "description": "Detects the use of rar.exe, on the command line, to create an archive with password protection or with a specific compression level. This is pretty indicative of malicious actions.",
    "tags": [
      "attack.collection",
      "attack.t1560.001",
      "attack.exfiltration",
      "attack.t1002"
    ],
    "query": "(winlog.event_data.CommandLine.keyword:*\\ \\-hp* AND winlog.event_data.CommandLine.keyword:*\\ \\-m*)"
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
                    "query": "(winlog.event_data.CommandLine.keyword:*\\ \\-hp* AND winlog.event_data.CommandLine.keyword:*\\ \\-m*)",
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
        "subject": "Sigma Rule 'Rar with Password or Compression Level'",
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
(CommandLine.keyword:* \-hp* AND CommandLine.keyword:* \-m*)
```


### splunk
    
```
(CommandLine="* -hp*" CommandLine="* -m*")
```


### logpoint
    
```
(CommandLine="* -hp*" CommandLine="* -m*")
```


### grep
    
```
grep -P '^(?:.*(?=.*.* -hp.*)(?=.*.* -m.*))'
```



