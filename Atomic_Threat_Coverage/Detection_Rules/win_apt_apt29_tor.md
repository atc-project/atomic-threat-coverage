| Title                    | APT29 Google Update Service Install       |
|:-------------------------|:------------------|
| **Description**          | This method detects malicious services mentioned in APT29 report by FireEye. The legitimate path for the Google update service is C:\Program Files (x86)\Google\Update\GoogleUpdate.exe so the service names and executable locations used by APT29 are specific enough to be detected in log files. |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0003: Persistence](https://attack.mitre.org/tactics/TA0003)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1050: New Service](https://attack.mitre.org/techniques/T1050)</li></ul>  |
| **Data Needed**          | <ul><li>[DN0001_4688_windows_process_creation](../Data_Needed/DN0001_4688_windows_process_creation.md)</li><li>[DN0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN0003_1_windows_sysmon_process_creation](../Data_Needed/DN0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| **Trigger**              |  There is no documented Trigger for this Detection Rule yet  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           | <ul><li>[https://www.fireeye.com/blog/threat-research/2017/03/apt29_domain_frontin.html](https://www.fireeye.com/blog/threat-research/2017/03/apt29_domain_frontin.html)</li></ul>  |
| **Author**               | Thomas Patzke |
| Other Tags           | <ul><li>attack.g0016</li></ul> | 

## Detection Rules

### Sigma rule

```
action: global
title: APT29 Google Update Service Install
id: c069f460-2b87-4010-8dcf-e45bab362624
description: This method detects malicious services mentioned in APT29 report by FireEye. The legitimate path for the Google update service is C:\Program Files (x86)\Google\Update\GoogleUpdate.exe
    so the service names and executable locations used by APT29 are specific enough to be detected in log files.
references:
    - https://www.fireeye.com/blog/threat-research/2017/03/apt29_domain_frontin.html
tags:
    - attack.persistence
    - attack.g0016
    - attack.t1050
date: 2017/11/01
author: Thomas Patzke 
logsource:
    product: windows
    service: system
detection:
    service_install:
        EventID: 7045
        ServiceName: 'Google Update'
    timeframe: 5m
    condition: service_install | near process
falsepositives:
    - Unknown
level: high
---
logsource:
    category: process_creation
    product: windows
detection:
    process:
        Image:
            - 'C:\Program Files(x86)\Google\GoogleService.exe'
            - 'C:\Program Files(x86)\Google\GoogleUpdate.exe'
fields:
    - ComputerName
    - User
    - CommandLine

```





### powershell
    
```
An unsupported feature is required for this Sigma rule (detection_rules/sigma/rules/windows/builtin/win_apt_apt29_tor.yml): Only COUNT aggregation function is implemented for this backend
Feel free to contribute for fun and fame, this is open source :) -> https://github.com/Neo23x0/sigma
```


### es-qs
    
```
An unsupported feature is required for this Sigma rule (detection_rules/sigma/rules/windows/builtin/win_apt_apt29_tor.yml): Aggregations not implemented for this backend
Feel free to contribute for fun and fame, this is open source :) -> https://github.com/Neo23x0/sigma
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/c069f460-2b87-4010-8dcf-e45bab362624 <<EOF
{
  "metadata": {
    "title": "APT29 Google Update Service Install",
    "description": "This method detects malicious services mentioned in APT29 report by FireEye. The legitimate path for the Google update service is C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe so the service names and executable locations used by APT29 are specific enough to be detected in log files.",
    "tags": [
      "attack.persistence",
      "attack.g0016",
      "attack.t1050"
    ],
    "query": "(winlog.event_id:\"7045\" AND winlog.event_data.ServiceName:\"Google\\ Update\")"
  },
  "trigger": {
    "schedule": {
      "interval": "5m"
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
                    "query": "(winlog.event_id:\"7045\" AND winlog.event_data.ServiceName:\"Google\\ Update\")",
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
        "subject": "Sigma Rule 'APT29 Google Update Service Install'",
        "body": "Hits:\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\nComputerName = {{_source.ComputerName}}\n        User = {{_source.User}}\n CommandLine = {{_source.CommandLine}}================================================================================\n{{/ctx.payload.hits.hits}}",
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
An unsupported feature is required for this Sigma rule (detection_rules/sigma/rules/windows/builtin/win_apt_apt29_tor.yml): Aggregations not implemented for this backend
Feel free to contribute for fun and fame, this is open source :) -> https://github.com/Neo23x0/sigma
```


### splunk
    
```
An unsupported feature is required for this Sigma rule (detection_rules/sigma/rules/windows/builtin/win_apt_apt29_tor.yml): The 'near' aggregation operator is not yet implemented for this backend
Feel free to contribute for fun and fame, this is open source :) -> https://github.com/Neo23x0/sigma
```


### logpoint
    
```
An unsupported feature is required for this Sigma rule (detection_rules/sigma/rules/windows/builtin/win_apt_apt29_tor.yml): The 'near' aggregation operator is not yet implemented for this backend
Feel free to contribute for fun and fame, this is open source :) -> https://github.com/Neo23x0/sigma
```


### grep
    
```
grep -P '^(?:.*(?=.*7045)(?=.*Google Update))'
```



