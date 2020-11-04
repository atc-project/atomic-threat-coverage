| Title                    | Mimikatz In-Memory       |
|:-------------------------|:------------------|
| **Description**          | Detects certain DLL loads when Mimikatz gets executed |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0008: Lateral Movement](https://attack.mitre.org/tactics/TA0008)</li><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1003: OS Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0011_7_windows_sysmon_image_loaded](../Data_Needed/DN_0011_7_windows_sysmon_image_loaded.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1003: OS Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://securityriskadvisors.com/blog/post/detecting-in-memory-mimikatz/](https://securityriskadvisors.com/blog/post/detecting-in-memory-mimikatz/)</li></ul>  |
| **Author**               |  Author of this Detection Rule haven't introduced himself  |
| Other Tags           | <ul><li>attack.s0002</li><li>car.2019-04-004</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Mimikatz In-Memory
id: c0478ead-5336-46c2-bd5e-b4c84bc3a36e
status: experimental
description: Detects certain DLL loads when Mimikatz gets executed
references:
    - https://securityriskadvisors.com/blog/post/detecting-in-memory-mimikatz/
tags:
    - attack.s0002
    - attack.t1003
    - attack.lateral_movement
    - attack.credential_access
    - car.2019-04-004
logsource:
    product: windows
    service: sysmon
date: 2017/03/13
detection:
    selector:
        EventID: 7
        Image: 'C:\Windows\System32\rundll32.exe'
    dllload1:
        ImageLoaded: '*\vaultcli.dll'
    dllload2:
        ImageLoaded: '*\wlanapi.dll'
    exclusion:
        ImageLoaded:
            - 'ntdsapi.dll'
            - 'netapi32.dll'
            - 'imm32.dll'
            - 'samlib.dll'
            - 'combase.dll'
            - 'srvcli.dll'
            - 'shcore.dll'
            - 'ntasn1.dll'
            - 'cryptdll.dll'
            - 'logoncli.dll'
    timeframe: 30s
    condition: selector | near dllload1 and dllload2 and not exclusion
falsepositives:
    - unknown
level: medium

```





### powershell
    
```
An unsupported feature is required for this Sigma rule (detection_rules/sigma/rules/windows/sysmon/sysmon_mimikatz_inmemory_detection.yml): Only COUNT aggregation function is implemented for this backend
Feel free to contribute for fun and fame, this is open source :) -> https://github.com/Neo23x0/sigma
```


### es-qs
    
```
An unsupported feature is required for this Sigma rule (detection_rules/sigma/rules/windows/sysmon/sysmon_mimikatz_inmemory_detection.yml): Aggregations not implemented for this backend
Feel free to contribute for fun and fame, this is open source :) -> https://github.com/Neo23x0/sigma
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/c0478ead-5336-46c2-bd5e-b4c84bc3a36e <<EOF
{
  "metadata": {
    "title": "Mimikatz In-Memory",
    "description": "Detects certain DLL loads when Mimikatz gets executed",
    "tags": [
      "attack.s0002",
      "attack.t1003",
      "attack.lateral_movement",
      "attack.credential_access",
      "car.2019-04-004"
    ],
    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"7\" AND winlog.event_data.Image:\"C\\:\\\\Windows\\\\System32\\\\rundll32.exe\")"
  },
  "trigger": {
    "schedule": {
      "interval": "30s"
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
                    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"7\" AND winlog.event_data.Image:\"C\\:\\\\Windows\\\\System32\\\\rundll32.exe\")",
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
        "subject": "Sigma Rule 'Mimikatz In-Memory'",
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
An unsupported feature is required for this Sigma rule (detection_rules/sigma/rules/windows/sysmon/sysmon_mimikatz_inmemory_detection.yml): Aggregations not implemented for this backend
Feel free to contribute for fun and fame, this is open source :) -> https://github.com/Neo23x0/sigma
```


### splunk
    
```
An unsupported feature is required for this Sigma rule (detection_rules/sigma/rules/windows/sysmon/sysmon_mimikatz_inmemory_detection.yml): The 'near' aggregation operator is not yet implemented for this backend
Feel free to contribute for fun and fame, this is open source :) -> https://github.com/Neo23x0/sigma
```


### logpoint
    
```
An unsupported feature is required for this Sigma rule (detection_rules/sigma/rules/windows/sysmon/sysmon_mimikatz_inmemory_detection.yml): The 'near' aggregation operator is not yet implemented for this backend
Feel free to contribute for fun and fame, this is open source :) -> https://github.com/Neo23x0/sigma
```


### grep
    
```
grep -P '^(?:.*(?=.*7)(?=.*C:\Windows\System32\rundll32\.exe))'
```



