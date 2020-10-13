| Title                    | Tap Driver Installation       |
|:-------------------------|:------------------|
| **Description**          | Well-known TAP software installation. Possible preparation for data exfiltration using tunnelling techniques |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0010: Exfiltration](https://attack.mitre.org/tactics/TA0010)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1048: Exfiltration Over Alternative Protocol](https://attack.mitre.org/techniques/T1048)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0005_7045_windows_service_insatalled](../Data_Needed/DN_0005_7045_windows_service_insatalled.md)</li><li>[DN_0010_6_windows_sysmon_driver_loaded](../Data_Needed/DN_0010_6_windows_sysmon_driver_loaded.md)</li><li>[DN_0063_4697_service_was_installed_in_the_system](../Data_Needed/DN_0063_4697_service_was_installed_in_the_system.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1048: Exfiltration Over Alternative Protocol](../Triggers/T1048.md)</li></ul>  |
| **Severity Level**       | medium |
| **False Positives**      | <ul><li>Legitimate OpenVPN TAP insntallation</li></ul>  |
| **Development Status**   | experimental |
| **References**           |  There are no documented References for this Detection Rule yet  |
| **Author**               | Daniil Yugoslavskiy, Ian Davis, oscd.community |


## Detection Rules

### Sigma rule

```
action: global
title: Tap Driver Installation
id: 8e4cf0e5-aa5d-4dc3-beff-dc26917744a9
description: Well-known TAP software installation. Possible preparation for data exfiltration using tunnelling techniques
status: experimental
author: Daniil Yugoslavskiy, Ian Davis, oscd.community
date: 2019/10/24
tags:
    - attack.exfiltration
    - attack.t1048
falsepositives:
    - Legitimate OpenVPN TAP insntallation
level: medium
detection:
    selection_1:
        ImagePath|contains: 'tap0901'
    condition: selection and selection_1
---
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 7045
---
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 6
---
 logsource:
     product: windows
     service: security
 detection:
     selection:
         EventID: 4697

```





### powershell
    
```
Get-WinEvent -LogName System | where {($_.ID -eq "7045" -and $_.message -match "ImagePath.*.*tap0901.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "6" -and $_.message -match "ImagePath.*.*tap0901.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
Get-WinEvent -LogName Security | where {($_.ID -eq "4697" -and $_.message -match "ImagePath.*.*tap0901.*") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.event_id:"7045" AND winlog.event_data.ImagePath.keyword:*tap0901*)
(winlog.channel:"Microsoft\-Windows\-Sysmon\/Operational" AND winlog.event_id:"6" AND winlog.event_data.ImagePath.keyword:*tap0901*)
(winlog.channel:"Security" AND winlog.event_id:"4697" AND winlog.event_data.ImagePath.keyword:*tap0901*)
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/8e4cf0e5-aa5d-4dc3-beff-dc26917744a9 <<EOF
{
  "metadata": {
    "title": "Tap Driver Installation",
    "description": "Well-known TAP software installation. Possible preparation for data exfiltration using tunnelling techniques",
    "tags": [
      "attack.exfiltration",
      "attack.t1048"
    ],
    "query": "(winlog.event_id:\"7045\" AND winlog.event_data.ImagePath.keyword:*tap0901*)"
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
                    "query": "(winlog.event_id:\"7045\" AND winlog.event_data.ImagePath.keyword:*tap0901*)",
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
        "subject": "Sigma Rule 'Tap Driver Installation'",
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
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/8e4cf0e5-aa5d-4dc3-beff-dc26917744a9-2 <<EOF
{
  "metadata": {
    "title": "Tap Driver Installation",
    "description": "Well-known TAP software installation. Possible preparation for data exfiltration using tunnelling techniques",
    "tags": [
      "attack.exfiltration",
      "attack.t1048"
    ],
    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"6\" AND winlog.event_data.ImagePath.keyword:*tap0901*)"
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
                    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"6\" AND winlog.event_data.ImagePath.keyword:*tap0901*)",
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
        "subject": "Sigma Rule 'Tap Driver Installation'",
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
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/8e4cf0e5-aa5d-4dc3-beff-dc26917744a9-3 <<EOF
{
  "metadata": {
    "title": "Tap Driver Installation",
    "description": "Well-known TAP software installation. Possible preparation for data exfiltration using tunnelling techniques",
    "tags": [
      "attack.exfiltration",
      "attack.t1048"
    ],
    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"4697\" AND winlog.event_data.ImagePath.keyword:*tap0901*)"
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
                    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"4697\" AND winlog.event_data.ImagePath.keyword:*tap0901*)",
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
        "subject": "Sigma Rule 'Tap Driver Installation'",
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
(EventID:"7045" AND ImagePath.keyword:*tap0901*)
(EventID:"6" AND ImagePath.keyword:*tap0901*)
(EventID:"4697" AND ImagePath.keyword:*tap0901*)
```


### splunk
    
```
(source="WinEventLog:System" EventCode="7045" ImagePath="*tap0901*")
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="6" ImagePath="*tap0901*")
(source="WinEventLog:Security" EventCode="4697" ImagePath="*tap0901*")
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id="7045" ImagePath="*tap0901*")
(event_id="6" ImagePath="*tap0901*")
(event_source="Microsoft-Windows-Security-Auditing" event_id="4697" ImagePath="*tap0901*")
```


### grep
    
```
grep -P '^(?:.*(?=.*7045)(?=.*.*tap0901.*))'
grep -P '^(?:.*(?=.*6)(?=.*.*tap0901.*))'
grep -P '^(?:.*(?=.*4697)(?=.*.*tap0901.*))'
```



