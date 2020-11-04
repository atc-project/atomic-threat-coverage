| Title                    | Dumpert Process Dumper       |
|:-------------------------|:------------------|
| **Description**          | Detects the use of Dumpert process dumper, which dumps the lsass.exe process memory |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1003: OS Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0006_2_windows_sysmon_process_changed_a_file_creation_time](../Data_Needed/DN_0006_2_windows_sysmon_process_changed_a_file_creation_time.md)</li><li>[DN_0007_3_windows_sysmon_network_connection](../Data_Needed/DN_0007_3_windows_sysmon_network_connection.md)</li><li>[DN_0008_4_windows_sysmon_sysmon_service_state_changed](../Data_Needed/DN_0008_4_windows_sysmon_sysmon_service_state_changed.md)</li><li>[DN_0009_5_windows_sysmon_process_terminated](../Data_Needed/DN_0009_5_windows_sysmon_process_terminated.md)</li><li>[DN_0010_6_windows_sysmon_driver_loaded](../Data_Needed/DN_0010_6_windows_sysmon_driver_loaded.md)</li><li>[DN_0011_7_windows_sysmon_image_loaded](../Data_Needed/DN_0011_7_windows_sysmon_image_loaded.md)</li><li>[DN_0012_8_windows_sysmon_CreateRemoteThread](../Data_Needed/DN_0012_8_windows_sysmon_CreateRemoteThread.md)</li><li>[DN_0013_9_windows_sysmon_RawAccessRead](../Data_Needed/DN_0013_9_windows_sysmon_RawAccessRead.md)</li><li>[DN_0014_10_windows_sysmon_ProcessAccess](../Data_Needed/DN_0014_10_windows_sysmon_ProcessAccess.md)</li><li>[DN_0015_11_windows_sysmon_FileCreate](../Data_Needed/DN_0015_11_windows_sysmon_FileCreate.md)</li><li>[DN_0016_12_windows_sysmon_RegistryEvent](../Data_Needed/DN_0016_12_windows_sysmon_RegistryEvent.md)</li><li>[DN_0017_13_windows_sysmon_RegistryEvent](../Data_Needed/DN_0017_13_windows_sysmon_RegistryEvent.md)</li><li>[DN_0018_14_windows_sysmon_RegistryEvent](../Data_Needed/DN_0018_14_windows_sysmon_RegistryEvent.md)</li><li>[DN_0019_15_windows_sysmon_FileCreateStreamHash](../Data_Needed/DN_0019_15_windows_sysmon_FileCreateStreamHash.md)</li><li>[DN_0020_17_windows_sysmon_PipeEvent](../Data_Needed/DN_0020_17_windows_sysmon_PipeEvent.md)</li><li>[DN_0021_18_windows_sysmon_PipeEvent](../Data_Needed/DN_0021_18_windows_sysmon_PipeEvent.md)</li><li>[DN_0022_19_windows_sysmon_WmiEvent](../Data_Needed/DN_0022_19_windows_sysmon_WmiEvent.md)</li><li>[DN_0023_20_windows_sysmon_WmiEvent](../Data_Needed/DN_0023_20_windows_sysmon_WmiEvent.md)</li><li>[DN_0024_21_windows_sysmon_WmiEvent](../Data_Needed/DN_0024_21_windows_sysmon_WmiEvent.md)</li><li>[DN_0085_22_windows_sysmon_DnsQuery](../Data_Needed/DN_0085_22_windows_sysmon_DnsQuery.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1003: OS Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| **Severity Level**       | critical |
| **False Positives**      | <ul><li>Very unlikely</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           | <ul><li>[https://github.com/outflanknl/Dumpert](https://github.com/outflanknl/Dumpert)</li><li>[https://unit42.paloaltonetworks.com/actors-still-exploiting-sharepoint-vulnerability/](https://unit42.paloaltonetworks.com/actors-still-exploiting-sharepoint-vulnerability/)</li></ul>  |
| **Author**               | Florian Roth |


## Detection Rules

### Sigma rule

```
action: global
title: Dumpert Process Dumper
id: 2704ab9e-afe2-4854-a3b1-0c0706d03578
description: Detects the use of Dumpert process dumper, which dumps the lsass.exe process memory
author: Florian Roth
references:
    - https://github.com/outflanknl/Dumpert
    - https://unit42.paloaltonetworks.com/actors-still-exploiting-sharepoint-vulnerability/
date: 2020/02/04
tags:
    - attack.credential_access
    - attack.t1003
logsource:
    product: windows
    service: sysmon
falsepositives:
    - Very unlikely
level: critical
---
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Imphash: '09D278F9DE118EF09163C6140255C690'
    condition: selection
---
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 11
        TargetFilename: C:\Windows\Temp\dumpert.dmp
    condition: selection
```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.message -match "Imphash.*09D278F9DE118EF09163C6140255C690") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "11" -and $_.message -match "TargetFilename.*C:\\Windows\\Temp\\dumpert.dmp") } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\-Windows\-Sysmon\/Operational" AND winlog.event_data.Imphash:"09D278F9DE118EF09163C6140255C690")
(winlog.channel:"Microsoft\-Windows\-Sysmon\/Operational" AND winlog.event_id:"11" AND winlog.event_data.TargetFilename:"C\:\\Windows\\Temp\\dumpert.dmp")
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/2704ab9e-afe2-4854-a3b1-0c0706d03578 <<EOF
{
  "metadata": {
    "title": "Dumpert Process Dumper",
    "description": "Detects the use of Dumpert process dumper, which dumps the lsass.exe process memory",
    "tags": [
      "attack.credential_access",
      "attack.t1003"
    ],
    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_data.Imphash:\"09D278F9DE118EF09163C6140255C690\")"
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
                    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_data.Imphash:\"09D278F9DE118EF09163C6140255C690\")",
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
        "subject": "Sigma Rule 'Dumpert Process Dumper'",
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
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/2704ab9e-afe2-4854-a3b1-0c0706d03578-2 <<EOF
{
  "metadata": {
    "title": "Dumpert Process Dumper",
    "description": "Detects the use of Dumpert process dumper, which dumps the lsass.exe process memory",
    "tags": [
      "attack.credential_access",
      "attack.t1003"
    ],
    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"11\" AND winlog.event_data.TargetFilename:\"C\\:\\\\Windows\\\\Temp\\\\dumpert.dmp\")"
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
                    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"11\" AND winlog.event_data.TargetFilename:\"C\\:\\\\Windows\\\\Temp\\\\dumpert.dmp\")",
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
        "subject": "Sigma Rule 'Dumpert Process Dumper'",
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
Imphash:"09D278F9DE118EF09163C6140255C690"
(EventID:"11" AND TargetFilename:"C\:\\Windows\\Temp\\dumpert.dmp")
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" Imphash="09D278F9DE118EF09163C6140255C690")
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="11" TargetFilename="C:\\Windows\\Temp\\dumpert.dmp")
```


### logpoint
    
```
Imphash="09D278F9DE118EF09163C6140255C690"
(event_id="11" TargetFilename="C:\\Windows\\Temp\\dumpert.dmp")
```


### grep
    
```
grep -P '^09D278F9DE118EF09163C6140255C690'
grep -P '^(?:.*(?=.*11)(?=.*C:\Windows\Temp\dumpert\.dmp))'
```



