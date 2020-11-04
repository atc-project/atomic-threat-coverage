| Title                    | Credential Dumping Tools Service Execution       |
|:-------------------------|:------------------|
| **Description**          | Detects well-known credential dumping tools execution via service execution events |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li><li>[TA0002: Execution](https://attack.mitre.org/tactics/TA0002)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1003: OS Credential Dumping](https://attack.mitre.org/techniques/T1003)</li><li>[T1035: Service Execution](https://attack.mitre.org/techniques/T1035)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0005_7045_windows_service_insatalled](../Data_Needed/DN_0005_7045_windows_service_insatalled.md)</li><li>[DN_0010_6_windows_sysmon_driver_loaded](../Data_Needed/DN_0010_6_windows_sysmon_driver_loaded.md)</li><li>[DN_0063_4697_service_was_installed_in_the_system](../Data_Needed/DN_0063_4697_service_was_installed_in_the_system.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1003: OS Credential Dumping](../Triggers/T1003.md)</li><li>[T1035: Service Execution](../Triggers/T1035.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Legitimate Administrator using credential dumping tool for password recovery</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           | <ul><li>[https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment](https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment)</li></ul>  |
| **Author**               | Florian Roth, Teymur Kheirkhabarov, Daniil Yugoslavskiy, oscd.community |
| Other Tags           | <ul><li>attack.s0005</li></ul> | 

## Detection Rules

### Sigma rule

```
---
action: global
title: Credential Dumping Tools Service Execution
description: Detects well-known credential dumping tools execution via service execution events
author: Florian Roth, Teymur Kheirkhabarov, Daniil Yugoslavskiy, oscd.community
id: 4976aa50-8f41-45c6-8b15-ab3fc10e79ed
date: 2017/03/05
modified: 2019/11/01
references:
    - https://www.slideshare.net/heirhabarov/hunting-for-credentials-dumping-in-windows-environment
tags:
    - attack.credential_access
    - attack.execution
    - attack.t1003
    - attack.t1035
    - attack.s0005
detection:
    selection_1:
        - ServiceName|contains:
            - 'fgexec'
            - 'wceservice'
            - 'wce service'
            - 'pwdump'
            - 'gsecdump'
            - 'cachedump'
            - 'mimikatz'
            - 'mimidrv'
        - ImagePath|contains:
            - 'fgexec'
            - 'dumpsvc'
            - 'cachedump'
            - 'mimidrv'
            - 'gsecdump'
            - 'servpw'
            - 'pwdump'
        - ImagePath|re: '((\\\\.*\\.*|.*\\)([{]?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}[}])?\.(exe|scr|cpl|bat|js|cmd|vbs).*)'
    condition: selection and selection_1
falsepositives:
    - Legitimate Administrator using credential dumping tool for password recovery
level: high
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
An unsupported feature is required for this Sigma rule (detection_rules/sigma/rules/windows/builtin/win_mal_creddumper.yml): Backend does not support map values of type <class 'sigma.parser.modifiers.type.SigmaRegularExpressionModifier'>
Feel free to contribute for fun and fame, this is open source :) -> https://github.com/Neo23x0/sigma
```


### es-qs
    
```
(winlog.event_id:"7045" AND (winlog.event_data.ServiceName.keyword:(*fgexec* OR *wceservice* OR *wce\ service* OR *pwdump* OR *gsecdump* OR *cachedump* OR *mimikatz* OR *mimidrv*) OR winlog.event_data.ImagePath.keyword:(*fgexec* OR *dumpsvc* OR *cachedump* OR *mimidrv* OR *gsecdump* OR *servpw* OR *pwdump*) OR winlog.event_data.ImagePath:/((\\\\.*\\.*|.*\\)([{]?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}[}])?\.(exe|scr|cpl|bat|js|cmd|vbs).*)/))
(winlog.channel:"Microsoft\-Windows\-Sysmon\/Operational" AND winlog.event_id:"6" AND (winlog.event_data.ServiceName.keyword:(*fgexec* OR *wceservice* OR *wce\ service* OR *pwdump* OR *gsecdump* OR *cachedump* OR *mimikatz* OR *mimidrv*) OR winlog.event_data.ImagePath.keyword:(*fgexec* OR *dumpsvc* OR *cachedump* OR *mimidrv* OR *gsecdump* OR *servpw* OR *pwdump*) OR winlog.event_data.ImagePath:/((\\\\.*\\.*|.*\\)([{]?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}[}])?\.(exe|scr|cpl|bat|js|cmd|vbs).*)/))
(winlog.channel:"Security" AND winlog.event_id:"4697" AND (winlog.event_data.ServiceName.keyword:(*fgexec* OR *wceservice* OR *wce\ service* OR *pwdump* OR *gsecdump* OR *cachedump* OR *mimikatz* OR *mimidrv*) OR winlog.event_data.ImagePath.keyword:(*fgexec* OR *dumpsvc* OR *cachedump* OR *mimidrv* OR *gsecdump* OR *servpw* OR *pwdump*) OR winlog.event_data.ImagePath:/((\\\\.*\\.*|.*\\)([{]?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}[}])?\.(exe|scr|cpl|bat|js|cmd|vbs).*)/))
```


### xpack-watcher
    
```
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/4976aa50-8f41-45c6-8b15-ab3fc10e79ed <<EOF
{
  "metadata": {
    "title": "Credential Dumping Tools Service Execution",
    "description": "Detects well-known credential dumping tools execution via service execution events",
    "tags": [
      "attack.credential_access",
      "attack.execution",
      "attack.t1003",
      "attack.t1035",
      "attack.s0005"
    ],
    "query": "(winlog.event_id:\"7045\" AND (winlog.event_data.ServiceName.keyword:(*fgexec* OR *wceservice* OR *wce\\ service* OR *pwdump* OR *gsecdump* OR *cachedump* OR *mimikatz* OR *mimidrv*) OR winlog.event_data.ImagePath.keyword:(*fgexec* OR *dumpsvc* OR *cachedump* OR *mimidrv* OR *gsecdump* OR *servpw* OR *pwdump*) OR winlog.event_data.ImagePath:/((\\\\\\\\.*\\\\.*|.*\\\\)([{]?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}[}])?\\.(exe|scr|cpl|bat|js|cmd|vbs).*)/))"
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
                    "query": "(winlog.event_id:\"7045\" AND (winlog.event_data.ServiceName.keyword:(*fgexec* OR *wceservice* OR *wce\\ service* OR *pwdump* OR *gsecdump* OR *cachedump* OR *mimikatz* OR *mimidrv*) OR winlog.event_data.ImagePath.keyword:(*fgexec* OR *dumpsvc* OR *cachedump* OR *mimidrv* OR *gsecdump* OR *servpw* OR *pwdump*) OR winlog.event_data.ImagePath:/((\\\\\\\\.*\\\\.*|.*\\\\)([{]?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}[}])?\\.(exe|scr|cpl|bat|js|cmd|vbs).*)/))",
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
        "subject": "Sigma Rule 'Credential Dumping Tools Service Execution'",
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
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/4976aa50-8f41-45c6-8b15-ab3fc10e79ed-2 <<EOF
{
  "metadata": {
    "title": "Credential Dumping Tools Service Execution",
    "description": "Detects well-known credential dumping tools execution via service execution events",
    "tags": [
      "attack.credential_access",
      "attack.execution",
      "attack.t1003",
      "attack.t1035",
      "attack.s0005"
    ],
    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"6\" AND (winlog.event_data.ServiceName.keyword:(*fgexec* OR *wceservice* OR *wce\\ service* OR *pwdump* OR *gsecdump* OR *cachedump* OR *mimikatz* OR *mimidrv*) OR winlog.event_data.ImagePath.keyword:(*fgexec* OR *dumpsvc* OR *cachedump* OR *mimidrv* OR *gsecdump* OR *servpw* OR *pwdump*) OR winlog.event_data.ImagePath:/((\\\\\\\\.*\\\\.*|.*\\\\)([{]?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}[}])?\\.(exe|scr|cpl|bat|js|cmd|vbs).*)/))"
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
                    "query": "(winlog.channel:\"Microsoft\\-Windows\\-Sysmon\\/Operational\" AND winlog.event_id:\"6\" AND (winlog.event_data.ServiceName.keyword:(*fgexec* OR *wceservice* OR *wce\\ service* OR *pwdump* OR *gsecdump* OR *cachedump* OR *mimikatz* OR *mimidrv*) OR winlog.event_data.ImagePath.keyword:(*fgexec* OR *dumpsvc* OR *cachedump* OR *mimidrv* OR *gsecdump* OR *servpw* OR *pwdump*) OR winlog.event_data.ImagePath:/((\\\\\\\\.*\\\\.*|.*\\\\)([{]?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}[}])?\\.(exe|scr|cpl|bat|js|cmd|vbs).*)/))",
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
        "subject": "Sigma Rule 'Credential Dumping Tools Service Execution'",
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
curl -s -XPUT -H 'Content-Type: application/json' --data-binary @- localhost:9200/_watcher/watch/4976aa50-8f41-45c6-8b15-ab3fc10e79ed-3 <<EOF
{
  "metadata": {
    "title": "Credential Dumping Tools Service Execution",
    "description": "Detects well-known credential dumping tools execution via service execution events",
    "tags": [
      "attack.credential_access",
      "attack.execution",
      "attack.t1003",
      "attack.t1035",
      "attack.s0005"
    ],
    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"4697\" AND (winlog.event_data.ServiceName.keyword:(*fgexec* OR *wceservice* OR *wce\\ service* OR *pwdump* OR *gsecdump* OR *cachedump* OR *mimikatz* OR *mimidrv*) OR winlog.event_data.ImagePath.keyword:(*fgexec* OR *dumpsvc* OR *cachedump* OR *mimidrv* OR *gsecdump* OR *servpw* OR *pwdump*) OR winlog.event_data.ImagePath:/((\\\\\\\\.*\\\\.*|.*\\\\)([{]?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}[}])?\\.(exe|scr|cpl|bat|js|cmd|vbs).*)/))"
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
                    "query": "(winlog.channel:\"Security\" AND winlog.event_id:\"4697\" AND (winlog.event_data.ServiceName.keyword:(*fgexec* OR *wceservice* OR *wce\\ service* OR *pwdump* OR *gsecdump* OR *cachedump* OR *mimikatz* OR *mimidrv*) OR winlog.event_data.ImagePath.keyword:(*fgexec* OR *dumpsvc* OR *cachedump* OR *mimidrv* OR *gsecdump* OR *servpw* OR *pwdump*) OR winlog.event_data.ImagePath:/((\\\\\\\\.*\\\\.*|.*\\\\)([{]?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}[}])?\\.(exe|scr|cpl|bat|js|cmd|vbs).*)/))",
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
        "subject": "Sigma Rule 'Credential Dumping Tools Service Execution'",
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
(EventID:"7045" AND (ServiceName.keyword:(*fgexec* *wceservice* *wce service* *pwdump* *gsecdump* *cachedump* *mimikatz* *mimidrv*) OR ImagePath.keyword:(*fgexec* *dumpsvc* *cachedump* *mimidrv* *gsecdump* *servpw* *pwdump*) OR ImagePath:/((\\\\.*\\.*|.*\\)([{]?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}[}])?\.(exe|scr|cpl|bat|js|cmd|vbs).*)/))
(EventID:"6" AND (ServiceName.keyword:(*fgexec* *wceservice* *wce service* *pwdump* *gsecdump* *cachedump* *mimikatz* *mimidrv*) OR ImagePath.keyword:(*fgexec* *dumpsvc* *cachedump* *mimidrv* *gsecdump* *servpw* *pwdump*) OR ImagePath:/((\\\\.*\\.*|.*\\)([{]?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}[}])?\.(exe|scr|cpl|bat|js|cmd|vbs).*)/))
(EventID:"4697" AND (ServiceName.keyword:(*fgexec* *wceservice* *wce service* *pwdump* *gsecdump* *cachedump* *mimikatz* *mimidrv*) OR ImagePath.keyword:(*fgexec* *dumpsvc* *cachedump* *mimidrv* *gsecdump* *servpw* *pwdump*) OR ImagePath:/((\\\\.*\\.*|.*\\)([{]?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}[}])?\.(exe|scr|cpl|bat|js|cmd|vbs).*)/))
```


### splunk
    
```
An unsupported feature is required for this Sigma rule (detection_rules/sigma/rules/windows/builtin/win_mal_creddumper.yml): Type modifier 're' is not supported by backend
Feel free to contribute for fun and fame, this is open source :) -> https://github.com/Neo23x0/sigma
```


### logpoint
    
```
An unsupported feature is required for this Sigma rule (detection_rules/sigma/rules/windows/builtin/win_mal_creddumper.yml): Type modifier 're' is not supported by backend
Feel free to contribute for fun and fame, this is open source :) -> https://github.com/Neo23x0/sigma
```


### grep
    
```
An unsupported feature is required for this Sigma rule (detection_rules/sigma/rules/windows/builtin/win_mal_creddumper.yml): Node type not implemented for this backend
Feel free to contribute for fun and fame, this is open source :) -> https://github.com/Neo23x0/sigma
```



