| Title                    | Windows Defender Exclusion Set       |
|:-------------------------|:------------------|
| **Description**          | Detects scenarios where an windows defender exclusion was added in registry where an entity would want to bypass antivirus scanning from windows defender |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1089: Disabling Security Tools](https://attack.mitre.org/techniques/T1089)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0058_4656_handle_to_an_object_was_requested](../Data_Needed/DN_0058_4656_handle_to_an_object_was_requested.md)</li><li>[DN_0059_4657_registry_value_was_modified](../Data_Needed/DN_0059_4657_registry_value_was_modified.md)</li><li>[DN_0061_4660_object_was_deleted](../Data_Needed/DN_0061_4660_object_was_deleted.md)</li><li>[DN_0062_4663_attempt_was_made_to_access_an_object](../Data_Needed/DN_0062_4663_attempt_was_made_to_access_an_object.md)</li></ul>  |
| **Trigger**              | <ul><li>[T1089: Disabling Security Tools](../Triggers/T1089.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Intended inclusions by administrator</li></ul>  |
| **Development Status**   |  Development Status wasn't defined for this Detection Rule yet  |
| **References**           | <ul><li>[https://www.bleepingcomputer.com/news/security/gootkit-malware-bypasses-windows-defender-by-setting-path-exclusions/](https://www.bleepingcomputer.com/news/security/gootkit-malware-bypasses-windows-defender-by-setting-path-exclusions/)</li></ul>  |
| **Author**               | @BarryShooshooga |


## Detection Rules

### Sigma rule

```
title: Windows Defender Exclusion Set
id: e9c8808f-4cfb-4ba9-97d4-e5f3beaa244d
description: 'Detects scenarios where an windows defender exclusion was added in registry where an entity would want to bypass antivirus scanning from windows defender'
references:
    - https://www.bleepingcomputer.com/news/security/gootkit-malware-bypasses-windows-defender-by-setting-path-exclusions/
tags:
    - attack.defense_evasion
    - attack.t1089
author: "@BarryShooshooga"
date: 2019/10/26
logsource:
    product: windows
    service: security
    definition: 'Requirements: Audit Policy : Security Settings/Local Policies/Audit Policy, Registry System Access Control (SACL): Auditing/User'
detection:
    selection:
        EventID: 
            - 4657
            - 4656
            - 4660
            - 4663
        ObjectName|contains: '\Microsoft\Windows Defender\Exclusions\'
    condition: selection
falsepositives: 
    - Intended inclusions by administrator
level: high

```





### es-qs
    
```
(EventID:("4657" OR "4656" OR "4660" OR "4663") AND ObjectName.keyword:*\\\\Microsoft\\\\Windows\\ Defender\\\\Exclusions\\\\*)
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/e9c8808f-4cfb-4ba9-97d4-e5f3beaa244d <<EOF\n{\n  "metadata": {\n    "title": "Windows Defender Exclusion Set",\n    "description": "Detects scenarios where an windows defender exclusion was added in registry where an entity would want to bypass antivirus scanning from windows defender",\n    "tags": [\n      "attack.defense_evasion",\n      "attack.t1089"\n    ],\n    "query": "(EventID:(\\"4657\\" OR \\"4656\\" OR \\"4660\\" OR \\"4663\\") AND ObjectName.keyword:*\\\\\\\\Microsoft\\\\\\\\Windows\\\\ Defender\\\\\\\\Exclusions\\\\\\\\*)"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:(\\"4657\\" OR \\"4656\\" OR \\"4660\\" OR \\"4663\\") AND ObjectName.keyword:*\\\\\\\\Microsoft\\\\\\\\Windows\\\\ Defender\\\\\\\\Exclusions\\\\\\\\*)",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Windows Defender Exclusion Set\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:("4657" "4656" "4660" "4663") AND ObjectName.keyword:*\\\\Microsoft\\\\Windows Defender\\\\Exclusions\\\\*)
```


### splunk
    
```
((EventID="4657" OR EventID="4656" OR EventID="4660" OR EventID="4663") ObjectName="*\\\\Microsoft\\\\Windows Defender\\\\Exclusions\\\\*")
```


### logpoint
    
```
(event_source="Microsoft-Windows-Security-Auditing" event_id IN ["4657", "4656", "4660", "4663"] ObjectName="*\\\\Microsoft\\\\Windows Defender\\\\Exclusions\\\\*")
```


### grep
    
```
grep -P '^(?:.*(?=.*(?:.*4657|.*4656|.*4660|.*4663))(?=.*.*\\Microsoft\\Windows Defender\\Exclusions\\\\.*))'
```



