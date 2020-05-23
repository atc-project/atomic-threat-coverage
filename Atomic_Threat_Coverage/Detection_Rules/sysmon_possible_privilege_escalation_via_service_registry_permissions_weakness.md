| Title                    | Possible Privilege Escalation via Service Permissions Weakness       |
|:-------------------------|:------------------|
| **Description**          | Detect modification of services configuration (ImagePath, FailureCommand and ServiceDLL) in registry by processes with Medium integrity level |
| **ATT&amp;CK Tactic**    |  <ul><li>[TA0004: Privilege Escalation](https://attack.mitre.org/tactics/TA0004)</li></ul>  |
| **ATT&amp;CK Technique** | <ul><li>[T1058: Service Registry Permissions Weakness](https://attack.mitre.org/techniques/T1058)</li></ul>  |
| **Data Needed**          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0017_13_windows_sysmon_RegistryEvent](../Data_Needed/DN_0017_13_windows_sysmon_RegistryEvent.md)</li></ul>  |
| **Enrichment** |<ul><li>[EN_0001_cache_sysmon_event_id_1_info](../Enrichments/EN_0001_cache_sysmon_event_id_1_info.md)</li><li>[EN_0003_enrich_other_sysmon_events_with_event_id_1_data](../Enrichments/EN_0003_enrich_other_sysmon_events_with_event_id_1_data.md)</li></ul> |
| **Trigger**              | <ul><li>[T1058: Service Registry Permissions Weakness](../Triggers/T1058.md)</li></ul>  |
| **Severity Level**       | high |
| **False Positives**      | <ul><li>Unknown</li></ul>  |
| **Development Status**   | experimental |
| **References**           | <ul><li>[https://speakerdeck.com/heirhabarov/hunting-for-privilege-escalation-in-windows-environment](https://speakerdeck.com/heirhabarov/hunting-for-privilege-escalation-in-windows-environment)</li><li>[https://pentestlab.blog/2017/03/31/insecure-registry-permissions/](https://pentestlab.blog/2017/03/31/insecure-registry-permissions/)</li></ul>  |
| **Author**               | Teymur Kheirkhabarov |


## Detection Rules

### Sigma rule

```
title: Possible Privilege Escalation via Service Permissions Weakness
id: 0f9c21f1-6a73-4b0e-9809-cb562cb8d981
description: Detect modification of services configuration (ImagePath, FailureCommand and ServiceDLL) in registry by processes with Medium integrity level
references:
    - https://speakerdeck.com/heirhabarov/hunting-for-privilege-escalation-in-windows-environment
    - https://pentestlab.blog/2017/03/31/insecure-registry-permissions/
tags:
    - attack.privilege_escalation
    - attack.t1058
status: experimental
author: Teymur Kheirkhabarov
date: 2019/10/26
modified: 2019/11/11
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 13
        IntegrityLevel: 'Medium'
        TargetObject|contains: '\services\'
        TargetObject|endswith:
            - '\ImagePath'
            - '\FailureCommand'
            - '\Parameters\ServiceDll'
    condition: selection
falsepositives:
    - Unknown
level: high
enrichment:
    - EN_0001_cache_sysmon_event_id_1_info                      # http://bit.ly/314zc6x
    - EN_0003_enrich_other_sysmon_events_with_event_id_1_data   # http://bit.ly/2ojW7fw

```





### powershell
    
```
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | where {($_.ID -eq "13" -and $_.message -match "IntegrityLevel.*Medium" -and $_.message -match "TargetObject.*.*\\\\services\\\\.*" -and ($_.message -match "TargetObject.*.*\\\\ImagePath" -or $_.message -match "TargetObject.*.*\\\\FailureCommand" -or $_.message -match "TargetObject.*.*\\\\Parameters\\\\ServiceDll")) } | select TimeCreated,Id,RecordId,ProcessId,MachineName,Message
```


### es-qs
    
```
(winlog.channel:"Microsoft\\-Windows\\-Sysmon\\/Operational" AND winlog.event_id:"13" AND IntegrityLevel:"Medium" AND winlog.event_data.TargetObject.keyword:*\\\\services\\\\* AND winlog.event_data.TargetObject.keyword:(*\\\\ImagePath OR *\\\\FailureCommand OR *\\\\Parameters\\\\ServiceDll))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/0f9c21f1-6a73-4b0e-9809-cb562cb8d981 <<EOF\n{\n  "metadata": {\n    "title": "Possible Privilege Escalation via Service Permissions Weakness",\n    "description": "Detect modification of services configuration (ImagePath, FailureCommand and ServiceDLL) in registry by processes with Medium integrity level",\n    "tags": [\n      "attack.privilege_escalation",\n      "attack.t1058"\n    ],\n    "query": "(winlog.channel:\\"Microsoft\\\\-Windows\\\\-Sysmon\\\\/Operational\\" AND winlog.event_id:\\"13\\" AND IntegrityLevel:\\"Medium\\" AND winlog.event_data.TargetObject.keyword:*\\\\\\\\services\\\\\\\\* AND winlog.event_data.TargetObject.keyword:(*\\\\\\\\ImagePath OR *\\\\\\\\FailureCommand OR *\\\\\\\\Parameters\\\\\\\\ServiceDll))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(winlog.channel:\\"Microsoft\\\\-Windows\\\\-Sysmon\\\\/Operational\\" AND winlog.event_id:\\"13\\" AND IntegrityLevel:\\"Medium\\" AND winlog.event_data.TargetObject.keyword:*\\\\\\\\services\\\\\\\\* AND winlog.event_data.TargetObject.keyword:(*\\\\\\\\ImagePath OR *\\\\\\\\FailureCommand OR *\\\\\\\\Parameters\\\\\\\\ServiceDll))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": [\n          "winlogbeat-*"\n        ]\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Possible Privilege Escalation via Service Permissions Weakness\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"13" AND IntegrityLevel:"Medium" AND TargetObject.keyword:*\\\\services\\\\* AND TargetObject.keyword:(*\\\\ImagePath *\\\\FailureCommand *\\\\Parameters\\\\ServiceDll))
```


### splunk
    
```
(source="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode="13" IntegrityLevel="Medium" TargetObject="*\\\\services\\\\*" (TargetObject="*\\\\ImagePath" OR TargetObject="*\\\\FailureCommand" OR TargetObject="*\\\\Parameters\\\\ServiceDll"))
```


### logpoint
    
```
(event_id="13" IntegrityLevel="Medium" TargetObject="*\\\\services\\\\*" TargetObject IN ["*\\\\ImagePath", "*\\\\FailureCommand", "*\\\\Parameters\\\\ServiceDll"])
```


### grep
    
```
grep -P '^(?:.*(?=.*13)(?=.*Medium)(?=.*.*\\services\\\\.*)(?=.*(?:.*.*\\ImagePath|.*.*\\FailureCommand|.*.*\\Parameters\\ServiceDll)))'
```



