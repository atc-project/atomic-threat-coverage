| Title                | OceanLotus Registry Activity                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects registry keys created in OceanLotus (also known as APT32) attacks                                                                                                                                           |
| ATT&amp;CK Tactic    |   This Detection Rule wasn't mapped to ATT&amp;CK Tactic yet  |
| ATT&amp;CK Technique | <ul><li>[T1112: Modify Registry](https://attack.mitre.org/techniques/T1112)</li></ul>  |
| Data Needed          | <ul><li>[DN_0017_13_windows_sysmon_RegistryEvent](../Data_Needed/DN_0017_13_windows_sysmon_RegistryEvent.md)</li></ul>  |
| Trigger              | <ul><li>[T1112: Modify Registry](../Triggers/T1112.md)</li></ul>  |
| Severity Level       | critical |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://www.welivesecurity.com/2019/03/20/fake-or-fake-keeping-up-with-oceanlotus-decoys/](https://www.welivesecurity.com/2019/03/20/fake-or-fake-keeping-up-with-oceanlotus-decoys/)</li></ul>  |
| Author               | megan201296 |


## Detection Rules

### Sigma rule

```
title: OceanLotus Registry Activity
id: 4ac5fc44-a601-4c06-955b-309df8c4e9d4
status: experimental
description: Detects registry keys created in OceanLotus (also known as APT32) attacks
references:
    - https://www.welivesecurity.com/2019/03/20/fake-or-fake-keeping-up-with-oceanlotus-decoys/
tags:
    - attack.t1112
author: megan201296
date: 2019/04/14
logsource:
    product: windows
    service: sysmon
detection:
    selection:
        EventID: 13
        TargetObject: 
            - 'HKCR\CLSID\{E08A0F4B-1F65-4D4D-9A09-BD4625B9C5A1}\Model'
            - 'HKU\\*_Classes\CLSID\{E08A0F4B-1F65-4D4D-9A09-BD4625B9C5A1}\Model'
              # covers HKU\* and HKLM..
            - '*\SOFTWARE\App\AppXbf13d4ea2945444d8b13e2121cb6b663\Application'
            - '*\SOFTWARE\App\AppXbf13d4ea2945444d8b13e2121cb6b663\DefaultIcon'
            - '*\SOFTWARE\App\AppX70162486c7554f7f80f481985d67586d\Application'
            - '*\SOFTWARE\App\AppX70162486c7554f7f80f481985d67586d\DefaultIcon'
            - '*\SOFTWARE\App\AppX37cc7fdccd644b4f85f4b22d5a3f105a\Application'
            - '*\SOFTWARE\App\AppX37cc7fdccd644b4f85f4b22d5a3f105a\DefaultIcon'
            # HKCU\SOFTWARE\Classes\AppXc52346ec40fb4061ad96be0e6cb7d16a\
            - 'HKU\\*_Classes\AppXc52346ec40fb4061ad96be0e6cb7d16a\\*'
            # HKCU\SOFTWARE\Classes\AppX3bbba44c6cae4d9695755183472171e2\
            - 'HKU\\*_Classes\AppX3bbba44c6cae4d9695755183472171e2\\*'
            # HKCU\SOFTWARE\Classes\CLSID\{E3517E26-8E93-458D-A6DF-8030BC80528B}\
            - 'HKU\\*_Classes\CLSID\{E3517E26-8E93-458D-A6DF-8030BC80528B}\\*'
    condition: selection
falsepositives:
    - Unknown
level: critical

```





### es-qs
    
```
(EventID:"13" AND TargetObject.keyword:(HKCR\\\\CLSID\\\\\\{E08A0F4B\\-1F65\\-4D4D\\-9A09\\-BD4625B9C5A1\\}\\\\Model OR HKU\\\\*_Classes\\\\CLSID\\\\\\{E08A0F4B\\-1F65\\-4D4D\\-9A09\\-BD4625B9C5A1\\}\\\\Model OR *\\\\SOFTWARE\\\\App\\\\AppXbf13d4ea2945444d8b13e2121cb6b663\\\\Application OR *\\\\SOFTWARE\\\\App\\\\AppXbf13d4ea2945444d8b13e2121cb6b663\\\\DefaultIcon OR *\\\\SOFTWARE\\\\App\\\\AppX70162486c7554f7f80f481985d67586d\\\\Application OR *\\\\SOFTWARE\\\\App\\\\AppX70162486c7554f7f80f481985d67586d\\\\DefaultIcon OR *\\\\SOFTWARE\\\\App\\\\AppX37cc7fdccd644b4f85f4b22d5a3f105a\\\\Application OR *\\\\SOFTWARE\\\\App\\\\AppX37cc7fdccd644b4f85f4b22d5a3f105a\\\\DefaultIcon OR HKU\\\\*_Classes\\\\AppXc52346ec40fb4061ad96be0e6cb7d16a\\\\* OR HKU\\\\*_Classes\\\\AppX3bbba44c6cae4d9695755183472171e2\\\\* OR HKU\\\\*_Classes\\\\CLSID\\\\\\{E3517E26\\-8E93\\-458D\\-A6DF\\-8030BC80528B\\}\\\\*))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/4ac5fc44-a601-4c06-955b-309df8c4e9d4 <<EOF\n{\n  "metadata": {\n    "title": "OceanLotus Registry Activity",\n    "description": "Detects registry keys created in OceanLotus (also known as APT32) attacks",\n    "tags": [\n      "attack.t1112"\n    ],\n    "query": "(EventID:\\"13\\" AND TargetObject.keyword:(HKCR\\\\\\\\CLSID\\\\\\\\\\\\{E08A0F4B\\\\-1F65\\\\-4D4D\\\\-9A09\\\\-BD4625B9C5A1\\\\}\\\\\\\\Model OR HKU\\\\\\\\*_Classes\\\\\\\\CLSID\\\\\\\\\\\\{E08A0F4B\\\\-1F65\\\\-4D4D\\\\-9A09\\\\-BD4625B9C5A1\\\\}\\\\\\\\Model OR *\\\\\\\\SOFTWARE\\\\\\\\App\\\\\\\\AppXbf13d4ea2945444d8b13e2121cb6b663\\\\\\\\Application OR *\\\\\\\\SOFTWARE\\\\\\\\App\\\\\\\\AppXbf13d4ea2945444d8b13e2121cb6b663\\\\\\\\DefaultIcon OR *\\\\\\\\SOFTWARE\\\\\\\\App\\\\\\\\AppX70162486c7554f7f80f481985d67586d\\\\\\\\Application OR *\\\\\\\\SOFTWARE\\\\\\\\App\\\\\\\\AppX70162486c7554f7f80f481985d67586d\\\\\\\\DefaultIcon OR *\\\\\\\\SOFTWARE\\\\\\\\App\\\\\\\\AppX37cc7fdccd644b4f85f4b22d5a3f105a\\\\\\\\Application OR *\\\\\\\\SOFTWARE\\\\\\\\App\\\\\\\\AppX37cc7fdccd644b4f85f4b22d5a3f105a\\\\\\\\DefaultIcon OR HKU\\\\\\\\*_Classes\\\\\\\\AppXc52346ec40fb4061ad96be0e6cb7d16a\\\\\\\\* OR HKU\\\\\\\\*_Classes\\\\\\\\AppX3bbba44c6cae4d9695755183472171e2\\\\\\\\* OR HKU\\\\\\\\*_Classes\\\\\\\\CLSID\\\\\\\\\\\\{E3517E26\\\\-8E93\\\\-458D\\\\-A6DF\\\\-8030BC80528B\\\\}\\\\\\\\*))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "(EventID:\\"13\\" AND TargetObject.keyword:(HKCR\\\\\\\\CLSID\\\\\\\\\\\\{E08A0F4B\\\\-1F65\\\\-4D4D\\\\-9A09\\\\-BD4625B9C5A1\\\\}\\\\\\\\Model OR HKU\\\\\\\\*_Classes\\\\\\\\CLSID\\\\\\\\\\\\{E08A0F4B\\\\-1F65\\\\-4D4D\\\\-9A09\\\\-BD4625B9C5A1\\\\}\\\\\\\\Model OR *\\\\\\\\SOFTWARE\\\\\\\\App\\\\\\\\AppXbf13d4ea2945444d8b13e2121cb6b663\\\\\\\\Application OR *\\\\\\\\SOFTWARE\\\\\\\\App\\\\\\\\AppXbf13d4ea2945444d8b13e2121cb6b663\\\\\\\\DefaultIcon OR *\\\\\\\\SOFTWARE\\\\\\\\App\\\\\\\\AppX70162486c7554f7f80f481985d67586d\\\\\\\\Application OR *\\\\\\\\SOFTWARE\\\\\\\\App\\\\\\\\AppX70162486c7554f7f80f481985d67586d\\\\\\\\DefaultIcon OR *\\\\\\\\SOFTWARE\\\\\\\\App\\\\\\\\AppX37cc7fdccd644b4f85f4b22d5a3f105a\\\\\\\\Application OR *\\\\\\\\SOFTWARE\\\\\\\\App\\\\\\\\AppX37cc7fdccd644b4f85f4b22d5a3f105a\\\\\\\\DefaultIcon OR HKU\\\\\\\\*_Classes\\\\\\\\AppXc52346ec40fb4061ad96be0e6cb7d16a\\\\\\\\* OR HKU\\\\\\\\*_Classes\\\\\\\\AppX3bbba44c6cae4d9695755183472171e2\\\\\\\\* OR HKU\\\\\\\\*_Classes\\\\\\\\CLSID\\\\\\\\\\\\{E3517E26\\\\-8E93\\\\-458D\\\\-A6DF\\\\-8030BC80528B\\\\}\\\\\\\\*))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'OceanLotus Registry Activity\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}{{_source}}\\n================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
(EventID:"13" AND TargetObject.keyword:(HKCR\\\\CLSID\\\\\\{E08A0F4B\\-1F65\\-4D4D\\-9A09\\-BD4625B9C5A1\\}\\\\Model HKU\\\\*_Classes\\\\CLSID\\\\\\{E08A0F4B\\-1F65\\-4D4D\\-9A09\\-BD4625B9C5A1\\}\\\\Model *\\\\SOFTWARE\\\\App\\\\AppXbf13d4ea2945444d8b13e2121cb6b663\\\\Application *\\\\SOFTWARE\\\\App\\\\AppXbf13d4ea2945444d8b13e2121cb6b663\\\\DefaultIcon *\\\\SOFTWARE\\\\App\\\\AppX70162486c7554f7f80f481985d67586d\\\\Application *\\\\SOFTWARE\\\\App\\\\AppX70162486c7554f7f80f481985d67586d\\\\DefaultIcon *\\\\SOFTWARE\\\\App\\\\AppX37cc7fdccd644b4f85f4b22d5a3f105a\\\\Application *\\\\SOFTWARE\\\\App\\\\AppX37cc7fdccd644b4f85f4b22d5a3f105a\\\\DefaultIcon HKU\\\\*_Classes\\\\AppXc52346ec40fb4061ad96be0e6cb7d16a\\\\* HKU\\\\*_Classes\\\\AppX3bbba44c6cae4d9695755183472171e2\\\\* HKU\\\\*_Classes\\\\CLSID\\\\\\{E3517E26\\-8E93\\-458D\\-A6DF\\-8030BC80528B\\}\\\\*))
```


### splunk
    
```
(EventID="13" (TargetObject="HKCR\\\\CLSID\\\\{E08A0F4B-1F65-4D4D-9A09-BD4625B9C5A1}\\\\Model" OR TargetObject="HKU\\\\*_Classes\\\\CLSID\\\\{E08A0F4B-1F65-4D4D-9A09-BD4625B9C5A1}\\\\Model" OR TargetObject="*\\\\SOFTWARE\\\\App\\\\AppXbf13d4ea2945444d8b13e2121cb6b663\\\\Application" OR TargetObject="*\\\\SOFTWARE\\\\App\\\\AppXbf13d4ea2945444d8b13e2121cb6b663\\\\DefaultIcon" OR TargetObject="*\\\\SOFTWARE\\\\App\\\\AppX70162486c7554f7f80f481985d67586d\\\\Application" OR TargetObject="*\\\\SOFTWARE\\\\App\\\\AppX70162486c7554f7f80f481985d67586d\\\\DefaultIcon" OR TargetObject="*\\\\SOFTWARE\\\\App\\\\AppX37cc7fdccd644b4f85f4b22d5a3f105a\\\\Application" OR TargetObject="*\\\\SOFTWARE\\\\App\\\\AppX37cc7fdccd644b4f85f4b22d5a3f105a\\\\DefaultIcon" OR TargetObject="HKU\\\\*_Classes\\\\AppXc52346ec40fb4061ad96be0e6cb7d16a\\\\*" OR TargetObject="HKU\\\\*_Classes\\\\AppX3bbba44c6cae4d9695755183472171e2\\\\*" OR TargetObject="HKU\\\\*_Classes\\\\CLSID\\\\{E3517E26-8E93-458D-A6DF-8030BC80528B}\\\\*"))
```


### logpoint
    
```
(event_id="13" TargetObject IN ["HKCR\\\\CLSID\\\\{E08A0F4B-1F65-4D4D-9A09-BD4625B9C5A1}\\\\Model", "HKU\\\\*_Classes\\\\CLSID\\\\{E08A0F4B-1F65-4D4D-9A09-BD4625B9C5A1}\\\\Model", "*\\\\SOFTWARE\\\\App\\\\AppXbf13d4ea2945444d8b13e2121cb6b663\\\\Application", "*\\\\SOFTWARE\\\\App\\\\AppXbf13d4ea2945444d8b13e2121cb6b663\\\\DefaultIcon", "*\\\\SOFTWARE\\\\App\\\\AppX70162486c7554f7f80f481985d67586d\\\\Application", "*\\\\SOFTWARE\\\\App\\\\AppX70162486c7554f7f80f481985d67586d\\\\DefaultIcon", "*\\\\SOFTWARE\\\\App\\\\AppX37cc7fdccd644b4f85f4b22d5a3f105a\\\\Application", "*\\\\SOFTWARE\\\\App\\\\AppX37cc7fdccd644b4f85f4b22d5a3f105a\\\\DefaultIcon", "HKU\\\\*_Classes\\\\AppXc52346ec40fb4061ad96be0e6cb7d16a\\\\*", "HKU\\\\*_Classes\\\\AppX3bbba44c6cae4d9695755183472171e2\\\\*", "HKU\\\\*_Classes\\\\CLSID\\\\{E3517E26-8E93-458D-A6DF-8030BC80528B}\\\\*"])
```


### grep
    
```
grep -P '^(?:.*(?=.*13)(?=.*(?:.*HKCR\\CLSID\\\\{E08A0F4B-1F65-4D4D-9A09-BD4625B9C5A1\\}\\Model|.*HKU\\\\.*_Classes\\CLSID\\\\{E08A0F4B-1F65-4D4D-9A09-BD4625B9C5A1\\}\\Model|.*.*\\SOFTWARE\\App\\AppXbf13d4ea2945444d8b13e2121cb6b663\\Application|.*.*\\SOFTWARE\\App\\AppXbf13d4ea2945444d8b13e2121cb6b663\\DefaultIcon|.*.*\\SOFTWARE\\App\\AppX70162486c7554f7f80f481985d67586d\\Application|.*.*\\SOFTWARE\\App\\AppX70162486c7554f7f80f481985d67586d\\DefaultIcon|.*.*\\SOFTWARE\\App\\AppX37cc7fdccd644b4f85f4b22d5a3f105a\\Application|.*.*\\SOFTWARE\\App\\AppX37cc7fdccd644b4f85f4b22d5a3f105a\\DefaultIcon|.*HKU\\\\.*_Classes\\AppXc52346ec40fb4061ad96be0e6cb7d16a\\\\.*|.*HKU\\\\.*_Classes\\AppX3bbba44c6cae4d9695755183472171e2\\\\.*|.*HKU\\\\.*_Classes\\CLSID\\\\{E3517E26-8E93-458D-A6DF-8030BC80528B\\}\\\\.*)))'
```



