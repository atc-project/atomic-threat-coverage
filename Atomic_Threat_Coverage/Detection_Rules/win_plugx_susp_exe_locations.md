| Title                | Executable used by PlugX in Uncommon Location - Sysmon Version                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects the execution of an executable that is typically used by PlugX for DLL side loading started from an uncommon location                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1073: DLL Side-Loading](https://attack.mitre.org/techniques/T1073)</li></ul>  |
| Data Needed          | <ul><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0001_4688_windows_process_creation](../Data_Needed/DN_0001_4688_windows_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1073: DLL Side-Loading](../Triggers/T1073.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Unknown</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[http://www.hexacorn.com/blog/2016/03/10/beyond-good-ol-run-key-part-36/](http://www.hexacorn.com/blog/2016/03/10/beyond-good-ol-run-key-part-36/)</li><li>[https://countuponsecurity.com/2017/06/07/threat-hunting-in-the-enterprise-with-appcompatprocessor/](https://countuponsecurity.com/2017/06/07/threat-hunting-in-the-enterprise-with-appcompatprocessor/)</li></ul>  |
| Author               | Florian Roth |
| Other Tags           | <ul><li>attack.s0013</li><li>attack.s0013</li></ul> | 

## Detection Rules

### Sigma rule

```
title: Executable used by PlugX in Uncommon Location - Sysmon Version
status: experimental
description: Detects the execution of an executable that is typically used by PlugX for DLL side loading started from an uncommon location
references:
    - http://www.hexacorn.com/blog/2016/03/10/beyond-good-ol-run-key-part-36/
    - https://countuponsecurity.com/2017/06/07/threat-hunting-in-the-enterprise-with-appcompatprocessor/
author: Florian Roth
date: 2017/06/12
tags:
    - attack.s0013
    - attack.defense_evasion
    - attack.t1073
logsource:
    category: process_creation
    product: windows
detection:
    selection_cammute:
        Image: '*\CamMute.exe'
    filter_cammute:
        Image: '*\Lenovo\Communication Utility\\*'
    selection_chrome_frame:
        Image: '*\chrome_frame_helper.exe'
    filter_chrome_frame:
        Image: '*\Google\Chrome\application\\*'
    selection_devemu:
        Image: '*\dvcemumanager.exe'
    filter_devemu:
        Image: '*\Microsoft Device Emulator\\*'
    selection_gadget:
        Image: '*\Gadget.exe'
    filter_gadget:
        Image: '*\Windows Media Player\\*'
    selection_hcc:
        Image: '*\hcc.exe'
    filter_hcc:
        Image: '*\HTML Help Workshop\\*'
    selection_hkcmd:
        Image: '*\hkcmd.exe'
    filter_hkcmd:
        Image:
            - '*\System32\\*'
            - '*\SysNative\\*'
            - '*\SysWowo64\\*'
    selection_mc:
        Image: '*\Mc.exe'
    filter_mc:
        Image:
            - '*\Microsoft Visual Studio*'
            - '*\Microsoft SDK*'
            - '*\Windows Kit*'
    selection_msmpeng:
        Image: '*\MsMpEng.exe'
    filter_msmpeng:
        Image:
            - '*\Microsoft Security Client\\*'
            - '*\Windows Defender\\*'
            - '*\AntiMalware\\*'
    selection_msseces:
        Image: '*\msseces.exe'
    filter_msseces:
        Image: 
            - '*\Microsoft Security Center\\*'
            - '*\Microsoft Security Client\\*'
            - '*\Microsoft Security Essentials\\*'
    selection_oinfo:
        Image: '*\OInfoP11.exe'
    filter_oinfo:
        Image: '*\Common Files\Microsoft Shared\\*'
    selection_oleview:
        Image: '*\OleView.exe'
    filter_oleview:
        Image:
            - '*\Microsoft Visual Studio*'
            - '*\Microsoft SDK*'
            - '*\Windows Kit*'
            - '*\Windows Resource Kit\\*'
    selection_rc:
        Image: '*\rc.exe'
    filter_rc:
        Image:
            - '*\Microsoft Visual Studio*'
            - '*\Microsoft SDK*'
            - '*\Windows Kit*'
            - '*\Windows Resource Kit\\*'
            - '*\Microsoft.NET\\*'
    condition: ( selection_cammute and not filter_cammute ) or ( selection_chrome_frame and not filter_chrome_frame ) or ( selection_devemu and not filter_devemu )
        or ( selection_gadget and not filter_gadget ) or ( selection_hcc and not filter_hcc ) or ( selection_hkcmd and not filter_hkcmd ) or ( selection_mc and not filter_mc
        ) or ( selection_msmpeng and not filter_msmpeng ) or ( selection_msseces and not filter_msseces ) or ( selection_oinfo and not filter_oinfo ) or ( selection_oleview
        and not filter_oleview ) or ( selection_rc and not filter_rc )
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Unknown
level: high

```





### es-qs
    
```
((((((((((((Image.keyword:*\\\\CamMute.exe AND (NOT (Image.keyword:*\\\\Lenovo\\\\Communication\\ Utility\\\\*))) OR (Image.keyword:*\\\\chrome_frame_helper.exe AND (NOT (Image.keyword:*\\\\Google\\\\Chrome\\\\application\\\\*)))) OR (Image.keyword:*\\\\dvcemumanager.exe AND (NOT (Image.keyword:*\\\\Microsoft\\ Device\\ Emulator\\\\*)))) OR (Image.keyword:*\\\\Gadget.exe AND (NOT (Image.keyword:*\\\\Windows\\ Media\\ Player\\\\*)))) OR (Image.keyword:*\\\\hcc.exe AND (NOT (Image.keyword:*\\\\HTML\\ Help\\ Workshop\\\\*)))) OR (Image.keyword:*\\\\hkcmd.exe AND (NOT (Image.keyword:(*\\\\System32\\\\* *\\\\SysNative\\\\* *\\\\SysWowo64\\\\*))))) OR (Image.keyword:*\\\\Mc.exe AND (NOT (Image.keyword:(*\\\\Microsoft\\ Visual\\ Studio* *\\\\Microsoft\\ SDK* *\\\\Windows\\ Kit*))))) OR (Image.keyword:*\\\\MsMpEng.exe AND (NOT (Image.keyword:(*\\\\Microsoft\\ Security\\ Client\\\\* *\\\\Windows\\ Defender\\\\* *\\\\AntiMalware\\\\*))))) OR (Image.keyword:*\\\\msseces.exe AND (NOT (Image.keyword:(*\\\\Microsoft\\ Security\\ Center\\\\* *\\\\Microsoft\\ Security\\ Client\\\\* *\\\\Microsoft\\ Security\\ Essentials\\\\*))))) OR (Image.keyword:*\\\\OInfoP11.exe AND (NOT (Image.keyword:*\\\\Common\\ Files\\\\Microsoft\\ Shared\\\\*)))) OR (Image.keyword:*\\\\OleView.exe AND (NOT (Image.keyword:(*\\\\Microsoft\\ Visual\\ Studio* *\\\\Microsoft\\ SDK* *\\\\Windows\\ Kit* *\\\\Windows\\ Resource\\ Kit\\\\*))))) OR (Image.keyword:*\\\\rc.exe AND (NOT (Image.keyword:(*\\\\Microsoft\\ Visual\\ Studio* *\\\\Microsoft\\ SDK* *\\\\Windows\\ Kit* *\\\\Windows\\ Resource\\ Kit\\\\* *\\\\Microsoft.NET\\\\*)))))
```


### xpack-watcher
    
```
curl -s -XPUT -H \'Content-Type: application/json\' --data-binary @- localhost:9200/_watcher/watch/Executable-used-by-PlugX-in-Uncommon-Location---Sysmon-Version <<EOF\n{\n  "metadata": {\n    "title": "Executable used by PlugX in Uncommon Location - Sysmon Version",\n    "description": "Detects the execution of an executable that is typically used by PlugX for DLL side loading started from an uncommon location",\n    "tags": [\n      "attack.s0013",\n      "attack.defense_evasion",\n      "attack.t1073"\n    ],\n    "query": "((((((((((((Image.keyword:*\\\\\\\\CamMute.exe AND (NOT (Image.keyword:*\\\\\\\\Lenovo\\\\\\\\Communication\\\\ Utility\\\\\\\\*))) OR (Image.keyword:*\\\\\\\\chrome_frame_helper.exe AND (NOT (Image.keyword:*\\\\\\\\Google\\\\\\\\Chrome\\\\\\\\application\\\\\\\\*)))) OR (Image.keyword:*\\\\\\\\dvcemumanager.exe AND (NOT (Image.keyword:*\\\\\\\\Microsoft\\\\ Device\\\\ Emulator\\\\\\\\*)))) OR (Image.keyword:*\\\\\\\\Gadget.exe AND (NOT (Image.keyword:*\\\\\\\\Windows\\\\ Media\\\\ Player\\\\\\\\*)))) OR (Image.keyword:*\\\\\\\\hcc.exe AND (NOT (Image.keyword:*\\\\\\\\HTML\\\\ Help\\\\ Workshop\\\\\\\\*)))) OR (Image.keyword:*\\\\\\\\hkcmd.exe AND (NOT (Image.keyword:(*\\\\\\\\System32\\\\\\\\* *\\\\\\\\SysNative\\\\\\\\* *\\\\\\\\SysWowo64\\\\\\\\*))))) OR (Image.keyword:*\\\\\\\\Mc.exe AND (NOT (Image.keyword:(*\\\\\\\\Microsoft\\\\ Visual\\\\ Studio* *\\\\\\\\Microsoft\\\\ SDK* *\\\\\\\\Windows\\\\ Kit*))))) OR (Image.keyword:*\\\\\\\\MsMpEng.exe AND (NOT (Image.keyword:(*\\\\\\\\Microsoft\\\\ Security\\\\ Client\\\\\\\\* *\\\\\\\\Windows\\\\ Defender\\\\\\\\* *\\\\\\\\AntiMalware\\\\\\\\*))))) OR (Image.keyword:*\\\\\\\\msseces.exe AND (NOT (Image.keyword:(*\\\\\\\\Microsoft\\\\ Security\\\\ Center\\\\\\\\* *\\\\\\\\Microsoft\\\\ Security\\\\ Client\\\\\\\\* *\\\\\\\\Microsoft\\\\ Security\\\\ Essentials\\\\\\\\*))))) OR (Image.keyword:*\\\\\\\\OInfoP11.exe AND (NOT (Image.keyword:*\\\\\\\\Common\\\\ Files\\\\\\\\Microsoft\\\\ Shared\\\\\\\\*)))) OR (Image.keyword:*\\\\\\\\OleView.exe AND (NOT (Image.keyword:(*\\\\\\\\Microsoft\\\\ Visual\\\\ Studio* *\\\\\\\\Microsoft\\\\ SDK* *\\\\\\\\Windows\\\\ Kit* *\\\\\\\\Windows\\\\ Resource\\\\ Kit\\\\\\\\*))))) OR (Image.keyword:*\\\\\\\\rc.exe AND (NOT (Image.keyword:(*\\\\\\\\Microsoft\\\\ Visual\\\\ Studio* *\\\\\\\\Microsoft\\\\ SDK* *\\\\\\\\Windows\\\\ Kit* *\\\\\\\\Windows\\\\ Resource\\\\ Kit\\\\\\\\* *\\\\\\\\Microsoft.NET\\\\\\\\*)))))"\n  },\n  "trigger": {\n    "schedule": {\n      "interval": "30m"\n    }\n  },\n  "input": {\n    "search": {\n      "request": {\n        "body": {\n          "size": 0,\n          "query": {\n            "bool": {\n              "must": [\n                {\n                  "query_string": {\n                    "query": "((((((((((((Image.keyword:*\\\\\\\\CamMute.exe AND (NOT (Image.keyword:*\\\\\\\\Lenovo\\\\\\\\Communication\\\\ Utility\\\\\\\\*))) OR (Image.keyword:*\\\\\\\\chrome_frame_helper.exe AND (NOT (Image.keyword:*\\\\\\\\Google\\\\\\\\Chrome\\\\\\\\application\\\\\\\\*)))) OR (Image.keyword:*\\\\\\\\dvcemumanager.exe AND (NOT (Image.keyword:*\\\\\\\\Microsoft\\\\ Device\\\\ Emulator\\\\\\\\*)))) OR (Image.keyword:*\\\\\\\\Gadget.exe AND (NOT (Image.keyword:*\\\\\\\\Windows\\\\ Media\\\\ Player\\\\\\\\*)))) OR (Image.keyword:*\\\\\\\\hcc.exe AND (NOT (Image.keyword:*\\\\\\\\HTML\\\\ Help\\\\ Workshop\\\\\\\\*)))) OR (Image.keyword:*\\\\\\\\hkcmd.exe AND (NOT (Image.keyword:(*\\\\\\\\System32\\\\\\\\* *\\\\\\\\SysNative\\\\\\\\* *\\\\\\\\SysWowo64\\\\\\\\*))))) OR (Image.keyword:*\\\\\\\\Mc.exe AND (NOT (Image.keyword:(*\\\\\\\\Microsoft\\\\ Visual\\\\ Studio* *\\\\\\\\Microsoft\\\\ SDK* *\\\\\\\\Windows\\\\ Kit*))))) OR (Image.keyword:*\\\\\\\\MsMpEng.exe AND (NOT (Image.keyword:(*\\\\\\\\Microsoft\\\\ Security\\\\ Client\\\\\\\\* *\\\\\\\\Windows\\\\ Defender\\\\\\\\* *\\\\\\\\AntiMalware\\\\\\\\*))))) OR (Image.keyword:*\\\\\\\\msseces.exe AND (NOT (Image.keyword:(*\\\\\\\\Microsoft\\\\ Security\\\\ Center\\\\\\\\* *\\\\\\\\Microsoft\\\\ Security\\\\ Client\\\\\\\\* *\\\\\\\\Microsoft\\\\ Security\\\\ Essentials\\\\\\\\*))))) OR (Image.keyword:*\\\\\\\\OInfoP11.exe AND (NOT (Image.keyword:*\\\\\\\\Common\\\\ Files\\\\\\\\Microsoft\\\\ Shared\\\\\\\\*)))) OR (Image.keyword:*\\\\\\\\OleView.exe AND (NOT (Image.keyword:(*\\\\\\\\Microsoft\\\\ Visual\\\\ Studio* *\\\\\\\\Microsoft\\\\ SDK* *\\\\\\\\Windows\\\\ Kit* *\\\\\\\\Windows\\\\ Resource\\\\ Kit\\\\\\\\*))))) OR (Image.keyword:*\\\\\\\\rc.exe AND (NOT (Image.keyword:(*\\\\\\\\Microsoft\\\\ Visual\\\\ Studio* *\\\\\\\\Microsoft\\\\ SDK* *\\\\\\\\Windows\\\\ Kit* *\\\\\\\\Windows\\\\ Resource\\\\ Kit\\\\\\\\* *\\\\\\\\Microsoft.NET\\\\\\\\*)))))",\n                    "analyze_wildcard": true\n                  }\n                }\n              ],\n              "filter": {\n                "range": {\n                  "timestamp": {\n                    "gte": "now-30m/m"\n                  }\n                }\n              }\n            }\n          }\n        },\n        "indices": []\n      }\n    }\n  },\n  "condition": {\n    "compare": {\n      "ctx.payload.hits.total": {\n        "not_eq": 0\n      }\n    }\n  },\n  "actions": {\n    "send_email": {\n      "email": {\n        "to": "root@localhost",\n        "subject": "Sigma Rule \'Executable used by PlugX in Uncommon Location - Sysmon Version\'",\n        "body": "Hits:\\n{{#ctx.payload.hits.hits}}Hit on {{_source.@timestamp}}:\\n      CommandLine = {{_source.CommandLine}}\\nParentCommandLine = {{_source.ParentCommandLine}}================================================================================\\n{{/ctx.payload.hits.hits}}",\n        "attachments": {\n          "data.json": {\n            "data": {\n              "format": "json"\n            }\n          }\n        }\n      }\n    }\n  }\n}\nEOF\n
```


### graylog
    
```
((((((((((((Image:"*\\\\CamMute.exe" AND NOT (Image:"*\\\\Lenovo\\\\Communication Utility\\\\*")) OR (Image:"*\\\\chrome_frame_helper.exe" AND NOT (Image:"*\\\\Google\\\\Chrome\\\\application\\\\*"))) OR (Image:"*\\\\dvcemumanager.exe" AND NOT (Image:"*\\\\Microsoft Device Emulator\\\\*"))) OR (Image:"*\\\\Gadget.exe" AND NOT (Image:"*\\\\Windows Media Player\\\\*"))) OR (Image:"*\\\\hcc.exe" AND NOT (Image:"*\\\\HTML Help Workshop\\\\*"))) OR (Image:"*\\\\hkcmd.exe" AND NOT (Image:("*\\\\System32\\\\*" "*\\\\SysNative\\\\*" "*\\\\SysWowo64\\\\*")))) OR (Image:"*\\\\Mc.exe" AND NOT (Image:("*\\\\Microsoft Visual Studio*" "*\\\\Microsoft SDK*" "*\\\\Windows Kit*")))) OR (Image:"*\\\\MsMpEng.exe" AND NOT (Image:("*\\\\Microsoft Security Client\\\\*" "*\\\\Windows Defender\\\\*" "*\\\\AntiMalware\\\\*")))) OR (Image:"*\\\\msseces.exe" AND NOT (Image:("*\\\\Microsoft Security Center\\\\*" "*\\\\Microsoft Security Client\\\\*" "*\\\\Microsoft Security Essentials\\\\*")))) OR (Image:"*\\\\OInfoP11.exe" AND NOT (Image:"*\\\\Common Files\\\\Microsoft Shared\\\\*"))) OR (Image:"*\\\\OleView.exe" AND NOT (Image:("*\\\\Microsoft Visual Studio*" "*\\\\Microsoft SDK*" "*\\\\Windows Kit*" "*\\\\Windows Resource Kit\\\\*")))) OR (Image:"*\\\\rc.exe" AND NOT (Image:("*\\\\Microsoft Visual Studio*" "*\\\\Microsoft SDK*" "*\\\\Windows Kit*" "*\\\\Windows Resource Kit\\\\*" "*\\\\Microsoft.NET\\\\*"))))
```


### splunk
    
```
((((((((((((Image="*\\\\CamMute.exe" NOT (Image="*\\\\Lenovo\\\\Communication Utility\\\\*")) OR (Image="*\\\\chrome_frame_helper.exe" NOT (Image="*\\\\Google\\\\Chrome\\\\application\\\\*"))) OR (Image="*\\\\dvcemumanager.exe" NOT (Image="*\\\\Microsoft Device Emulator\\\\*"))) OR (Image="*\\\\Gadget.exe" NOT (Image="*\\\\Windows Media Player\\\\*"))) OR (Image="*\\\\hcc.exe" NOT (Image="*\\\\HTML Help Workshop\\\\*"))) OR (Image="*\\\\hkcmd.exe" NOT ((Image="*\\\\System32\\\\*" OR Image="*\\\\SysNative\\\\*" OR Image="*\\\\SysWowo64\\\\*")))) OR (Image="*\\\\Mc.exe" NOT ((Image="*\\\\Microsoft Visual Studio*" OR Image="*\\\\Microsoft SDK*" OR Image="*\\\\Windows Kit*")))) OR (Image="*\\\\MsMpEng.exe" NOT ((Image="*\\\\Microsoft Security Client\\\\*" OR Image="*\\\\Windows Defender\\\\*" OR Image="*\\\\AntiMalware\\\\*")))) OR (Image="*\\\\msseces.exe" NOT ((Image="*\\\\Microsoft Security Center\\\\*" OR Image="*\\\\Microsoft Security Client\\\\*" OR Image="*\\\\Microsoft Security Essentials\\\\*")))) OR (Image="*\\\\OInfoP11.exe" NOT (Image="*\\\\Common Files\\\\Microsoft Shared\\\\*"))) OR (Image="*\\\\OleView.exe" NOT ((Image="*\\\\Microsoft Visual Studio*" OR Image="*\\\\Microsoft SDK*" OR Image="*\\\\Windows Kit*" OR Image="*\\\\Windows Resource Kit\\\\*")))) OR (Image="*\\\\rc.exe" NOT ((Image="*\\\\Microsoft Visual Studio*" OR Image="*\\\\Microsoft SDK*" OR Image="*\\\\Windows Kit*" OR Image="*\\\\Windows Resource Kit\\\\*" OR Image="*\\\\Microsoft.NET\\\\*")))) | table CommandLine,ParentCommandLine
```


### logpoint
    
```
((((((((((((Image="*\\\\CamMute.exe"  -(Image="*\\\\Lenovo\\\\Communication Utility\\\\*")) OR (Image="*\\\\chrome_frame_helper.exe"  -(Image="*\\\\Google\\\\Chrome\\\\application\\\\*"))) OR (Image="*\\\\dvcemumanager.exe"  -(Image="*\\\\Microsoft Device Emulator\\\\*"))) OR (Image="*\\\\Gadget.exe"  -(Image="*\\\\Windows Media Player\\\\*"))) OR (Image="*\\\\hcc.exe"  -(Image="*\\\\HTML Help Workshop\\\\*"))) OR (Image="*\\\\hkcmd.exe"  -(Image IN ["*\\\\System32\\\\*", "*\\\\SysNative\\\\*", "*\\\\SysWowo64\\\\*"]))) OR (Image="*\\\\Mc.exe"  -(Image IN ["*\\\\Microsoft Visual Studio*", "*\\\\Microsoft SDK*", "*\\\\Windows Kit*"]))) OR (Image="*\\\\MsMpEng.exe"  -(Image IN ["*\\\\Microsoft Security Client\\\\*", "*\\\\Windows Defender\\\\*", "*\\\\AntiMalware\\\\*"]))) OR (Image="*\\\\msseces.exe"  -(Image IN ["*\\\\Microsoft Security Center\\\\*", "*\\\\Microsoft Security Client\\\\*", "*\\\\Microsoft Security Essentials\\\\*"]))) OR (Image="*\\\\OInfoP11.exe"  -(Image="*\\\\Common Files\\\\Microsoft Shared\\\\*"))) OR (Image="*\\\\OleView.exe"  -(Image IN ["*\\\\Microsoft Visual Studio*", "*\\\\Microsoft SDK*", "*\\\\Windows Kit*", "*\\\\Windows Resource Kit\\\\*"]))) OR (Image="*\\\\rc.exe"  -(Image IN ["*\\\\Microsoft Visual Studio*", "*\\\\Microsoft SDK*", "*\\\\Windows Kit*", "*\\\\Windows Resource Kit\\\\*", "*\\\\Microsoft.NET\\\\*"])))
```


### grep
    
```
grep -P '^(?:.*(?:.*(?:.*(?:.*(?:.*(?:.*(?:.*(?:.*(?:.*(?:.*(?:.*(?:.*(?:.*(?:.*(?:.*(?:.*(?:.*(?:.*(?:.*(?:.*(?:.*(?:.*(?:.*(?=.*.*\\CamMute\\.exe)(?=.*(?!.*(?:.*(?=.*.*\\Lenovo\\Communication Utility\\\\.*)))))|.*(?:.*(?=.*.*\\chrome_frame_helper\\.exe)(?=.*(?!.*(?:.*(?=.*.*\\Google\\Chrome\\application\\\\.*)))))))|.*(?:.*(?=.*.*\\dvcemumanager\\.exe)(?=.*(?!.*(?:.*(?=.*.*\\Microsoft Device Emulator\\\\.*)))))))|.*(?:.*(?=.*.*\\Gadget\\.exe)(?=.*(?!.*(?:.*(?=.*.*\\Windows Media Player\\\\.*)))))))|.*(?:.*(?=.*.*\\hcc\\.exe)(?=.*(?!.*(?:.*(?=.*.*\\HTML Help Workshop\\\\.*)))))))|.*(?:.*(?=.*.*\\hkcmd\\.exe)(?=.*(?!.*(?:.*(?=.*(?:.*.*\\System32\\\\.*|.*.*\\SysNative\\\\.*|.*.*\\SysWowo64\\\\.*))))))))|.*(?:.*(?=.*.*\\Mc\\.exe)(?=.*(?!.*(?:.*(?=.*(?:.*.*\\Microsoft Visual Studio.*|.*.*\\Microsoft SDK.*|.*.*\\Windows Kit.*))))))))|.*(?:.*(?=.*.*\\MsMpEng\\.exe)(?=.*(?!.*(?:.*(?=.*(?:.*.*\\Microsoft Security Client\\\\.*|.*.*\\Windows Defender\\\\.*|.*.*\\AntiMalware\\\\.*))))))))|.*(?:.*(?=.*.*\\msseces\\.exe)(?=.*(?!.*(?:.*(?=.*(?:.*.*\\Microsoft Security Center\\\\.*|.*.*\\Microsoft Security Client\\\\.*|.*.*\\Microsoft Security Essentials\\\\.*))))))))|.*(?:.*(?=.*.*\\OInfoP11\\.exe)(?=.*(?!.*(?:.*(?=.*.*\\Common Files\\Microsoft Shared\\\\.*)))))))|.*(?:.*(?=.*.*\\OleView\\.exe)(?=.*(?!.*(?:.*(?=.*(?:.*.*\\Microsoft Visual Studio.*|.*.*\\Microsoft SDK.*|.*.*\\Windows Kit.*|.*.*\\Windows Resource Kit\\\\.*))))))))|.*(?:.*(?=.*.*\\rc\\.exe)(?=.*(?!.*(?:.*(?=.*(?:.*.*\\Microsoft Visual Studio.*|.*.*\\Microsoft SDK.*|.*.*\\Windows Kit.*|.*.*\\Windows Resource Kit\\\\.*|.*.*\\Microsoft\\.NET\\\\.*))))))))'
```



