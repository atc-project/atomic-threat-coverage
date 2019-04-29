| Title                | Executable used by PlugX in Uncommon Location - Sysmon Version                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects the execution of an executable that is typically used by PlugX for DLL side loading started from an uncommon location                                                                                                                                           |
| ATT&amp;CK Tactic    | <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1073: DLL Side-Loading](https://attack.mitre.org/techniques/T1073)</li></ul>                             |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0001_4688_windows_process_creation](../Data_Needed/DN_0001_4688_windows_process_creation.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>                                                         |
| Trigger              | <ul><li>[T1073: DLL Side-Loading](../Triggers/T1073.md)</li></ul>  |
| Severity Level       | high                                                                                                                                                 |
| False Positives      | <ul><li>Unknown</li></ul>                                                                  |
| Development Status   | experimental                                                                                                                                                |
| References           | <ul><li>[http://www.hexacorn.com/blog/2016/03/10/beyond-good-ol-run-key-part-36/](http://www.hexacorn.com/blog/2016/03/10/beyond-good-ol-run-key-part-36/)</li><li>[https://countuponsecurity.com/2017/06/07/threat-hunting-in-the-enterprise-with-appcompatprocessor/](https://countuponsecurity.com/2017/06/07/threat-hunting-in-the-enterprise-with-appcompatprocessor/)</li></ul>                                                          |
| Author               | Florian Roth                                                                                                                                                |
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

```


### xpack-watcher
    
```

```


### graylog
    
```
((((((((((((Image:"*\\\\CamMute.exe" AND NOT (Image:"*\\\\Lenovo\\\\Communication Utility\\\\*")) OR (Image:"*\\\\chrome_frame_helper.exe" AND NOT (Image:"*\\\\Google\\\\Chrome\\\\application\\\\*"))) OR (Image:"*\\\\dvcemumanager.exe" AND NOT (Image:"*\\\\Microsoft Device Emulator\\\\*"))) OR (Image:"*\\\\Gadget.exe" AND NOT (Image:"*\\\\Windows Media Player\\\\*"))) OR (Image:"*\\\\hcc.exe" AND NOT (Image:"*\\\\HTML Help Workshop\\\\*"))) OR (Image:"*\\\\hkcmd.exe" AND NOT (Image:("*\\\\System32\\\\*" "*\\\\SysNative\\\\*" "*\\\\SysWowo64\\\\*")))) OR (Image:"*\\\\Mc.exe" AND NOT (Image:("*\\\\Microsoft Visual Studio*" "*\\\\Microsoft SDK*" "*\\\\Windows Kit*")))) OR (Image:"*\\\\MsMpEng.exe" AND NOT (Image:("*\\\\Microsoft Security Client\\\\*" "*\\\\Windows Defender\\\\*" "*\\\\AntiMalware\\\\*")))) OR (Image:"*\\\\msseces.exe" AND NOT (Image:("*\\\\Microsoft Security Center\\\\*" "*\\\\Microsoft Security Client\\\\*" "*\\\\Microsoft Security Essentials\\\\*")))) OR (Image:"*\\\\OInfoP11.exe" AND NOT (Image:"*\\\\Common Files\\\\Microsoft Shared\\\\*"))) OR (Image:"*\\\\OleView.exe" AND NOT (Image:("*\\\\Microsoft Visual Studio*" "*\\\\Microsoft SDK*" "*\\\\Windows Kit*" "*\\\\Windows Resource Kit\\\\*")))) OR (Image:"*\\\\rc.exe" AND NOT (Image:("*\\\\Microsoft Visual Studio*" "*\\\\Microsoft SDK*" "*\\\\Windows Kit*" "*\\\\Windows Resource Kit\\\\*" "*\\\\Microsoft.NET\\\\*"))))
```


### splunk
    
```

```


### logpoint
    
```

```


### grep
    
```
grep -P '^(?:.*(?:.*(?:.*(?:.*(?:.*(?:.*(?:.*(?:.*(?:.*(?:.*(?:.*(?:.*(?:.*(?:.*(?:.*(?:.*(?:.*(?:.*(?:.*(?:.*(?:.*(?:.*(?:.*(?=.*.*\\CamMute\\.exe)(?=.*(?!.*(?:.*(?=.*.*\\Lenovo\\Communication Utility\\\\.*)))))|.*(?:.*(?=.*.*\\chrome_frame_helper\\.exe)(?=.*(?!.*(?:.*(?=.*.*\\Google\\Chrome\\application\\\\.*)))))))|.*(?:.*(?=.*.*\\dvcemumanager\\.exe)(?=.*(?!.*(?:.*(?=.*.*\\Microsoft Device Emulator\\\\.*)))))))|.*(?:.*(?=.*.*\\Gadget\\.exe)(?=.*(?!.*(?:.*(?=.*.*\\Windows Media Player\\\\.*)))))))|.*(?:.*(?=.*.*\\hcc\\.exe)(?=.*(?!.*(?:.*(?=.*.*\\HTML Help Workshop\\\\.*)))))))|.*(?:.*(?=.*.*\\hkcmd\\.exe)(?=.*(?!.*(?:.*(?=.*(?:.*.*\\System32\\\\.*|.*.*\\SysNative\\\\.*|.*.*\\SysWowo64\\\\.*))))))))|.*(?:.*(?=.*.*\\Mc\\.exe)(?=.*(?!.*(?:.*(?=.*(?:.*.*\\Microsoft Visual Studio.*|.*.*\\Microsoft SDK.*|.*.*\\Windows Kit.*))))))))|.*(?:.*(?=.*.*\\MsMpEng\\.exe)(?=.*(?!.*(?:.*(?=.*(?:.*.*\\Microsoft Security Client\\\\.*|.*.*\\Windows Defender\\\\.*|.*.*\\AntiMalware\\\\.*))))))))|.*(?:.*(?=.*.*\\msseces\\.exe)(?=.*(?!.*(?:.*(?=.*(?:.*.*\\Microsoft Security Center\\\\.*|.*.*\\Microsoft Security Client\\\\.*|.*.*\\Microsoft Security Essentials\\\\.*))))))))|.*(?:.*(?=.*.*\\OInfoP11\\.exe)(?=.*(?!.*(?:.*(?=.*.*\\Common Files\\Microsoft Shared\\\\.*)))))))|.*(?:.*(?=.*.*\\OleView\\.exe)(?=.*(?!.*(?:.*(?=.*(?:.*.*\\Microsoft Visual Studio.*|.*.*\\Microsoft SDK.*|.*.*\\Windows Kit.*|.*.*\\Windows Resource Kit\\\\.*))))))))|.*(?:.*(?=.*.*\\rc\\.exe)(?=.*(?!.*(?:.*(?=.*(?:.*.*\\Microsoft Visual Studio.*|.*.*\\Microsoft SDK.*|.*.*\\Windows Kit.*|.*.*\\Windows Resource Kit\\\\.*|.*.*\\Microsoft\\.NET\\\\.*))))))))'
```



