| Title                | Executable used by PlugX in Uncommon Location - Sysmon Version                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects the execution of an executable that is typically used by PlugX for DLL side loading started from an uncommon location                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0005: Defense Evasion](https://attack.mitre.org/tactics/TA0005)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1073: DLL Side-Loading](https://attack.mitre.org/techniques/T1073)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li><li>[DN_0001_4688_windows_process_creation](../Data_Needed/DN_0001_4688_windows_process_creation.md)</li></ul>  |
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
id: aeab5ec5-be14-471a-80e8-e344418305c2
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





### splunk
    
```
((((((((((((Image="*\\\\CamMute.exe" NOT (Image="*\\\\Lenovo\\\\Communication Utility\\\\*")) OR (Image="*\\\\chrome_frame_helper.exe" NOT (Image="*\\\\Google\\\\Chrome\\\\application\\\\*"))) OR (Image="*\\\\dvcemumanager.exe" NOT (Image="*\\\\Microsoft Device Emulator\\\\*"))) OR (Image="*\\\\Gadget.exe" NOT (Image="*\\\\Windows Media Player\\\\*"))) OR (Image="*\\\\hcc.exe" NOT (Image="*\\\\HTML Help Workshop\\\\*"))) OR (Image="*\\\\hkcmd.exe" NOT ((Image="*\\\\System32\\\\*" OR Image="*\\\\SysNative\\\\*" OR Image="*\\\\SysWowo64\\\\*")))) OR (Image="*\\\\Mc.exe" NOT ((Image="*\\\\Microsoft Visual Studio*" OR Image="*\\\\Microsoft SDK*" OR Image="*\\\\Windows Kit*")))) OR (Image="*\\\\MsMpEng.exe" NOT ((Image="*\\\\Microsoft Security Client\\\\*" OR Image="*\\\\Windows Defender\\\\*" OR Image="*\\\\AntiMalware\\\\*")))) OR (Image="*\\\\msseces.exe" NOT ((Image="*\\\\Microsoft Security Center\\\\*" OR Image="*\\\\Microsoft Security Client\\\\*" OR Image="*\\\\Microsoft Security Essentials\\\\*")))) OR (Image="*\\\\OInfoP11.exe" NOT (Image="*\\\\Common Files\\\\Microsoft Shared\\\\*"))) OR (Image="*\\\\OleView.exe" NOT ((Image="*\\\\Microsoft Visual Studio*" OR Image="*\\\\Microsoft SDK*" OR Image="*\\\\Windows Kit*" OR Image="*\\\\Windows Resource Kit\\\\*")))) OR (Image="*\\\\rc.exe" NOT ((Image="*\\\\Microsoft Visual Studio*" OR Image="*\\\\Microsoft SDK*" OR Image="*\\\\Windows Kit*" OR Image="*\\\\Windows Resource Kit\\\\*" OR Image="*\\\\Microsoft.NET\\\\*")))) | table CommandLine,ParentCommandLine
```






### Saved Search for Splunk

```
Generated with Sigma2SplunkAlert
[Executable used by PlugX in Uncommon Location - Sysmon Version]
action.email = 1
action.email.subject.alert = Splunk Alert: $name$
action.email.to = test@test.de
action.email.message.alert = Splunk Alert $name$ triggered \
List of interesting fields:  \
CommandLine: $result.CommandLine$ \
ParentCommandLine: $result.ParentCommandLine$  \
title: Executable used by PlugX in Uncommon Location - Sysmon Version status: experimental \
description: Detects the execution of an executable that is typically used by PlugX for DLL side loading started from an uncommon location \
references: ['http://www.hexacorn.com/blog/2016/03/10/beyond-good-ol-run-key-part-36/', 'https://countuponsecurity.com/2017/06/07/threat-hunting-in-the-enterprise-with-appcompatprocessor/'] \
tags: ['attack.s0013', 'attack.defense_evasion', 'attack.t1073'] \
author: Florian Roth \
date:  \
falsepositives: ['Unknown'] \
level: high
action.email.useNSSubject = 1
alert.severity = 1
alert.suppress = 0
alert.track = 1
alert.expires = 24h
counttype = number of events
cron_schedule = */10 * * * *
allow_skew = 50%
schedule_window = auto
description = Detects the execution of an executable that is typically used by PlugX for DLL side loading started from an uncommon location
dispatch.earliest_time = -10m
dispatch.latest_time = now
enableSched = 1
quantity = 0
relation = greater than
request.ui_dispatch_app = sigma_hunting_app
request.ui_dispatch_view = search
search = ((((((((((((Image="*\\CamMute.exe" NOT (Image="*\\Lenovo\\Communication Utility\\*")) OR (Image="*\\chrome_frame_helper.exe" NOT (Image="*\\Google\\Chrome\\application\\*"))) OR (Image="*\\dvcemumanager.exe" NOT (Image="*\\Microsoft Device Emulator\\*"))) OR (Image="*\\Gadget.exe" NOT (Image="*\\Windows Media Player\\*"))) OR (Image="*\\hcc.exe" NOT (Image="*\\HTML Help Workshop\\*"))) OR (Image="*\\hkcmd.exe" NOT ((Image="*\\System32\\*" OR Image="*\\SysNative\\*" OR Image="*\\SysWowo64\\*")))) OR (Image="*\\Mc.exe" NOT ((Image="*\\Microsoft Visual Studio*" OR Image="*\\Microsoft SDK*" OR Image="*\\Windows Kit*")))) OR (Image="*\\MsMpEng.exe" NOT ((Image="*\\Microsoft Security Client\\*" OR Image="*\\Windows Defender\\*" OR Image="*\\AntiMalware\\*")))) OR (Image="*\\msseces.exe" NOT ((Image="*\\Microsoft Security Center\\*" OR Image="*\\Microsoft Security Client\\*" OR Image="*\\Microsoft Security Essentials\\*")))) OR (Image="*\\OInfoP11.exe" NOT (Image="*\\Common Files\\Microsoft Shared\\*"))) OR (Image="*\\OleView.exe" NOT ((Image="*\\Microsoft Visual Studio*" OR Image="*\\Microsoft SDK*" OR Image="*\\Windows Kit*" OR Image="*\\Windows Resource Kit\\*")))) OR (Image="*\\rc.exe" NOT ((Image="*\\Microsoft Visual Studio*" OR Image="*\\Microsoft SDK*" OR Image="*\\Windows Kit*" OR Image="*\\Windows Resource Kit\\*" OR Image="*\\Microsoft.NET\\*")))) | table CommandLine,ParentCommandLine,host | search NOT [| inputlookup Executable_used_by_PlugX_in_Uncommon_Location_-_Sysmon_Version_whitelist.csv] | collect index=threat-hunting marker="sigma_tag=attack.s0013,sigma_tag=attack.defense_evasion,sigma_tag=attack.t1073,level=high"
```
