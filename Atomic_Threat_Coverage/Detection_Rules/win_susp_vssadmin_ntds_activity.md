| Title                | Activity Related to NTDS.dit Domain Hash Retrieval                                                                                                                                                 |
|:---------------------|:------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Description          | Detects suspicious commands that could be related to activity that uses volume shadow copy to steal and retrieve hashes from the NTDS.dit file remotely                                                                                                                                           |
| ATT&amp;CK Tactic    |  <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| ATT&amp;CK Technique | <ul><li>[T1003: Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>  |
| Data Needed          | <ul><li>[DN_0002_4688_windows_process_creation_with_commandline](../Data_Needed/DN_0002_4688_windows_process_creation_with_commandline.md)</li><li>[DN_0003_1_windows_sysmon_process_creation](../Data_Needed/DN_0003_1_windows_sysmon_process_creation.md)</li></ul>  |
| Enrichment           |  Data for this Detection Rule doesn't require any Enrichments.  |
| Trigger              | <ul><li>[T1003: Credential Dumping](../Triggers/T1003.md)</li></ul>  |
| Severity Level       | high |
| False Positives      | <ul><li>Administrative activity</li></ul>  |
| Development Status   | experimental |
| References           | <ul><li>[https://www.swordshield.com/2015/07/getting-hashes-from-ntds-dit-file/](https://www.swordshield.com/2015/07/getting-hashes-from-ntds-dit-file/)</li><li>[https://room362.com/post/2013/2013-06-10-volume-shadow-copy-ntdsdit-domain-hashes-remotely-part-1/](https://room362.com/post/2013/2013-06-10-volume-shadow-copy-ntdsdit-domain-hashes-remotely-part-1/)</li><li>[https://www.trustwave.com/Resources/SpiderLabs-Blog/Tutorial-for-NTDS-goodness-(VSSADMIN,-WMIS,-NTDS-dit,-SYSTEM)/](https://www.trustwave.com/Resources/SpiderLabs-Blog/Tutorial-for-NTDS-goodness-(VSSADMIN,-WMIS,-NTDS-dit,-SYSTEM)/)</li><li>[https://securingtomorrow.mcafee.com/mcafee-labs/new-teslacrypt-ransomware-arrives-via-spam/](https://securingtomorrow.mcafee.com/mcafee-labs/new-teslacrypt-ransomware-arrives-via-spam/)</li><li>[https://dfironthemountain.wordpress.com/2018/12/06/locked-file-access-using-esentutl-exe/](https://dfironthemountain.wordpress.com/2018/12/06/locked-file-access-using-esentutl-exe/)</li></ul>  |
| Author               | Florian Roth, Michael Haag |


## Detection Rules

### Sigma rule

```
title: Activity Related to NTDS.dit Domain Hash Retrieval
id: b932b60f-fdda-4d53-8eda-a170c1d97bbd
status: experimental
description: Detects suspicious commands that could be related to activity that uses volume shadow copy to steal and retrieve hashes from the NTDS.dit file remotely
author: Florian Roth, Michael Haag
references:
    - https://www.swordshield.com/2015/07/getting-hashes-from-ntds-dit-file/
    - https://room362.com/post/2013/2013-06-10-volume-shadow-copy-ntdsdit-domain-hashes-remotely-part-1/
    - https://www.trustwave.com/Resources/SpiderLabs-Blog/Tutorial-for-NTDS-goodness-(VSSADMIN,-WMIS,-NTDS-dit,-SYSTEM)/
    - https://securingtomorrow.mcafee.com/mcafee-labs/new-teslacrypt-ransomware-arrives-via-spam/
    - https://dfironthemountain.wordpress.com/2018/12/06/locked-file-access-using-esentutl-exe/
tags:
    - attack.credential_access
    - attack.t1003
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine:
            - vssadmin.exe Delete Shadows
            - 'vssadmin create shadow /for=C:'
            - copy \\?\GLOBALROOT\Device\\*\windows\ntds\ntds.dit
            - copy \\?\GLOBALROOT\Device\\*\config\SAM
            - 'vssadmin delete shadows /for=C:'
            - 'reg SAVE HKLM\SYSTEM '
            - esentutl.exe /y /vss *\ntds.dit*
    condition: selection
fields:
    - CommandLine
    - ParentCommandLine
falsepositives:
    - Administrative activity
level: high

```





### splunk
    
```
(CommandLine="vssadmin.exe Delete Shadows" OR CommandLine="vssadmin create shadow /for=C:" OR CommandLine="copy \\\\?\\\\GLOBALROOT\\\\Device\\\\*\\\\windows\\\\ntds\\\\ntds.dit" OR CommandLine="copy \\\\?\\\\GLOBALROOT\\\\Device\\\\*\\\\config\\\\SAM" OR CommandLine="vssadmin delete shadows /for=C:" OR CommandLine="reg SAVE HKLM\\\\SYSTEM " OR CommandLine="esentutl.exe /y /vss *\\\\ntds.dit*") | table CommandLine,ParentCommandLine
```



