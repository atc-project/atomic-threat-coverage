| Title                 | MP_0001_windows_asr_block_credential_stealing_from_lsass                                                                          |
|:----------------------|:-------------------------------------------------------------------------------------|
| Description           | Attack surface reduction (ASR) rule ID 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2:  "Block credential stealing from the Windows local security authority subsystem  (lsass.exe)" blocks a program when it opens lsass process memory                                                                    |
| Platform              | <ul><li>Windows</li></ul>                   |
| ATT&amp;CK Tactic     | <ul><li>[TA0006: Credential Access](https://attack.mitre.org/tactics/TA0006)</li></ul>  |
| ATT&amp;CK Technique  | <ul><li>[T1003: Credential Dumping](https://attack.mitre.org/techniques/T1003)</li></ul>  |
| ATT&amp;CK Mitigation | <ul><li>[M1043: Credential Access Protection](https://attack.mitre.org/mitigations/M1043)</li></ul>  |
| Mitigation System     | <ul><li>[MS_0001_microsoft_defender_advanced_threat_protection](../Mitigation_Systems/MS_0001_microsoft_defender_advanced_threat_protection.md)</li></ul>  |
| Prerequisites         | <ul><li>Windows 10 versions 1709 or later</li><li>Windows Server version 1803 or later</li><li>Windows 10 Enterprise license</li><li>Windows Defender Antivirus enabled</li></ul>                |
| References            | <ul><li>[https://www.tenforums.com/windows-10-news/115985-interpreting-windows-defender-exploit-guard-asr-audit-alerts.html](https://www.tenforums.com/windows-10-news/115985-interpreting-windows-defender-exploit-guard-asr-audit-alerts.html)</li><li>[https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-exploit-guard/enable-attack-surface-reduction](https://docs.microsoft.com/en-us/windows/security/threat-protection/windows-defender-exploit-guard/enable-attack-surface-reduction)</li></ul>      |


## Configuration

Recommended way is to first enable the rule in audit mode:

```
PS> Add-MpPreference -AttackSurfaceReductionRules_Ids 9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2 -AttackSurfaceReductionRules_Actions AuditMode
```

Then exclude legitimate processes (like `GoogleUpdate.exe` and `taskmgr.exe`) reviewing events generated, then enforce blocking mode:

```
PS> Add-MpPreference -AttackSurfaceReductionRules_Ids 9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2 -AttackSurfaceReductionRules_Actions Enabled
```