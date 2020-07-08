| Title              | DN0051_1121_attack_surface_reduction_blocking_mode_event       |
|:-------------------|:------------------|
| **Author**         | @atc_project        |
| **Description**    | Event generated when an attack surface reduction rule fires in block mode |
| **Logging Policy** | <ul><li> Not existing </li></ul> |
| **Mitigation Policy** |<ul><li>[MP_0001_windows_asr_block_credential_stealing_from_lsass](../Mitigation_Policies/MP_0001_windows_asr_block_credential_stealing_from_lsass.md)</li></ul> |
| **References**     | <ul><li>[https://github.com/MicrosoftDocs/windows-itpro-docs/blob/d0a832b119a518a2c6b5f19ffd9dc44f0328c9a6/windows/security/threat-protection/windows-defender-exploit-guard/evaluate-attack-surface-reduction.md](https://github.com/MicrosoftDocs/windows-itpro-docs/blob/d0a832b119a518a2c6b5f19ffd9dc44f0328c9a6/windows/security/threat-protection/windows-defender-exploit-guard/evaluate-attack-surface-reduction.md)</li></ul> |
| **Platform**       | Windows    |
| **Type**           | Applications and Services Logs        |
| **Channel**        | Microsoft-Windows-Windows Defender/Operational     |
| **Provider**       | Microsoft-Windows-Windows Defender    |
| **Fields**         | <ul><li>EventID</li><li>ComputerName</li><li>Computer</li><li>Hostname</li><li>ProductName</li><li>ProductVersion</li><li>Unused</li><li>RuleID</li><li>ASR_RuleID</li><li>DetectionTime</li><li>User</li><li>Path</li><li>ProcessName</li><li>SecurityintelligenceVersion</li><li>EngineVersion</li></ul> |


## Log Samples

### Raw Log

```
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  - <System>
    <Provider Name="Microsoft-Windows-Windows Defender" Guid="{11cd958a-c507-4ef3-b3f2-5fd9dfbd2c78}" /> 
    <EventID>1121</EventID> 
    <Version>0</Version> 
    <Level>3</Level> 
    <Task>0</Task> 
    <Opcode>0</Opcode> 
    <Keywords>0x8000000000000000</Keywords> 
    <TimeCreated SystemTime="2019-07-29T12:13:55.890328700Z" /> 
    <EventRecordID>66</EventRecordID> 
    <Correlation /> 
    <Execution ProcessID="2896" ThreadID="6928" /> 
    <Channel>Microsoft-Windows-Windows Defender/Operational</Channel> 
    <Computer>ATC-WIN-10</Computer> 
    <Security UserID="S-1-5-18" /> 
  </System>
  - <EventData>
    <Data Name="Product Name">%%827</Data> 
    <Data Name="Product Version">4.18.1907.4</Data> 
    <Data Name="Unused" /> 
    <Data Name="ID">9E6C4E1F-7D60-472F-BA1A-A39EF669E4B2</Data> 
    <Data Name="Detection Time">2019-07-29T12:13:55.890Z</Data> 
    <Data Name="User">ATC-WIN-10\yugoslavskiy</Data> 
    <Data Name="Path">C:\Windows\System32\lsass.exe</Data> 
    <Data Name="Process Name">C:\Program Files (x86)\GUM7534.tmp\GoogleUpdate.exe</Data> 
    <Data Name="Security intelligence Version">1.299.756.0</Data> 
    <Data Name="Engine Version">1.1.16200.1</Data> 
  </EventData>
</Event>

```




