| Title              | DN_0087_5156_windows_filtering_platform_has_permitted_connection       |
|:-------------------|:------------------|
| **Description**    | The Windows Filtering Platform has permitted a connection |
| **Logging Policy** | <ul><li>[LP_0045_windows_audit_filtering_platform_connection](../Logging_Policies/LP_0045_windows_audit_filtering_platform_connection.md)</li></ul> |
| **References**     | <ul><li>[https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5156](https://docs.microsoft.com/en-us/windows/security/threat-protection/auditing/event-5156)</li></ul> |
| **Platform**       | Windows    |
| **Type**           | Windows Log        |
| **Channel**        | Security     |
| **Provider**       | Microsoft-Windows-Security-Auditing    |
| **Fields**         | <ul><li>EventID</li><li>ComputerName</li><li>Computer</li><li>Hostname</li><li>ProcessID</li><li>Application</li><li>Direction</li><li>SourceAddress</li><li>SourcePort</li><li>DestAddress</li><li>DestPort</li><li>Protocol</li><li>FilterRTID</li><li>LayerName</li><li>LayerRTID</li><li>RemoteUserID</li><li>RemoteMachineID</li></ul> |


## Log Samples

### Raw Log

```
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  - <System>
    <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}" /> 
    <EventID>5156</EventID> 
    <Version>1</Version> 
    <Level>0</Level> 
    <Task>12810</Task> 
    <Opcode>0</Opcode> 
    <Keywords>0x8020000000000000</Keywords> 
    <TimeCreated SystemTime="2019-07-11T23:32:31.307121600Z" /> 
    <EventRecordID>1360</EventRecordID> 
    <Correlation /> 
    <Execution ProcessID="4" ThreadID="288" /> 
    <Channel>Security</Channel> 
    <Computer>atc-win-2k12</Computer> 
    <Security /> 
  </System>
  - <EventData>
    <Data Name="ProcessID">4</Data> 
    <Data Name="Application">System</Data> 
    <Data Name="Direction">%%14593</Data> 
    <Data Name="SourceAddress">fe80::e8a5:2a62:cc49:96cb</Data> 
    <Data Name="SourcePort">143</Data> 
    <Data Name="DestAddress">ff02::16</Data> 
    <Data Name="DestPort">0</Data> 
    <Data Name="Protocol">58</Data> 
    <Data Name="FilterRTID">67456</Data> 
    <Data Name="LayerName">%%14611</Data> 
    <Data Name="LayerRTID">50</Data> 
    <Data Name="RemoteUserID">S-1-0-0</Data> 
    <Data Name="RemoteMachineID">S-1-0-0</Data> 
  </EventData>
</Event>

```




