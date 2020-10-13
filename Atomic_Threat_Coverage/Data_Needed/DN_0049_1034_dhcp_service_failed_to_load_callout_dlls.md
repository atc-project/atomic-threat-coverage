| Title              | DN_0049_1034_dhcp_service_failed_to_load_callout_dlls       |
|:-------------------|:------------------|
| **Description**    | The DHCP service has failed to load one or more callout DLLs |
| **Logging Policy** | <ul><li> Not existing </li></ul> |
| **References**     | <ul><li>[https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc774858(v=ws.10)](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc774858(v=ws.10))</li><li>[https://blog.3or.de/mimilib-dhcp-server-callout-dll-injection.html](https://blog.3or.de/mimilib-dhcp-server-callout-dll-injection.html)</li></ul> |
| **Platform**       | Windows    |
| **Type**           | Windows Log        |
| **Channel**        | System     |
| **Provider**       | Microsoft-Windows-DHCP-Server    |
| **Fields**         | <ul><li>EventID</li><li>Computer</li><li>Hostname</li></ul> |


## Log Samples

### Raw Log

```
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  - <System>
    <Provider Name="Microsoft-Windows-DHCP-Server" Guid="{6D64F02C-A125-4DAC-9A01-F0555B41CA84}" EventSourceName="DhcpServer" /> 
    <EventID Qualifiers="0">1034</EventID> 
    <Version>0</Version> 
    <Level>3</Level> 
    <Task>0</Task> 
    <Opcode>0</Opcode> 
    <Keywords>0x80000000000000</Keywords> 
    <TimeCreated SystemTime="2019-07-11T15:48:53.000000000Z" /> 
    <EventRecordID>551</EventRecordID> 
    <Correlation /> 
    <Execution ProcessID="0" ThreadID="0" /> 
    <Channel>System</Channel> 
    <Computer>atc-win-2k12</Computer> 
    <Security /> 
  </System>
  - <EventData>
    <Data>The specified module could not be found.</Data> 
    <Binary>7E000000</Binary> 
  </EventData>
</Event>
```




