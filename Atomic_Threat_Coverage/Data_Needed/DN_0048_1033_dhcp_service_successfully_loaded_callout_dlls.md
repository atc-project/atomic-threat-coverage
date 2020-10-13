| Title              | DN_0048_1033_dhcp_service_successfully_loaded_callout_dlls       |
|:-------------------|:------------------|
| **Description**    | The DHCP service has successfully loaded one or more callout DLLs |
| **Logging Policy** | <ul><li> Not existing </li></ul> |
| **References**     | <ul><li>[https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc726937(v%3dws.10)](https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc726937(v%3dws.10))</li><li>[https://blog.3or.de/mimilib-dhcp-server-callout-dll-injection.html](https://blog.3or.de/mimilib-dhcp-server-callout-dll-injection.html)</li></ul> |
| **Platform**       | Windows    |
| **Type**           | Applications and Services Logs        |
| **Channel**        | System     |
| **Provider**       | Microsoft-Windows-DHCP-Server    |
| **Fields**         | <ul><li>EventID</li><li>Computer</li><li>Hostname</li></ul> |


## Log Samples

### Raw Log

```
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  - <System>
    <Provider Name="Microsoft-Windows-DHCP-Server" Guid="{6D64F02C-A125-4DAC-9A01-F0555B41CA84}" EventSourceName="DhcpServer" />
    <EventID Qualifiers="0">1033</EventID>
    <Version>0</Version>
    <Level>4</Level>
    <Task>0</Task>
    <Opcode>0</Opcode>
    <Keywords>0x80000000000000</Keywords>
    <TimeCreated SystemTime="2017-05-10T16:46:59.000000000Z" />
    EventRecordID>6653</EventRecordID>
    <Correlation />
    <Execution ProcessID="0" ThreadID="0" />
    <Channel>System</Channel>
    <Computer>dc1.lab.internal</Computer>
  <Security />
  </System>
  - <EventData>
    <Data>Der Vorgang wurde erfolgreich beendet.</Data>
    <Binary>00000000</Binary>
  </EventData>
</Event>

```




