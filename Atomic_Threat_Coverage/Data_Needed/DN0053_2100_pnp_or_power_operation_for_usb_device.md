| Title              | DN0053_2100_pnp_or_power_operation_for_usb_device       |
|:-------------------|:------------------|
| **Author**         | @atc_project        |
| **Description**    | Received a Pnp or Power operation for USB device |
| **Logging Policy** | <ul><li> Not existing </li></ul> |
| **References**     | <ul><li>[https://www.techrepublic.com/article/how-to-track-down-usb-flash-drive-usage-in-windows-10s-event-viewer/](https://www.techrepublic.com/article/how-to-track-down-usb-flash-drive-usage-in-windows-10s-event-viewer/)</li></ul> |
| **Platform**       | Windows    |
| **Type**           | Applications and Services Logs        |
| **Channel**        | Microsoft-Windows-DriverFrameworks-UserMode/Operational     |
| **Provider**       | Microsoft-Windows-DriverFrameworks-UserMode    |
| **Fields**         | <ul><li>EventID</li><li>ComputerName</li><li>Computer</li><li>UMDFHostDeviceRequest</li><li>lifetime</li><li>instance</li></ul> |


## Log Samples

### Raw Log

```
- <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  - <System>
    <Provider Name="Microsoft-Windows-DriverFrameworks-UserMode" Guid="{2E35AAEB-857F-4BEB-A418-2E6C0E54D988}" />
    <EventID>2100</EventID>
    <Version>1</Version>
    <Level>4</Level>
    <Task>37</Task>
    <Opcode>1</Opcode>
    <Keywords>0x8000000000000000</Keywords>
    <TimeCreated SystemTime="2017-07-08T19:59:02.925841500Z" />
    <EventRecordID>240</EventRecordID>
    <Correlation />
    <Execution ProcessID="2012" ThreadID="2496" />
    <Channel>Microsoft-Windows-DriverFrameworks-UserMode/Operational</Channel>
    <Computer>DavidClient</Computer>
    <Security UserID="S-1-5-19" />
  </System>
    - <UserData>
      - <UMDFHostDeviceRequest instance="SWD\WPDBUSENUM\{72D37FD9-05B1-11E6-8253-001A7DDA7113}#0000000000007E00" lifetime="{9A4B17EA-9EC2-4A46-BE0B-480915F9A030}" xmlns="http://www.microsoft.com/DriverFrameworks/UserMode/Event">
        - <Request major="22" minor="2">
          <Argument>0x51100</Argument>
          <Argument>0x200000001</Argument>
          <Argument>0x0</Argument>
          <Argument>0x0</Argument>
        </Request>
      <Status>3221225659</Status>
      </UMDFHostDeviceRequest>
    </UserData>
</Event>

```




