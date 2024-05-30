using System.Diagnostics.Eventing.Reader;
using System.Runtime.Versioning;

[SupportedOSPlatform("windows")]
internal class Program
{
    private const string LISTFORMAT = "{0,-12} {1,-12} {2,-20} {3,-43} {4}";
    private const int MAXLENGTHOFMESSAGE = 80;
    private const string SYSTEM_EVENTS = "System";
    private const string SECURITY_EVENTS = "Security";
    private const int HOURS_TO_SHOW = 5;

    private static void Main(string[] args)
    {
        var fromTime = DateTime.Now.AddHours(HOURS_TO_SHOW * -1);
        var milliseconds = (long)DateTime.Now.Subtract(fromTime).TotalMilliseconds;

        var logsToShow = args.Length > 0 ? args[0] : null;
        EventLogQuery? eventsQuery = null;
        switch (logsToShow)
        {
            case "logon": eventsQuery = GetLogOnEvents(milliseconds); break;
            case "kernel": eventsQuery = GetKernelPowerEvents(milliseconds); break;
            case "system": eventsQuery = GetAllSystemEvents(milliseconds); break;
            default:
                ShowHelp();
                break;
        }
        PrintEvents(eventsQuery);
    }

    private static void ShowHelp()
    {
        Console.WriteLine("\n| ALLOWED PARAMTERS:\n|\tlogon\n|\tkernel\n|\tsystem");
        Console.WriteLine("|\n| From System: Kernel-Power and System events");
        Console.WriteLine("| From Security: Logon events");
        Console.WriteLine($"| All events shown are within the last {HOURS_TO_SHOW} hours\n");
    }

    private static EventLogQuery GetAllSystemEvents(long fromMilliseconds)
    {
        Console.WriteLine("ALL SYSTEM EVENTS\n");

        string queryEventsSinceMoment = $"*[System[TimeCreated[timediff(@SystemTime) <= {fromMilliseconds}]]]";

        return new EventLogQuery(SYSTEM_EVENTS, PathType.LogName, queryEventsSinceMoment);
    }

    private static EventLogQuery GetKernelPowerEvents(long fromMilliseconds)
    {
        Console.WriteLine("SYSTEM - KERNEL POWER EVENTS\n");

        string queryKernelPowerEvents = "*[System/Provider[@Name='Microsoft-Windows-Kernel-Power'] "
            + $"and System[TimeCreated[timediff(@SystemTime) <= {fromMilliseconds}]]]";

        return new EventLogQuery(SYSTEM_EVENTS, PathType.LogName, queryKernelPowerEvents);
    }

    private static EventLogQuery GetLogOnEvents(long fromMilliseconds)
    {
        Console.WriteLine("LOG ON EVENTS\n");

       string queryLogOnEvents = "*[System[(EventID=4672 or EventID=4624 or EventID=4625 or EventID=4634 "
            + "or EventID=4647 or EventID=4648 or EventID=4779)] "
            + $"and System[TimeCreated[timediff(@SystemTime) <= {fromMilliseconds}]]"
            + "and EventData[Data[@Name='LogonType']='2' or Data[@Name='LogonType']='10']]";

        return new EventLogQuery(SECURITY_EVENTS, PathType.LogName, queryLogOnEvents);
    }

    private static void PrintEvents(EventLogQuery? eventsQuery)
    {
        if (eventsQuery is null) return;

        EventLogReader logReader = new EventLogReader(eventsQuery);

        PrintHeaders();

        EventRecord eventInstance;
        do
        {
            eventInstance = logReader.ReadEvent();
            PrintEventRecord(eventInstance);
        } while (eventInstance != null);
    }

    private static void PrintEventRecord(EventRecord record)
    {
        if (record is null) return;

        var message = record.FormatDescription()?.Replace("\n", " ") ?? "";
        var level = string.IsNullOrEmpty(record.OpcodeDisplayName) ? record.LevelDisplayName : record.OpcodeDisplayName;
        Console.WriteLine(LISTFORMAT, 
            record.Id, 
            level, 
            record.TimeCreated, 
            record.ProviderName,
            message.Length > MAXLENGTHOFMESSAGE ? message.Substring(0, MAXLENGTHOFMESSAGE) : message);
    }

    private static void PrintHeaders()
    {
        Console.WriteLine(LISTFORMAT, "Event ID", "Entry Type", "Time Generated", "Origin", "Message");
        Console.WriteLine(LISTFORMAT, "--------", "----------", "--------------", "------", "-------");
    }
}