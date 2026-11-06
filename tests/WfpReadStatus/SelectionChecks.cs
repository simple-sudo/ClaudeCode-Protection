namespace WfpExistingEvents;

internal static class SelectionChecks
{
    internal static object Run()
    {
        Native.Layout();var count=0;
        void Check(bool condition){if(!condition)throw new InvalidDataException("SelectionFixtureFailed" );count++;}
        var plan=new Selection(100,500,200,210,"S-1-5-21-1-2-3-1001","S-1-15-2-1-2-3-4-5-6-7",@"\version\ProtectionBroker.exe");
        plan.Validate();count++;
        bool Match(long t=205,uint flags=0x460,string? u=null,string? p=null,string? image=null)=>
            plan.Matches(t,flags,u??plan.UserSid,p??plan.PackageSid,image??@"\device\disk\version\ProtectionBroker.exe");
        Check(Match());Check(Match(100));Check(Match(500));Check(!Match(99));Check(!Match(501));
        Check(!Match(flags:0x60));Check(!Match(flags:0x420));Check(!Match(flags:0x440));
        Check(!Match(u:"S-1-5-18"));Check(!Match(p:"S-1-15-2-99"));
        Check(!Match(image:@"\version\ProtectionBroker.exe.extra"));Check(!Match(image:@"\other\ProtectionBroker.exe"));
        Check(Match(image:@"\device\disk\VERSION\PROTECTIONBROKER.EXE"));
        foreach(var invalid in new[]{plan with{Start=501},plan with{End=TimeSpan.TicksPerSecond*6},plan with{CallStart=99},
            plan with{CallEnd=501},plan with{CallEnd=199},plan with{PackageSid="S-1-5-18"},plan with{ImageSuffix=@"\..\ProtectionBroker.exe"}})
        {var rejected=false;try{invalid.Validate();}catch(InvalidDataException){rejected=true;}Check(rejected);}
        return new{Scope="ORDINARY_WFP_SELECTION_FIXTURES_NO_ENGINE_OR_HISTORY_READ",Passed=count,NativeLayoutChecked=true,
            NativeEngineOpened=false,PidBindingProven=false,NetworkAdmission=false};
    }
}
