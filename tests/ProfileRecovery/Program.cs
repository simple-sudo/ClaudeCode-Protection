using ProtectionLifecycle;

if(args.Length!=0)return 125;
ProfileRecoveryCases.Run();
Console.WriteLine("PASS profile recovery and unrecorded task-workspace cleanup/closure state machine; native filesystem, Job and process operations are simulated");
return 0;
