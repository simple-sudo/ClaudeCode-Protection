using ProtectionLifecycle;

if(args.Length!=0)return 125;
ProfileRecoveryCases.Run();
Console.WriteLine("PASS profile recovery journal fixtures with ordinary Windows identity; protected-state and native mutation collaborators are fakes");
return 0;
