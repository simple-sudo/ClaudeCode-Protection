using System.Text.Json;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace ProtectionCenter;

internal static class App
{
    [STAThread]
    private static void Main(string[] args)
    {
        ClaudeCodeProtection.Workspaces.WorkspaceFiles.RequireOrdinaryUser();
        var application = new Application();
        Window window = args.Length==2 && args[0]=="--render-edit-task-preview" ? EditPreview() : args.Length==2 && args[0]=="--render-task-preview"
            ? new ProjectTaskWindow(@"C:\ExampleProject",new[]{"src/Entry.cs","tests/Checks.cs"}) : new CenterWindow();
        if (args.Length == 2 && args[0] is "--render-preview" or "--render-task-preview" or "--render-edit-task-preview")
        {
            var content = window.Content as UIElement ?? throw new InvalidOperationException();
            window.Content = null;
            var width=window.Width;var height=window.Height;
            var frame = new Border { Background = window.Background, Width = width, Height = height, Child = content };
            frame.Measure(new Size(width, height)); frame.Arrange(new Rect(0, 0, width, height)); frame.UpdateLayout();
            var bitmap = new RenderTargetBitmap((int)width, (int)height, 96, 96, PixelFormats.Pbgra32); bitmap.Render(frame);
            var encoder = new PngBitmapEncoder(); encoder.Frames.Add(BitmapFrame.Create(bitmap));
            using var stream = File.Create(Path.GetFullPath(args[1])); encoder.Save(stream);
            application.Shutdown(); return;
        }
        application.Run(window);
    }
    private static ProjectTaskWindow EditPreview()
    {
        // Fixed nonsecret data for the existing offscreen preview path only.
        // No input path, project execution, installed owner or admission.
        var definition=new ClaudeCodeProtection.Workspaces.CSharpProjectDefinition(2,ClaudeCodeProtection.Workspaces.CSharpProjectTask.DataKind,
            new[]{"src/Entry.cs","tests/Checks.cs"},new[]{new ClaudeCodeProtection.Workspaces.CSharpProjectEdit("src/Entry.cs","return -1;","return 0;")},"Demo.Entry","Demo.Checks",2,
            new[]{"data/value.txt"},new[]{new ClaudeCodeProtection.Workspaces.CSharpProjectOutput("cpc-results/report.json",128)});
        var draft=CallerProjectSession.FromRevision(new[]{
            new ClaudeCodeProtection.Workspaces.WorkspaceFile("src/Entry.cs",System.Text.Encoding.UTF8.GetBytes("namespace Demo; public static class Entry { public static int Run(){ return -1; } }"),""),
            new ClaudeCodeProtection.Workspaces.WorkspaceFile("tests/Checks.cs",System.Text.Encoding.UTF8.GetBytes("namespace Demo; public static class Checks { public static int Run(){ return 2; } }"),""),
            new ClaudeCodeProtection.Workspaces.WorkspaceFile("data/value.txt",new byte[]{55},"")},definition).EditTask();
        return new ProjectTaskWindow("",draft.Sources,draft);
    }
}

internal sealed class CenterWindow : Window
{
    private static readonly Brush Ink = new SolidColorBrush(Color.FromRgb(30, 43, 60));
    private static readonly Brush Muted = new SolidColorBrush(Color.FromRgb(88, 102, 122));
    private readonly TextBlock proxy = Value("尚未检查");
    private readonly TextBlock components = Value("尚未验收");
    private readonly TextBlock activity = new() { Text = "就绪。检查和维护均不会启动真实 Claude。", Foreground = Muted, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 10, 0, 0) };
    private readonly TextBox details = new() { IsReadOnly = true, FontFamily = new FontFamily("Consolas"), FontSize = 11, TextWrapping = TextWrapping.NoWrap, VerticalScrollBarVisibility = ScrollBarVisibility.Auto, HorizontalScrollBarVisibility = ScrollBarVisibility.Auto, BorderThickness = new Thickness(0), Background = Brushes.White, Padding = new Thickness(12) };
    private readonly List<Button> actions = new();
    private readonly System.Windows.Threading.DispatcherTimer evidenceRefresh = new() { Interval = TimeSpan.FromSeconds(15) };
    private string? environmentOutput, baselineDisplay;
    private string environmentError = "";
    private bool busy, closeWhenDone;
    private CallerProjectSession? preparedProject;
    private Button? startProject;
    private Button? saveProject;
    private Button? editProject;
    private readonly Button cancelProject=new(){Content="取消本次项目",Padding=new Thickness(14,9,14,9),Margin=new Thickness(0,0,10,6),IsEnabled=false};
    private CancellationTokenSource? projectCancellation;
    internal CenterWindow()
    {
        Title = "Claude Code 保护中心"; Width = 940; Height = 720; MinWidth = 820; MinHeight = 640;
        Background = new SolidColorBrush(Color.FromRgb(246, 248, 251)); Foreground = Ink;
        FontFamily = new FontFamily("Microsoft YaHei UI"); FontSize = 14;
        var root = new Grid { Margin = new Thickness(30, 24, 30, 20) };
        foreach (var height in new[] { GridLength.Auto, GridLength.Auto, GridLength.Auto, new GridLength(1, GridUnitType.Star), GridLength.Auto }) root.RowDefinitions.Add(new RowDefinition { Height = height });
        var header = new StackPanel();
        header.Children.Add(new TextBlock { Text = "Claude Code 保护中心", FontSize = 26, FontWeight = FontWeights.SemiBold });
        header.Children.Add(new TextBlock { Text = "检查环境 · 项目开发 · 结果恢复", Foreground = Muted, Margin = new Thickness(0, 7, 0, 0) });
        root.Children.Add(header);

        var mode = new StackPanel();
        mode.Children.Add(new TextBlock { Text = "当前模式：维护与项目任务", FontSize = 17, FontWeight = FontWeights.SemiBold });
        mode.Children.Add(new TextBlock { Text = "无需登录 Claude 账号。真实 Claude 会话与正式启动验收按你的要求延期。", Foreground = Muted, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 8, 0, 0) });
        mode.Children.Add(new TextBlock { Text = "日常网络沿用 FlClash；保护模块验收另行记录。", Foreground = Muted, Margin = new Thickness(0, 5, 0, 0) });
        var modeCard = Card(mode); modeCard.Margin = new Thickness(0, 22, 0, 16); Grid.SetRow(modeCard, 1); root.Children.Add(modeCard);

        var status = new Grid(); status.ColumnDefinitions.Add(new ColumnDefinition()); status.ColumnDefinitions.Add(new ColumnDefinition());
        var network = new StackPanel(); network.Children.Add(Label("日常代理")); network.Children.Add(proxy);
        network.Children.Add(new TextBlock { Text = "同时核对 Windows 的两套代理配置", Foreground = Muted, FontSize = 12, Margin = new Thickness(0, 6, 0, 0) });
        var modules = new StackPanel(); modules.Children.Add(Label("保护模块")); modules.Children.Add(components);
        modules.Children.Add(new TextBlock { Text = "正式会话尚未启用；项目任务单独确认", Foreground = Muted, FontSize = 12, Margin = new Thickness(0, 6, 0, 0) });
        var networkCard = Card(network); networkCard.Margin = new Thickness(0, 0, 8, 0);
        var modulesCard = Card(modules); modulesCard.Margin = new Thickness(8, 0, 0, 0); Grid.SetColumn(modulesCard, 1);
        status.Children.Add(networkCard); status.Children.Add(modulesCard); Grid.SetRow(status, 2); root.Children.Add(status);

        var lower = new Grid { Margin = new Thickness(0, 18, 0, 0) }; lower.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); lower.RowDefinitions.Add(new RowDefinition());
        var buttons = new WrapPanel { Margin = new Thickness(0, 0, 0, 12) };
        AddAction(buttons, "检查环境", () => Inspect(false));
        AddAction(buttons, "检查代理连通性", () => Inspect(true));
        AddAction(buttons, "修复 Claude 代理配置", Repair);
        AddAction(buttons, "撤销上次配置修改", Restore);
        AddAction(buttons, "选择 C# 项目", () => PrepareProject(false));
        AddAction(buttons, "创建项目任务", CreateProject);
        saveProject=AddAction(buttons, "保存项目任务包", SaveProject);saveProject.IsEnabled=false;
        editProject=AddAction(buttons, "编辑当前任务", EditProject);editProject.IsEnabled=false;
        AddAction(buttons, "导入项目任务包", () => PrepareProject(true));
        startProject=AddAction(buttons, "开始项目开发", RunProject);startProject.IsEnabled=false;
        cancelProject.Click+=(_,_)=>{if(projectCancellation is null || projectCancellation.IsCancellationRequested)return;projectCancellation.Cancel();cancelProject.IsEnabled=false;activity.Text="已请求取消，正在等待本次操作结束；保护侧关闭与清理状态尚未确认。";};
        buttons.Children.Add(cancelProject);
        AddAction(buttons, "用结果继续开发", ContinueProject);
        AddAction(buttons, "审阅开发结果", () => ReviewWorkspace(false));
        AddAction(buttons, "提取开发结果", () => ReviewWorkspace(true));
        lower.Children.Add(buttons);
        var report = Card(details); report.Padding = new Thickness(0); Grid.SetRow(report, 1); lower.Children.Add(report);
        details.Text = "检查结果会显示在这里。\r\n\r\n日常入口不提供故障注入或进程终止测试。\r\n日志中保留失败和未知项，不保存提示词或登录凭据。";
        Grid.SetRow(lower, 3); root.Children.Add(lower);
        Grid.SetRow(activity, 4); root.Children.Add(activity); Content = root;
        Closing += (_, e) => { if (busy) { closeWhenDone = true; e.Cancel = true; activity.Text = "正在完成当前操作，结束后自动关闭。"; } };
        // Re-render freshness without repeating the worker or any network test.
        evidenceRefresh.Tick += (_, _) => { if (!busy) RefreshEnvironmentDisplay(); };
        Closed += (_, _) => evidenceRefresh.Stop();
        evidenceRefresh.Start();
    }
    private static TextBlock Value(string text) => new() { Text = text, FontSize = 20, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 8, 0, 0) };
    private static TextBlock Label(string text) => new() { Text = text, Foreground = Muted, FontSize = 13 };
    private static Border Card(UIElement content) => new() { Child = content, Background = Brushes.White, BorderBrush = new SolidColorBrush(Color.FromRgb(222, 228, 236)), BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(10), Padding = new Thickness(18) };
    private void RefreshActions()
    {foreach(var action in actions)action.IsEnabled=!busy;if(startProject is not null)startProject.IsEnabled=!busy && preparedProject is not null;if(saveProject is not null)saveProject.IsEnabled=!busy && preparedProject is not null;if(editProject is not null)editProject.IsEnabled=!busy && preparedProject is not null;cancelProject.IsEnabled=busy && projectCancellation is not null && !projectCancellation.IsCancellationRequested;}
    private Button AddAction(Panel panel, string label, Func<Task> work)
    {
        var button = new Button { Content = label, Padding = new Thickness(14, 9, 14, 9), Margin = new Thickness(0, 0, 10, 6), Background = Brushes.White, Foreground = Ink, BorderBrush = new SolidColorBrush(Color.FromRgb(200, 211, 224)), Cursor = System.Windows.Input.Cursors.Hand };
        button.Click += async (_, _) =>
        {
            if(busy)return;busy = true;RefreshActions();
            try { await work(); }
            catch (InvalidDataException ex) { activity.Text = "操作未完成：" + ex.Message; }
            catch (Exception ex) { activity.Text = "操作未完成：" + ex.GetType().Name + "。已有记录保留，请查看诊断结果。"; }
            finally { busy = false;RefreshActions(); if (closeWhenDone) Close(); }
        };
        actions.Add(button); panel.Children.Add(button);return button;
    }
    private Task CreateProject()
    {
        var folder=new Microsoft.Win32.OpenFolderDialog{Title="选择独立 C# 项目的根目录",Multiselect=false};
        if(folder.ShowDialog(this)!=true){activity.Text="已取消创建；已有任务保留。";return Task.CompletedTask;}
        ClaudeCodeProtection.Workspaces.WorkspaceFiles.RequireExternalProjectPath(folder.FolderName);
        var files=new Microsoft.Win32.OpenFileDialog{Title="明确选择参与编译的 .cs 源码（最多32份）",Filter="C# 源码 (*.cs)|*.cs",InitialDirectory=folder.FolderName,Multiselect=true,CheckFileExists=true};
        if(files.ShowDialog(this)!=true){activity.Text="已取消选择源码；已有任务保留。";return Task.CompletedTask;}
        var sources=files.FileNames.Select(path=>Path.GetRelativePath(folder.FolderName,path).Replace('\\','/')).ToArray();
        if(sources.Length is <1 or >32)throw new InvalidDataException("请选择1–32份源码。");
        foreach(var source in sources)_=ClaudeCodeProtection.Workspaces.WorkspaceBundle.Relative(source);
        var editor=new ProjectTaskWindow(folder.FolderName,sources){Owner=this};
        if(editor.ShowDialog()==true && editor.Prepared is { } project)
        {
            environmentOutput=null;preparedProject=project;details.Text=project.ReviewText;
            activity.Text="任务已准备，请审阅；可保存任务包，或通过已安装的保护链开始开发。";
        }
        else activity.Text="已取消准备；已有任务保留。";
        return Task.CompletedTask;
    }
    private Task EditProject()
    {
        var current=preparedProject??throw new InvalidOperationException("请先准备或导入项目任务。");
        var draft=current.EditTask();
        var editor=new ProjectTaskWindow("",draft.Sources,draft){Owner=this};
        if(editor.ShowDialog()==true && editor.Prepared is { } next)
        {
            environmentOutput=null;preparedProject=next;
            details.Text=next.ReviewText+"\r\n编辑前任务指纹："+draft.SourceTaskSHA256;
            activity.Text="任务修改已准备，请重新审阅并保存或开始开发。原输入和已有运行记录保留；本次编辑没有运行代码。";
        }
        else activity.Text="已取消编辑；原任务和运行记录保留。";
        return Task.CompletedTask;
    }
    private async Task ContinueProject()
    {
        var input=SelectBundle("选择上一次的项目输入包（input.bundle.json）");
        if(input is null){activity.Text="已取消选择；已有任务保留。";return;}
        var result=SelectBundle("选择对应的结果包（result.bundle.json）");
        if(result is null){activity.Text="已取消选择；已有任务保留。";return;}
        activity.Text="正在校验上一次的修改、测试结果和文件清单……";
        var revision=await Task.Run(()=>CallerProjectSession.OpenRevision(input,result));
        var editor=new ProjectTaskWindow("",revision.Sources,revision){Owner=this};
        if(editor.ShowDialog()==true && editor.Prepared is { } next)
        {
            environmentOutput=null;preparedProject=next;details.Text=next.ReviewText;
            details.Text+="\r\n沿用的结果指纹："+revision.PreviousResultSHA256;
            activity.Text="下一次任务已准备；请重新审阅修改，再开始开发。本次仅校验所选文件，未运行项目。";
        }
        else activity.Text="已取消继续开发；已有任务保留。";
    }
    private async Task SaveProject()
    {
        var project=preparedProject??throw new InvalidOperationException("请先准备项目任务。");
        var dialog=new Microsoft.Win32.SaveFileDialog{Title="保存已审阅的任务快照（选择新文件）",Filter="工作区数据包 (*.json)|*.json",FileName="project-task.json",OverwritePrompt=false};
        if(dialog.ShowDialog(this)!=true){activity.Text="已取消保存；任务仍保留。";return;}
        try{await Task.Run(()=>project.SaveBundle(dialog.FileName));}
        catch(System.ComponentModel.Win32Exception ex)when(ex.NativeErrorCode is 80 or 183)
        {activity.Text="文件已存在，请选择新文件名；已有文件保留，未覆盖。";return;}
        activity.Text="任务快照已保存，可稍后导入；未执行项目代码。";
    }
    private async Task PrepareProject(bool bundle)
    {
        string? path;
        if(bundle){var dialog=new Microsoft.Win32.OpenFileDialog{Title="选择项目任务包",Filter="工作区数据包 (*.json)|*.json",CheckFileExists=true,Multiselect=false};path=dialog.ShowDialog(this)==true?dialog.FileName:null;}
        else{var dialog=new Microsoft.Win32.OpenFolderDialog{Title="选择项目文件夹（需含 cpc-project.json）",Multiselect=false};path=dialog.ShowDialog(this)==true?dialog.FolderName:null;}
        if(path is null){activity.Text="已取消选择；已有任务保留。";return;}
        activity.Text="正在读取所选项目并核对修改与测试声明……";
        var selected=await Task.Run(()=>bundle?CallerProjectSession.OpenBundle(path):CallerProjectSession.OpenFolder(path));
        environmentOutput=null;preparedProject=selected;
        details.Text=preparedProject.ReviewText;activity.Text="请审阅修改内容；点击“开始项目开发”后需确认 Windows 权限提示。";
    }
    private async Task RunProject()
    {
        var project=preparedProject??throw new InvalidOperationException("请先选择项目或导入任务包。");
        environmentOutput=null;BackendClient.AssertProjectLocation();
        var parent=new Microsoft.Win32.OpenFolderDialog{Title="选择本次开发记录与结果的保存位置",Multiselect=false};
        if(parent.ShowDialog(this)!=true){activity.Text="已取消启动，准备好的项目仍保留。";return;}
        var run=project.PlanRun(parent.FolderName);BackendResult? result=null;
        using var cancel=new CancellationTokenSource();
        try
        {
            activity.Text="正在保存已审阅的项目快照……";await Task.Run(()=>project.WriteInput(run));
            details.Text=project.ReviewText+"\r\n本次运行目录："+run.Directory;
            activity.Text="正在发起项目开发，请确认 Windows 权限提示。原项目保留。";
            projectCancellation=cancel;RefreshActions();
            try{result=await BackendClient.BuildCallerProject(run.InputPath,run.ResultPath,project.InputSHA256,cancel.Token);}
            finally{projectCancellation=null;RefreshActions();}
            cancel.Token.ThrowIfCancellationRequested();
            if(result.ExitCode!=0 || result.Error.Length!=0)
            {
                var message=project.DescribeFailure(result);activity.Text=message;
                details.Text+="\r\n\r\n"+message;return;
            }
            var restored=await Task.Run(()=>project.AcceptResult(run,result));
            details.Text=restored.ReviewText+"\r\n本次仅核对所列的"+ClaudeCodeProtection.Workspaces.HostPrivacyContract.Roles.Length+"项资源/权限；其他保护范围尚未完整验收。\r\n本次运行目录："+run.Directory;
            activity.Text="项目已返回结果，正在提取到新目录……";
            await Task.Run(()=>restored.ExtractNew(Path.Combine(run.Directory,"files")));
            activity.Text=$"本次项目已完成，{project.ExpectedTests} 项测试通过；两名执行者对所列资源的权限打开均被拒绝。";
            details.Text+="\r\n结果目录："+Path.Combine(run.Directory,"files");
        }
        catch(OperationCanceledException)when(cancel.IsCancellationRequested)
        {
            result=BackendClient.CancelledProjectResult();
            activity.Text="本次操作已取消，结果未自动提取。请保留运行目录；保护侧关闭与清理状态尚未从界面确认。若权限提示仍在等待，请取消该提示。";
            details.Text+="\r\n"+activity.Text;
        }
        catch(OperationCanceledException){activity.Text="等待项目返回超时，任务状态未确认。请保留运行目录，并取消仍未确认的权限提示；不会自动重试。";}
        catch(Exception ex){activity.Text="项目或结果恢复未完成："+ex.GetType().Name+"。请保留运行目录，其中可能已有部分文件；原项目保留。";}
        finally
        {
            projectCancellation=null;RefreshActions();
            if(!details.Text.Contains(run.Directory,StringComparison.Ordinal))details.Text+="\r\n本次运行目录："+run.Directory;
            if(result is not null)try{activity.Text+="\n诊断记录："+BackendClient.SaveReport("project-build",result);}catch(Exception ex){activity.Text+="\n诊断记录未能保存："+ex.GetType().Name+"。以上操作结果保留。";}
        }
    }
    private async Task Inspect(bool online)
    {
        environmentOutput = null;
        activity.Text = "正在核对代理配置和环境……";
        var baseline = await BackendClient.Command("system-proxy-baseline");
        if (baseline.ExitCode == 0)
        {
            try
            {
                using var json = JsonDocument.Parse(baseline.Output);
                proxy.Text = json.RootElement.GetProperty("ExpectedFlClashProxy").GetBoolean() ? "配置一致" : "需要检查";
            }
            catch (Exception ex) when (ex is JsonException or KeyNotFoundException or InvalidOperationException)
            { proxy.Text = "结果无法读取"; }
        }
        else proxy.Text = "检查未完成";
        // Show the first stage before dispatching the next. A later backend or
        // report failure must not erase the baseline failure/output.
        details.Text = "Windows 代理配置：\r\n" + baseline.Output + "\r\n" + baseline.Error;
        BackendResult result;
        try { result = online ? await BackendClient.Command("preflight", "--online") : await BackendClient.Command("preflight"); }
        catch (Exception ex) { result = new(125, "", "Environment audit invocation failed: " + ex.GetType().Name); }
        baselineDisplay = details.Text;
        environmentOutput = result.Output;
        environmentError = result.Error;
        RefreshEnvironmentDisplay();
        var message = result.ExitCode == 125 ? "环境检查未能完成，阶段结果如下；保护仍未激活。" : "环境检查已返回。失败和未知项保留；保护仍未激活。";
        activity.Text = message;
        try { activity.Text += "\n记录：" + BackendClient.SaveReport("environment", result, baseline); }
        catch (Exception ex)
        { activity.Text = message + "\n完整报告未能保存：" + ex.GetType().Name + "。已显示的阶段结果保留。"; }
    }
    private async Task Repair()
    {
        environmentOutput = null;
        activity.Text = "核对 Claude 的三个代理字段；Windows 全局代理保持原样。";
        var plan = await BackendClient.Command("repair-proxy-plan");
        if (plan.ExitCode != 0) { ShowMaintenance(plan, "config-repair"); return; }
        using var json = JsonDocument.Parse(plan.Output);
        var hash = json.RootElement.GetProperty("sha256").GetString() ?? throw new InvalidDataException();
        var result = await BackendClient.Command("repair-proxy", hash);
        ShowMaintenance(result, "config-repair");
    }
    private async Task Restore()
    {
        environmentOutput = null;
        activity.Text = "正在核对上次修改记录；有后续编辑时拒绝覆盖。";
        ShowMaintenance(await BackendClient.Command("restore-proxy"), "config-restore");
    }
    private string? SelectBundle(string title)
    {
        var dialog = new Microsoft.Win32.OpenFileDialog
        {
            Title = title, Filter = "工作区数据包 (*.json)|*.json",
            CheckFileExists = true, Multiselect = false
        };
        return dialog.ShowDialog(this) == true ? dialog.FileName : null;
    }
    private async Task ReviewWorkspace(bool extract)
    {
        environmentOutput = null;
        var baseline = SelectBundle("选择开发前的输入数据包");
        if (baseline is null) { activity.Text = "已取消选择输入数据包。"; return; }
        var result = SelectBundle("选择开发后的结果数据包");
        if (result is null) { activity.Text = "已取消选择结果数据包。"; return; }
        activity.Text = "正在校验所选文件并比较开发变化……";
        var session = await Task.Run(() => WorkspaceResultSession.Open(baseline, result));
        details.Text = session.ReviewText;
        activity.Text = "结果文件校验完成；可以查看上方文件变化。";
        if (!extract) return;
        var parent = new Microsoft.Win32.OpenFolderDialog { Title = "选择结果的保存位置（将在其中创建新目录）", Multiselect = false };
        if (parent.ShowDialog(this) != true) { activity.Text = "已取消提取；文件校验结果保留。"; return; }
        var destination = Path.Combine(parent.FolderName, "project-result-" + DateTime.UtcNow.ToString("yyyyMMdd-HHmmss") + "-" + Guid.NewGuid().ToString("N")[..6]);
        activity.Text = "正在将已审阅的结果提取到新目录……";
        try
        {
            await Task.Run(() => session.ExtractNew(destination));
            details.Text += "\r\n提取目录：" + destination;
            activity.Text = $"已提取 {session.FileCount} 个文件；原项目保留，未运行结果中的程序。";
        }
        catch (Exception ex)
        {
            // The shared writer preserves partial output on failure. Do not
            // hide its location, claim no writes, delete it or retry silently.
            details.Text += "\r\n未确认提取完成的目录：" + destination;
            activity.Text = "提取未完成：" + ex.GetType().Name + "。该目录可能已有部分文件，请保留检查；所选数据包和原项目保留。";
        }
    }
    private void RefreshEnvironmentDisplay()
    {
        if (environmentOutput is not null)
        {
            var display = baselineDisplay + "\r\n\r\n" + PreflightDisplay.Render(environmentOutput, DateTimeOffset.UtcNow) + "\r\n" + environmentError;
            if (details.Text != display) details.Text = display;
        }
    }
    private void ShowMaintenance(BackendResult result, string reportKind)
    {
        // Display the operation outcome before report I/O: report failure must
        // never turn an already-applied change into an apparent no-op.
        details.Text = result.Output + "\r\n" + result.Error;
        string message;
        try
        {
            using var json = JsonDocument.Parse(result.Output);
            message = json.RootElement.GetProperty("status").GetString() switch
            {
                "APPLIED" => reportKind == "config-restore" ? "已恢复修改前的配置；本次恢复也已备份，可再次撤销。" : "已修复 Claude 的三个代理字段；修改前的完整内容已私有备份。",
                "UNCHANGED" => "配置已符合要求，无需修改；原有恢复记录保留。",
                "NO_CURRENT_USER_BACKUP" => "当前用户没有本工具的恢复记录；未迁移或使用旧项目备份。",
                "REFUSED_LATER_EDIT" => "检测到修改后的用户编辑，已拒绝恢复，未覆盖当前配置。",
                "REFUSED_STALE_PLAN" or "REFUSED_CONCURRENT_EDIT" => "配置在核对后发生变化，已停止本次修改。请重新检查当前配置。",
                "REFUSED_UNVERIFIABLE_BACKUP" => "恢复记录或备份无法核验，已拒绝覆盖当前配置；原有文件保留。",
                "RECOVERED_APPLIED" => "上次中断的配置修改已核实完成，恢复入口已补齐。本次未再修改配置。",
                "RECOVERED_NOT_APPLIED" => "上次中断的操作未应用，配置与修改前一致。本次未再修改配置；可重新选择操作。",
                "RECOVERY_CONFLICT" => "中断记录与当前配置冲突，已停止自动修改；备份和失败记录保留。",
                "RECOVERY_REQUIRED" => "配置可能已改变，尚未核实完成。请保留备份和中断记录；后续维护会先核对，不会盲目覆盖。",
                _ => "配置操作未确认完成，请查看诊断结果。"
            };
        }
        catch (Exception ex) when (ex is JsonException or KeyNotFoundException or InvalidOperationException)
        { message = "配置操作未确认完成，请查看诊断结果；不要假定配置保持原样。"; }
        activity.Text = message;
        try { activity.Text += "\n记录：" + BackendClient.SaveReport(reportKind, result); }
        catch (Exception ex)
        { activity.Text = message + "\n诊断报告未能保存：" + ex.GetType().Name + "。操作结果如上，已有备份与记录保留。"; }
    }
}

