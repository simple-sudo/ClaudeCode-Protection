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
        var application = new Application();
        var window = new CenterWindow();
        if (args.Length == 2 && args[0] == "--render-preview")
        {
            var content = window.Content as UIElement ?? throw new InvalidOperationException();
            window.Content = null;
            var frame = new Border { Background = window.Background, Width = 940, Height = 720, Child = content };
            frame.Measure(new Size(940, 720)); frame.Arrange(new Rect(0, 0, 940, 720)); frame.UpdateLayout();
            var bitmap = new RenderTargetBitmap(940, 720, 96, 96, PixelFormats.Pbgra32); bitmap.Render(frame);
            var encoder = new PngBitmapEncoder(); encoder.Frames.Add(BitmapFrame.Create(bitmap));
            using var stream = File.Create(Path.GetFullPath(args[1])); encoder.Save(stream);
            application.Shutdown(); return;
        }
        application.Run(window);
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
    internal CenterWindow()
    {
        Title = "Claude Code 保护中心"; Width = 940; Height = 720; MinWidth = 820; MinHeight = 640;
        Background = new SolidColorBrush(Color.FromRgb(246, 248, 251)); Foreground = Ink;
        FontFamily = new FontFamily("Microsoft YaHei UI"); FontSize = 14;
        var root = new Grid { Margin = new Thickness(30, 24, 30, 20) };
        foreach (var height in new[] { GridLength.Auto, GridLength.Auto, GridLength.Auto, new GridLength(1, GridUnitType.Star), GridLength.Auto }) root.RowDefinitions.Add(new RowDefinition { Height = height });
        var header = new StackPanel();
        header.Children.Add(new TextBlock { Text = "Claude Code 保护中心", FontSize = 26, FontWeight = FontWeights.SemiBold });
        header.Children.Add(new TextBlock { Text = "检查环境 · 维护代理配置 · 保留可恢复记录", Foreground = Muted, Margin = new Thickness(0, 7, 0, 0) });
        root.Children.Add(header);

        var mode = new StackPanel();
        mode.Children.Add(new TextBlock { Text = "当前模式：检查与维护", FontSize = 17, FontWeight = FontWeights.SemiBold });
        mode.Children.Add(new TextBlock { Text = "无需登录 Claude 账号。真实 Claude 会话与正式启动验收按你的要求延期。", Foreground = Muted, TextWrapping = TextWrapping.Wrap, Margin = new Thickness(0, 8, 0, 0) });
        mode.Children.Add(new TextBlock { Text = "日常网络沿用 FlClash；保护模块验收另行记录。", Foreground = Muted, Margin = new Thickness(0, 5, 0, 0) });
        var modeCard = Card(mode); modeCard.Margin = new Thickness(0, 22, 0, 16); Grid.SetRow(modeCard, 1); root.Children.Add(modeCard);

        var status = new Grid(); status.ColumnDefinitions.Add(new ColumnDefinition()); status.ColumnDefinitions.Add(new ColumnDefinition());
        var network = new StackPanel(); network.Children.Add(Label("日常代理")); network.Children.Add(proxy);
        network.Children.Add(new TextBlock { Text = "同时核对 Windows 的两套代理配置", Foreground = Muted, FontSize = 12, Margin = new Thickness(0, 6, 0, 0) });
        var modules = new StackPanel(); modules.Children.Add(Label("保护模块")); modules.Children.Add(components);
        modules.Children.Add(new TextBlock { Text = "保护尚未启用；工程验证不在日常入口提供", Foreground = Muted, FontSize = 12, Margin = new Thickness(0, 6, 0, 0) });
        var networkCard = Card(network); networkCard.Margin = new Thickness(0, 0, 8, 0);
        var modulesCard = Card(modules); modulesCard.Margin = new Thickness(8, 0, 0, 0); Grid.SetColumn(modulesCard, 1);
        status.Children.Add(networkCard); status.Children.Add(modulesCard); Grid.SetRow(status, 2); root.Children.Add(status);

        var lower = new Grid { Margin = new Thickness(0, 18, 0, 0) }; lower.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto }); lower.RowDefinitions.Add(new RowDefinition());
        var buttons = new WrapPanel { Margin = new Thickness(0, 0, 0, 12) };
        AddAction(buttons, "检查环境", () => Inspect(false));
        AddAction(buttons, "检查代理连通性", () => Inspect(true));
        AddAction(buttons, "修复 Claude 代理配置", Repair);
        AddAction(buttons, "撤销上次配置修改", Restore);
        AddAction(buttons, "审阅开发结果", () => ReviewWorkspace(false));
        AddAction(buttons, "提取开发结果", () => ReviewWorkspace(true));
        lower.Children.Add(buttons);
        var report = Card(details); report.Padding = new Thickness(0); Grid.SetRow(report, 1); lower.Children.Add(report);
        details.Text = "检查结果会显示在这里。\r\n\r\n日常入口不提供故障注入或进程终止测试。\r\n日志中保留失败和未知项，不保存提示词或登录凭据。";
        Grid.SetRow(lower, 3); root.Children.Add(lower);
        Grid.SetRow(activity, 4); root.Children.Add(activity); Content = root;
        Closing += (_, e) => { if (busy) { closeWhenDone = true; e.Cancel = true; activity.Text = "正在完成检查或清理，结束后自动关闭。"; } };
        // Re-render freshness without repeating the worker or any network test.
        evidenceRefresh.Tick += (_, _) => { if (!busy) RefreshEnvironmentDisplay(); };
        Closed += (_, _) => evidenceRefresh.Stop();
        evidenceRefresh.Start();
    }
    private static TextBlock Value(string text) => new() { Text = text, FontSize = 20, FontWeight = FontWeights.SemiBold, Margin = new Thickness(0, 8, 0, 0) };
    private static TextBlock Label(string text) => new() { Text = text, Foreground = Muted, FontSize = 13 };
    private static Border Card(UIElement content) => new() { Child = content, Background = Brushes.White, BorderBrush = new SolidColorBrush(Color.FromRgb(222, 228, 236)), BorderThickness = new Thickness(1), CornerRadius = new CornerRadius(10), Padding = new Thickness(18) };
    private void AddAction(Panel panel, string label, Func<Task> work)
    {
        var button = new Button { Content = label, Padding = new Thickness(14, 9, 14, 9), Margin = new Thickness(0, 0, 10, 6), Background = Brushes.White, Foreground = Ink, BorderBrush = new SolidColorBrush(Color.FromRgb(200, 211, 224)), Cursor = System.Windows.Input.Cursors.Hand };
        button.Click += async (_, _) =>
        {
            busy = true; foreach (var action in actions) action.IsEnabled = false;
            try { await work(); }
            catch (Exception ex) { activity.Text = "检查未完成：" + ex.GetType().Name + "。已有记录保留，请查看诊断结果。"; }
            finally { busy = false; foreach (var action in actions) action.IsEnabled = true; if (closeWhenDone) Close(); }
        };
        actions.Add(button); panel.Children.Add(button);
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
    private async Task ReviewWorkspace(bool extract)
    {
        environmentOutput = null;
        string? SelectBundle(string title)
        {
            var dialog = new Microsoft.Win32.OpenFileDialog
            {
                Title = title, Filter = "工作区数据包 (*.json)|*.json",
                CheckFileExists = true, Multiselect = false
            };
            return dialog.ShowDialog(this) == true ? dialog.FileName : null;
        }
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

