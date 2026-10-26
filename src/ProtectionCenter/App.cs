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
        AddAction(buttons, "检查环境", Inspect);
        AddAction(buttons, "修复 Claude 代理配置", Repair);
        lower.Children.Add(buttons);
        var report = Card(details); report.Padding = new Thickness(0); Grid.SetRow(report, 1); lower.Children.Add(report);
        details.Text = "检查结果会显示在这里。\r\n\r\n日常入口不提供故障注入或进程终止测试。\r\n日志中保留失败和未知项，不保存提示词或登录凭据。";
        Grid.SetRow(lower, 3); root.Children.Add(lower);
        Grid.SetRow(activity, 4); root.Children.Add(activity); Content = root;
        Closing += (_, e) => { if (busy) { closeWhenDone = true; e.Cancel = true; activity.Text = "正在完成检查或清理，结束后自动关闭。"; } };
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
    private async Task Inspect()
    {
        activity.Text = "正在核对代理配置和环境……";
        var baseline = await BackendClient.Command("system-proxy-baseline");
        if (baseline.ExitCode == 0)
        {
            using var json = JsonDocument.Parse(baseline.Output);
            proxy.Text = json.RootElement.GetProperty("ExpectedFlClashProxy").GetBoolean() ? "配置一致" : "需要检查";
        }
        else proxy.Text = "检查未完成";
        var result = await BackendClient.Command("audit", "--online");
        var file = BackendClient.SaveReport("environment", result);
        details.Text = result.Output + "\r\n" + result.Error;
        activity.Text = "环境检查记录已保存。正式启动的必要项可能仍显示失败或未知；本阶段保持未激活。\n" + file;
    }
    private async Task Repair()
    {
        activity.Text = "核对 Claude 的三个代理字段；Windows 全局代理保持原样。";
        var plan = await BackendClient.Command("repair-proxy-plan");
        if (plan.ExitCode != 0) throw new InvalidOperationException("配置计划无法读取");
        using var json = JsonDocument.Parse(plan.Output);
        var hash = json.RootElement.GetProperty("sha256").GetString() ?? throw new InvalidDataException();
        var result = await BackendClient.Command("repair-proxy", hash);
        var file = BackendClient.SaveReport("config-repair", result);
        details.Text = result.Output + "\r\n" + result.Error;
        activity.Text = result.ExitCode == 0 ? "配置维护已完成。只合并 Claude 代理字段；原始内容在需要修改时保留私有备份。" : "配置未完成修复，已停止以保留原设置。记录：" + file;
    }
}

