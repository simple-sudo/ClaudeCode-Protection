using System.IO;
using System.Windows;
using System.Windows.Controls;
using ClaudeCodeProtection.Workspaces;

namespace ProtectionCenter;

// Ordinary data preparation only. The existing Center action remains the
// sole execution path, with its installed-version, review and UAC checks.
internal sealed class ProjectTaskWindow : Window
{
    private readonly ComboBox editSource=new(){MinWidth=240};
    private readonly TextBox before=Editor(true),after=Editor(true),entry=Editor(false),tests=Editor(false),count=Editor(false);
    private readonly TextBlock status=new(){TextWrapping=TextWrapping.Wrap,Margin=new Thickness(0,12,0,0)};
    private readonly string directory;
    private readonly string[] sources;
    private bool busy;
    internal CallerProjectSession? Prepared {get;private set;}
    internal ProjectTaskWindow(string directory,string[] sources)
    {
        this.directory=directory;this.sources=sources;
        Title="准备 C# 项目任务";Width=700;Height=700;MinWidth=580;MinHeight=540;WindowStartupLocation=WindowStartupLocation.CenterOwner;
        Background=System.Windows.Media.Brushes.White;FontFamily=new System.Windows.Media.FontFamily("Microsoft YaHei UI");FontSize=14;
        var panel=new StackPanel{Margin=new Thickness(22)};
        panel.Children.Add(new TextBlock{Text="仅复制所选源码；原项目保持原样。填写一项文字修改及编译后的运行、测试入口。",TextWrapping=TextWrapping.Wrap});
        var files=new TextBox{Text=string.Join(Environment.NewLine,sources),IsReadOnly=true,MaxHeight=90,VerticalScrollBarVisibility=ScrollBarVisibility.Auto,Margin=new Thickness(0,8,0,0)};
        panel.Children.Add(files);
        foreach(var source in sources)editSource.Items.Add(source);editSource.SelectedIndex=0;
        Field("要修改的源码",editSource);Field("原文字（必须恰好匹配一次）",before);Field("替换后的文字（可留空）",after);
        Field("运行类型（公开 static int Run()，例如 Demo.Entry）",entry);
        Field("测试类型（公开 static int Run()，返回通过项数，例如 Demo.Checks）",tests);
        count.Text="1";Field("预期通过项数（1–256）",count);
        var buttons=new StackPanel{Orientation=Orientation.Horizontal,Margin=new Thickness(0,14,0,0)};
        var prepare=new Button{Content="准备并审阅",Padding=new Thickness(14,7,14,7),IsDefault=true};
        var cancel=new Button{Content="取消",Padding=new Thickness(14,7,14,7),Margin=new Thickness(10,0,0,0),IsCancel=true};
        prepare.Click+=async (_,_)=>
        {
            if(busy)return;
            if(!int.TryParse(count.Text,System.Globalization.NumberStyles.None,System.Globalization.CultureInfo.InvariantCulture,out var expected) || expected is <1 or >256)
            {status.Text="请输入 1–256 之间的预期通过项数。";return;}
            var edits=new[]{new CSharpProjectEdit((string)editSource.SelectedItem,before.Text,after.Text)};
            var entryType=entry.Text.Trim();var testType=tests.Text.Trim();
            busy=true;prepare.IsEnabled=false;cancel.IsEnabled=false;panel.IsEnabled=false;status.Text="正在保存所选源码的内存快照并校验任务……";
            try
            {
                Prepared=await Task.Run(()=>CallerProjectSession.Create(directory,sources,edits,entryType,testType,expected));
                DialogResult=true;
            }
            catch(Exception ex)when(ex is IOException or InvalidDataException or UnauthorizedAccessException or ArgumentException or System.ComponentModel.Win32Exception)
            {status.Text="任务未准备完成："+ex.Message+" 请检查所选文件、类型名和文字修改。";}
            finally{busy=false;panel.IsEnabled=true;prepare.IsEnabled=true;cancel.IsEnabled=true;}
        };
        Closing+=(_,e)=>{if(busy && Prepared is null)e.Cancel=true;};
        buttons.Children.Add(prepare);buttons.Children.Add(cancel);panel.Children.Add(buttons);panel.Children.Add(status);
        Content=new ScrollViewer{Content=panel,VerticalScrollBarVisibility=ScrollBarVisibility.Auto};
        void Field(string label,Control control)
        {panel.Children.Add(new TextBlock{Text=label,Margin=new Thickness(0,10,0,4)});panel.Children.Add(control);}
    }
    private static TextBox Editor(bool multiline)=>new(){AcceptsReturn=multiline,MinHeight=multiline?65:26,MaxHeight=multiline?120:26,
        MaxLength=multiline?16384:256,VerticalScrollBarVisibility=multiline?ScrollBarVisibility.Auto:ScrollBarVisibility.Hidden};
}
