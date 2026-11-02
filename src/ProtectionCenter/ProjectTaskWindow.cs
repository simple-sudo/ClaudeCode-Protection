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
    private readonly TextBox before=Editor(true),after=Editor(true),entry=Editor(false),tests=Editor(false),count=Editor(false),results=Editor(true);
    private readonly TextBlock status=new(){TextWrapping=TextWrapping.Wrap,Margin=new Thickness(0,12,0,0)};
    private readonly string directory;
    private readonly string[] sources;
    private string[] dataFiles=Array.Empty<string>();
    private bool busy;
    internal CallerProjectSession? Prepared {get;private set;}
    internal ProjectTaskWindow(string directory,string[] sources,CallerProjectRevision? revision=null)
    {
        this.directory=directory;this.sources=sources;
        Title="准备 C# 项目任务";Width=700;Height=820;MinWidth=580;MinHeight=540;WindowStartupLocation=WindowStartupLocation.CenterOwner;
        Background=System.Windows.Media.Brushes.White;FontFamily=new System.Windows.Media.FontFamily("Microsoft YaHei UI");FontSize=14;
        var panel=new StackPanel{Margin=new Thickness(22)};
        panel.Children.Add(new TextBlock{Text=revision is null?"仅复制所选源码；原项目保持原样。可同时修改实现与测试；将每项文字修改加入列表，再填写运行、测试入口。":"继续修改已校验的结果源码。沿用原数据、运行/测试入口及结果限制；将新的文字修改加入列表，可同时修改实现与测试。",TextWrapping=TextWrapping.Wrap});
        var files=new TextBox{Text=string.Join(Environment.NewLine,sources),IsReadOnly=true,MaxHeight=90,VerticalScrollBarVisibility=ScrollBarVisibility.Auto,Margin=new Thickness(0,8,0,0)};
        panel.Children.Add(files);
        var dataList=new TextBox{IsReadOnly=true,MaxHeight=70,VerticalScrollBarVisibility=ScrollBarVisibility.Auto,Text="尚未选择数据文件"};
        var selectData=new Button{Content="选择项目数据文件",HorizontalAlignment=HorizontalAlignment.Left,Padding=new Thickness(10,5,10,5),Margin=new Thickness(0,8,0,4)};
        selectData.Click+=(_,_)=>
        {
            var dialog=new Microsoft.Win32.OpenFileDialog{Title="选择项目内需要读取的数据（最多64份；本次选择会替换之前的数据选择）",InitialDirectory=directory,Multiselect=true,CheckFileExists=true};
            if(dialog.ShowDialog(this)!=true)return;
            try
            {
                var selected=dialog.FileNames.Select(path=>WorkspaceBundle.Relative(Path.GetRelativePath(directory,path).Replace('\\','/'))).ToArray();
                if(selected.Length>64 || selected.Intersect(sources,StringComparer.OrdinalIgnoreCase).Any())throw new InvalidDataException("请选择最多64份源码以外的数据文件。");
                dataFiles=selected;dataList.Text=string.Join(Environment.NewLine,selected);status.Text="数据文件已选择，准备任务时才会读取内容。";
            }
            catch(InvalidDataException error){status.Text=error.Message;}
        };
        if(revision is not null)
        {
            selectData.IsEnabled=false;dataFiles=revision.DataFiles;
            dataList.Text=dataFiles.Length==0?"原任务未选择数据文件":string.Join(Environment.NewLine,dataFiles);
            entry.Text=revision.EntryType;tests.Text=revision.TestType;count.Text=revision.ExpectedTests.ToString(System.Globalization.CultureInfo.InvariantCulture);
            results.Text=string.Join(Environment.NewLine,revision.GeneratedFiles.Select(f=>f.Path+"（最多 "+f.MaxBytes+" 字节）"));
            foreach(var field in new[]{entry,tests,results})field.IsReadOnly=true;
        }
        panel.Children.Add(selectData);panel.Children.Add(dataList);
        foreach(var source in sources)editSource.Items.Add(source);editSource.SelectedIndex=0;
        var queue=new ProjectEditQueue(sources);
        var editList=new ListBox{MinHeight=70,MaxHeight=120};var selectedEdit=-1;var selecting=false;
        Field("本次修改（最多32项，按列表顺序执行）",editList);
        var editButtons=new WrapPanel{Margin=new Thickness(0,5,0,0)};
        CSharpProjectEdit Draft()=>new((string)editSource.SelectedItem,before.Text,after.Text);
        void RequireSavedDraft()
        {if(queue.IsPending(selectedEdit,Draft()))throw new InvalidDataException("编辑框还有未保存的修改，请先加入列表或更新所选修改。");}
        void ShowEdit(int index)
        {
            selectedEdit=index;
            if(index>=0){var edit=queue.Snapshot()[index];editSource.SelectedItem=edit.Path;before.Text=edit.Before;after.Text=edit.After;}
            else{before.Clear();after.Clear();}
        }
        void RefreshEdits(int index)
        {
            selecting=true;
            try{editList.ItemsSource=queue.Snapshot().Select((edit,i)=>$"{i+1}. {edit.Path}（{edit.Before.Length}字 → {edit.After.Length}字）").ToArray();editList.SelectedIndex=index;ShowEdit(index);}
            finally{selecting=false;}
        }
        void EditAction(string label,Action action)
        {
            var button=new Button{Content=label,Padding=new Thickness(9,5,9,5),Margin=new Thickness(0,0,6,4)};
            button.Click+=(_,_)=>{try{action();}catch(InvalidDataException error){status.Text=error.Message;}};
            editButtons.Children.Add(button);
        }
        editList.SelectionChanged+=(_,_)=>
        {
            if(selecting)return;
            if(queue.IsPending(selectedEdit,Draft()))
            {
                selecting=true;try{editList.SelectedIndex=selectedEdit;}finally{selecting=false;}
                status.Text="编辑框还有未保存的修改，请先加入列表或更新所选修改。";return;
            }
            ShowEdit(editList.SelectedIndex);
        };
        EditAction("加入列表",()=>{queue.Add(Draft());RefreshEdits(queue.Count-1);status.Text=$"已加入，共{queue.Count}项修改。可选择“新增一项”继续。";});
        EditAction("更新所选",()=>{queue.Update(selectedEdit,Draft());RefreshEdits(selectedEdit);status.Text="所选修改已更新。";});
        EditAction("新增一项",()=>{RequireSavedDraft();RefreshEdits(-1);status.Text="填写下一项修改后，选择“加入列表”。";});
        EditAction("撤销当前编辑",()=>{ShowEdit(selectedEdit);status.Text="编辑框已恢复为列表中的内容；未加入的文字已撤销。";});
        EditAction("删除所选",()=>{RequireSavedDraft();queue.Remove(selectedEdit);RefreshEdits(Math.Min(selectedEdit,queue.Count-1));status.Text="所选修改已删除。";});
        EditAction("上移",()=>{RequireSavedDraft();RefreshEdits(queue.Move(selectedEdit,-1));status.Text="修改顺序已更新。";});
        EditAction("下移",()=>{RequireSavedDraft();RefreshEdits(queue.Move(selectedEdit,1));status.Text="修改顺序已更新。";});
        panel.Children.Add(editButtons);
        Field("要修改的源码",editSource);
        if(revision is not null)
        {
            var preview=new TextBox{IsReadOnly=true,Text=revision.ReadSource(sources[0]),AcceptsReturn=true,MinHeight=90,MaxHeight=180,
                VerticalScrollBarVisibility=ScrollBarVisibility.Auto,HorizontalScrollBarVisibility=ScrollBarVisibility.Auto,
                FontFamily=new System.Windows.Media.FontFamily("Consolas")};
            editSource.SelectionChanged+=(_,_)=>preview.Text=revision.ReadSource((string)editSource.SelectedItem);
            Field("上轮结果中的原始源码（修改按列表顺序执行，可复制原文字）",preview);
        }
        Field("原文字（必须恰好匹配一次）",before);Field("替换后的文字（可留空）",after);
        Field("运行类型（公开 static int Run()，例如 Demo.Entry）",entry);
        Field("测试类型（公开 static int Run()，返回通过项数，例如 Demo.Checks）",tests);
        if(revision is null)count.Text="1";Field("预期通过项数（1–256）",count);
        Field(revision is null?"要保存的结果文件（每行一个，如 summary.json；保存在 cpc-results 下，每份最多64 KiB）":"沿用的结果文件及大小限制",results);
        var buttons=new StackPanel{Orientation=Orientation.Horizontal,Margin=new Thickness(0,14,0,0)};
        var prepare=new Button{Content="准备并审阅",Padding=new Thickness(14,7,14,7),IsDefault=true};
        var cancel=new Button{Content="取消",Padding=new Thickness(14,7,14,7),Margin=new Thickness(10,0,0,0),IsCancel=true};
        prepare.Click+=async (_,_)=>
        {
            if(busy)return;
            if(!int.TryParse(count.Text,System.Globalization.NumberStyles.None,System.Globalization.CultureInfo.InvariantCulture,out var expected) || expected is <1 or >256)
            {status.Text="请输入 1–256 之间的预期通过项数。";return;}
            if(queue.Count==0){status.Text="请先把至少一项文字修改加入列表，再准备任务。";return;}
            if(queue.IsPending(selectedEdit,Draft())){status.Text="编辑框还有未保存的修改，请先加入列表或更新所选修改。";return;}
            var edits=queue.Snapshot();
            var entryType=entry.Text.Trim();var testType=tests.Text.Trim();
            var outputs=results.Text.Split(new[]{'\r','\n'},StringSplitOptions.RemoveEmptyEntries).Select(p=>new CSharpProjectOutput(CSharpProjectTask.ResultDirectory+"/"+p.Trim(),65536)).ToArray();
            var data=dataFiles.ToArray();
            busy=true;prepare.IsEnabled=false;cancel.IsEnabled=false;panel.IsEnabled=false;status.Text="正在保存所选源码的内存快照并校验任务……";
            try
            {
                Prepared=await Task.Run(()=>revision is not null?revision.Prepare(edits,expected):CallerProjectSession.Create(directory,sources,edits,entryType,testType,expected,
                    data.Length==0 && outputs.Length==0?null:data,data.Length==0 && outputs.Length==0?null:outputs));
                DialogResult=true;
            }
            catch(Exception ex)when(ex is IOException or InvalidDataException or UnauthorizedAccessException or ArgumentException or System.ComponentModel.Win32Exception)
            {status.Text="任务未准备完成："+ex.Message+" 请检查所选文件、类型名和文字修改。";}
            finally{busy=false;panel.IsEnabled=true;prepare.IsEnabled=true;cancel.IsEnabled=true;}
        };
        Closing+=(_,e)=>{if(busy && Prepared is null)e.Cancel=true;};
        buttons.Children.Add(prepare);buttons.Children.Add(cancel);
        var footer=new StackPanel{Margin=new Thickness(22,0,22,18)};footer.Children.Add(buttons);footer.Children.Add(status);
        var layout=new DockPanel();DockPanel.SetDock(footer,Dock.Bottom);layout.Children.Add(footer);
        layout.Children.Add(new ScrollViewer{Content=panel,VerticalScrollBarVisibility=ScrollBarVisibility.Auto});Content=layout;
        void Field(string label,Control control)
        {panel.Children.Add(new TextBlock{Text=label,Margin=new Thickness(0,10,0,4)});panel.Children.Add(control);}
    }
    private static TextBox Editor(bool multiline)=>new(){AcceptsReturn=multiline,MinHeight=multiline?65:26,MaxHeight=multiline?120:26,
        MaxLength=multiline?16384:256,VerticalScrollBarVisibility=multiline?ScrollBarVisibility.Auto:ScrollBarVisibility.Hidden};
}
