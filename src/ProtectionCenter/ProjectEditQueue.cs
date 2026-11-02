using ClaudeCodeProtection.Workspaces;

namespace ProtectionCenter;

// Ordinary editor state only. Every final snapshot still passes the original
// CSharpProjectTask parser and sequential exact-once literal-edit validation.
internal sealed class ProjectEditQueue
{
    private readonly HashSet<string> sources;
    private readonly List<CSharpProjectEdit> edits=new();
    internal int Count=>edits.Count;
    internal ProjectEditQueue(IEnumerable<string> sources)
    {
        var selected=sources.ToArray();
        if(selected.Length is <1 or >32 || selected.Any(s=>WorkspaceBundle.Relative(s)!=s || !s.EndsWith(".cs",StringComparison.Ordinal)) ||
            selected.Distinct(StringComparer.OrdinalIgnoreCase).Count()!=selected.Length)throw new InvalidDataException("请选择1–32份不同的源码。");
        this.sources=selected.ToHashSet(StringComparer.Ordinal);
    }
    private CSharpProjectEdit Validate(CSharpProjectEdit edit)
    {
        if(edit is null || !sources.Contains(edit.Path) || edit.Before is not {Length:>0 and <=16384} || edit.After is not {Length:<=16384})
            throw new InvalidDataException("请选择已授权源码，并填写1–16384字的原文字；新文字最多16384字。");
        return edit;
    }
    private void Index(int index)
    {if(index<0 || index>=edits.Count)throw new InvalidDataException("请先选择列表中的一项修改。");}
    internal void Add(CSharpProjectEdit edit)
    {
        if(edits.Count==32)throw new InvalidDataException("一次任务最多32项修改。");
        edits.Add(Validate(edit));
    }
    internal void Update(int index,CSharpProjectEdit edit)
    {Index(index);var valid=Validate(edit);edits[index]=valid;}
    internal void Remove(int index){Index(index);edits.RemoveAt(index);}
    internal int Move(int index,int direction)
    {
        Index(index);if(direction is not (-1 or 1) || index+direction<0 || index+direction>=edits.Count)
            throw new InvalidDataException("该修改不能移到列表之外。");
        var next=index+direction;(edits[index],edits[next])=(edits[next],edits[index]);return next;
    }
    internal CSharpProjectEdit[] Snapshot()=>edits.ToArray();
    // Uncommitted editor text must never be silently omitted from preparation,
    // selection changes, removal, or reordering.
    internal bool IsPending(int index,CSharpProjectEdit draft)
        =>!(index>=0 && index<edits.Count?edits[index]==draft:draft.Before.Length==0 && draft.After.Length==0);
}
