namespace ClaudeCodeProtection.Security;

internal enum FenceMigrationAction { ReplaceKernelThenSelect, SelectCommittedKernel, VerifySelectedKernel }

// Used only after the WFP owner has checked every object and its security in a
// transaction. These hashes describe frozen policy images, never session PASS.
internal static class FenceMigrationSelection
{
    internal static FenceMigrationAction Decide(string prior,string next,string selected,string kernel,bool fullQuarantine)
    {
        static bool Hash(string value)=>value is not null && value.Length==64 &&
            value.All(c=>c is >= '0' and <= '9' or >= 'A' and <= 'F');
        if(!Hash(prior) || !Hash(next) || !Hash(selected) || !Hash(kernel) || prior==next || !fullQuarantine)
            throw new InvalidDataException("Migration images or quarantine not qualified");
        if(selected==prior && kernel==prior)return FenceMigrationAction.ReplaceKernelThenSelect;
        if(selected==prior && kernel==next)return FenceMigrationAction.SelectCommittedKernel;
        if(selected==next && kernel==next)return FenceMigrationAction.VerifySelectedKernel;
        // In particular, selected NEXT with kernel PRIOR is not a crash phase
        // of this ordered protocol. Do not silently roll forward or roll back.
        throw new InvalidDataException("Migration selection and kernel identity differ");
    }
}
