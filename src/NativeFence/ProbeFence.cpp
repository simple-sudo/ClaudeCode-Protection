#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <initguid.h>
#include <fwpmu.h>
#include <userenv.h>
#include <sddl.h>
#include <filesystem>
#include <iostream>
#include <string>
#include <vector>
#include <chrono>
#include <stdexcept>
#include <limits>

namespace fs = std::filesystem;
struct Failure { DWORD code; const char* stage; };
static void check(DWORD value, const char* stage) { if (value != ERROR_SUCCESS) throw Failure{value, stage}; }
// Same-directory flushed replacement prevents a partially truncated recovery
// journal. This is NOT the protected admin-state boundary of a production install.
static void write(const fs::path& file, const std::string& data) {
    GUID suffix{}; check(static_cast<DWORD>(CoCreateGuid(&suffix)), "EvidenceTempGuid");
    wchar_t text[40]{};
    if (!StringFromGUID2(suffix, text, 40)) throw Failure{ERROR_INVALID_DATA, "EvidenceTempName"};
    const fs::path temporary = file.wstring() + L"." + text + L".tmp";
    const std::string bytes = data + '\n';
    if (bytes.size() > (std::numeric_limits<DWORD>::max)()) throw Failure{ERROR_INVALID_DATA, "EvidenceSize"};
    HANDLE handle = CreateFileW(temporary.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_WRITE_THROUGH, nullptr);
    if (handle == INVALID_HANDLE_VALUE) throw Failure{GetLastError(), "EvidenceCreate"};
    try {
        DWORD written = 0;
        if (!WriteFile(handle, bytes.data(), static_cast<DWORD>(bytes.size()), &written, nullptr) || written != bytes.size())
            throw Failure{ERROR_WRITE_FAULT, "EvidenceWrite"};
        if (!FlushFileBuffers(handle)) throw Failure{GetLastError(), "EvidenceFlush"};
        if (!CloseHandle(handle)) { handle = INVALID_HANDLE_VALUE; throw Failure{GetLastError(), "EvidenceClose"}; }
        handle = INVALID_HANDLE_VALUE;
        if (!MoveFileExW(temporary.c_str(), file.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
            throw Failure{GetLastError(), "EvidenceReplace"};
    } catch (...) {
        if (handle != INVALID_HANDLE_VALUE) CloseHandle(handle);
        DeleteFileW(temporary.c_str()); throw;
    }
}
struct Engine {
    HANDLE handle = nullptr;
    ~Engine() { if (handle) FwpmEngineClose0(handle); }
    void close() { if (handle) { FwpmEngineClose0(handle); handle = nullptr; } }
};
#include "FenceOwnership.h"

static GUID parse_key(const wchar_t* text) {
    GUID key{};
    check(static_cast<DWORD>(IIDFromString(text, &key)), "RecoveryGuid");
    if (IsEqualGUID(key, GUID_NULL)) throw Failure{ERROR_INVALID_DATA, "NullRecoveryGuid"};
    return key;
}
static void new_ref(std::vector<FilterRef>& refs) {
    FilterRef ref; check(static_cast<DWORD>(CoCreateGuid(&ref.key)), "CreateFilterGuid"); refs.push_back(ref);
}
static void add_role(HANDLE engine, PSID sid, const std::wstring& run, const GUID& sublayer, std::vector<FilterRef>& refs, size_t role, bool persistent) {
    FWPM_FILTER_CONDITION0 conditions[2]{};
    conditions[0].fieldKey = FWPM_CONDITION_ALE_PACKAGE_ID;
    conditions[0].matchType = FWP_MATCH_EQUAL;
    conditions[0].conditionValue.type = FWP_SID;
    conditions[0].conditionValue.sid = static_cast<SID*>(sid);
    auto& extra = conditions[1]; extra.matchType = FWP_MATCH_NOT_EQUAL;
    if (role == 0) {
        extra.fieldKey = FWPM_CONDITION_IP_REMOTE_ADDRESS; extra.conditionValue.type = FWP_UINT32; extra.conditionValue.uint32 = 0x7f000001;
    } else if (role == 1) {
        extra.fieldKey = FWPM_CONDITION_IP_REMOTE_PORT; extra.conditionValue.type = FWP_UINT16; extra.conditionValue.uint16 = 7890;
    } else if (role == 2) {
        extra.fieldKey = FWPM_CONDITION_IP_PROTOCOL; extra.conditionValue.type = FWP_UINT8; extra.conditionValue.uint8 = 6;
    }
    auto name = filter_name(run, role);
    FWPM_FILTER0 filter{};
    filter.filterKey = refs.at(role).key;
    filter.displayData.name = name.data();
    filter.layerKey = role == 3 ? FWPM_LAYER_ALE_AUTH_CONNECT_V6 : FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    filter.subLayerKey = sublayer;
    filter.action.type = FWP_ACTION_BLOCK;
    filter.flags = persistent ? FWPM_FILTER_FLAG_PERSISTENT : 0;
    UINT64 weight = UINT64_MAX; filter.weight.type = FWP_UINT64; filter.weight.uint64 = &weight;
    filter.numFilterConditions = role < 3 ? 2 : 1; filter.filterCondition = conditions;
    check(FwpmFilterAdd0(engine, &filter, nullptr, &refs.at(role).observedId), "FilterAdd");
}
int wmain(int argc, wchar_t** argv) {
    const std::wstring mode = argc > 1 ? argv[1] : L"";
    const bool legacy = mode == L"cleanup-legacy-ids";
    const bool recovery = legacy || mode == L"cleanup" || mode == L"inspect" || mode == L"block-proxy";
    const bool persistent = mode == L"lease-persistent" || recovery;
    const bool cleanup = mode == L"cleanup" || legacy;
    if ((!recovery && (argc != 4 || (mode != L"lease" && mode != L"lease-persistent"))) ||
        (recovery && argc != 8 && !(cleanup && argc == 9))) {
        std::cout << "PLAN ONLY: lease|lease-persistent RUN SECONDS; inspect|block-proxy|cleanup RUN SUBLAYER_GUID KEY_ADDRESS KEY_PORT KEY_PROTOCOL KEY_IPV6 [KEY_PROXY only cleanup]. Historical records: cleanup-legacy-ids RUN SUBLAYER_GUID ID1 ID2 ID3 ID4 [ID5]. No automatic ID fallback.\n";
        return argc == 1 ? 0 : 64;
    }
    const std::wstring run = argv[2];
    if (run.size() != 32 || run.find_first_not_of(L"0123456789abcdef") != std::wstring::npos) return 64;
    int seconds = 0;
    try { if (!recovery) { size_t used = 0; seconds = std::stoi(argv[3], &used); if (used != std::wstring(argv[3]).size()) return 64; } }
    catch (...) { return 64; }
    if (!recovery && (seconds < 30 || seconds > 180)) return 64;
    wchar_t module[32768]{};
    const DWORD length = GetModuleFileNameW(nullptr, module, 32768);
    if (!length || length >= 32768) return 125;
    const auto root = fs::path(module).parent_path().parent_path().parent_path();
    const auto directory = root / L"state" / L"isolation-probe" / run;
    for (const auto& path : {root, root / L"state", root / L"state" / L"isolation-probe", directory}) {
        const DWORD attributes = GetFileAttributesW(path.c_str());
        if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_REPARSE_POINT)) return 125;
    }
    if (!fs::is_regular_file(directory / L"manifest.json") || (!recovery && fs::exists(directory / L"wfp-plan.json"))) return 125;
    Engine engine;
    PSID sid = nullptr;
    std::vector<FilterRef> refs;
    GUID sublayer{};
    bool transaction = false, committed = false;
    int result = 0;
    const char* failureStage = "NONE";
    DWORD failureCode = 0;
    try {
        const auto profile = L"ClaudeProtectionProbe." + run;
        check(static_cast<DWORD>(DeriveAppContainerSidFromAppContainerName(profile.c_str(), &sid)), "DeriveProbeSid");
        if (recovery) {
            sublayer = parse_key(argv[3]);
            std::vector<UINT64> ids;
            for (int i = 4; i < argc; ++i) {
                if (legacy) {
                    const std::wstring text = argv[i];
                    if (text.empty() || text.find_first_not_of(L"0123456789") != std::wstring::npos) throw Failure{ERROR_INVALID_DATA, "LegacyRecoveryIds"};
                    size_t used = 0; const auto id = std::stoull(text, &used);
                    if (used != text.size() || !id || std::find(ids.begin(), ids.end(), id) != ids.end()) throw Failure{ERROR_INVALID_DATA, "LegacyRecoveryIds"};
                    ids.push_back(id);
                } else {
                    const auto key = parse_key(argv[i]);
                    if (IsEqualGUID(key, sublayer) || std::any_of(refs.begin(), refs.end(), [&](const auto& ref) {return IsEqualGUID(ref.key, key);}))
                        throw Failure{ERROR_INVALID_DATA, "DuplicateRecoveryKeys"};
                    refs.push_back({key, 0});
                }
            }
            check(FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, nullptr, &engine.handle), "RecoveryEngineOpen");
            if (legacy) {
                // Separate protocol, cleanup only, never a health qualification.
                delete_legacy_ids(engine.handle, sid, run, sublayer, ids);
                const bool absent = absent_owned(engine.handle, sublayer, {});
                write(directory / L"wfp-legacy-recovered.json", std::string("{\"Protocol\":\"LEGACY_IDS_CLEANUP_ONLY\",\"GuidRecoveryQualified\":false,\"Cleanup\":\"") + (absent ? "PASS" : "FAIL") + "\"}");
                engine.close(); FreeSid(sid); return absent ? 0 : 2;
            }
            if (mode == L"inspect" || mode == L"block-proxy") {
                check(FwpmTransactionBegin0(engine.handle, mode == L"inspect" ? FWPM_TXN_READ_ONLY : 0), "PolicyTransactionBegin"); transaction = true;
                const auto owned = validate_owned(engine.handle, sid, run, sublayer, refs, true);
                const bool valid = owned.present == 4 && owned.persistent == 4 && owned.healthy == 4 && owned.layerHealthy;
                if (mode == L"inspect") {
                    check(FwpmTransactionCommit0(engine.handle), "InspectTransactionCommit"); transaction = false;
                    write(directory / L"wfp-after-controller-exit.json", std::string("{\"SchemaVersion\":2,\"Verified\":") + (valid ? "true" : "false") +
                        ",\"PolicySemanticsVerified\":" + (valid ? "true" : "false") + ",\"Present\":" + std::to_string(owned.present) +
                        ",\"Persistent\":" + std::to_string(owned.persistent) + ",\"HealthyRoles\":" + std::to_string(owned.healthy) + "}");
                    engine.close(); FreeSid(sid); return valid ? 0 : 2;
                }
                if (!valid) throw Failure{ERROR_INVALID_STATE, "ExpectedHealthyFourRolePolicy"};
                new_ref(refs);
                // Recoverable key exists on disk before adding the fifth rule.
                write(directory / L"wfp-plan.json", state_json(run, sublayer, refs, true, "PROXY_FAILURE_BEFORE_ADD"));
                add_role(engine.handle, sid, run, sublayer, refs, 4, true);
                write(directory / L"wfp-plan.json", state_json(run, sublayer, refs, true, "PROXY_FAILURE_BEFORE_COMMIT"));
                check(FwpmTransactionCommit0(engine.handle), "ProxyFailureCommit"); transaction = false;
                write(directory / L"wfp-proxy-blocked.json", state_json(run, sublayer, refs, true, "PROXY_PATH_BLOCKED"));
                engine.close(); FreeSid(sid); return 0; // Exact broker cleanup owns removal.
            }
            delete_owned(engine.handle, sid, run, sublayer, refs, true);
            const bool absent = absent_owned(engine.handle, sublayer, refs);
            write(directory / L"wfp-recovered.json", std::string("{\"SchemaVersion\":2,\"Cleanup\":\"") + (absent ? "PASS" : "FAIL") + "\",\"ExactOwnershipChecked\":true,\"RecoveryIdentity\":\"GUID\"}");
            engine.close(); FreeSid(sid); return absent ? 0 : 2;
        }
        FWPM_SESSION0 session{};
        session.displayData.name = const_cast<wchar_t*>(L"ClaudeProtection disposable probe fence");
        session.flags = persistent ? 0 : FWPM_SESSION_FLAG_DYNAMIC;
        check(FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, &session, &engine.handle), "EngineOpen");
        check(static_cast<DWORD>(CoCreateGuid(&sublayer)), "CreateSublayerGuid");
        for (size_t role = 0; role < 4; ++role) new_ref(refs);
        write(directory / L"wfp-plan.json", state_json(run, sublayer, refs, persistent, "BEFORE_ADD"));
        check(FwpmTransactionBegin0(engine.handle, 0), "TransactionBegin"); transaction = true;
        auto name = layer_name(run);
        FWPM_SUBLAYER0 layer{};
        layer.subLayerKey = sublayer; layer.displayData.name = name.data(); layer.weight = 0xffff;
        layer.flags = persistent ? FWPM_SUBLAYER_FLAG_PERSISTENT : 0;
        check(FwpmSubLayerAdd0(engine.handle, &layer, nullptr), "SublayerAdd");
        for (size_t role = 0; role < 4; ++role) add_role(engine.handle, sid, run, sublayer, refs, role, persistent);
        write(directory / L"wfp-plan.json", state_json(run, sublayer, refs, persistent, "BEFORE_COMMIT"));
        check(FwpmTransactionCommit0(engine.handle), "TransactionCommit"); transaction = false; committed = true;
        write(directory / L"wfp-ready.json", state_json(run, sublayer, refs, persistent, "READY"));
        const auto begin = std::chrono::steady_clock::now();
        while (!fs::exists(directory / L"wfp-finish.signal") && std::chrono::steady_clock::now() - begin < std::chrono::seconds(seconds)) Sleep(100);
    }
    catch (const Failure& ex) { failureCode = ex.code; failureStage = ex.stage; result = 2; }
    catch (...) { failureCode = ERROR_UNHANDLED_EXCEPTION; failureStage = "Unhandled"; result = 2; }
    if (transaction && engine.handle) FwpmTransactionAbort0(engine.handle);
    if (committed && engine.handle) {
        try { delete_owned(engine.handle, sid, run, sublayer, refs, persistent); }
        catch (const Failure& ex) { failureCode = ex.code; failureStage = ex.stage; result = 2; }
    }
    engine.close();
    bool absent = false;
    try {
        if (!refs.empty()) {
            Engine query;
            check(FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, nullptr, &query.handle), "CleanupQueryOpen");
            absent = absent_owned(query.handle, sublayer, refs);
        }
        write(directory / (recovery ? L"wfp-recovery-error.json" : L"wfp-cleaned.json"), std::string("{\"SchemaVersion\":2,\"Cleanup\":\"") +
            (absent && !failureCode ? "PASS" : "FAIL_OR_UNKNOWN") + "\",\"ObjectsObservedAbsent\":" + (absent ? "true" : "false") +
            ",\"FailureCode\":" + std::to_string(failureCode) + ",\"FailureStage\":\"" + failureStage + "\"}");
    } catch (...) { absent = false; }
    if (sid) FreeSid(sid);
    return absent ? result : 2;
}
