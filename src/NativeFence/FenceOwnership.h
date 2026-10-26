#pragma once
#include <algorithm>
#include <array>

// Fixed order is part of journal schema 2 and the explicit GUID CLI protocol.
static constexpr std::array<const char*, 5> role_names = {
    "ipv4-address", "ipv4-port", "ipv4-protocol", "ipv6-deny", "proxy-failure"
};
struct FilterRef { GUID key{}; UINT64 observedId = 0; };
static std::string guid_text(const GUID& guid) {
    wchar_t text[40]{};
    if (!StringFromGUID2(guid, text, 40)) throw Failure{ERROR_INVALID_DATA, "GuidText"};
    std::string result; for (const auto c : text) { if (!c) break; result.push_back(static_cast<char>(c)); }
    return result;
}
static std::string ascii(const std::wstring& value) {
    std::string result;
    for (const auto c : value) result.push_back(static_cast<char>(c));
    return result; // Validated hex run IDs only.
}
static std::wstring layer_name(const std::wstring& run) { return L"ClaudeProtection probe fence v2:" + run; }
static std::wstring filter_name(const std::wstring& run, size_t role) {
    const std::string name = role_names.at(role);
    return L"Probe:" + run + L":" + std::wstring(name.begin(), name.end());
}
static std::string state_json(const std::wstring& run, const GUID& layer, const std::vector<FilterRef>& refs, bool persistent, const char* state) {
    std::string result = std::string("{\"SchemaVersion\":2,\"Run\":\"") + ascii(run) + "\",\"State\":\"" + state +
        "\",\"Scope\":\"Temporary probe AppContainer SID only\",\"Dynamic\":" + (persistent ? "false" : "true") +
        ",\"Persistent\":" + (persistent ? "true" : "false") + ",\"SublayerKey\":\"" + guid_text(layer) + "\",\"Filters\":[";
    for (size_t i = 0; i < refs.size(); ++i) {
        if (i) result += ',';
        result += std::string("{\"Role\":\"") + role_names.at(i) + "\",\"Key\":\"" + guid_text(refs[i].key) +
            "\",\"ObservedId\":" + std::to_string(refs[i].observedId) + "}";
    }
    return result + "]}";
}
static bool package_owned(const FWPM_FILTER0& filter, PSID sid) {
    size_t packages = 0;
    for (UINT32 i = 0; i < filter.numFilterConditions; ++i) {
        const auto& c = filter.filterCondition[i];
        if (!IsEqualGUID(c.fieldKey, FWPM_CONDITION_ALE_PACKAGE_ID)) continue;
        if (c.matchType != FWP_MATCH_EQUAL || c.conditionValue.type != FWP_SID || !c.conditionValue.sid ||
            !IsValidSid(c.conditionValue.sid) || !EqualSid(c.conditionValue.sid, sid)) return false;
        ++packages;
    }
    return packages == 1;
}
// Health is stricter than cleanup ownership: compare each complete role.
static bool role_healthy(const FWPM_FILTER0& filter, size_t role, bool persistent) {
    if (role >= role_names.size() || filter.action.type != FWP_ACTION_BLOCK || filter.providerKey ||
        filter.flags != (persistent ? FWPM_FILTER_FLAG_PERSISTENT : 0) ||
        filter.weight.type != FWP_UINT64 || !filter.weight.uint64 || *filter.weight.uint64 != UINT64_MAX ||
        filter.rawContext != 0 || !IsEqualGUID(filter.layerKey, role == 3 ? FWPM_LAYER_ALE_AUTH_CONNECT_V6 : FWPM_LAYER_ALE_AUTH_CONNECT_V4)) return false;
    const bool extra = role < 3;
    if (filter.numFilterConditions != (extra ? 2u : 1u)) return false;
    if (!extra) return true; // package_owned verifies the sole condition.
    for (UINT32 i = 0; i < filter.numFilterConditions; ++i) {
        const auto& c = filter.filterCondition[i];
        if (IsEqualGUID(c.fieldKey, FWPM_CONDITION_ALE_PACKAGE_ID)) continue;
        if (c.matchType != FWP_MATCH_NOT_EQUAL) return false;
        if (role == 0) return IsEqualGUID(c.fieldKey, FWPM_CONDITION_IP_REMOTE_ADDRESS) && c.conditionValue.type == FWP_UINT32 && c.conditionValue.uint32 == 0x7f000001;
        if (role == 1) return IsEqualGUID(c.fieldKey, FWPM_CONDITION_IP_REMOTE_PORT) && c.conditionValue.type == FWP_UINT16 && c.conditionValue.uint16 == 7890;
        return IsEqualGUID(c.fieldKey, FWPM_CONDITION_IP_PROTOCOL) && c.conditionValue.type == FWP_UINT8 && c.conditionValue.uint8 == 6;
    }
    return false;
}
struct OwnedCount { size_t present = 0; size_t persistent = 0; size_t healthy = 0; bool layerPresent = false; bool layerHealthy = false; };
static OwnedCount validate_owned(HANDLE engine, PSID sid, const std::wstring& run, const GUID& sublayer,
    const std::vector<FilterRef>& refs, bool persistent, bool legacy = false) {
    OwnedCount count;
    for (size_t i = 0; i < refs.size(); ++i) {
        FWPM_FILTER0* filter = nullptr;
        const auto status = FwpmFilterGetByKey0(engine, &refs[i].key, &filter);
        if (status == static_cast<DWORD>(FWP_E_FILTER_NOT_FOUND)) continue;
        check(status, "ValidateFilterReadByKey");
        const auto expectedName = filter_name(run, i);
        const bool nameMatches = filter->displayData.name && (legacy
            ? std::wstring(filter->displayData.name).find(L"Probe:") == 0
            : std::wstring(filter->displayData.name) == expectedName);
        const bool legacyShape = !legacy || (filter->action.type == FWP_ACTION_BLOCK &&
            (IsEqualGUID(filter->layerKey, FWPM_LAYER_ALE_AUTH_CONNECT_V4) || IsEqualGUID(filter->layerKey, FWPM_LAYER_ALE_AUTH_CONNECT_V6)));
        const bool owned = IsEqualGUID(filter->filterKey, refs[i].key) && package_owned(*filter, sid) &&
            IsEqualGUID(filter->subLayerKey, sublayer) && nameMatches && legacyShape;
        const bool durable = (filter->flags & FWPM_FILTER_FLAG_PERSISTENT) != 0;
        const bool healthy = owned && !legacy && role_healthy(*filter, i, persistent);
        FwpmFreeMemory0(reinterpret_cast<void**>(&filter));
        if (!owned) throw Failure{ERROR_ACCESS_DENIED, "ForeignFilterRefused"};
        ++count.present; if (durable) ++count.persistent; if (healthy) ++count.healthy;
    }
    FWPM_SUBLAYER0* layer = nullptr;
    const auto status = FwpmSubLayerGetByKey0(engine, &sublayer, &layer);
    if (status != static_cast<DWORD>(FWP_E_SUBLAYER_NOT_FOUND)) {
        check(status, "ValidateSublayerRead");
        const auto expectedName = legacy ? L"ClaudeProtection temporary package-specific probe fence" : layer_name(run);
        const bool owned = layer->displayData.name && std::wstring(layer->displayData.name) == expectedName;
        count.layerHealthy = owned && !legacy && layer->weight == 0xffff && !layer->providerKey &&
            layer->flags == (persistent ? FWPM_SUBLAYER_FLAG_PERSISTENT : 0);
        FwpmFreeMemory0(reinterpret_cast<void**>(&layer));
        if (!owned) throw Failure{ERROR_ACCESS_DENIED, "ForeignSublayerRefused"};
        count.layerPresent = true;
    }
    return count;
}
static void delete_in_transaction(HANDLE engine, const GUID& sublayer, const std::vector<FilterRef>& refs, const OwnedCount& owned) {
    for (const auto& ref : refs) {
        const auto status = FwpmFilterDeleteByKey0(engine, &ref.key);
        if (status != static_cast<DWORD>(FWP_E_FILTER_NOT_FOUND)) check(status, "DeleteOwnedFilterByKey");
    }
    if (owned.layerPresent) check(FwpmSubLayerDeleteByKey0(engine, &sublayer), "DeleteOwnedSublayer");
}
static void delete_owned(HANDLE engine, PSID sid, const std::wstring& run, const GUID& sublayer, const std::vector<FilterRef>& refs, bool persistent) {
    check(FwpmTransactionBegin0(engine, 0), "CleanupTransactionBegin");
    try {
        const auto owned = validate_owned(engine, sid, run, sublayer, refs, persistent);
        delete_in_transaction(engine, sublayer, refs, owned);
        check(FwpmTransactionCommit0(engine), "CleanupTransactionCommit");
    } catch (...) { FwpmTransactionAbort0(engine); throw; }
}
// Historical cleanup only. Never fallback when a GUID read fails. Resolve IDs
// to keys, validate ALL ownership, then delete inside the same transaction.
static void delete_legacy_ids(HANDLE engine, PSID sid, const std::wstring& run, const GUID& sublayer, const std::vector<UINT64>& ids) {
    check(FwpmTransactionBegin0(engine, 0), "LegacyCleanupTransactionBegin");
    try {
        std::vector<FilterRef> resolved;
        for (const auto id : ids) {
            FWPM_FILTER0* filter = nullptr;
            const auto status = FwpmFilterGetById0(engine, id, &filter);
            if (status == static_cast<DWORD>(FWP_E_FILTER_NOT_FOUND)) continue;
            check(status, "LegacyIdResolve");
            resolved.push_back({filter->filterKey, id});
            FwpmFreeMemory0(reinterpret_cast<void**>(&filter));
        }
        const auto owned = validate_owned(engine, sid, run, sublayer, resolved, true, true);
        delete_in_transaction(engine, sublayer, resolved, owned);
        check(FwpmTransactionCommit0(engine), "LegacyCleanupTransactionCommit");
    } catch (...) { FwpmTransactionAbort0(engine); throw; }
}
static bool absent_owned(HANDLE engine, const GUID& sublayer, const std::vector<FilterRef>& refs) {
    check(FwpmTransactionBegin0(engine, FWPM_TXN_READ_ONLY), "AbsentTransactionBegin");
    try {
        bool absent = true;
        for (const auto& ref : refs) {
            FWPM_FILTER0* found = nullptr;
            const auto status = FwpmFilterGetByKey0(engine, &ref.key, &found);
            if (found) FwpmFreeMemory0(reinterpret_cast<void**>(&found));
            if (status == ERROR_SUCCESS) absent = false;
            else if (status != static_cast<DWORD>(FWP_E_FILTER_NOT_FOUND)) check(status, "AbsentFilterRead");
        }
        FWPM_SUBLAYER0* remaining = nullptr;
        const auto status = FwpmSubLayerGetByKey0(engine, &sublayer, &remaining);
        if (remaining) FwpmFreeMemory0(reinterpret_cast<void**>(&remaining));
        if (status == ERROR_SUCCESS) absent = false;
        else if (status != static_cast<DWORD>(FWP_E_SUBLAYER_NOT_FOUND)) check(status, "AbsentSublayerRead");
        check(FwpmTransactionCommit0(engine), "AbsentTransactionCommit");
        return absent;
    } catch (...) { FwpmTransactionAbort0(engine); throw; }
}
