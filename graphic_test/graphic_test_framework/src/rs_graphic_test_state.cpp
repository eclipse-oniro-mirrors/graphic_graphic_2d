/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "rs_graphic_test_runner.h"

#include <cmath>
#include <limits>
#include <memory>
#include <utility>

#include "cJSON.h"
#include "rs_graphic_test_file.h"

namespace OHOS {
namespace Rosen {
namespace {

using JsonPtr = std::unique_ptr<cJSON, decltype(&cJSON_Delete)>;
constexpr uint32_t CURRENT_SCHEMA_VERSION = 1;
constexpr uint64_t MAX_JSON_SAFE_INTEGER = (uint64_t { 1 } << std::numeric_limits<double>::digits) - 1;
constexpr int64_t MIN_JSON_SAFE_INTEGER = -(MAX_JSON_SAFE_INTEGER + 1);

bool Fail(std::string& error, const std::string& message)
{
    error = message;
    return false;
}

bool AddString(cJSON* object, const char* key, const std::string& value)
{
    return cJSON_AddStringToObject(object, key, value.c_str()) != nullptr;
}

bool AddBool(cJSON* object, const char* key, bool value)
{
    return cJSON_AddBoolToObject(object, key, value) != nullptr;
}

bool AddUInt(cJSON* object, const char* key, uint64_t value)
{
    return value <= MAX_JSON_SAFE_INTEGER &&
        cJSON_AddNumberToObject(object, key, static_cast<double>(value)) != nullptr;
}

bool AddInt(cJSON* object, const char* key, int value)
{
    return cJSON_AddNumberToObject(object, key, static_cast<double>(value)) != nullptr;
}

bool AddInt64(cJSON* object, const char* key, int64_t value)
{
    return value >= MIN_JSON_SAFE_INTEGER && value <= static_cast<int64_t>(MAX_JSON_SAFE_INTEGER) &&
        cJSON_AddNumberToObject(object, key, static_cast<double>(value)) != nullptr;
}

const cJSON* Member(const cJSON* object, const char* key)
{
    return cJSON_GetObjectItemCaseSensitive(object, key);
}

bool ReadString(const cJSON* object, const char* key, std::string& value, std::string& error)
{
    const cJSON* item = Member(object, key);
    if (!cJSON_IsString(item) || item->valuestring == nullptr) {
        return Fail(error, std::string("invalid or missing string field: ") + key);
    }
    value = item->valuestring;
    return true;
}

bool ReadBool(const cJSON* object, const char* key, bool& value, std::string& error)
{
    const cJSON* item = Member(object, key);
    if (!cJSON_IsBool(item)) {
        return Fail(error, std::string("invalid or missing boolean field: ") + key);
    }
    value = cJSON_IsTrue(item);
    return true;
}

bool ReadOptionalBool(const cJSON* object, const char* key, bool& value, std::string& error)
{
    if (Member(object, key) == nullptr) {
        value = false;
        return true;
    }
    return ReadBool(object, key, value, error);
}

bool ReadUInt64(const cJSON* object, const char* key, uint64_t& value, std::string& error)
{
    const cJSON* item = Member(object, key);
    if (!cJSON_IsNumber(item) || !std::isfinite(item->valuedouble) || item->valuedouble < 0 ||
        item->valuedouble != std::floor(item->valuedouble) || item->valuedouble > MAX_JSON_SAFE_INTEGER) {
        return Fail(error, std::string("invalid or missing unsigned field: ") + key);
    }
    value = static_cast<uint64_t>(item->valuedouble);
    return true;
}

bool ReadInt64(const cJSON* object, const char* key, int64_t& value, std::string& error)
{
    const cJSON* item = Member(object, key);
    if (!cJSON_IsNumber(item) || !std::isfinite(item->valuedouble) || item->valuedouble != std::floor(
        item->valuedouble) || item->valuedouble < static_cast<double>(MIN_JSON_SAFE_INTEGER) ||
        item->valuedouble > static_cast<double>(MAX_JSON_SAFE_INTEGER)) {
        return Fail(error, std::string("invalid or missing signed field: ") + key);
    }
    value = static_cast<int64_t>(item->valuedouble);
    return true;
}

bool ReadUInt32(const cJSON* object, const char* key, uint32_t& value, std::string& error)
{
    uint64_t parsed = 0;
    if (!ReadUInt64(object, key, parsed, error) || parsed > std::numeric_limits<uint32_t>::max()) {
        return Fail(error, std::string("invalid or missing uint32 field: ") + key);
    }
    value = static_cast<uint32_t>(parsed);
    return true;
}

bool ReadInt(const cJSON* object, const char* key, int& value, std::string& error)
{
    const cJSON* item = Member(object, key);
    if (!cJSON_IsNumber(item) || !std::isfinite(item->valuedouble) ||
        item->valuedouble != std::floor(item->valuedouble) ||
        item->valuedouble < std::numeric_limits<int>::min() || item->valuedouble > std::numeric_limits<int>::max()) {
        return Fail(error, std::string("invalid or missing integer field: ") + key);
    }
    value = static_cast<int>(item->valuedouble);
    return true;
}

bool ReadStatus(const cJSON* object, const char* key, ExecutionStatus& status, std::string& error)
{
    std::string text;
    return ReadString(object, key, text, error) &&
        (ExecutionStatusFromString(text, status) || Fail(error, "invalid execution status: " + text));
}

bool ReadMode(const cJSON* object, const char* key, GraphicCaseMode& mode, std::string& error)
{
    std::string text;
    return ReadString(object, key, text, error) &&
        (GraphicCaseModeFromString(text, mode) || Fail(error, "invalid graphic case mode: " + text));
}

cJSON* CaseInfoToJson(const GraphicTestCaseInfo& info)
{
    JsonPtr object(cJSON_CreateObject(), &cJSON_Delete);
    if (object == nullptr || !AddString(object.get(), "suite", info.suite) ||
        !AddString(object.get(), "name", info.name) || !AddString(object.get(), "type", info.type) ||
        !AddString(object.get(), "mode", std::string(GraphicCaseModeToString(info.mode))) ||
        !AddBool(object.get(), "isMultiple", info.isMultiple) ||
        !AddString(object.get(), "sourcePath", info.sourcePath)) {
        return nullptr;
    }
    return object.release();
}

cJSON* AttemptToJson(const AttemptRecord& attempt)
{
    JsonPtr object(cJSON_CreateObject(), &cJSON_Delete);
    if (object == nullptr) {
        return nullptr;
    }
    const bool valid = AddUInt(object.get(), "attempt", attempt.attempt) &&
        AddString(object.get(), "status", std::string(ExecutionStatusToString(attempt.status))) &&
        AddBool(object.get(), "diagnostic", attempt.diagnostic) && AddInt(object.get(), "exitCode", attempt.exitCode) &&
        AddInt(object.get(), "termSignal", attempt.termSignal) &&
        AddUInt(object.get(), "durationMs", attempt.durationMs) &&
        AddString(object.get(), "logPath", attempt.logPath) && AddString(object.get(), "error", attempt.error) &&
        AddString(object.get(), "requestedCaptureMode", attempt.requestedCaptureMode) &&
        AddString(object.get(), "actualCaptureMode", attempt.actualCaptureMode) &&
        AddString(object.get(), "fallbackReason", attempt.fallbackReason) &&
        AddString(object.get(), "cropRect", attempt.cropRect) &&
        AddUInt(object.get(), "expectedWidth", attempt.expectedWidth) &&
        AddUInt(object.get(), "expectedHeight", attempt.expectedHeight) &&
        AddString(object.get(), "pngRelativePath", attempt.pngRelativePath) &&
        AddUInt(object.get(), "pngSize", attempt.pngSize) && AddUInt(object.get(), "pngWidth", attempt.pngWidth) &&
        AddUInt(object.get(), "pngHeight", attempt.pngHeight) &&
        AddUInt(object.get(), "readyRetries", attempt.readyRetries) &&
        AddBool(object.get(), "captureUnstable", attempt.captureUnstable);
    return valid ? object.release() : nullptr;
}

cJSON* CaseToJson(const CaseRunRecord& item)
{
    JsonPtr object(cJSON_CreateObject(), &cJSON_Delete);
    JsonPtr info(CaseInfoToJson(item.info), &cJSON_Delete);
    JsonPtr attempts(cJSON_CreateArray(), &cJSON_Delete);
    if (object == nullptr || info == nullptr || attempts == nullptr) {
        return nullptr;
    }
    for (const auto& attempt : item.attempts) {
        cJSON* json = AttemptToJson(attempt);
        if (json == nullptr) {
            return nullptr;
        }
        cJSON_AddItemToArray(attempts.get(), json);
    }
    cJSON_AddItemToObject(object.get(), "info", info.release());
    cJSON_AddItemToObject(object.get(), "attempts", attempts.release());
    const bool valid = AddString(object.get(), "finalStatus", std::string(ExecutionStatusToString(item.finalStatus))) &&
        AddBool(object.get(), "flaky", item.flaky) && AddString(object.get(), "skipReason", item.skipReason) &&
        AddString(object.get(), "missingPngReason", item.missingPngReason);
    return valid ? object.release() : nullptr;
}

cJSON* SuiteToJson(const SuiteRunRecord& suite)
{
    JsonPtr object(cJSON_CreateObject(), &cJSON_Delete);
    JsonPtr cases(cJSON_CreateArray(), &cJSON_Delete);
    if (object == nullptr || cases == nullptr) {
        return nullptr;
    }
    for (const auto& item : suite.cases) {
        cJSON* json = CaseToJson(item);
        if (json == nullptr) {
            return nullptr;
        }
        cJSON_AddItemToArray(cases.get(), json);
    }
    cJSON_AddItemToObject(object.get(), "cases", cases.release());
    const bool valid = AddString(object.get(), "name", suite.name) &&
        AddString(object.get(), "status", std::string(ExecutionStatusToString(suite.status))) &&
        AddString(object.get(), "activeCase", suite.activeCase) && AddString(object.get(), "error", suite.error);
    return valid ? object.release() : nullptr;
}

cJSON* IdentityToJson(const RunIdentity& identity)
{
    JsonPtr object(cJSON_CreateObject(), &cJSON_Delete);
    if (object == nullptr) {
        return nullptr;
    }
    const bool valid = AddString(object.get(), "testBuild", identity.testBuild) &&
        AddUInt(object.get(), "testBinarySize", identity.testBinarySize) &&
        AddInt64(object.get(), "testBinaryMtime", identity.testBinaryMtime) &&
        AddString(object.get(), "product", identity.product) && AddUInt(object.get(), "width", identity.width) &&
        AddUInt(object.get(), "height", identity.height) &&
        AddString(object.get(), "renderMode", identity.renderMode) &&
        AddString(object.get(), "executionPolicy", identity.executionPolicy);
    return valid ? object.release() : nullptr;
}

cJSON* StateToJson(const EmulatorRunState& state)
{
    if (state.schemaVersion != CURRENT_SCHEMA_VERSION) {
        return nullptr;
    }
    JsonPtr root(cJSON_CreateObject(), &cJSON_Delete);
    JsonPtr identity(IdentityToJson(state.identity), &cJSON_Delete);
    JsonPtr suites(cJSON_CreateArray(), &cJSON_Delete);
    JsonPtr phases(cJSON_CreateObject(), &cJSON_Delete);
    if (root == nullptr || identity == nullptr || suites == nullptr || phases == nullptr) {
        return nullptr;
    }
    for (const auto& suite : state.suites) {
        cJSON* json = SuiteToJson(suite);
        if (json == nullptr) {
            return nullptr;
        }
        cJSON_AddItemToArray(suites.get(), json);
    }
    for (const auto& phase : state.phaseDurationsMs) {
        if (!AddUInt(phases.get(), phase.first.c_str(), phase.second)) {
            return nullptr;
        }
    }
    cJSON_AddItemToObject(root.get(), "identity", identity.release());
    cJSON_AddItemToObject(root.get(), "suites", suites.release());
    cJSON_AddItemToObject(root.get(), "phaseDurationsMs", phases.release());
    const bool valid = AddUInt(root.get(), "schemaVersion", state.schemaVersion) &&
        AddString(root.get(), "runId", state.runId) && AddString(root.get(), "outputRoot", state.outputRoot) &&
        AddString(root.get(), "startTime", state.startTime) &&
        AddString(root.get(), "endTime", state.endTime) && AddBool(root.get(), "finished", state.finished);
    return valid ? root.release() : nullptr;
}

bool ParseCaseInfo(const cJSON* object, GraphicTestCaseInfo& info, std::string& error)
{
    return cJSON_IsObject(object) && ReadString(object, "suite", info.suite, error) &&
        ReadString(object, "name", info.name, error) && ReadString(object, "type", info.type, error) &&
        ReadMode(object, "mode", info.mode, error) && ReadBool(object, "isMultiple", info.isMultiple, error) &&
        ReadString(object, "sourcePath", info.sourcePath, error);
}

bool ParseAttempt(const cJSON* object, AttemptRecord& attempt, std::string& error)
{
    return cJSON_IsObject(object) && ReadUInt32(object, "attempt", attempt.attempt, error) &&
        ReadStatus(object, "status", attempt.status, error) &&
        ReadBool(object, "diagnostic", attempt.diagnostic, error) &&
        ReadInt(object, "exitCode", attempt.exitCode, error) &&
        ReadInt(object, "termSignal", attempt.termSignal, error) &&
        ReadUInt64(object, "durationMs", attempt.durationMs, error) &&
        ReadString(object, "logPath", attempt.logPath, error) &&
        ReadString(object, "error", attempt.error, error) &&
        ReadString(object, "requestedCaptureMode", attempt.requestedCaptureMode, error) &&
        ReadString(object, "actualCaptureMode", attempt.actualCaptureMode, error) &&
        ReadString(object, "fallbackReason", attempt.fallbackReason, error) &&
        ReadString(object, "cropRect", attempt.cropRect, error) &&
        ReadUInt32(object, "expectedWidth", attempt.expectedWidth, error) &&
        ReadUInt32(object, "expectedHeight", attempt.expectedHeight, error) &&
        ReadString(object, "pngRelativePath", attempt.pngRelativePath, error) &&
        ReadUInt64(object, "pngSize", attempt.pngSize, error) &&
        ReadUInt32(object, "pngWidth", attempt.pngWidth, error) &&
        ReadUInt32(object, "pngHeight", attempt.pngHeight, error) &&
        ReadUInt32(object, "readyRetries", attempt.readyRetries, error) &&
        ReadOptionalBool(object, "captureUnstable", attempt.captureUnstable, error);
}

bool ParseCase(const cJSON* object, CaseRunRecord& item, std::string& error)
{
    if (!cJSON_IsObject(object) || !ParseCaseInfo(Member(object, "info"), item.info, error) ||
        !ReadStatus(object, "finalStatus", item.finalStatus, error) || !ReadBool(object, "flaky", item.flaky, error) ||
        !ReadString(object, "skipReason", item.skipReason, error) ||
        !ReadString(object, "missingPngReason", item.missingPngReason, error)) {
        return false;
    }
    const cJSON* attempts = Member(object, "attempts");
    if (!cJSON_IsArray(attempts)) {
        return Fail(error, "case attempts must be an array");
    }
    for (const cJSON* json = attempts->child; json != nullptr; json = json->next) {
        AttemptRecord attempt;
        if (!ParseAttempt(json, attempt, error)) {
            return false;
        }
        item.attempts.push_back(std::move(attempt));
    }
    return true;
}

bool ParseSuite(const cJSON* object, SuiteRunRecord& suite, std::string& error)
{
    if (!cJSON_IsObject(object) || !ReadString(object, "name", suite.name, error) ||
        !ReadStatus(object, "status", suite.status, error) ||
        !ReadString(object, "activeCase", suite.activeCase, error) ||
        !ReadString(object, "error", suite.error, error)) {
        return false;
    }
    const cJSON* cases = Member(object, "cases");
    if (!cJSON_IsArray(cases)) {
        return Fail(error, "suite cases must be an array");
    }
    for (const cJSON* json = cases->child; json != nullptr; json = json->next) {
        CaseRunRecord item;
        if (!ParseCase(json, item, error)) {
            return false;
        }
        suite.cases.push_back(std::move(item));
    }
    return true;
}

bool ParseIdentity(const cJSON* object, RunIdentity& identity, std::string& error)
{
    return cJSON_IsObject(object) && ReadString(object, "testBuild", identity.testBuild, error) &&
        ReadUInt64(object, "testBinarySize", identity.testBinarySize, error) &&
        ReadInt64(object, "testBinaryMtime", identity.testBinaryMtime, error) &&
        ReadString(object, "product", identity.product, error) && ReadUInt32(object, "width", identity.width, error) &&
        ReadUInt32(object, "height", identity.height, error) &&
        ReadString(object, "renderMode", identity.renderMode, error) &&
        ReadString(object, "executionPolicy", identity.executionPolicy, error);
}

bool ParsePhases(const cJSON* object, std::map<std::string, uint64_t>& phases, std::string& error)
{
    if (!cJSON_IsObject(object)) {
        return Fail(error, "phaseDurationsMs must be an object");
    }
    for (const cJSON* item = object->child; item != nullptr; item = item->next) {
        if (item->string == nullptr || !cJSON_IsNumber(item) || !std::isfinite(item->valuedouble) ||
            item->valuedouble < 0 || item->valuedouble != std::floor(item->valuedouble) ||
            item->valuedouble > MAX_JSON_SAFE_INTEGER || item->string[0] == '\0') {
            return Fail(error, "invalid phase duration");
        }
        const uint64_t value = static_cast<uint64_t>(item->valuedouble);
        if (!phases.emplace(item->string, value).second) {
            return Fail(error, "duplicate phase duration");
        }
    }
    return true;
}

bool ParseState(const cJSON* root, EmulatorRunState& state, std::string& error)
{
    if (!cJSON_IsObject(root) || !ReadUInt32(root, "schemaVersion", state.schemaVersion, error) ||
        state.schemaVersion != CURRENT_SCHEMA_VERSION) {
        return Fail(error, "unsupported or missing state schemaVersion");
    }
    if (!ReadString(root, "runId", state.runId, error) || !ReadString(root, "outputRoot", state.outputRoot, error) ||
        !ParseIdentity(Member(root, "identity"), state.identity, error) ||
        !ReadString(root, "startTime", state.startTime, error) || !ReadString(root, "endTime", state.endTime, error) ||
        !ParsePhases(Member(root, "phaseDurationsMs"), state.phaseDurationsMs, error) ||
        !ReadBool(root, "finished", state.finished, error)) {
        return false;
    }
    const cJSON* suites = Member(root, "suites");
    if (!cJSON_IsArray(suites)) {
        return Fail(error, "state suites must be an array");
    }
    for (const cJSON* json = suites->child; json != nullptr; json = json->next) {
        SuiteRunRecord suite;
        if (!ParseSuite(json, suite, error)) {
            return false;
        }
        state.suites.push_back(std::move(suite));
    }
    return true;
}

} // namespace

std::string_view ExecutionStatusToString(ExecutionStatus status)
{
    switch (status) {
        case ExecutionStatus::NOT_RUN: return "not_run";
        case ExecutionStatus::PENDING: return "pending";
        case ExecutionStatus::RUNNING: return "running";
        case ExecutionStatus::PASSED: return "passed";
        case ExecutionStatus::FAILED: return "failed";
        case ExecutionStatus::TIMEOUT: return "timeout";
        case ExecutionStatus::CRASH: return "crash";
        case ExecutionStatus::SKIPPED: return "skipped";
        case ExecutionStatus::MANUAL: return "manual";
        case ExecutionStatus::INFRA_ERROR: return "infra_error";
        case ExecutionStatus::CANCELLED: return "cancelled";
        default: return "unknown";
    }
}

bool ExecutionStatusFromString(const std::string& value, ExecutionStatus& status)
{
    static constexpr ExecutionStatus STATUSES[] = { ExecutionStatus::NOT_RUN, ExecutionStatus::PENDING,
        ExecutionStatus::RUNNING, ExecutionStatus::PASSED, ExecutionStatus::FAILED, ExecutionStatus::TIMEOUT,
        ExecutionStatus::CRASH, ExecutionStatus::SKIPPED, ExecutionStatus::MANUAL, ExecutionStatus::INFRA_ERROR,
        ExecutionStatus::CANCELLED };
    for (const auto candidate : STATUSES) {
        if (value == ExecutionStatusToString(candidate)) {
            status = candidate;
            return true;
        }
    }
    return false;
}

std::string SerializeEmulatorRunState(const EmulatorRunState& state)
{
    JsonPtr root(StateToJson(state), &cJSON_Delete);
    if (root == nullptr) {
        return {};
    }
    std::unique_ptr<char, decltype(&cJSON_free)> text(cJSON_PrintUnformatted(root.get()), &cJSON_free);
    return text == nullptr ? std::string() : std::string(text.get());
}

bool SaveEmulatorRunState(const EmulatorRunState& state, const std::string& path, std::string& error)
{
    const std::string json = SerializeEmulatorRunState(state);
    if (json.empty()) {
        return Fail(error, "cannot serialize emulator run state with schemaVersion=1");
    }
    return WriteTextFileAtomic(path, json, &error);
}

bool LoadEmulatorRunState(const std::string& path, EmulatorRunState& state, std::string& error)
{
    std::string text;
    if (!ReadTextFile(path, text, &error)) {
        return false;
    }
    JsonPtr root(cJSON_ParseWithOpts(text.c_str(), nullptr, 1), &cJSON_Delete);
    if (root == nullptr) {
        return Fail(error, "invalid emulator run state JSON");
    }
    EmulatorRunState parsed;
    if (!ParseState(root.get(), parsed, error)) {
        return false;
    }
    state = std::move(parsed);
    error.clear();
    return true;
}

} // namespace Rosen
} // namespace OHOS
