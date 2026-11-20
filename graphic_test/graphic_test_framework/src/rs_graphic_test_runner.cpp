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
#include "rs_graphic_test_runner_log.h"

#include <algorithm>
#include <cctype>
#include <ctime>
#include <filesystem>
#include <iomanip>
#include <limits>
#include <map>
#include <set>
#include <sstream>
#include <sys/stat.h>
#include <tuple>
#include <utility>

#include "rs_graphic_test_catalog.h"
#include "rs_graphic_test_environment.h"
#include "rs_graphic_test_file.h"
#include "rs_graphic_test_health.h"
#include "rs_graphic_test_png.h"
#include "rs_graphic_test_process.h"

namespace OHOS {
namespace Rosen {
namespace {

constexpr const char* STATE_FILE_NAME = "run_state.json";
constexpr const char* LOG_FILE_NAME = "process.log";
constexpr const char* EXCLUDE_FILE_NAME = "exclude_cases.txt";
constexpr uint64_t MAX_TIMEOUT_MS = std::numeric_limits<uint32_t>::max();

// Pre-attempt case statuses, kept locally so a progress-free diagnostic attempt can restore them.
using StatusSnapshot = std::map<CaseRunRecord*, ExecutionStatus>;

struct Session {
    const EmulatorRunConfig& config;
    IProcessController& processController;
    IEmulatorHealthProbe* healthProbe;
    EmulatorRunState& state;
    std::string runDirectory;
    std::string statePath;
    std::string previousSuiteLog;
    std::string& error;
};

struct AttemptOutcome {
    bool abnormal = false;
    bool infrastructureFailure = false;
    bool persistenceFailure = false;
    // An abnormal exit that produced no new case records at all; restarting cannot make progress.
    bool noProgress = false;
    std::string activeCase;
};
bool Fail(std::string& error, const std::string& message)
{
    error = message;
    return false;
}

std::string JoinPath(const std::string& left, const std::string& right)
{
    return (std::filesystem::path(left) / right).string();
}

bool IsAbsoluteSafePath(const std::string& path)
{
    return path.size() > 1 && path.front() == '/' && IsSafeRelativePath(path.substr(1));
}

bool IsSinglePathComponent(const std::string& value)
{
    return IsSafeRelativePath(value) && value.find('/') == std::string::npos;
}

bool ValidateConfig(const EmulatorRunConfig& config, std::string& error)
{
    if (!IsSinglePathComponent(config.runId) || !IsAbsoluteSafePath(config.outputRoot) ||
        !IsAbsoluteSafePath(config.testBinary)) {
        return Fail(error, "runId, outputRoot, or testBinary is unsafe");
    }
    if (!config.workingDirectory.empty() && !IsAbsoluteSafePath(config.workingDirectory)) {
        return Fail(error, "working directory is unsafe");
    }
    if (config.suiteTimeoutMs == 0 || config.suiteTimeoutMs > MAX_TIMEOUT_MS || config.expectedWidth == 0 ||
        config.expectedHeight == 0 || config.maxPngBytes == 0 || config.readyMaxRetries == 0) {
        return Fail(error, "timeout, display, PNG, or ready retry limit is invalid");
    }
    std::set<std::string> selected;
    for (const auto& suite : config.suites) {
        if (!IsSinglePathComponent(suite) || !selected.insert(suite).second) {
            return Fail(error, "suite selection is invalid or contains duplicates");
        }
    }
    return true;
}

std::string MakeExecutionPolicy(const EmulatorRunConfig& config)
{
    std::ostringstream policy;
    policy << "suiteTimeoutMs=" << config.suiteTimeoutMs << ";maxPngBytes=" << config.maxPngBytes <<
        ";readyMaxRetries=" << config.readyMaxRetries <<
        ";readyDelayMs=" << config.readyDelayMs << ";displayFallback=" << config.displayFallback <<
        ";includeManual=" << config.includeManual <<
        ";skipDisplayCheck=" << config.skipDisplayCheck << ";workingDirectory=" << config.workingDirectory <<
        ";flushSettleMs=" << config.flushSettleMs <<
        ";suites=";
    for (const auto& suite : config.suites) {
        policy << suite << ',';
    }
    return policy.str();
}

bool BuildIdentity(const EmulatorRunConfig& config, RunIdentity& identity, std::string& error)
{
    identity.testBuild = config.testBinary;
    identity.product = EMULATOR_PRODUCT_NAME;
    identity.width = config.expectedWidth;
    identity.height = config.expectedHeight;
    identity.renderMode = "divided";
    identity.executionPolicy = MakeExecutionPolicy(config);
    if (!FileSize(config.testBinary, identity.testBinarySize, &error)) {
        return false;
    }
    struct stat info {};
    if (stat(config.testBinary.c_str(), &info) != 0) {
        error = "cannot read test binary modification time";
        return false;
    }
    identity.testBinaryMtime = static_cast<int64_t>(info.st_mtime);
    return true;
}

bool SelectSuites(const TestCatalog& catalog, const EmulatorRunConfig& config,
    std::vector<std::string>& selected, std::string& error)
{
    selected = catalog.Suites();
    for (const auto& requested : config.suites) {
        if (std::find(selected.begin(), selected.end(), requested) == selected.end()) {
            return Fail(error, "requested suite is absent from catalog: " + requested);
        }
    }
    if (!config.suites.empty()) {
        const auto matches = [&config](const std::string& suite) {
            return std::find(config.suites.begin(), config.suites.end(), suite) != config.suites.end();
        };
        selected.erase(std::remove_if(selected.begin(), selected.end(),
            [&matches](const std::string& suite) { return !matches(suite); }), selected.end());
    }
    return !selected.empty() || Fail(error, "catalog contains no selected suites");
}

CaseRunRecord MakeCaseRecord(const EmulatorRunConfig& config, const GraphicTestCaseInfo& info)
{
    CaseRunRecord record;
    record.info = info;
    record.finalStatus = ExecutionStatus::PENDING;
    if (info.mode == GraphicCaseMode::MANUAL && !config.includeManual) {
        record.finalStatus = ExecutionStatus::MANUAL;
        record.skipReason = "manual case is listed but not executed without includeManual";
    }
    return record;
}

EmulatorRunState MakeFreshState(const EmulatorRunConfig& config, const TestCatalog& catalog,
    const std::vector<std::string>& suites, const RunIdentity& identity)
{
    EmulatorRunState state;
    state.runId = config.runId;
    state.outputRoot = config.outputRoot;
    state.identity = identity;
    for (const auto& suiteName : suites) {
        SuiteRunRecord suite;
        suite.name = suiteName;
        for (const auto& info : catalog.CasesForSuite(suiteName)) {
            suite.cases.push_back(MakeCaseRecord(config, info));
        }
        state.suites.push_back(std::move(suite));
    }
    return state;
}

std::string CurrentUtcTime()
{
    const std::time_t now = std::time(nullptr);
    std::tm utc {};
    gmtime_r(&now, &utc);
    std::ostringstream text;
    text << std::put_time(&utc, "%Y-%m-%dT%H:%M:%SZ");
    return text.str();
}

bool SameIdentity(const RunIdentity& left, const RunIdentity& right)
{
    return std::tie(left.testBuild, left.testBinarySize, left.testBinaryMtime, left.product, left.width,
        left.height, left.renderMode, left.executionPolicy) ==
        std::tie(right.testBuild, right.testBinarySize, right.testBinaryMtime, right.product, right.width,
        right.height, right.renderMode, right.executionPolicy);
}

bool SameCaseInfo(const GraphicTestCaseInfo& left, const GraphicTestCaseInfo& right)
{
    return std::tie(left.suite, left.name, left.type, left.mode, left.isMultiple, left.sourcePath) ==
        std::tie(right.suite, right.name, right.type, right.mode, right.isMultiple, right.sourcePath);
}

bool ValidateResumedLayout(const EmulatorRunState& resumed, const EmulatorRunState& expected, std::string& error)
{
    if (resumed.suites.size() != expected.suites.size()) {
        return Fail(error, "resumed suite layout differs from catalog");
    }
    for (size_t index = 0; index < expected.suites.size(); ++index) {
        const auto& actualSuite = resumed.suites[index];
        const auto& expectedSuite = expected.suites[index];
        if (actualSuite.name != expectedSuite.name || actualSuite.cases.size() != expectedSuite.cases.size()) {
            return Fail(error, "resumed suite or case count differs from catalog");
        }
        for (size_t caseIndex = 0; caseIndex < expectedSuite.cases.size(); ++caseIndex) {
            if (!SameCaseInfo(actualSuite.cases[caseIndex].info, expectedSuite.cases[caseIndex].info)) {
                return Fail(error, "resumed case identity differs from catalog");
            }
        }
    }
    return true;
}

bool PathExists(const std::string& path)
{
    std::error_code error;
    return std::filesystem::exists(path, error) && !error;
}

std::string FindUnusedRunId(const EmulatorRunConfig& config)
{
    if (!PathExists(JoinPath(config.outputRoot, config.runId))) {
        return config.runId;
    }
    for (uint32_t suffix = 1; suffix != 0; ++suffix) {
        std::string candidate = config.runId + "-r" + std::to_string(suffix);
        if (!PathExists(JoinPath(config.outputRoot, candidate))) {
            return candidate;
        }
    }
    return {};
}

bool UseResumedState(Session& session, EmulatorRunState& resumed, const EmulatorRunState& expected)
{
    if (resumed.runId != session.config.runId || resumed.outputRoot != session.config.outputRoot) {
        return Fail(session.error, "resumed runId or outputRoot does not match configuration");
    }
    if (!ValidateResumedLayout(resumed, expected, session.error)) {
        return false;
    }
    session.state = std::move(resumed);
    session.state.finished = false;
    session.state.endTime.clear();
    for (auto& suite : session.state.suites) {
        suite.status = ExecutionStatus::PENDING;
        suite.activeCase.clear();
        suite.error.clear();
        for (auto& item : suite.cases) {
            if (item.finalStatus == ExecutionStatus::RUNNING) {
                item.finalStatus = ExecutionStatus::PENDING;
            }
        }
    }
    return true;
}

bool PrepareState(Session& session, const TestCatalog& catalog, const std::vector<std::string>& suites)
{
    EmulatorRunState expected = MakeFreshState(session.config, catalog, suites, session.state.identity);
    const std::string originalDirectory = JoinPath(session.config.outputRoot, session.config.runId);
    const std::string originalStatePath = JoinPath(originalDirectory, STATE_FILE_NAME);
    if (session.config.resume && PathExists(originalStatePath)) {
        EmulatorRunState resumed;
        if (!LoadEmulatorRunState(originalStatePath, resumed, session.error)) {
            return false;
        }
        if (SameIdentity(resumed.identity, session.state.identity)) {
            if (!UseResumedState(session, resumed, expected)) {
                return false;
            }
        } else {
            session.state = std::move(expected);
            const std::string unused = FindUnusedRunId(session.config);
            if (unused.empty()) {
                return Fail(session.error, "cannot allocate an unused runId");
            }
            session.state.runId = unused;
        }
    } else {
        session.state = std::move(expected);
        const std::string unused = FindUnusedRunId(session.config);
        if (unused.empty()) {
            return Fail(session.error, "cannot allocate an unused runId");
        }
        session.state.runId = unused;
    }
    session.runDirectory = JoinPath(session.config.outputRoot, session.state.runId);
    session.statePath = JoinPath(session.runDirectory, STATE_FILE_NAME);
    if (session.state.startTime.empty()) {
        session.state.startTime = CurrentUtcTime();
    }
    return EnsureDirectory(session.runDirectory, &session.error) &&
        SaveEmulatorRunState(session.state, session.statePath, session.error);
}

void AccumulatePhaseDurations(Session& session, const ParsedLog& parsed)
{
    for (const auto& phase : parsed.phaseDurationsMs) {
        uint64_t& total = session.state.phaseDurationsMs[phase.first];
        if (phase.second <= std::numeric_limits<uint64_t>::max() - total) {
            total += phase.second;
        }
    }
}

std::vector<CaseRunRecord*> EligibleCases(SuiteRunRecord& suite, bool continuation)
{
    std::vector<CaseRunRecord*> result;
    for (auto& item : suite.cases) {
        const ExecutionStatus status = item.finalStatus;
        const bool pending = status == ExecutionStatus::PENDING || status == ExecutionStatus::NOT_RUN ||
            status == ExecutionStatus::RUNNING;
        const bool retry = !continuation && status != ExecutionStatus::PASSED && status != ExecutionStatus::SKIPPED &&
            status != ExecutionStatus::MANUAL;
        if (pending || retry) {
            result.push_back(&item);
        }
    }
    return result;
}

std::string QualifiedName(const CaseRunRecord& item)
{
    return MakeQualifiedCaseName(item.info.suite, item.info.name);
}

std::string MakeExcludeFile(const SuiteRunRecord& suite, const std::vector<CaseRunRecord*>& eligible)
{
    std::set<const CaseRunRecord*> running(eligible.begin(), eligible.end());
    std::ostringstream content;
    for (const auto& item : suite.cases) {
        if (running.count(&item) == 0) {
            content << QualifiedName(item) << '\n';
        }
    }
    return content.str();
}

ProcessSpec MakeProcessSpec(const Session& session, const SuiteRunRecord& suite, const std::string& directory,
    const std::string& excludePath, const std::string& diagnosticCase)
{
    ProcessSpec spec;
    spec.executable = session.config.testBinary;
    spec.args = { "-emulator-unit", "--suite", suite.name, "--output-dir", directory,
        "--expected-width", std::to_string(session.config.expectedWidth),
        "--expected-height", std::to_string(session.config.expectedHeight),
        "--max-png-bytes", std::to_string(session.config.maxPngBytes),
        "--ready-max-retries", std::to_string(session.config.readyMaxRetries),
        "--ready-delay-ms", std::to_string(session.config.readyDelayMs),
        "--flush-settle-ms", std::to_string(session.config.flushSettleMs),
        "--exclude-cases-file", excludePath };
    if (!diagnosticCase.empty()) {
        spec.args.insert(spec.args.end(), { "--case", diagnosticCase });
    }
    if (session.config.displayFallback) {
        spec.args.push_back("--display-fallback");
    }
    if (session.config.includeManual) {
        spec.args.push_back("--include-manual");
    }
    if (!session.config.workingDirectory.empty()) {
        spec.args.insert(spec.args.end(), { "--working-directory", session.config.workingDirectory });
    }
    spec.logPath = JoinPath(directory, LOG_FILE_NAME);
    spec.timeoutMs = static_cast<uint32_t>(session.config.suiteTimeoutMs);
    spec.workingDirectory = session.config.workingDirectory;
    return spec;
}

std::string RelativeLogPath(const Session& session, const ProcessSpec& spec)
{
    const std::string prefix = session.runDirectory + "/";
    return spec.logPath.compare(0, prefix.size(), prefix) == 0 ? spec.logPath.substr(prefix.size()) : spec.logPath;
}

ExecutionStatus ActiveFailureStatus(const ProcessResult& result)
{
    if (result.timedOut) {
        return ExecutionStatus::TIMEOUT;
    }
    return result.spawnError ? ExecutionStatus::INFRA_ERROR : ExecutionStatus::CRASH;
}

std::string ProcessFailureReason(const ProcessResult& result)
{
    if (!result.error.empty()) {
        return result.error;
    }
    if (result.timedOut) {
        return "suite process timed out";
    }
    if (result.termSignal != 0) {
        return "suite process terminated by signal " + std::to_string(result.termSignal);
    }
    return "suite process exited with code " + std::to_string(result.exitCode) + " before completing all cases";
}

bool PreviousFailure(const CaseRunRecord& item)
{
    return std::any_of(item.attempts.begin(), item.attempts.end(), [](const AttemptRecord& attempt) {
        return attempt.status == ExecutionStatus::FAILED || attempt.status == ExecutionStatus::TIMEOUT ||
            attempt.status == ExecutionStatus::CRASH || attempt.status == ExecutionStatus::INFRA_ERROR;
    });
}

bool IsPathWithin(const std::filesystem::path& path, const std::filesystem::path& root)
{
    const auto normalizedPath = path.lexically_normal();
    const auto normalizedRoot = root.lexically_normal();
    auto pathPart = normalizedPath.begin();
    for (auto rootPart = normalizedRoot.begin(); rootPart != normalizedRoot.end(); ++rootPart, ++pathPart) {
        if (pathPart == normalizedPath.end() || *pathPart != *rootPart) {
            return false;
        }
    }
    return true;
}

void PopulatePng(const Session& session, const std::string& attemptDirectory, const std::string& reportedPath,
    CaseRunRecord& item, AttemptRecord& attempt)
{
    if (reportedPath.empty()) {
        return;
    }
    std::filesystem::path png = reportedPath;
    if (png.is_relative()) {
        if (!IsSafeRelativePath(reportedPath)) {
            item.missingPngReason = "reported PNG path is unsafe";
            return;
        }
        png = std::filesystem::path(attemptDirectory) / png;
    }
    if (!IsPathWithin(png, attemptDirectory)) {
        item.missingPngReason = "reported PNG path escapes the attempt directory";
        return;
    }
    std::string error;
    PngFileInfo info;
    if (!ReadPngFileHeader(png.string(), info, error) || info.size > session.config.maxPngBytes) {
        item.missingPngReason = error.empty() ? "reported PNG exceeds maxPngBytes" : error;
        return;
    }
    if ((attempt.expectedWidth != 0 && info.width != attempt.expectedWidth) ||
        (attempt.expectedHeight != 0 && info.height != attempt.expectedHeight)) {
        item.missingPngReason = "PNG size mismatch: expected " + std::to_string(attempt.expectedWidth) + "x" +
            std::to_string(attempt.expectedHeight) + ", actual " + std::to_string(info.width) + "x" +
            std::to_string(info.height);
        return;
    }
    attempt.pngSize = info.size;
    attempt.pngWidth = info.width;
    attempt.pngHeight = info.height;
    attempt.pngRelativePath = png.string().substr(session.runDirectory.size() + 1);
}

AttemptRecord MakeAttempt(const Session& session, const ProcessSpec& spec, const ProcessResult& result,
    const CaseRunRecord& item, uint32_t number, ExecutionStatus status, bool diagnostic)
{
    AttemptRecord attempt;
    attempt.attempt = number;
    attempt.status = status;
    attempt.diagnostic = diagnostic;
    attempt.exitCode = result.exitCode;
    attempt.termSignal = result.termSignal;
    attempt.durationMs = result.durationMs;
    attempt.logPath = RelativeLogPath(session, spec);
    attempt.error = result.error;
    attempt.requestedCaptureMode = item.info.mode == GraphicCaseMode::DYNAMIC ? "display" : "surface";
    if (IsAutomaticCaptureCandidate(item.info.mode)) {
        attempt.expectedWidth = session.config.expectedWidth;
        attempt.expectedHeight = session.config.expectedHeight;
    }
    return attempt;
}

void RecordCaseAttempt(const Session& session, const ProcessSpec& spec, const ProcessResult& result,
    CaseRunRecord& item, const CaseProgress& progress, uint32_t number, ExecutionStatus status, bool diagnostic,
    const std::string& attemptDirectory)
{
    const bool hadFailure = PreviousFailure(item);
    AttemptRecord attempt = MakeAttempt(session, spec, result, item, number, status, diagnostic);
    attempt.durationMs = progress.durationMs != 0 ? progress.durationMs : result.durationMs;
    attempt.actualCaptureMode = progress.captureMode.empty() ? (progress.pngPath.empty() ? "none" : "unknown") :
        progress.captureMode;
    attempt.fallbackReason = progress.fallbackReason;
    attempt.readyRetries = progress.readyRetries;
    attempt.captureUnstable = progress.captureUnstable;
    attempt.cropRect = progress.cropRect;
    if (IsAutomaticCaptureCandidate(item.info.mode)) {
        attempt.expectedWidth = progress.expectedWidth != 0 ? progress.expectedWidth : session.config.expectedWidth;
        attempt.expectedHeight = progress.expectedHeight != 0 ? progress.expectedHeight : session.config.expectedHeight;
    }
    if (status == ExecutionStatus::FAILED || status == ExecutionStatus::TIMEOUT || status == ExecutionStatus::CRASH ||
        status == ExecutionStatus::INFRA_ERROR) {
        attempt.error = ProcessFailureReason(result);
    }
    item.missingPngReason.clear();
    PopulatePng(session, attemptDirectory, progress.pngPath, item, attempt);
    item.attempts.push_back(std::move(attempt));
    item.finalStatus = status;
    item.flaky = item.flaky || (status == ExecutionStatus::PASSED && hadFailure);
}

const CaseProgress* FindProgress(const ParsedLog& parsed, const CaseRunRecord& item)
{
    const auto found = parsed.cases.find(QualifiedName(item));
    return found == parsed.cases.end() ? nullptr : &found->second;
}

void MarkUnreportedInfra(const Session& session, const ProcessSpec& spec, const ProcessResult& result,
    const std::vector<CaseRunRecord*>& eligible, const ParsedLog& parsed, uint32_t number,
    const std::string& directory, const std::string& reason, bool diagnostic)
{
    for (auto* item : eligible) {
        const auto found = parsed.cases.find(QualifiedName(*item));
        const bool terminal = found != parsed.cases.end() && found->second.status != ExecutionStatus::RUNNING &&
            found->second.status != ExecutionStatus::NOT_RUN;
        if (!terminal) {
            CaseProgress progress;
            RecordCaseAttempt(session, spec, result, *item, progress, number, ExecutionStatus::INFRA_ERROR, diagnostic,
                directory);
            item->attempts.back().error = reason;
        }
    }
}

// The child died before reporting any case (bad exclude file, init crash, SetUpTestCase crash).
// A main attempt marks every unreported case INFRA_ERROR so the runner never loops on a hopeless
// restart; a diagnostic attempt leaves the active case's earlier record for RunChildAndApply
// to restore.
AttemptOutcome MarkNoProgressAttempt(const Session& session, const ProcessSpec& spec,
    const ProcessResult& result, const std::vector<CaseRunRecord*>& eligible, const ParsedLog& parsed,
    uint32_t number, const std::string& directory, bool diagnostic)
{
    AttemptOutcome outcome;
    if (!diagnostic) {
        MarkUnreportedInfra(session, spec, result, eligible, parsed, number, directory,
            ProcessFailureReason(result), diagnostic);
    }
    outcome.noProgress = true;
    return outcome;
}

AttemptOutcome ApplyProcessResult(const Session& session, SuiteRunRecord& suite,
    const std::vector<CaseRunRecord*>& eligible, const ProcessSpec& spec, const ProcessResult& result,
    const ParsedLog& parsed, uint32_t number, const std::string& directory, bool diagnostic)
{
    AttemptOutcome outcome;
    std::set<std::string> observed;
    for (auto* item : eligible) {
        const CaseProgress* progress = FindProgress(parsed, *item);
        if (progress == nullptr || progress->status == ExecutionStatus::RUNNING ||
            progress->status == ExecutionStatus::NOT_RUN) {
            continue;
        }
        RecordCaseAttempt(session, spec, result, *item, *progress, number, progress->status, diagnostic, directory);
        observed.insert(QualifiedName(*item));
    }
    const bool interrupted = result.timedOut || result.termSignal != 0 || result.exitCode != 0;
    const bool hadUnreported = observed.size() != eligible.size();
    if (!parsed.lastRun.empty()) {
        auto active = std::find_if(eligible.begin(), eligible.end(), [&parsed](const CaseRunRecord* item) {
            return QualifiedName(*item) == parsed.lastRun;
        });
        if (active != eligible.end() && observed.count(parsed.lastRun) == 0 && interrupted) {
            const ExecutionStatus status = ActiveFailureStatus(result);
            RecordCaseAttempt(session, spec, result, **active, parsed.cases.at(parsed.lastRun), number, status,
                diagnostic, directory);
            observed.insert(parsed.lastRun);
            outcome.activeCase = (*active)->info.name;
        }
    }
    outcome.abnormal = interrupted && hadUnreported;
    outcome.infrastructureFailure = !interrupted && hadUnreported;
    if (outcome.abnormal && observed.empty()) {
        return MarkNoProgressAttempt(session, spec, result, eligible, parsed, number, directory, diagnostic);
    }
    if (outcome.infrastructureFailure) {
        MarkUnreportedInfra(session, spec, result, eligible, parsed, number, directory,
            "process completed without a complete gtest progress log", diagnostic);
        outcome.abnormal = false;
    }
    if (outcome.abnormal) {
        suite.error = ProcessFailureReason(result);
        suite.activeCase = outcome.activeCase;
    }
    return outcome;
}

std::vector<CaseRunRecord*> AttemptCases(SuiteRunRecord& suite, bool continuation,
    const std::string& diagnosticCase)
{
    auto eligible = EligibleCases(suite, continuation);
    if (!diagnosticCase.empty()) {
        eligible.erase(std::remove_if(eligible.begin(), eligible.end(), [&diagnosticCase](const CaseRunRecord* item) {
            return item->info.name != diagnosticCase;
        }), eligible.end());
    }
    return eligible;
}

StatusSnapshot SnapshotStatuses(const std::vector<CaseRunRecord*>& eligible)
{
    StatusSnapshot snapshot;
    for (auto* item : eligible) {
        snapshot[item] = item->finalStatus;
    }
    return snapshot;
}

void RestoreStatuses(const std::vector<CaseRunRecord*>& eligible, const StatusSnapshot& snapshot)
{
    for (auto* item : eligible) {
        const auto saved = snapshot.find(item);
        if (saved != snapshot.end()) {
            item->finalStatus = saved->second;
        }
    }
}

AttemptOutcome PersistenceFailure()
{
    AttemptOutcome failed;
    failed.persistenceFailure = true;
    return failed;
}

bool PrepareAttemptDirectory(const Session& session, const SuiteRunRecord& suite,
    const std::vector<CaseRunRecord*>& eligible, uint32_t number, const std::string& diagnosticCase,
    std::string& directory, std::string& excludePath)
{
    directory = JoinPath(JoinPath(session.runDirectory, suite.name), "attempt" + std::to_string(number));
    excludePath = JoinPath(directory, EXCLUDE_FILE_NAME);
    return EnsureDirectory(directory, &session.error) && WriteTextFileAtomic(excludePath,
        diagnosticCase.empty() ? MakeExcludeFile(suite, eligible) : std::string(), &session.error);
}

AttemptOutcome HandleUnreadableLog(Session& session, SuiteRunRecord& suite, const ProcessSpec& spec,
    const ProcessResult& result, const std::vector<CaseRunRecord*>& eligible, uint32_t number,
    const std::string& directory, const std::string& diagnosticCase)
{
    if (result.spawnError) {
        session.error = result.error;
    }
    suite.error = session.error;
    MarkUnreportedInfra(session, spec, result, eligible, {}, number, directory, session.error,
        !diagnosticCase.empty());
    AttemptOutcome failed;
    failed.infrastructureFailure = true;
    return failed;
}

AttemptOutcome RunChildAndApply(Session& session, SuiteRunRecord& suite,
    const std::vector<CaseRunRecord*>& eligible, const ProcessSpec& spec, uint32_t number,
    const std::string& directory, const std::string& diagnosticCase, const StatusSnapshot& snapshot)
{
    const ProcessResult result = session.processController.Run(spec);
    session.previousSuiteLog = spec.logPath;
    session.state.phaseDurationsMs["execution"] += result.durationMs;
    std::string log;
    if (result.spawnError || !ReadTextFile(spec.logPath, log, &session.error)) {
        return HandleUnreadableLog(session, suite, spec, result, eligible, number, directory, diagnosticCase);
    }
    suite.activeCase.clear();
    suite.error.clear();
    const ParsedLog parsed = ParseLog(log);
    AccumulatePhaseDurations(session, parsed);
    AttemptOutcome outcome = ApplyProcessResult(session, suite, eligible, spec, result, parsed, number, directory,
        !diagnosticCase.empty());
    if (outcome.noProgress && !diagnosticCase.empty()) {
        // The diagnostic child died before reporting; restore pre-attempt case statuses.
        RestoreStatuses(eligible, snapshot);
    }
    return outcome;
}

AttemptOutcome ExecuteAttempt(Session& session, SuiteRunRecord& suite, uint32_t number, bool continuation,
    const std::string& diagnosticCase)
{
    const auto eligible = AttemptCases(suite, continuation, diagnosticCase);
    if (eligible.empty()) {
        return AttemptOutcome {};
    }
    const StatusSnapshot snapshot = SnapshotStatuses(eligible);
    std::string directory;
    std::string excludePath;
    if (!PrepareAttemptDirectory(session, suite, eligible, number, diagnosticCase, directory, excludePath)) {
        return PersistenceFailure();
    }
    const ProcessSpec spec = MakeProcessSpec(session, suite, directory, excludePath, diagnosticCase);
    for (auto* item : eligible) {
        item->finalStatus = ExecutionStatus::PENDING;
    }
    suite.status = ExecutionStatus::RUNNING;
    suite.activeCase = diagnosticCase;
    if (!SaveEmulatorRunState(session.state, session.statePath, session.error)) {
        return PersistenceFailure();
    }
    return RunChildAndApply(session, suite, eligible, spec, number, directory, diagnosticCase, snapshot);
}



uint32_t NextAttemptNumber(const Session& session, const SuiteRunRecord& suite)
{
    uint32_t largest = 0;
    for (const auto& item : suite.cases) {
        for (const auto& attempt : item.attempts) {
            largest = std::max(largest, attempt.attempt);
        }
    }
    if (largest == std::numeric_limits<uint32_t>::max()) {
        return 0;
    }
    const std::string suiteDirectory = JoinPath(session.runDirectory, suite.name);
    for (uint32_t number = largest + 1; number != 0; number++) {
        if (!PathExists(JoinPath(suiteDirectory, "attempt" + std::to_string(number)))) {
            return number;
        }
        if (number == std::numeric_limits<uint32_t>::max()) {
            break;
        }
    }
    return 0;
}

void CancelUnfinished(SuiteRunRecord& suite)
{
    for (auto& item : suite.cases) {
        if (item.finalStatus == ExecutionStatus::PENDING || item.finalStatus == ExecutionStatus::NOT_RUN ||
            item.finalStatus == ExecutionStatus::RUNNING) {
            item.finalStatus = ExecutionStatus::CANCELLED;
            item.skipReason = "attempt budget exhausted before this case was resumed";
        }
    }
}

void UpdateSuiteStatus(SuiteRunRecord& suite)
{
    ExecutionStatus status = ExecutionStatus::PASSED;
    bool allManual = !suite.cases.empty();
    for (const auto& item : suite.cases) {
        allManual = allManual && item.finalStatus == ExecutionStatus::MANUAL;
        if (item.finalStatus == ExecutionStatus::INFRA_ERROR) {
            status = ExecutionStatus::INFRA_ERROR;
        } else if (item.finalStatus == ExecutionStatus::TIMEOUT && status != ExecutionStatus::INFRA_ERROR) {
            status = ExecutionStatus::TIMEOUT;
        } else if (item.finalStatus == ExecutionStatus::CRASH && status != ExecutionStatus::INFRA_ERROR &&
            status != ExecutionStatus::TIMEOUT) {
            status = ExecutionStatus::CRASH;
        } else if (item.finalStatus == ExecutionStatus::FAILED && status == ExecutionStatus::PASSED) {
            status = ExecutionStatus::FAILED;
        } else if ((item.finalStatus == ExecutionStatus::CANCELLED || item.finalStatus == ExecutionStatus::PENDING ||
            item.finalStatus == ExecutionStatus::NOT_RUN) && status == ExecutionStatus::PASSED) {
            status = ExecutionStatus::CANCELLED;
        }
    }
    suite.status = allManual ? ExecutionStatus::MANUAL : status;
    if (suite.status == ExecutionStatus::PASSED || suite.status == ExecutionStatus::MANUAL) {
        suite.error.clear();
        suite.activeCase.clear();
    }
}

void UpdateMissingPngReasons(SuiteRunRecord& suite)
{
    for (auto& item : suite.cases) {
        if (!IsAutomaticCaptureCandidate(item.info.mode) || item.finalStatus == ExecutionStatus::SKIPPED) {
            item.missingPngReason.clear();
            continue;
        }
        const bool hasPng = !item.attempts.empty() && !item.attempts.back().pngRelativePath.empty();
        if (hasPng) {
            item.missingPngReason.clear();
        } else if (item.missingPngReason.empty()) {
            item.missingPngReason = "no PNG in final attempt; final status is " +
                std::string(ExecutionStatusToString(item.finalStatus));
        }
    }
}

bool RunSuite(Session& session, SuiteRunRecord& suite)
{
    uint32_t number = NextAttemptNumber(session, suite);
    bool continuation = number > 1;
    if (continuation) {
        for (auto& item : suite.cases) {
            if (item.finalStatus == ExecutionStatus::FAILED || item.finalStatus == ExecutionStatus::TIMEOUT ||
                item.finalStatus == ExecutionStatus::CRASH || item.finalStatus == ExecutionStatus::INFRA_ERROR) {
                item.finalStatus = ExecutionStatus::PENDING;
            }
        }
    }
    while (number != 0 && !EligibleCases(suite, continuation).empty()) {
        AttemptOutcome outcome = ExecuteAttempt(session, suite, number, continuation, "");
        ++number;
        if (outcome.persistenceFailure) {
            return false;
        }
        if (!SaveEmulatorRunState(session.state, session.statePath, session.error)) {
            return false;
        }
        // A main attempt that records no case at all is hopeless; stop instead of restarting.
        if (outcome.noProgress) {
            suite.error = "child exited without reporting any case";
            break;
        }
        if (outcome.infrastructureFailure || !outcome.abnormal) {
            break;
        }
        if (!outcome.activeCase.empty()) {
            AttemptOutcome diagnostic = ExecuteAttempt(session, suite, number, false, outcome.activeCase);
            ++number;
            if (diagnostic.persistenceFailure) {
                return false;
            }
            if (!SaveEmulatorRunState(session.state, session.statePath, session.error)) {
                return false;
            }
            // The diagnostic outcome never drives the loop; the next round is always a continuation.
        }
        continuation = true;
    }
    CancelUnfinished(suite);
    UpdateSuiteStatus(suite);
    UpdateMissingPngReasons(suite);
    return SaveEmulatorRunState(session.state, session.statePath, session.error);
}

uint64_t PlannedImages(SuiteRunRecord& suite)
{
    const auto eligible = EligibleCases(suite, false);
    return static_cast<uint64_t>(std::count_if(eligible.begin(), eligible.end(), [](const CaseRunRecord* item) {
        return IsAutomaticCaptureCandidate(item->info.mode);
    }));
}

bool CheckSuitePreconditions(Session& session, SuiteRunRecord& suite, IEmulatorHealthProbe& probe)
{
    const EmulatorHealthStatus health = probe.Check();
    std::string healthError;
    if (ValidateSuiteHealth(health, healthError) &&
        CheckSpaceBudget(session.runDirectory, PlannedImages(suite), session.config.maxPngBytes, healthError)) {
        return true;
    }
    suite.status = ExecutionStatus::INFRA_ERROR;
    suite.error = healthError;
    session.state.finished = false;
    session.state.endTime = CurrentUtcTime();
    std::string persistenceError;
    if (!SaveEmulatorRunState(session.state, session.statePath, persistenceError)) {
        session.error = healthError + "; failed to save state: " + persistenceError;
    } else {
        session.error = healthError;
    }
    return false;
}

bool RunSuites(Session& session)
{
    DefaultEmulatorHealthProbe defaultProbe;
    IEmulatorHealthProbe* probe = session.healthProbe != nullptr ? session.healthProbe : &defaultProbe;
    for (auto& suite : session.state.suites) {
        if (!CheckSuitePreconditions(session, suite, *probe) || !RunSuite(session, suite)) {
            return false;
        }
    }
    session.state.finished = true;
    session.state.endTime = CurrentUtcTime();
    return true;
}

bool FinalizeRun(Session& session, bool runSucceeded)
{
    const std::string runError = session.error;
    std::string saveError;
    const bool saved = SaveEmulatorRunState(session.state, session.statePath, saveError);
    if (runSucceeded && saved) {
        session.error.clear();
        return true;
    }
    session.error = runSucceeded ? saveError : runError;
    if (!saved && !runSucceeded) {
        session.error += "; failed to save final state: " + saveError;
    }
    return false;
}

} // namespace

EmulatorRunner::EmulatorRunner(IProcessController& processController, IEmulatorHealthProbe* healthProbe)
    : processController_(processController), healthProbe_(healthProbe)
{}

bool EmulatorRunner::Run(const EmulatorRunConfig& config, const TestCatalog& catalog, EmulatorRunState& state,
    std::string& error)
{
    error.clear();
    if (!ValidateConfig(config, error)) {
        return false;
    }
    std::vector<std::string> suites;
    if (!SelectSuites(catalog, config, suites, error)) {
        return false;
    }
    EmulatorRunState candidate;
    if (!BuildIdentity(config, candidate.identity, error)) {
        return false;
    }
    Session session { config, processController_, healthProbe_, candidate, {}, {}, {}, error };
    if (!PrepareState(session, catalog, suites)) {
        return false;
    }
    const bool succeeded = FinalizeRun(session, RunSuites(session));
    state = std::move(candidate);
    return succeeded;
}

} // namespace Rosen
} // namespace OHOS
