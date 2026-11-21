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

#include <algorithm>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <unistd.h>

#include "rs_graphic_test_capture.h"
#include "rs_graphic_test_catalog.h"
#include "rs_graphic_test_emulator.h"
#include "rs_graphic_test_environment.h"
#include "rs_graphic_test_file.h"
#include "rs_graphic_test_process.h"
#include "rs_graphic_test_resource.h"
#include "rs_graphic_test_resource_table.h"
#include "rs_graphic_test_runner.h"

namespace OHOS {
namespace Rosen {
namespace {

using TextLines = std::vector<std::string>;

void AddIssue(TextLines& lines, const std::string& code, const std::string& message, const std::string& path = "")
{
    std::string line = "FAIL " + code + " " + message;
    if (!path.empty()) {
        line += " " + path;
    }
    lines.push_back(line);
}

bool AppendBinaryCheck(const EmulatorOptions& options, TextLines& lines)
{
    uint64_t size = 0;
    std::string error;
    if (!FileSize(options.testBinary, size, &error)) {
        AddIssue(lines, "binary_unavailable", error, options.testBinary);
        return false;
    }
    lines.push_back("INFO testBinary=" + options.testBinary + " size=" + std::to_string(size));
    return true;
}

bool AppendEnvironmentCheck(const EmulatorOptions& options, TextLines& lines)
{
    DisplayEnvironmentInfo info;
    std::string error;
    bool valid = true;
    if (!options.skipDisplayCheck && !ProbeDisplayEnvironment(info, error)) {
        AddIssue(lines, "display_unavailable", error);
        valid = false;
    } else if (!options.skipDisplayCheck && !ValidateEmulatorEnvironment(info,
        static_cast<int32_t>(options.expectedWidth), static_cast<int32_t>(options.expectedHeight), error)) {
        AddIssue(lines, "display_mismatch", error);
        valid = false;
    }
    lines.push_back("INFO product=" + info.product + " renderMode=" + info.renderMode +
        " width=" + std::to_string(info.width) + " height=" + std::to_string(info.height) +
        " displayCheck=" + (options.skipDisplayCheck ? "skipped" : "strict"));
    return valid;
}

bool AppendSpaceCheck(const EmulatorOptions& options, TextLines& lines)
{
    TestCatalog catalog;
    std::string error;
    if (!TestCatalog::FromRegistry(catalog, error)) {
        AddIssue(lines, "catalog_unavailable", error);
        return false;
    }
    uint64_t plannedImages = 0;
    for (const auto& testCase : catalog.Cases()) {
        if (!options.suites.empty() && std::find(options.suites.begin(), options.suites.end(), testCase.suite) ==
            options.suites.end()) {
            continue;
        }
        plannedImages += IsAutomaticCaptureCandidate(testCase.mode) ? 1 : 0;
    }
    SpaceInfo info;
    const bool valid = CheckSpaceBudget(options.outputRoot, plannedImages, options.maxPngBytes, error, &info);
    if (!valid) {
        AddIssue(lines, "space_unavailable", error, options.outputRoot);
    }
    lines.push_back("INFO space available=" + std::to_string(info.availableBytes) +
        " required=" + std::to_string(info.requiredBytes) +
        " plannedImages=" + std::to_string(info.plannedImages) +
        " maxBytesPerImage=" + std::to_string(info.maxBytesPerImage));
    return valid;
}

bool AppendResourceCheck(TextLines& lines, const std::vector<ResourceEntry>& entries)
{
    ResourceValidator validator;
    const bool valid = validator.ValidateDevice(entries);
    for (const auto& issue : validator.issues) {
        AddIssue(lines, issue.code, issue.message, issue.devicePath);
    }
    lines.push_back("INFO resources=" + std::to_string(entries.size()));
    return valid;
}

int RunPreflight(const EmulatorOptions& options)
{
    TextLines lines;
    const bool resourcesValid = AppendResourceCheck(lines, BuiltinResourceEntries());
    const bool binaryValid = AppendBinaryCheck(options, lines);
    const bool environmentValid = AppendEnvironmentCheck(options, lines);
    const bool spaceValid = AppendSpaceCheck(options, lines);
    for (const auto& line : lines) {
        std::cout << line << std::endl;
    }
    const bool passed = resourcesValid && binaryValid && environmentValid && spaceValid;
    std::cout << (passed ? "PASSED" : "FAILED") << std::endl;
    return passed ? EMULATOR_EXIT_SUCCESS : EMULATOR_EXIT_INFRA_ERROR;
}

std::string MakeRunId()
{
    const std::time_t now = std::time(nullptr);
    std::tm utc = {};
    gmtime_r(&now, &utc);
    std::ostringstream output;
    output << "graphic-" << std::put_time(&utc, "%Y%m%dT%H%M%SZ") << "-" << getpid();
    return output.str();
}

bool ValidateRunEnvironment(const EmulatorOptions& options, std::string& error)
{
    DisplayEnvironmentInfo info;
    if (!ProbeDisplayEnvironment(info, error) || !ValidateEmulatorProduct(info, error)) {
        return false;
    }
    if (!options.skipDisplayCheck && !ValidateEmulatorEnvironment(info,
        static_cast<int32_t>(options.expectedWidth), static_cast<int32_t>(options.expectedHeight), error)) {
        return false;
    }
    // Capture permission is not checked here: the child process sets its own native token in
    // SetUp and reports capture failures through the case log.
    return true;
}

bool ValidateRunResources(const std::vector<ResourceEntry>& entries, std::string& error)
{
    ResourceValidator validator;
    if (validator.ValidateDevice(entries)) {
        error.clear();
        return true;
    }
    std::ostringstream summary;
    for (const auto& issue : validator.issues) {
        summary << (issue.fatal ? "FATAL" : "WARN") << " [" << issue.code << "]";
        if (!issue.devicePath.empty()) {
            summary << ' ' << issue.devicePath;
        }
        summary << ": " << issue.message << '\n';
    }
    error = summary.str();
    return false;
}

EmulatorRunConfig MakeRunConfig(const EmulatorOptions& options)
{
    EmulatorRunConfig config;
    config.runId = options.runId.empty() ? MakeRunId() : options.runId;
    config.outputRoot = options.outputRoot;
    config.testBinary = options.testBinary;
    config.workingDirectory = options.workingDirectory;
    config.suites = options.suites;
    if (!options.suite.empty()) {
        config.suites.push_back(options.suite);
    }
    config.suiteTimeoutMs = options.suiteTimeoutMs;
    config.expectedWidth = static_cast<uint32_t>(options.expectedWidth);
    config.expectedHeight = static_cast<uint32_t>(options.expectedHeight);
    config.maxPngBytes = options.maxPngBytes;
    config.readyMaxRetries = static_cast<uint32_t>(options.readyMaxRetries);
    config.readyDelayMs = static_cast<uint32_t>(options.readyDelayMs);
    // 0 keeps the legacy callback wait; run-level unset falls back to the default settle value.
    config.flushSettleMs = static_cast<uint32_t>(
        options.flushSettleMs > 0 ? options.flushSettleMs : EmulatorOptions::DEFAULT_FLUSH_SETTLE_MS);
    config.resume = options.resume;
    config.displayFallback = options.displayFallback;
    config.skipDisplayCheck = options.skipDisplayCheck;
    config.includeManual = options.includeManual;
    return config;
}

bool StateHasFailures(const EmulatorRunState& state)
{
    for (const auto& suite : state.suites) {
        if (suite.status == ExecutionStatus::FAILED || suite.status == ExecutionStatus::TIMEOUT ||
            suite.status == ExecutionStatus::CRASH || suite.status == ExecutionStatus::INFRA_ERROR ||
            suite.status == ExecutionStatus::CANCELLED) {
            return true;
        }
    }
    return false;
}

int RunEmulatorRun(const EmulatorOptions& options)
{
    std::string error;
    if (!ValidateRunEnvironment(options, error)) {
        std::cerr << error << std::endl;
        return EMULATOR_EXIT_INFRA_ERROR;
    }
    TestCatalog catalog;
    if (!TestCatalog::FromRegistry(catalog, error)) {
        // A failed registry read leaves the catalog unusable; do not hand it to the runner.
        std::cerr << error << std::endl;
        return EMULATOR_EXIT_INFRA_ERROR;
    }
    auto config = MakeRunConfig(options);
    if (!ValidateRunResources(BuiltinResourceEntries(), error)) {
        std::cerr << error << std::endl;
        return EMULATOR_EXIT_INFRA_ERROR;
    }
    PosixProcessController processController;
    EmulatorRunner runner(processController);
    EmulatorRunState state;
    if (!runner.Run(config, catalog, state, error)) {
        std::cerr << error << std::endl;
        return EMULATOR_EXIT_INFRA_ERROR;
    }
    std::cout << "run completed: " << state.runId << ", output: " << state.outputRoot << "/" << state.runId <<
        std::endl;
    return StateHasFailures(state) ? EMULATOR_EXIT_FAILURE : EMULATOR_EXIT_SUCCESS;
}

} // namespace

int RunEmulatorCommand(const EmulatorOptions& options)
{
    switch (options.command) {
        case EmulatorCommand::PREFLIGHT:
            return RunPreflight(options);
        case EmulatorCommand::RUN:
            return RunEmulatorRun(options);
        default:
            std::cerr << "invalid emulator command" << std::endl;
            return EMULATOR_EXIT_INFRA_ERROR;
    }
}

} // namespace Rosen
} // namespace OHOS
