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

#ifndef RS_GRAPHIC_TEST_RUNNER_H
#define RS_GRAPHIC_TEST_RUNNER_H

#include <cstdint>
#include <map>
#include <string>
#include <string_view>
#include <vector>

#include "rs_graphic_test_types.h"

namespace OHOS {
namespace Rosen {

class TestCatalog;
class IProcessController;
class IEmulatorHealthProbe;

enum class ExecutionStatus : uint8_t {
    NOT_RUN,
    PENDING,
    RUNNING,
    PASSED,
    FAILED,
    TIMEOUT,
    CRASH,
    SKIPPED,
    MANUAL,
    INFRA_ERROR,
    CANCELLED,
};

struct AttemptRecord {
    uint32_t attempt = 0;
    ExecutionStatus status = ExecutionStatus::NOT_RUN;
    bool diagnostic = false;
    int exitCode = -1;
    int termSignal = 0;
    uint64_t durationMs = 0;
    std::string logPath;
    std::string error;
    std::string requestedCaptureMode = "surface";
    std::string actualCaptureMode = "none";
    std::string fallbackReason;
    std::string cropRect;
    uint32_t expectedWidth = 0;
    uint32_t expectedHeight = 0;
    std::string pngRelativePath;
    uint64_t pngSize = 0;
    uint32_t pngWidth = 0;
    uint32_t pngHeight = 0;
    uint32_t readyRetries = 0;
    bool captureUnstable = false;
};

struct CaseRunRecord {
    GraphicTestCaseInfo info;
    ExecutionStatus finalStatus = ExecutionStatus::NOT_RUN;
    bool flaky = false;
    std::string skipReason;
    std::string missingPngReason;
    std::vector<AttemptRecord> attempts;
};

struct SuiteRunRecord {
    std::string name;
    ExecutionStatus status = ExecutionStatus::PENDING;
    std::string activeCase;
    std::string error;
    std::vector<CaseRunRecord> cases;
};

// The binary identity uses size plus modification time; the compiled-in case table changes with the binary.
struct RunIdentity {
    std::string testBuild;
    uint64_t testBinarySize = 0;
    int64_t testBinaryMtime = 0;
    std::string product;
    uint32_t width = 0;
    uint32_t height = 0;
    std::string renderMode;
    std::string executionPolicy;
};

struct EmulatorRunConfig {
    std::string runId;
    std::string outputRoot = "/data/local/graphic_test_emulator";
    std::string testBinary = "/data/local/tmp/RSGraphicTest";
    std::string workingDirectory;
    std::vector<std::string> suites;
    uint64_t suiteTimeoutMs = 300000;
    uint32_t expectedWidth = 1200;
    uint32_t expectedHeight = 2000;
    uint64_t maxPngBytes = 10 * 1024 * 1024;
    uint32_t readyMaxRetries = 3;
    uint32_t readyDelayMs = 0;
    uint32_t flushSettleMs = 100;
    bool resume = false;
    bool displayFallback = false;
    bool skipDisplayCheck = false;
    bool includeManual = false;
};

struct EmulatorRunState {
    uint32_t schemaVersion = 1;
    std::string runId;
    std::string outputRoot;
    RunIdentity identity;
    std::string startTime;
    std::string endTime;
    std::map<std::string, uint64_t> phaseDurationsMs;
    bool finished = false;
    std::vector<SuiteRunRecord> suites;
};

std::string_view ExecutionStatusToString(ExecutionStatus status);
bool ExecutionStatusFromString(const std::string& value, ExecutionStatus& status);
std::string SerializeEmulatorRunState(const EmulatorRunState& state);
bool SaveEmulatorRunState(const EmulatorRunState& state, const std::string& path, std::string& error);
bool LoadEmulatorRunState(const std::string& path, EmulatorRunState& state, std::string& error);

class EmulatorRunner {
public:
    explicit EmulatorRunner(IProcessController& processController, IEmulatorHealthProbe* healthProbe = nullptr);

    // Test failures are data. False is reserved for invalid configuration or persistence/health failures.
    // An incompatible resume starts a new <runId>-rN directory without changing the old one.
    bool Run(const EmulatorRunConfig& config, const TestCatalog& catalog, EmulatorRunState& state,
        std::string& error);

private:
    IProcessController& processController_;
    IEmulatorHealthProbe* healthProbe_;
};

} // namespace Rosen
} // namespace OHOS

#endif // RS_GRAPHIC_TEST_RUNNER_H
