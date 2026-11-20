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

#ifndef RS_GRAPHIC_TEST_EMULATOR_H
#define RS_GRAPHIC_TEST_EMULATOR_H

#include <cstdint>
#include <string>
#include <vector>

namespace OHOS {
namespace Rosen {

enum class EmulatorCommand : uint8_t {
    NONE,
    PREFLIGHT,
    RUN,
    UNIT,
};

struct EmulatorOptions {
    static constexpr uint64_t DEFAULT_SUITE_TIMEOUT_MS = 300000;
    static constexpr uint64_t DEFAULT_MAX_PNG_BYTES = 10 * 1024 * 1024;
    static constexpr uint32_t DEFAULT_WIDTH = 1200;
    static constexpr uint32_t DEFAULT_HEIGHT = 2000;
    static constexpr uint64_t DEFAULT_READY_MAX_RETRIES = 3;
    // Under divided render the client render thread compiles shaders with Mesa software rendering on the
    // first frame; 100 ms left most filter cases capturing the desktop, 1000 ms covered them in practice.
    static constexpr uint64_t DEFAULT_FLUSH_SETTLE_MS = 1000;

    EmulatorCommand command = EmulatorCommand::NONE;
    std::string outputRoot = "/data/local/graphic_test_emulator";
    std::string outputDir;
    std::string runId;
    std::string testBinary = "/data/local/tmp/RSGraphicTest";
    std::string suite;
    std::string caseName;
    std::string excludeCasesFile;
    std::string workingDirectory;
    std::vector<std::string> suites;
    uint64_t suiteTimeoutMs = DEFAULT_SUITE_TIMEOUT_MS;
    uint64_t expectedWidth = DEFAULT_WIDTH;
    uint64_t expectedHeight = DEFAULT_HEIGHT;
    uint64_t maxPngBytes = DEFAULT_MAX_PNG_BYTES;
    uint64_t readyMaxRetries = DEFAULT_READY_MAX_RETRIES;
    uint64_t readyDelayMs = 0;
    uint64_t flushSettleMs = 0;
    bool resume = false;
    bool displayFallback = false;
    bool skipDisplayCheck = false;
    bool includeManual = false;
};

// preflight accepts display options; run accepts scheduling options;
// unit accepts only case selection, output/work directories and capture options.
// Every option is accepted at most once.
bool IsEmulatorCommand(const std::string& command);
bool ParseEmulatorOptions(int argc, const char* const argv[], EmulatorOptions& options, std::string& error);

// Dispatch preflight and emulator-run commands. The UNIT command is dispatched in main.cpp.
int RunEmulatorCommand(const EmulatorOptions& options);

} // namespace Rosen
} // namespace OHOS

#endif // RS_GRAPHIC_TEST_EMULATOR_H
