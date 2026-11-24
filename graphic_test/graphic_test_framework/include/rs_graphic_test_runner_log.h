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

#ifndef RS_GRAPHIC_TEST_RUNNER_LOG_H
#define RS_GRAPHIC_TEST_RUNNER_LOG_H

#include <cstdint>
#include <map>
#include <string>

#include "rs_graphic_test_runner.h"

namespace OHOS {
namespace Rosen {

// Per-case progress extracted from a child process log.
struct CaseProgress {
    ExecutionStatus status = ExecutionStatus::NOT_RUN;
    uint64_t durationMs = 0;
    uint32_t readyRetries = 0;
    bool captureUnstable = false;
    uint32_t expectedWidth = 0;
    uint32_t expectedHeight = 0;
    std::string cropRect;
    std::string captureMode;
    std::string fallbackReason;
    std::string pngPath;
};

// Full parse result of one child log: case progress plus phase timings.
struct ParsedLog {
    std::map<std::string, CaseProgress> cases;
    std::map<std::string, uint64_t> phaseDurationsMs;
    std::string lastRun;
};

ParsedLog ParseLog(const std::string& text);

} // namespace Rosen
} // namespace OHOS

#endif // RS_GRAPHIC_TEST_RUNNER_LOG_H
