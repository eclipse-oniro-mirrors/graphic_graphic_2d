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

#ifndef RS_GRAPHIC_TEST_PROCESS_H
#define RS_GRAPHIC_TEST_PROCESS_H

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace OHOS {
namespace Rosen {

using ProcessEnvironment = std::map<std::string, std::string>;

struct ProcessSpec {
    std::string executable;
    // Arguments after argv[0]; the controller supplies executable as argv[0].
    std::vector<std::string> args;
    // Values override the inherited environment without modifying this process.
    ProcessEnvironment environment;
    std::string logPath;
    uint32_t timeoutMs = 0;
    // Empty means inherit the parent's working directory.
    std::string workingDirectory;
};

struct ProcessResult {
    static constexpr int NO_EXIT_CODE = -1;

    int exitCode = NO_EXIT_CODE;
    int termSignal = 0;
    uint64_t durationMs = 0;
    bool timedOut = false;
    // Zero after a successful posix_spawn; otherwise a setup/spawn error number.
    int spawnError = 0;
    std::string error;
};

class IProcessController {
public:
    virtual ~IProcessController() = default;
    virtual ProcessResult Run(const ProcessSpec& spec) = 0;
};

class PosixProcessController final : public IProcessController {
public:
    ProcessResult Run(const ProcessSpec& spec) override;
};

} // namespace Rosen
} // namespace OHOS

#endif // RS_GRAPHIC_TEST_PROCESS_H
