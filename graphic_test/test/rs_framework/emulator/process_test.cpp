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

#include <cerrno>
#include <fstream>
#include <gtest/gtest.h>
#include <iterator>
#include <signal.h>
#include <string>
#include <unistd.h>

#include "rs_graphic_test_process.h"

namespace OHOS {
namespace Rosen {
namespace {

constexpr const char* SHELL_PATH = "/system/bin/sh";
constexpr uint32_t NORMAL_TIMEOUT_MS = 2000;
constexpr uint32_t SHORT_TIMEOUT_MS = 100;
constexpr uint32_t MAX_TIMEOUT_TEST_DURATION_MS = 5000;
constexpr uint64_t FAKE_DURATION_MS = 12;
constexpr int NONZERO_EXIT_CODE = 7;

class FakeProcessController final : public IProcessController {
public:
    ProcessResult Run(const ProcessSpec& spec) override
    {
        ++callCount;
        receivedSpec = spec;
        return nextResult;
    }

    int callCount = 0;
    ProcessSpec receivedSpec;
    ProcessResult nextResult;
};

std::string MakeLogPath()
{
    const auto* testInfo = testing::UnitTest::GetInstance()->current_test_info();
    return "/data/local/tmp/rs_graphic_test_process_" + std::to_string(getpid()) + "_" + testInfo->name() + ".log";
}

ProcessSpec MakeEmulatorUnitSpec()
{
    ProcessSpec spec;
    spec.executable = "/data/local/tmp/RSGraphicTest";
    spec.args = { "-emulator-unit", "--suite", "Alpha", "--output-dir", "/data/local/tmp/unit-output",
        "--display-fallback" };
    spec.environment = { { "TMPDIR", "/data/local/tmp/unit-output" } };
    spec.logPath = "/data/local/tmp/unit.log";
    spec.timeoutMs = NORMAL_TIMEOUT_MS;
    spec.workingDirectory = "/data/local/tmp";
    return spec;
}

ProcessSpec MakeShellSpec(const std::string& command, uint32_t timeoutMs = NORMAL_TIMEOUT_MS)
{
    ProcessSpec spec;
    spec.executable = SHELL_PATH;
    spec.args = { "-c", command };
    spec.logPath = MakeLogPath();
    spec.timeoutMs = timeoutMs;
    return spec;
}

bool ShellAvailable()
{
    return access(SHELL_PATH, X_OK) == 0;
}

TEST(ProcessControllerTest, RunnerCanUseFakeAndReceivesExplicitUnitArguments)
{
    FakeProcessController fake;
    fake.nextResult.exitCode = ProcessResult::NO_EXIT_CODE;
    fake.nextResult.termSignal = SIGKILL;
    fake.nextResult.durationMs = FAKE_DURATION_MS;
    fake.nextResult.timedOut = true;
    const ProcessSpec spec = MakeEmulatorUnitSpec();
    IProcessController& controller = fake;

    const ProcessResult result = controller.Run(spec);

    EXPECT_EQ(fake.callCount, 1);
    EXPECT_EQ(fake.receivedSpec.executable, spec.executable);
    EXPECT_EQ(fake.receivedSpec.args, spec.args);
    EXPECT_EQ(fake.receivedSpec.environment, spec.environment);
    EXPECT_EQ(fake.receivedSpec.logPath, spec.logPath);
    EXPECT_EQ(fake.receivedSpec.timeoutMs, spec.timeoutMs);
    EXPECT_EQ(fake.receivedSpec.workingDirectory, spec.workingDirectory);
    EXPECT_EQ(result.exitCode, ProcessResult::NO_EXIT_CODE);
    EXPECT_EQ(result.termSignal, SIGKILL);
    EXPECT_EQ(result.durationMs, FAKE_DURATION_MS);
    EXPECT_TRUE(result.timedOut);
    EXPECT_EQ(result.spawnError, 0);
    EXPECT_TRUE(result.error.empty());
}

TEST(PosixProcessControllerTest, RejectsZeroTimeoutBeforeSpawning)
{
    ProcessSpec spec;
    spec.executable = "/definitely/not/a/process";
    spec.logPath = "/definitely/not/a/log";
    PosixProcessController controller;

    const auto result = controller.Run(spec);

    EXPECT_EQ(result.exitCode, ProcessResult::NO_EXIT_CODE);
    EXPECT_EQ(result.spawnError, EINVAL);
    EXPECT_NE(result.error.find("timeoutMs"), std::string::npos);
    EXPECT_FALSE(result.timedOut);
}

TEST(PosixProcessControllerTest, ShellNormalExitRedirectsOutputAndOverridesEnvironment)
{
    if (!ShellAvailable()) {
        GTEST_SKIP() << SHELL_PATH << " is unavailable";
    }
    auto spec = MakeShellSpec("printf 'argv0:%s\\n' \"$0\"; printf 'out:%s\\n' \"$TMPDIR\"; "
                              "printf 'err:%s\\n' \"$TMPDIR\" >&2");
    spec.environment = { { "TMPDIR", "/data/local/tmp" } };
    PosixProcessController controller;

    const auto result = controller.Run(spec);

    ASSERT_EQ(result.spawnError, 0) << result.error;
    EXPECT_EQ(result.exitCode, 0);
    EXPECT_EQ(result.termSignal, 0);
    EXPECT_FALSE(result.timedOut);
    EXPECT_TRUE(result.error.empty());
    std::ifstream input(spec.logPath);
    ASSERT_TRUE(input.is_open());
    const std::string output((std::istreambuf_iterator<char>(input)), std::istreambuf_iterator<char>());
    EXPECT_EQ(output, "argv0:/system/bin/sh\nout:/data/local/tmp\nerr:/data/local/tmp\n");
}

TEST(PosixProcessControllerTest, ShellNonzeroExitIsNotAnInfrastructureError)
{
    if (!ShellAvailable()) {
        GTEST_SKIP() << SHELL_PATH << " is unavailable";
    }
    auto spec = MakeShellSpec("exit " + std::to_string(NONZERO_EXIT_CODE));
    PosixProcessController controller;

    const auto result = controller.Run(spec);

    ASSERT_EQ(result.spawnError, 0) << result.error;
    EXPECT_EQ(result.exitCode, NONZERO_EXIT_CODE);
    EXPECT_EQ(result.termSignal, 0);
    EXPECT_FALSE(result.timedOut);
    EXPECT_TRUE(result.error.empty());
}

TEST(PosixProcessControllerTest, ShellTimeoutKillsAndReapsProcessGroup)
{
    if (!ShellAvailable()) {
        GTEST_SKIP() << SHELL_PATH << " is unavailable";
    }
    auto spec = MakeShellSpec("sleep 2 & wait", SHORT_TIMEOUT_MS);
    PosixProcessController controller;

    const auto result = controller.Run(spec);

    ASSERT_EQ(result.spawnError, 0) << result.error;
    EXPECT_TRUE(result.timedOut);
    EXPECT_EQ(result.exitCode, ProcessResult::NO_EXIT_CODE);
    EXPECT_EQ(result.termSignal, SIGKILL);
    EXPECT_GE(result.durationMs, SHORT_TIMEOUT_MS);
    EXPECT_LT(result.durationMs, MAX_TIMEOUT_TEST_DURATION_MS);
    EXPECT_TRUE(result.error.empty()) << result.error;
}

} // namespace
} // namespace Rosen
} // namespace OHOS
