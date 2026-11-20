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

#include <gtest/gtest.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <csignal>
#include <deque>
#include <filesystem>
#include <functional>
#include <string>
#include <sys/stat.h>
#include <vector>

#include <unistd.h>

#include "rs_graphic_test_catalog.h"
#include "rs_graphic_test_file.h"
#include "rs_graphic_test_health.h"
#include "rs_graphic_test_process.h"
#include "rs_graphic_test_runner.h"

namespace OHOS {
namespace Rosen {
namespace {

constexpr uint64_t FAKE_DURATION_MS = 17;
constexpr int CHILD_INFRA_EXIT_CODE = 2;
constexpr uint32_t FLUSH_SETTLE_MS = 100;
constexpr uint32_t OTHER_FLUSH_SETTLE_MS = 200;
// SmallPng() is 1x1, so any other expected size is a mismatch.
constexpr uint32_t MISMATCHED_EXPECTED_SIZE = 2;
// Minimal 1x1 RGBA PNG header: signature, IHDR chunk type, big-endian width/height, bit depth, color type.
constexpr size_t PNG_HEADER_SIZE = 33;
constexpr size_t CHUNK_TYPE_OFFSET = 12;
constexpr size_t WIDTH_LOW_BYTE_OFFSET = 19;
constexpr size_t HEIGHT_LOW_BYTE_OFFSET = 23;
constexpr size_t BIT_DEPTH_OFFSET = 24;
constexpr size_t COLOR_TYPE_OFFSET = 25;
constexpr unsigned char BIT_DEPTH_8 = 8;
constexpr unsigned char COLOR_TYPE_RGBA = 6;
// Field values of the fully populated attempt used by the persistence round-trip tests.
constexpr uint32_t FULL_ATTEMPT_NUMBER = 2;
constexpr uint64_t FULL_DURATION_MS = 99;
constexpr uint32_t FULL_WIDTH = 10;
constexpr uint32_t FULL_HEIGHT = 20;
constexpr uint64_t FULL_PNG_SIZE = 1234;
constexpr uint32_t FULL_READY_RETRIES = 3;

using Action = std::function<ProcessResult(const ProcessSpec&)>;

class FakeProcessController final : public IProcessController {
public:
    void Push(Action action)
    {
        actions_.push_back(std::move(action));
    }

    ProcessResult Run(const ProcessSpec& spec) override
    {
        specs.push_back(spec);
        if (actions_.empty()) {
            ADD_FAILURE() << "unexpected child process";
            ProcessResult result;
            result.spawnError = ENOSYS;
            result.error = "no fake action";
            return result;
        }
        Action action = std::move(actions_.front());
        actions_.pop_front();
        return action(spec);
    }

    std::vector<ProcessSpec> specs;

private:
    std::deque<Action> actions_;
};

class FakeHealthProbe final : public IEmulatorHealthProbe {
public:
    EmulatorHealthStatus Check() override
    {
        return status;
    }

    EmulatorHealthStatus status { true, true, true };
};

std::string Arg(const ProcessSpec& spec, const std::string& name)
{
    for (size_t index = 0; index + 1 < spec.args.size(); ++index) {
        if (spec.args[index] == name) {
            return spec.args[index + 1];
        }
    }
    return {};
}

ProcessResult MakeResult(int exitCode = 0, int signal = 0, bool timedOut = false, int spawnError = 0)
{
    ProcessResult result;
    result.exitCode = exitCode;
    result.termSignal = signal;
    result.durationMs = FAKE_DURATION_MS;
    result.timedOut = timedOut;
    result.spawnError = spawnError;
    if (spawnError != 0) {
        result.error = "fake spawn failure";
    }
    return result;
}

ProcessResult LogResult(const ProcessSpec& spec, const std::string& log, const ProcessResult& result = MakeResult())
{
    std::string error;
    EXPECT_TRUE(WriteTextFileAtomic(spec.logPath, log, &error)) << error;
    return result;
}

std::string RunLine(const std::string& suite, const std::string& name)
{
    return "[ RUN      ] " + suite + "." + name + "\n";
}

std::string SmallPng()
{
    std::array<unsigned char, PNG_HEADER_SIZE> bytes { 0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n' };
    const std::string chunkType = "IHDR";
    std::copy(chunkType.begin(), chunkType.end(), bytes.begin() + CHUNK_TYPE_OFFSET);
    bytes[WIDTH_LOW_BYTE_OFFSET] = 1;
    bytes[HEIGHT_LOW_BYTE_OFFSET] = 1;
    bytes[BIT_DEPTH_OFFSET] = BIT_DEPTH_8;
    bytes[COLOR_TYPE_OFFSET] = COLOR_TYPE_RGBA;
    return std::string(reinterpret_cast<const char*>(bytes.data()), bytes.size());
}

std::string Passed(const ProcessSpec& spec, const std::string& suite, const std::string& name, bool png = true,
    const std::string& capture = "surface")
{
    std::string log = RunLine(suite, name);
    if (png) {
        const std::string path = (std::filesystem::path(Arg(spec, "--output-dir")) /
            (suite + "_" + name + ".png")).string();
        std::string error;
        EXPECT_TRUE(WriteTextFileAtomic(path, SmallPng(), &error)) << error;
        log += "RS_GRAPHIC_TEST_READY status=stable retries=2\n";
        log += "RS_GRAPHIC_TEST_CAPTURE mode=" + capture;
        if (capture == "display_fallback") {
            log += " reason=null_pixelmap";
        }
        log += "\npng write to " + path + "\n";
    }
    return log + "[       OK ] " + suite + "." + name + " (9 ms)\n";
}

std::string Failed(const std::string& suite, const std::string& name)
{
    return RunLine(suite, name) + "[  FAILED  ] " + suite + "." + name + " (11 ms)\n";
}

std::string Skipped(const std::string& suite, const std::string& name)
{
    return RunLine(suite, name) + "[  SKIPPED ] " + suite + "." + name + " (1 ms)\n";
}

std::string Read(const std::string& path)
{
    std::string content;
    std::string error;
    EXPECT_TRUE(ReadTextFile(path, content, &error)) << error;
    return content;
}

std::string SerializeToFile(const std::string& json)
{
    const std::string path = (std::filesystem::temp_directory_path() /
        ("rs-state-roundtrip-" + std::to_string(getpid()) + ".json")).string();
    std::string error;
    EXPECT_TRUE(WriteTextFileAtomic(path, json, &error)) << error;
    return path;
}

class EmulatorRunnerTest : public testing::Test {
protected:
    void SetUp() override
    {
        const std::string pattern = (std::filesystem::temp_directory_path() / "rs-runner-XXXXXX").string();
        std::vector<char> path(pattern.begin(), pattern.end());
        path.push_back('\0');
        ASSERT_NE(mkdtemp(path.data()), nullptr);
        root_ = path.data();
        config_.outputRoot = root_ + "/output";
        config_.testBinary = root_ + "/RSGraphicTest";
        config_.runId = "run";
        config_.suites = { "Alpha" };
        config_.expectedWidth = 1;
        config_.expectedHeight = 1;
        ASSERT_TRUE(WriteTextFileAtomic(config_.testBinary, "binary-v1", &error_));
        SetCatalog({ "Alpha.Good", "Alpha.Boom", "Alpha.Later", "Alpha.Manual", "Beta.Other" });
    }

    void TearDown() override
    {
        std::error_code error;
        std::filesystem::remove_all(root_, error);
    }

    void SetCatalog(const std::vector<std::string>& names)
    {
        std::vector<GraphicTestCaseInfo> cases;
        for (const auto& qualified : names) {
            const size_t dot = qualified.find('.');
            GraphicTestCaseInfo info;
            info.suite = qualified.substr(0, dot);
            info.name = qualified.substr(dot + 1);
            info.type = "FRAMEWORK_TEST";
            info.mode = info.name.find("Manual") == 0 ? GraphicCaseMode::MANUAL : GraphicCaseMode::AUTOMATIC;
            info.isMultiple = false;
            info.sourcePath = "test/rs_framework/example.cpp";
            cases.push_back(std::move(info));
        }
        std::string catalogError;
        catalog_ = TestCatalog::FromCases(cases, catalogError);
        ASSERT_TRUE(catalogError.empty()) << catalogError;
    }

    bool Run(EmulatorRunState& state)
    {
        EmulatorRunner runner(fake_, &health_);
        return runner.Run(config_, catalog_, state, error_);
    }

    const CaseRunRecord& Case(const EmulatorRunState& state, const std::string& name, size_t suite = 0)
    {
        const auto found = std::find_if(state.suites[suite].cases.begin(), state.suites[suite].cases.end(),
            [&name](const CaseRunRecord& item) { return item.info.name == name; });
        EXPECT_NE(found, state.suites[suite].cases.end());
        return *found;
    }

    std::string StatePath(const std::string& runId = "run") const
    {
        return config_.outputRoot + "/" + runId + "/run_state.json";
    }

    std::string root_;
    std::string error_;
    EmulatorRunConfig config_;
    TestCatalog catalog_;
    FakeProcessController fake_;
    FakeHealthProbe health_;
};

TEST_F(EmulatorRunnerTest, RunsSuitesSeriallyWithExplicitArgumentsAndPngMetadata)
{
    SetCatalog({ "Alpha.Good", "Beta.Other" });
    config_.suites = { "Alpha", "Beta" };
    config_.displayFallback = true;
    fake_.Push([](const ProcessSpec& spec) {
        return LogResult(spec, "RS_GRAPHIC_TEST_TIMING startup_ms=2 flush_ms=3 capture_ms=4 write_ms=5\n" +
            Passed(spec, "Alpha", "Good"));
    });
    fake_.Push([](const ProcessSpec& spec) {
        return LogResult(spec, Passed(spec, "Beta", "Other", true, "display_fallback"));
    });
    EmulatorRunState state;
    ASSERT_TRUE(Run(state)) << error_;
    ASSERT_EQ(fake_.specs.size(), 2U);
    EXPECT_EQ(Arg(fake_.specs[0], "--suite"), "Alpha");
    EXPECT_EQ(Arg(fake_.specs[1], "--suite"), "Beta");
    EXPECT_EQ(fake_.specs[0].args[0], "-emulator-unit");
    EXPECT_EQ(Arg(fake_.specs[0], "--expected-width"), "1");
    EXPECT_EQ(Arg(fake_.specs[0], "--output-dir"), config_.outputRoot + "/run/Alpha/attempt1");
    EXPECT_TRUE(fake_.specs[0].environment.empty());
    EXPECT_TRUE(state.finished);
    EXPECT_EQ(state.phaseDurationsMs.at("startup"), 2U);
    EXPECT_EQ(state.phaseDurationsMs.at("flush"), 3U);
    EXPECT_EQ(state.phaseDurationsMs.at("capture"), 4U);
    EXPECT_EQ(state.phaseDurationsMs.at("write"), 5U);
    EXPECT_EQ(Case(state, "Good").attempts.back().pngSize, 33U);
    EXPECT_EQ(Case(state, "Good").attempts.back().pngWidth, 1U);
    EXPECT_EQ(Case(state, "Good").attempts.back().pngHeight, 1U);
    EXPECT_EQ(Case(state, "Good").attempts.back().readyRetries, 2U);
    EXPECT_EQ(Case(state, "Other", 1).attempts.back().actualCaptureMode, "display_fallback");
    EXPECT_EQ(Case(state, "Other", 1).attempts.back().fallbackReason, "null_pixelmap");
}

TEST_F(EmulatorRunnerTest, PassesFlushSettleMsToChildProcess)
{
    SetCatalog({ "Alpha.Good" });
    config_.flushSettleMs = FLUSH_SETTLE_MS;
    fake_.Push([](const ProcessSpec& spec) { return LogResult(spec, Passed(spec, "Alpha", "Good")); });
    EmulatorRunState state;
    ASSERT_TRUE(Run(state)) << error_;
    ASSERT_EQ(fake_.specs.size(), 1U);
    EXPECT_EQ(Arg(fake_.specs[0], "--flush-settle-ms"), "100");
    EXPECT_NE(state.identity.executionPolicy.find("flushSettleMs=100"), std::string::npos);
}

TEST_F(EmulatorRunnerTest, ResumeWithDifferentFlushSettleUsesUnusedDirectory)
{
    SetCatalog({ "Alpha.Good" });
    fake_.Push([](const ProcessSpec& spec) { return LogResult(spec, Passed(spec, "Alpha", "Good")); });
    EmulatorRunState initial;
    config_.flushSettleMs = FLUSH_SETTLE_MS;
    ASSERT_TRUE(Run(initial)) << error_;
    EmulatorRunState replacement;
    config_.resume = true;
    config_.flushSettleMs = OTHER_FLUSH_SETTLE_MS;
    fake_.Push([](const ProcessSpec& spec) { return LogResult(spec, Passed(spec, "Alpha", "Good")); });
    ASSERT_TRUE(Run(replacement)) << error_;
    EXPECT_EQ(replacement.runId, "run-r1");
    EXPECT_NE(replacement.identity.executionPolicy, initial.identity.executionPolicy);
}

TEST_F(EmulatorRunnerTest, AssertionFailureIsDataAndDoesNotTriggerRecovery)
{
    SetCatalog({ "Alpha.Good", "Alpha.Boom" });
    fake_.Push([](const ProcessSpec& spec) {
        return LogResult(spec, Passed(spec, "Alpha", "Good") + Failed("Alpha", "Boom"), MakeResult(1));
    });
    EmulatorRunState state;
    ASSERT_TRUE(Run(state)) << error_;
    EXPECT_EQ(fake_.specs.size(), 1U);
    EXPECT_EQ(state.suites[0].status, ExecutionStatus::FAILED);
    EXPECT_EQ(Case(state, "Boom").finalStatus, ExecutionStatus::FAILED);
    EXPECT_FALSE(Case(state, "Boom").missingPngReason.empty());
}

TEST_F(EmulatorRunnerTest, TimeoutPreservesCompletedCasesDiagnosesActiveAndResumesRemaining)
{
    SetCatalog({ "Alpha.Good", "Alpha.Boom", "Alpha.Later" });
    fake_.Push([](const ProcessSpec& spec) {
        return LogResult(spec, Passed(spec, "Alpha", "Good") + RunLine("Alpha", "Boom"), MakeResult(-1, 0, true));
    });
    fake_.Push([](const ProcessSpec& spec) { return LogResult(spec, Failed("Alpha", "Boom"), MakeResult(1)); });
    fake_.Push([](const ProcessSpec& spec) { return LogResult(spec, Passed(spec, "Alpha", "Later")); });
    EmulatorRunState state;
    ASSERT_TRUE(Run(state)) << error_;
    ASSERT_EQ(fake_.specs.size(), 3U);
    EXPECT_EQ(Arg(fake_.specs[1], "--case"), "Boom");
    EXPECT_TRUE(Case(state, "Boom").attempts[0].status == ExecutionStatus::TIMEOUT);
    EXPECT_TRUE(Case(state, "Boom").attempts[1].diagnostic);
    EXPECT_EQ(Case(state, "Good").attempts.size(), 1U);
    EXPECT_EQ(Case(state, "Later").finalStatus, ExecutionStatus::PASSED);
    const std::string excluded = Read(Arg(fake_.specs[2], "--exclude-cases-file"));
    EXPECT_NE(excluded.find("Alpha.Good\n"), std::string::npos);
    EXPECT_NE(excluded.find("Alpha.Boom\n"), std::string::npos);
    EXPECT_EQ(excluded.find("Alpha.Later\n"), std::string::npos);
}

TEST_F(EmulatorRunnerTest, DefaultAttemptBudgetStillContinuesRemainingCases)
{
    SetCatalog({ "Alpha.Good", "Alpha.Boom", "Alpha.Later" });
    fake_.Push([](const ProcessSpec& spec) {
        return LogResult(spec, Passed(spec, "Alpha", "Good") + RunLine("Alpha", "Boom"), MakeResult(-1, 0, true));
    });
    fake_.Push([](const ProcessSpec& spec) { return LogResult(spec, Failed("Alpha", "Boom"), MakeResult(1)); });
    fake_.Push([](const ProcessSpec& spec) { return LogResult(spec, Passed(spec, "Alpha", "Later")); });
    EmulatorRunState state;
    ASSERT_TRUE(Run(state)) << error_;
    ASSERT_EQ(fake_.specs.size(), 3U);
    EXPECT_EQ(Case(state, "Later").finalStatus, ExecutionStatus::PASSED);
    EXPECT_NE(Case(state, "Later").finalStatus, ExecutionStatus::CANCELLED);
}

TEST_F(EmulatorRunnerTest, DiagnosticNoProgressKeepsCrashAndRunsRemainingOnce)
{
    SetCatalog({ "Alpha.Good", "Alpha.Boom", "Alpha.Later" });
    // Main: Good passes, Boom is killed by a signal mid-run, Later unreported -> diagnostic on Boom.
    fake_.Push([](const ProcessSpec& spec) {
        return LogResult(spec, Passed(spec, "Alpha", "Good") + RunLine("Alpha", "Boom"), MakeResult(-1, SIGSEGV));
    });
    // Diagnostic on Boom dies before any [RUN]: no progress, must not rewrite Boom's CRASH.
    fake_.Push([](const ProcessSpec& spec) { return LogResult(spec, "", MakeResult(CHILD_INFRA_EXIT_CODE)); });
    // Continuation runs the remaining Later exactly once.
    fake_.Push([](const ProcessSpec& spec) { return LogResult(spec, Passed(spec, "Alpha", "Later")); });
    EmulatorRunState state;
    ASSERT_TRUE(Run(state)) << error_;
    EXPECT_EQ(fake_.specs.size(), 3U);
    EXPECT_EQ(Arg(fake_.specs[1], "--case"), "Boom");
    const auto& boom = Case(state, "Boom");
    EXPECT_EQ(boom.finalStatus, ExecutionStatus::CRASH);
    ASSERT_EQ(boom.attempts.size(), 1U);
    EXPECT_EQ(boom.attempts[0].status, ExecutionStatus::CRASH);
    EXPECT_EQ(Case(state, "Later").finalStatus, ExecutionStatus::PASSED);
}

TEST_F(EmulatorRunnerTest, SignalDiagnosticTurningGreenIsFlaky)
{
    SetCatalog({ "Alpha.Boom" });
    fake_.Push([](const ProcessSpec& spec) {
        return LogResult(spec, RunLine("Alpha", "Boom"), MakeResult(-1, SIGSEGV));
    });
    fake_.Push([](const ProcessSpec& spec) { return LogResult(spec, Passed(spec, "Alpha", "Boom")); });
    EmulatorRunState state;
    ASSERT_TRUE(Run(state)) << error_;
    ASSERT_EQ(Case(state, "Boom").attempts.size(), 2U);
    EXPECT_EQ(Case(state, "Boom").attempts[0].status, ExecutionStatus::CRASH);
    EXPECT_EQ(Case(state, "Boom").attempts[0].termSignal, SIGSEGV);
    EXPECT_EQ(Case(state, "Boom").finalStatus, ExecutionStatus::PASSED);
    EXPECT_TRUE(Case(state, "Boom").flaky);
    EXPECT_TRUE(Case(state, "Boom").attempts[1].diagnostic);
}

TEST_F(EmulatorRunnerTest, PngDimensionMismatchIsReportedAsMissing)
{
    SetCatalog({ "Alpha.Good" });
    config_.expectedWidth = MISMATCHED_EXPECTED_SIZE;
    config_.expectedHeight = MISMATCHED_EXPECTED_SIZE;
    fake_.Push([](const ProcessSpec& spec) { return LogResult(spec, Passed(spec, "Alpha", "Good")); });
    EmulatorRunState state;
    ASSERT_TRUE(Run(state)) << error_;
    const auto& attempt = Case(state, "Good").attempts.back();
    EXPECT_TRUE(attempt.pngRelativePath.empty());
    EXPECT_EQ(attempt.pngWidth, 0U);
    EXPECT_NE(Case(state, "Good").missingPngReason.find("size mismatch"), std::string::npos);
}

TEST_F(EmulatorRunnerTest, UnstableCaptureIsRecordedWithoutFailingCase)
{
    SetCatalog({ "Alpha.Good" });
    fake_.Push([](const ProcessSpec& spec) {
        const std::string path = (std::filesystem::path(Arg(spec, "--output-dir")) / "Alpha_Good.png").string();
        std::string error;
        EXPECT_TRUE(WriteTextFileAtomic(path, SmallPng(), &error)) << error;
        const std::string log = RunLine("Alpha", "Good") +
            "RS_GRAPHIC_TEST_READY status=unstable retries=3\n"
            "RS_GRAPHIC_TEST_CAPTURE mode=display\n"
            "png write to " + path + "\n" +
            "[       OK ] Alpha.Good (7 ms)\n";
        return LogResult(spec, log);
    });
    EmulatorRunState state;
    ASSERT_TRUE(Run(state)) << error_;
    const auto& attempt = Case(state, "Good").attempts.back();
    EXPECT_TRUE(attempt.captureUnstable);
    EXPECT_EQ(Case(state, "Good").finalStatus, ExecutionStatus::PASSED);
    EXPECT_FALSE(attempt.pngRelativePath.empty());
}

TEST_F(EmulatorRunnerTest, FailedSummaryDoesNotCreateFakeCaseOrResetDuration)
{
    SetCatalog({ "Alpha.Boom" });
    fake_.Push([](const ProcessSpec& spec) {
        const std::string log = Failed("Alpha", "Boom") +
            "[  FAILED  ] 1 test, listed below:\n"
            "[  FAILED  ] Alpha.Boom\n";
        return LogResult(spec, log, MakeResult(1));
    });
    EmulatorRunState state;
    ASSERT_TRUE(Run(state)) << error_;
    EXPECT_EQ(Case(state, "Boom").attempts.back().durationMs, 11U);
    EXPECT_EQ(state.suites[0].cases.size(), 1U);
}

TEST_F(EmulatorRunnerTest, ManualCasesAreListedByDefaultAndRunOnlyWhenIncluded)
{
    SetCatalog({ "Alpha.Manual" });
    EmulatorRunState listed;
    ASSERT_TRUE(Run(listed)) << error_;
    EXPECT_TRUE(fake_.specs.empty());
    EXPECT_EQ(Case(listed, "Manual").finalStatus, ExecutionStatus::MANUAL);
    config_.runId = "manual-included";
    config_.includeManual = true;
    fake_.Push([](const ProcessSpec& spec) { return LogResult(spec, Passed(spec, "Alpha", "Manual", false)); });
    EmulatorRunState executed;
    ASSERT_TRUE(Run(executed)) << error_;
    EXPECT_EQ(Case(executed, "Manual").finalStatus, ExecutionStatus::PASSED);
    EXPECT_TRUE(Case(executed, "Manual").missingPngReason.empty());
}

TEST_F(EmulatorRunnerTest, ResumeSkipsPassedAndRetriesFailedWithHistory)
{
    SetCatalog({ "Alpha.Good", "Alpha.Boom" });
    fake_.Push([](const ProcessSpec& spec) {
        return LogResult(spec, Passed(spec, "Alpha", "Good") + Failed("Alpha", "Boom"), MakeResult(1));
    });
    EmulatorRunState initial;
    ASSERT_TRUE(Run(initial)) << error_;
    config_.resume = true;
    fake_.Push([](const ProcessSpec& spec) { return LogResult(spec, Passed(spec, "Alpha", "Boom")); });
    EmulatorRunState resumed;
    ASSERT_TRUE(Run(resumed)) << error_;
    ASSERT_EQ(fake_.specs.size(), 2U);
    EXPECT_EQ(Read(Arg(fake_.specs[1], "--exclude-cases-file")), "Alpha.Good\n");
    EXPECT_EQ(Case(resumed, "Good").attempts.size(), 1U);
    EXPECT_EQ(Case(resumed, "Boom").attempts.size(), 2U);
    EXPECT_TRUE(Case(resumed, "Boom").flaky);
}

TEST_F(EmulatorRunnerTest, ResumeSkipsOrphanAttemptDirectories)
{
    SetCatalog({ "Alpha.Good" });
    fake_.Push([](const ProcessSpec& spec) { return LogResult(spec, Failed("Alpha", "Good"), MakeResult(1)); });
    EmulatorRunState initial;
    ASSERT_TRUE(Run(initial)) << error_;
    const std::string orphan = config_.outputRoot + "/run/Alpha/attempt2";
    ASSERT_TRUE(EnsureDirectory(orphan, &error_)) << error_;
    ASSERT_TRUE(WriteTextFileAtomic(orphan + "/process.log", "old log", &error_));
    ASSERT_TRUE(WriteTextFileAtomic(orphan + "/Alpha_Good.png.tmp", "partial", &error_));
    config_.resume = true;
    fake_.Push([](const ProcessSpec& spec) { return LogResult(spec, Passed(spec, "Alpha", "Good")); });
    EmulatorRunState resumed;
    ASSERT_TRUE(Run(resumed)) << error_;
    ASSERT_EQ(fake_.specs.size(), 2U);
    EXPECT_EQ(Arg(fake_.specs[1], "--output-dir"), config_.outputRoot + "/run/Alpha/attempt3");
    EXPECT_EQ(Read(orphan + "/process.log"), "old log");
    EXPECT_EQ(Read(orphan + "/Alpha_Good.png.tmp"), "partial");
}

TEST_F(EmulatorRunnerTest, ResumeIdentityConflictUsesUnusedDirectoryAndPreservesOldState)
{
    SetCatalog({ "Alpha.Good" });
    fake_.Push([](const ProcessSpec& spec) { return LogResult(spec, Passed(spec, "Alpha", "Good")); });
    EmulatorRunState initial;
    ASSERT_TRUE(Run(initial)) << error_;
    const std::string oldState = Read(StatePath());
    ASSERT_TRUE(WriteTextFileAtomic(config_.testBinary, "binary-v2-longer", &error_));
    // The same-second rewrite may keep mtime; force a distinct identity via a different length.
    struct stat info {};
    ASSERT_EQ(stat(config_.testBinary.c_str(), &info), 0);
    EmulatorRunState replacement;
    config_.resume = true;
    fake_.Push([](const ProcessSpec& spec) { return LogResult(spec, Passed(spec, "Alpha", "Good")); });
    ASSERT_TRUE(Run(replacement)) << error_;
    EXPECT_EQ(replacement.runId, "run-r1");
    EXPECT_EQ(Read(StatePath("run")), oldState);
    EXPECT_NE(replacement.identity.testBinarySize, initial.identity.testBinarySize);
}

TEST_F(EmulatorRunnerTest, CorruptedResumeStateFailsWithoutStartingProcess)
{
    SetCatalog({ "Alpha.Good" });
    ASSERT_TRUE(EnsureDirectory(config_.outputRoot + "/run", &error_)) << error_;
    ASSERT_TRUE(WriteTextFileAtomic(StatePath(), "{broken", &error_));
    config_.resume = true;
    EmulatorRunState state;
    EXPECT_FALSE(Run(state));
    EXPECT_TRUE(fake_.specs.empty());
    EXPECT_EQ(Read(StatePath()), "{broken");
}

TEST_F(EmulatorRunnerTest, SuiteSelectionFiltersCatalogAndExcludeFileListsOthers)
{
    SetCatalog({ "Alpha.Good", "Alpha.Later", "Beta.Other" });
    config_.suites = { "Alpha" };
    fake_.Push([](const ProcessSpec& spec) {
        return LogResult(spec, Passed(spec, "Alpha", "Good") + Skipped("Alpha", "Later"));
    });
    EmulatorRunState state;
    ASSERT_TRUE(Run(state)) << error_;
    EXPECT_EQ(state.suites.size(), 1U);
    EXPECT_EQ(state.suites[0].name, "Alpha");
    EXPECT_EQ(Case(state, "Good").finalStatus, ExecutionStatus::PASSED);
    EXPECT_EQ(Case(state, "Later").finalStatus, ExecutionStatus::SKIPPED);
    // Both Alpha cases start pending, so the initial exclude file is empty; Beta is not in the suite.
    EXPECT_EQ(Read(Arg(fake_.specs[0], "--exclude-cases-file")), "");
}

TEST_F(EmulatorRunnerTest, RejectsDuplicateAndUnknownSuites)
{
    SetCatalog({ "Alpha.Good" });
    config_.suites = { "Alpha", "Alpha" };
    EmulatorRunState state;
    EXPECT_FALSE(Run(state));
    EXPECT_TRUE(fake_.specs.empty());
    config_.suites = { "Gamma" };
    EXPECT_FALSE(Run(state));
    EXPECT_TRUE(fake_.specs.empty());
}

TEST_F(EmulatorRunnerTest, ChildExitWithoutProgressMarksInfraAndStops)
{
    SetCatalog({ "Alpha.Good" });
    fake_.Push([](const ProcessSpec& spec) {
        return LogResult(spec, "", MakeResult(CHILD_INFRA_EXIT_CODE));
    });
    EmulatorRunState state;
    ASSERT_TRUE(Run(state)) << error_;
    ASSERT_EQ(fake_.specs.size(), 1U);
    EXPECT_EQ(Case(state, "Good").finalStatus, ExecutionStatus::INFRA_ERROR);
    EXPECT_EQ(state.suites[0].status, ExecutionStatus::INFRA_ERROR);
}

TEST_F(EmulatorRunnerTest, MissingLogAndSpawnFailureAreInfrastructureErrors)
{
    SetCatalog({ "Alpha.Good" });
    fake_.Push([](const ProcessSpec&) { return MakeResult(); });
    EmulatorRunState missing;
    ASSERT_TRUE(Run(missing)) << error_;
    EXPECT_EQ(missing.suites[0].status, ExecutionStatus::INFRA_ERROR);
    EXPECT_EQ(Case(missing, "Good").finalStatus, ExecutionStatus::INFRA_ERROR);
    config_.runId = "spawn-error";
    fake_.Push([](const ProcessSpec&) { return MakeResult(-1, 0, false, ENOENT); });
    EmulatorRunState spawn;
    ASSERT_TRUE(Run(spawn)) << error_;
    EXPECT_EQ(Case(spawn, "Good").attempts.back().status, ExecutionStatus::INFRA_ERROR);
    EXPECT_EQ(Case(spawn, "Good").attempts.back().error, "fake spawn failure");
}

TEST_F(EmulatorRunnerTest, HealthFailurePersistsStateAndStopsBeforeSpawn)
{
    SetCatalog({ "Alpha.Good", "Beta.Other" });
    config_.suites = { "Alpha", "Beta" };
    health_.status.rsAlive = false;
    EmulatorRunState state;
    EXPECT_FALSE(Run(state));
    EXPECT_FALSE(error_.empty());
    EXPECT_TRUE(fake_.specs.empty());
    EXPECT_FALSE(state.finished);
    EXPECT_EQ(state.suites[0].status, ExecutionStatus::INFRA_ERROR);
    EXPECT_EQ(state.suites[1].status, ExecutionStatus::PENDING);
    EmulatorRunState saved;
    ASSERT_TRUE(LoadEmulatorRunState(StatePath(), saved, error_)) << error_;
    EXPECT_FALSE(saved.finished);
    EXPECT_EQ(saved.suites[0].status, ExecutionStatus::INFRA_ERROR);
    EXPECT_EQ(saved.suites[1].status, ExecutionStatus::PENDING);
}

AttemptRecord MakeFullAttempt()
{
    AttemptRecord attempt;
    attempt.attempt = FULL_ATTEMPT_NUMBER;
    attempt.status = ExecutionStatus::PASSED;
    attempt.diagnostic = true;
    attempt.exitCode = 0;
    attempt.termSignal = SIGSEGV;
    attempt.durationMs = FULL_DURATION_MS;
    attempt.logPath = "log";
    attempt.error = "recovered";
    attempt.requestedCaptureMode = "surface";
    attempt.actualCaptureMode = "display_fallback";
    attempt.fallbackReason = "timeout";
    attempt.cropRect = "0,0,10,20";
    attempt.expectedWidth = FULL_WIDTH;
    attempt.expectedHeight = FULL_HEIGHT;
    attempt.pngRelativePath = "image.png";
    attempt.pngSize = FULL_PNG_SIZE;
    attempt.pngWidth = FULL_WIDTH;
    attempt.pngHeight = FULL_HEIGHT;
    attempt.readyRetries = FULL_READY_RETRIES;
    attempt.captureUnstable = true;
    return attempt;
}

EmulatorRunState MakeFullState()
{
    EmulatorRunState state;
    state.runId = "run";
    state.outputRoot = "/tmp/output";
    state.identity = { "build", 1234, 5678, "x86_64_virt", 1200, 2000, "divided", "policy" };
    state.startTime = "start";
    state.endTime = "end";
    state.phaseDurationsMs = { { "execution", 123 }, { "preflight", 4 } };
    state.finished = true;
    SuiteRunRecord suite;
    suite.name = "Alpha";
    suite.status = ExecutionStatus::FAILED;
    suite.activeCase = "Alpha.Boom";
    suite.error = "failure";
    CaseRunRecord item;
    item.info = { "Alpha", "Boom", "FRAMEWORK_TEST", GraphicCaseMode::DYNAMIC, true, "source.cpp" };
    item.finalStatus = ExecutionStatus::PASSED;
    item.flaky = true;
    item.skipReason = "skip";
    item.missingPngReason = "missing";
    item.attempts = { MakeFullAttempt() };
    suite.cases = { item };
    state.suites = { suite };
    return state;
}

TEST(EmulatorRunStateTest, StatusNamesRoundTrip)
{
    const ExecutionStatus statuses[] = { ExecutionStatus::NOT_RUN, ExecutionStatus::PENDING, ExecutionStatus::RUNNING,
        ExecutionStatus::PASSED, ExecutionStatus::FAILED, ExecutionStatus::TIMEOUT, ExecutionStatus::CRASH,
        ExecutionStatus::SKIPPED, ExecutionStatus::MANUAL, ExecutionStatus::INFRA_ERROR, ExecutionStatus::CANCELLED };
    for (const auto expected : statuses) {
        ExecutionStatus actual = ExecutionStatus::NOT_RUN;
        ASSERT_TRUE(ExecutionStatusFromString(std::string(ExecutionStatusToString(expected)), actual));
        EXPECT_EQ(actual, expected);
    }
}

TEST(EmulatorRunStateTest, CompleteJsonRoundTrip)
{
    const std::string json = SerializeEmulatorRunState(MakeFullState());
    ASSERT_FALSE(json.empty());
    EmulatorRunState loaded;
    std::string error;
    const std::string path = SerializeToFile(json);
    ASSERT_TRUE(LoadEmulatorRunState(path, loaded, error)) << error;
    EXPECT_EQ(SerializeEmulatorRunState(loaded), json);
    std::filesystem::remove(path);
}

TEST(EmulatorRunStateTest, FailedLoadAndSaveDoNotPolluteExistingData)
{
    EmulatorRunState original;
    original.runId = "unchanged";
    const std::string path = (std::filesystem::temp_directory_path() / "rs-state-atomic-test.json").string();
    std::string error;
    ASSERT_TRUE(SaveEmulatorRunState(original, path, error)) << error;
    const std::string valid = Read(path);
    std::string corrupt = valid;
    const size_t key = corrupt.find("\"schemaVersion\":1");
    ASSERT_NE(key, std::string::npos);
    corrupt.replace(key, std::char_traits<char>::length("\"schemaVersion\":1"), "\"schemaVersion\":\"bad\"");
    ASSERT_TRUE(WriteTextFileAtomic(path, corrupt, &error));
    EmulatorRunState loaded;
    loaded.runId = "sentinel";
    EXPECT_FALSE(LoadEmulatorRunState(path, loaded, error));
    EXPECT_EQ(loaded.runId, "sentinel");
    ASSERT_TRUE(WriteTextFileAtomic(path, valid, &error));
    original.schemaVersion = 2;
    EXPECT_FALSE(SaveEmulatorRunState(original, path, error));
    EXPECT_EQ(Read(path), valid);
    std::filesystem::remove(path);
}

} // namespace
} // namespace Rosen
} // namespace OHOS
