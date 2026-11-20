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

#include <string>
#include <vector>

#include "rs_graphic_test_catalog.h"
#include "rs_graphic_test_emulator.h"

namespace OHOS {
namespace Rosen {
namespace {

struct ParseResult {
    bool success = false;
    EmulatorOptions options;
    std::string error;
};

ParseResult Parse(std::vector<std::string> arguments)
{
    arguments.insert(arguments.begin(), "RSGraphicTest");
    std::vector<const char*> argv;
    for (const auto& argument : arguments) {
        argv.push_back(argument.c_str());
    }
    ParseResult result;
    result.success = ParseEmulatorOptions(static_cast<int>(argv.size()), argv.data(), result.options, result.error);
    return result;
}

void ExpectDefaults(const EmulatorOptions& options)
{
    EXPECT_EQ(options.outputRoot, "/data/local/graphic_test_emulator");
    EXPECT_EQ(options.testBinary, "/data/local/tmp/RSGraphicTest");
    EXPECT_EQ(options.suiteTimeoutMs, 300000ULL);
    EXPECT_EQ(options.expectedWidth, 1200U);
    EXPECT_EQ(options.expectedHeight, 2000U);
    EXPECT_EQ(options.maxPngBytes, 10U * 1024U * 1024U);
    EXPECT_EQ(options.readyMaxRetries, 3U);
    EXPECT_EQ(options.readyDelayMs, 0U);
    EXPECT_FALSE(options.resume);
    EXPECT_FALSE(options.displayFallback);
    EXPECT_FALSE(options.skipDisplayCheck);
    EXPECT_FALSE(options.includeManual);
}

GraphicTestCaseInfo MakeCase(const std::string& suite, const std::string& name, GraphicCaseMode mode,
    bool multiple = false)
{
    GraphicTestCaseInfo info;
    info.suite = suite;
    info.name = name;
    info.type = "FRAMEWORK_TEST";
    info.mode = mode;
    info.isMultiple = multiple;
    info.sourcePath = "test/demo.cpp";
    return info;
}

TEST(EmulatorCatalogTest, FromCasesSortsAndQueriesAllModes)
{
    std::string error;
    const auto catalog = TestCatalog::FromCases({
        MakeCase("Zeta", "Dynamic", GraphicCaseMode::DYNAMIC),
        MakeCase("Alpha", "Manual", GraphicCaseMode::MANUAL),
        MakeCase("Alpha", "Auto", GraphicCaseMode::AUTOMATIC, true),
    }, error);
    EXPECT_TRUE(error.empty()) << error;
    ASSERT_EQ(catalog.Cases().size(), 3U);
    EXPECT_EQ(catalog.Cases()[0].name, "Auto");
    EXPECT_EQ(catalog.Cases()[1].mode, GraphicCaseMode::MANUAL);
    EXPECT_EQ(catalog.Cases()[2].mode, GraphicCaseMode::DYNAMIC);
    EXPECT_EQ(catalog.Suites(), (std::vector<std::string> { "Alpha", "Zeta" }));
    EXPECT_EQ(catalog.CasesForSuite("Alpha").size(), 2U);
    const auto summary = catalog.Summary();
    EXPECT_EQ(summary.suites, 2U);
    EXPECT_EQ(summary.cases, 3U);
    EXPECT_EQ(summary.automatic, 1U);
    EXPECT_EQ(summary.manual, 1U);
    EXPECT_EQ(summary.dynamic, 1U);
    EXPECT_EQ(summary.multiple, 1U);
}

TEST(EmulatorCatalogTest, FromCasesReportsInvalidInput)
{
    std::string error;
    const auto duplicates = TestCatalog::FromCases({
        MakeCase("Alpha", "One", GraphicCaseMode::AUTOMATIC),
        MakeCase("Alpha", "One", GraphicCaseMode::MANUAL),
    }, error);
    EXPECT_NE(error.find("duplicate"), std::string::npos) << error;
    error.clear();
    const auto invalid = TestCatalog::FromCases({
        MakeCase("Bad-Suite", "Two", GraphicCaseMode::MANUAL),
    }, error);
    EXPECT_NE(error.find("invalid"), std::string::npos) << error;
    error.clear();
    const auto unknownType = TestCatalog::FromCases({
        MakeCase("Alpha", "Two", GraphicCaseMode::MANUAL),
    }, error);
    (void)unknownType;
    (void)duplicates;
}

TEST(EmulatorOptionsTest, RecognizesOnlyTheThreeNewCommands)
{
    const std::vector<std::pair<std::string, bool>> commands = {
        { "-preflight", true }, { "-emulator-run", true }, { "-emulator-unit", true },
        { "-unit", false }, { "-all", false }, { "-list", false },
        { "-list-json", false }, { "-compare", false }, { "-report", false },
    };
    for (const auto& command : commands) {
        EXPECT_EQ(IsEmulatorCommand(command.first), command.second) << command.first;
        if (!command.second) {
            EXPECT_FALSE(Parse({ command.first }).success);
        }
    }
}

TEST(EmulatorOptionsTest, ParsesEachCommandAndChecksRequiredOptions)
{
    EXPECT_EQ(Parse({ "-preflight" }).options.command, EmulatorCommand::PREFLIGHT);
    EXPECT_EQ(Parse({ "-emulator-run" }).options.command, EmulatorCommand::RUN);
    EXPECT_EQ(Parse({ "-emulator-unit", "--suite", "Alpha", "--output-dir", "/tmp/unit" }).options.command,
        EmulatorCommand::UNIT);
    const std::vector<std::vector<std::string>> invalid = {
        { "-emulator-run", "--resume" },
        { "-emulator-unit", "--suite", "Alpha" }, { "-emulator-unit", "--output-dir", "/tmp/unit" },
        { "-emulator-unit", "--case", "One" },
    };
    for (const auto& arguments : invalid) {
        const auto result = Parse(arguments);
        EXPECT_FALSE(result.success) << arguments.back();
        EXPECT_FALSE(result.error.empty());
    }
    EXPECT_TRUE(Parse({ "-emulator-run", "--resume", "--run-id", "run-1" }).success);
}

TEST(EmulatorOptionsTest, RunAndUnitUseSpecifiedDefaults)
{
    const auto run = Parse({ "-emulator-run" });
    ASSERT_TRUE(run.success) << run.error;
    ExpectDefaults(run.options);
    const auto unit = Parse({ "-emulator-unit", "--suite", "Alpha", "--output-dir", "/tmp/unit" });
    ASSERT_TRUE(unit.success) << unit.error;
    ExpectDefaults(unit.options);
    EXPECT_EQ(unit.options.suite, "Alpha");
    EXPECT_EQ(unit.options.outputDir, "/tmp/unit");
}

TEST(EmulatorOptionsTest, RejectsUnknownDuplicateMissingAndUnrelatedOptions)
{
    const std::vector<std::vector<std::string>> invalid = {
        { "-emulator-run", "--unknown" },
        { "-emulator-run", "--output-root", "/tmp/a", "--output-root", "/tmp/b" },
        { "-emulator-run", "--suite" },
        { "-emulator-unit", "--suite", "Alpha", "--output-dir", "/tmp/u", "--run-id", "r" },
        { "-preflight", "--suite", "Alpha" },
        { "-emulator-run", "--manifest", "/tmp/m" },
        { "-emulator-run", "--catalog", "/tmp/c" },
        { "-emulator-run", "--package-root", "/tmp/p" },
        { "-emulator-run", "--skip-preflight" },
    };
    for (const auto& arguments : invalid) {
        EXPECT_FALSE(Parse(arguments).success) << arguments.back();
    }
}

TEST(EmulatorOptionsTest, EnforcesNumericRangesAndCompleteValues)
{
    const std::vector<std::string> positiveOptions = {
        "--suite-timeout-ms", "--expected-width", "--expected-height", "--max-png-bytes",
    };
    for (const auto& option : positiveOptions) {
        EXPECT_FALSE(Parse({ "-emulator-run", option, "0" }).success) << option;
        EXPECT_FALSE(Parse({ "-emulator-run", option, "1x" }).success) << option;
        EXPECT_FALSE(Parse({ "-emulator-run", option, "-1" }).success) << option;
    }
    EXPECT_FALSE(Parse({ "-emulator-run", "--max-png-bytes", "18446744073709551616" }).success);
    EXPECT_TRUE(Parse({ "-emulator-unit", "--suite", "Alpha", "--output-dir", "/tmp/u",
        "--ready-max-retries", "1", "--ready-delay-ms", "0" }).success);
    EXPECT_FALSE(Parse({ "-emulator-unit", "--suite", "Alpha", "--output-dir", "/tmp/u",
        "--ready-max-retries", "0" }).success);
}

} // namespace
} // namespace Rosen
} // namespace OHOS
