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

#include "rs_graphic_test_emulator.h"

#include <algorithm>
#include <charconv>
#include <iterator>
#include <limits>
#include <set>
#include <string_view>
#include <utility>

namespace OHOS {
namespace Rosen {
namespace {

using StringMember = std::string EmulatorOptions::*;
using NumberMember = uint64_t EmulatorOptions::*;
using BoolMember = bool EmulatorOptions::*;

struct OptionSpec {
    const char* name;
    uint32_t commands;
    StringMember stringValue = nullptr;
    NumberMember numberValue = nullptr;
    BoolMember boolValue = nullptr;
    uint64_t minimum = 0;
    uint64_t maximum = 0;
};

constexpr uint32_t CommandMask(EmulatorCommand command)
{
    return 1U << static_cast<uint32_t>(command);
}

constexpr uint32_t PREFLIGHT = CommandMask(EmulatorCommand::PREFLIGHT);
constexpr uint32_t RUN = CommandMask(EmulatorCommand::RUN);
constexpr uint32_t UNIT = CommandMask(EmulatorCommand::UNIT);
constexpr uint32_t RUN_UNIT = RUN | UNIT;
constexpr uint32_t RUN_PREFLIGHT = RUN | PREFLIGHT;
constexpr uint32_t ALL_DISPLAY = RUN_UNIT | PREFLIGHT;
constexpr uint64_t MAX_U32 = std::numeric_limits<uint32_t>::max();
constexpr uint64_t MAX_U64 = std::numeric_limits<uint64_t>::max();

bool Fail(std::string& error, const std::string& message)
{
    error = message;
    return false;
}

const OptionSpec* FindOption(const std::string& name)
{
    static const OptionSpec SPECS[] = {
        { "--output-root", RUN, &EmulatorOptions::outputRoot },
        { "--output-dir", UNIT, &EmulatorOptions::outputDir },
        { "--run-id", RUN, &EmulatorOptions::runId },
        { "--test-binary", RUN_PREFLIGHT, &EmulatorOptions::testBinary },
        { "--suite", RUN_UNIT, &EmulatorOptions::suite },
        { "--case", RUN_UNIT, &EmulatorOptions::caseName },
        { "--exclude-cases-file", RUN_UNIT, &EmulatorOptions::excludeCasesFile },
        { "--working-directory", RUN_UNIT, &EmulatorOptions::workingDirectory },
        { "--suites", RUN },
        { "--suite-timeout-ms", RUN, nullptr, &EmulatorOptions::suiteTimeoutMs, nullptr, 1, MAX_U64 },
        { "--expected-width", ALL_DISPLAY, nullptr, &EmulatorOptions::expectedWidth, nullptr, 1, MAX_U32 },
        { "--expected-height", ALL_DISPLAY, nullptr, &EmulatorOptions::expectedHeight, nullptr, 1, MAX_U32 },
        { "--max-png-bytes", RUN_UNIT, nullptr, &EmulatorOptions::maxPngBytes, nullptr, 1, MAX_U64 },
        { "--ready-max-retries", RUN_UNIT, nullptr, &EmulatorOptions::readyMaxRetries, nullptr, 1, MAX_U32 },
        { "--ready-delay-ms", RUN_UNIT, nullptr, &EmulatorOptions::readyDelayMs, nullptr, 0, MAX_U64 },
        { "--flush-settle-ms", RUN_UNIT, nullptr, &EmulatorOptions::flushSettleMs, nullptr, 0, MAX_U32 },
        { "--resume", RUN, nullptr, nullptr, &EmulatorOptions::resume },
        { "--display-fallback", RUN_UNIT, nullptr, nullptr, &EmulatorOptions::displayFallback },
        { "--skip-display-check", RUN_PREFLIGHT, nullptr, nullptr, &EmulatorOptions::skipDisplayCheck },
        { "--include-manual", RUN_UNIT, nullptr, nullptr, &EmulatorOptions::includeManual },
    };
    const auto it = std::find_if(std::begin(SPECS), std::end(SPECS), [&name](const auto& spec) {
        return name == spec.name;
    });
    return it == std::end(SPECS) ? nullptr : it;
}

bool ParseCommand(const std::string& name, EmulatorCommand& command)
{
    if (name == "-preflight") {
        command = EmulatorCommand::PREFLIGHT;
    } else if (name == "-emulator-run") {
        command = EmulatorCommand::RUN;
    } else if (name == "-emulator-unit") {
        command = EmulatorCommand::UNIT;
    } else {
        return false;
    }
    return true;
}

bool NeedsValue(const OptionSpec& spec)
{
    return spec.stringValue != nullptr || spec.numberValue != nullptr || std::string_view(spec.name) == "--suites";
}

bool ParseUnsigned(const std::string& text, const OptionSpec& spec, uint64_t& value)
{
    const char* begin = text.data();
    const char* end = begin + text.size();
    const auto parsed = std::from_chars(begin, end, value);
    return parsed.ec == std::errc() && parsed.ptr == end && value >= spec.minimum && value <= spec.maximum;
}

bool ParseSuites(const std::string& value, std::vector<std::string>& suites)
{
    size_t begin = 0;
    while (begin <= value.size()) {
        const size_t end = value.find(',', begin);
        const std::string suite = value.substr(begin, end == std::string::npos ? end : end - begin);
        if (suite.empty() || std::find(suites.begin(), suites.end(), suite) != suites.end()) {
            return false;
        }
        suites.push_back(suite);
        if (end == std::string::npos) {
            break;
        }
        begin = end + 1;
    }
    return !suites.empty();
}

bool ApplyOption(EmulatorOptions& options, const OptionSpec& spec, const std::string& value, std::string& error)
{
    if (std::string_view(spec.name) == "--suites") {
        return ParseSuites(value, options.suites) || Fail(error, "invalid --suites value");
    }
    if (spec.stringValue != nullptr) {
        options.*(spec.stringValue) = value;
        return true;
    }
    uint64_t number = 0;
    if (spec.numberValue == nullptr || !ParseUnsigned(value, spec, number)) {
        return Fail(error, std::string("invalid numeric value for ") + spec.name);
    }
    options.*(spec.numberValue) = number;
    return true;
}

bool ValidateRequired(const EmulatorOptions& options, std::string& error)
{
    if (!options.suite.empty() && !options.suites.empty()) {
        return Fail(error, "--suite and --suites are mutually exclusive");
    }
    if (!options.caseName.empty() && options.suite.empty()) {
        return Fail(error, "--case requires --suite");
    }
    switch (options.command) {
        case EmulatorCommand::PREFLIGHT:
            return true;
        case EmulatorCommand::RUN:
            if (options.resume && options.runId.empty()) {
                return Fail(error, "--resume requires --run-id");
            }
            return true;
        case EmulatorCommand::UNIT:
            return (!options.suite.empty() && !options.outputDir.empty()) ||
                Fail(error, "-emulator-unit requires --suite and --output-dir");
        default:
            return Fail(error, "missing emulator command");
    }
}

} // namespace

bool IsEmulatorCommand(const std::string& command)
{
    EmulatorCommand parsed = EmulatorCommand::NONE;
    return ParseCommand(command, parsed);
}

bool ParseEmulatorOptions(int argc, const char* const argv[], EmulatorOptions& options, std::string& error)
{
    if (argc < 2 || argv == nullptr || argv[1] == nullptr) {
        return Fail(error, "one emulator command is required");
    }
    EmulatorOptions result;
    if (!ParseCommand(argv[1], result.command)) {
        return Fail(error, std::string("unsupported emulator command: ") + argv[1]);
    }
    const uint32_t commandMask = CommandMask(result.command);
    std::set<std::string> seen;
    for (int index = 2; index < argc; ++index) {
        if (argv[index] == nullptr) {
            return Fail(error, "null emulator option");
        }
        const OptionSpec* spec = FindOption(argv[index]);
        if (spec == nullptr || (spec->commands & commandMask) == 0) {
            return Fail(error, std::string("unknown or unrelated option: ") + argv[index]);
        }
        if (!seen.insert(spec->name).second) {
            return Fail(error, std::string("duplicate option: ") + spec->name);
        }
        std::string value;
        if (NeedsValue(*spec)) {
            if (index + 1 >= argc || argv[index + 1] == nullptr || argv[index + 1][0] == '\0' ||
                argv[index + 1][0] == '-') {
                return Fail(error, std::string("missing value for ") + spec->name);
            }
            value = argv[++index];
        } else {
            result.*(spec->boolValue) = true;
            continue;
        }
        if (!ApplyOption(result, *spec, value, error)) {
            return false;
        }
    }
    if (!ValidateRequired(result, error)) {
        return false;
    }
    options = std::move(result);
    error.clear();
    return true;
}

} // namespace Rosen
} // namespace OHOS
