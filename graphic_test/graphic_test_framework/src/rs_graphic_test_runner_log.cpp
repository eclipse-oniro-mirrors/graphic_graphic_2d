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

#include "rs_graphic_test_runner_log.h"

#include <algorithm>
#include <cctype>
#include <cerrno>
#include <cstdlib>
#include <map>
#include <sstream>

#include "rs_graphic_test_runner.h"

namespace OHOS {
namespace Rosen {
namespace {

// The framework is built with -fno-exceptions; parse numbers via strtoull instead of std::stoull.
uint64_t SafeStoull(const std::string& value, uint64_t fallback = 0)
{
    if (value.empty()) {
        return fallback;
    }
    errno = 0;
    char* end = nullptr;
    const unsigned long long parsed = std::strtoull(value.c_str(), &end, 10);
    if (errno != 0 || end == value.c_str()) {
        return fallback;
    }
    return static_cast<uint64_t>(parsed);
}

std::string Trim(const std::string& value)
{
    const auto first = std::find_if_not(value.begin(), value.end(), [](unsigned char ch) { return std::isspace(ch); });
    const auto last = std::find_if_not(value.rbegin(), value.rend(), [](unsigned char ch) {
        return std::isspace(ch);
    }).base();
    return first < last ? std::string(first, last) : std::string();
}

std::string MarkerPayload(const std::string& line, const std::string& compact, const std::string& standard)
{
    for (const auto* marker : { &compact, &standard }) {
        if (line.compare(0, marker->size(), *marker) == 0) {
            return Trim(line.substr(marker->size()));
        }
    }
    return {};
}

std::string ParseCaseToken(const std::string& payload)
{
    const size_t end = payload.find_first_of(" \t");
    return payload.substr(0, end);
}

uint64_t ParseDuration(const std::string& payload)
{
    const size_t open = payload.rfind('(');
    const size_t close = payload.rfind(" ms)");
    if (open == std::string::npos || close == std::string::npos || close <= open) {
        return 0;
    }
    return SafeStoull(payload.substr(open + 1, close - open - 1));
}

void ParseStatusLine(const std::string& line, ParsedLog& parsed)
{
    const struct {
        const char* compact;
        const char* standard;
        ExecutionStatus status;
    } markers[] = {
        { "[RUN]", "[ RUN      ]", ExecutionStatus::RUNNING },
        { "[OK]", "[       OK ]", ExecutionStatus::PASSED },
        { "[FAILED]", "[  FAILED  ]", ExecutionStatus::FAILED },
        { "[SKIPPED]", "[  SKIPPED ]", ExecutionStatus::SKIPPED },
    };
    for (const auto& marker : markers) {
        std::string payload = MarkerPayload(line, marker.compact, marker.standard);
        if (payload.empty()) {
            continue;
        }
        const std::string name = ParseCaseToken(payload);
        if (name.find('.') == std::string::npos) {
            return;
        }
        if (marker.status == ExecutionStatus::RUNNING) {
            parsed.lastRun = name;
            parsed.cases[name].status = ExecutionStatus::RUNNING;
        } else {
            auto& item = parsed.cases[name];
            item.status = marker.status;
            const uint64_t durationMs = ParseDuration(payload);
            if (durationMs != 0) {
                item.durationMs = durationMs;
            }
        }
        return;
    }
}

void ParseCaptureLine(const std::string& line, CaseProgress& progress)
{
    constexpr const char* PREFIX = "RS_GRAPHIC_TEST_CAPTURE ";
    if (line.compare(0, std::char_traits<char>::length(PREFIX), PREFIX) != 0) {
        return;
    }
    std::istringstream fields(line.substr(std::char_traits<char>::length(PREFIX)));
    std::string field;
    while (fields >> field) {
        if (field.compare(0, 5, "mode=") == 0) {
            progress.captureMode = field.substr(5);
        } else if (field.compare(0, 7, "reason=") == 0) {
            progress.fallbackReason = field.substr(7);
        }
    }
}

void ParseReadyLine(const std::string& line, CaseProgress& progress)
{
    constexpr const char* PREFIX = "RS_GRAPHIC_TEST_READY ";
    constexpr const char* RETRIES = "retries=";
    const size_t marker = line.find(RETRIES);
    if (line.compare(0, std::char_traits<char>::length(PREFIX), PREFIX) != 0 || marker == std::string::npos) {
        return;
    }
    const std::string value = line.substr(marker + std::char_traits<char>::length(RETRIES));
    if (line.find("status=unstable") != std::string::npos) {
        progress.captureUnstable = true;
    }
    const uint64_t parsed = SafeStoull(Trim(value));
    if (parsed <= std::numeric_limits<uint32_t>::max()) {
        progress.readyRetries = static_cast<uint32_t>(parsed);
    }
}

void ParseExpectedCaptureLine(const std::string& line, CaseProgress& progress)
{
    constexpr const char* SIZE_PREFIX = "RS_GRAPHIC_TEST_EXPECT_SIZE ";
    constexpr const char* CROP_PREFIX = "RS_GRAPHIC_TEST_CROP ";
    if (line.compare(0, std::char_traits<char>::length(SIZE_PREFIX), SIZE_PREFIX) == 0) {
        std::istringstream fields(line.substr(std::char_traits<char>::length(SIZE_PREFIX)));
        std::string width;
        std::string height;
        fields >> width >> height;
        const uint64_t widthValue = SafeStoull(width.substr(6));
        const uint64_t heightValue = SafeStoull(height.substr(7));
        progress.expectedWidth = widthValue <= std::numeric_limits<uint32_t>::max() ?
            static_cast<uint32_t>(widthValue) : 0;
        progress.expectedHeight = heightValue <= std::numeric_limits<uint32_t>::max() ?
            static_cast<uint32_t>(heightValue) : 0;
        return;
    }
    if (line.compare(0, std::char_traits<char>::length(CROP_PREFIX), CROP_PREFIX) == 0) {
        const std::string payload = Trim(line.substr(std::char_traits<char>::length(CROP_PREFIX)));
        progress.cropRect = payload == "rect=none" ? "" : payload.substr(std::char_traits<char>::length("rect="));
    }
}

void ParseTimingLine(const std::string& line, ParsedLog& parsed)
{
    constexpr const char* PREFIX = "RS_GRAPHIC_TEST_TIMING ";
    if (line.compare(0, std::char_traits<char>::length(PREFIX), PREFIX) != 0) {
        return;
    }
    static constexpr const char* PHASES[] = { "startup", "flush", "capture", "write" };
    std::istringstream fields(line.substr(std::char_traits<char>::length(PREFIX)));
    std::string field;
    while (fields >> field) {
        for (const char* phase : PHASES) {
            const std::string prefix = std::string(phase) + "_ms=";
            if (field.compare(0, prefix.size(), prefix) != 0) {
                continue;
            }
            const uint64_t value = SafeStoull(field.substr(prefix.size()));
            uint64_t& total = parsed.phaseDurationsMs[phase];
            if (value <= std::numeric_limits<uint64_t>::max() - total) {
                total += value;
            }
        }
    }
}

} // namespace

ParsedLog ParseLog(const std::string& text)
{
    ParsedLog parsed;
    std::istringstream input(text);
    std::string line;
    while (std::getline(input, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        ParseStatusLine(line, parsed);
        ParseTimingLine(line, parsed);
        if (parsed.lastRun.empty()) {
            continue;
        }
        auto& current = parsed.cases[parsed.lastRun];
        ParseCaptureLine(line, current);
        ParseReadyLine(line, current);
        ParseExpectedCaptureLine(line, current);
        constexpr const char* PNG_PREFIX = "png write to ";
        if (line.compare(0, std::char_traits<char>::length(PNG_PREFIX), PNG_PREFIX) == 0) {
            current.pngPath = Trim(line.substr(std::char_traits<char>::length(PNG_PREFIX)));
        }
    }
    return parsed;
}

} // namespace Rosen
} // namespace OHOS
