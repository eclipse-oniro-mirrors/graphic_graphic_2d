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

#include "rs_graphic_test_catalog.h"

#include <algorithm>
#include <cctype>
#include <iterator>
#include <string_view>
#include <tuple>
#include <utility>

#include "rs_graphic_test_ext.h"

namespace OHOS {
namespace Rosen {
namespace {

constexpr std::string_view TEST_TYPE_NAMES[] = {
    "FRAMEWORK_TEST", "ANIMATION_TEST", "CONTENT_DISPLAY_TEST", "SCREEN_MANAGER_TEST",
    "HARDWARE_PRESENT_TEST", "DRAWING_TEST", "LTPO_TEST", "TEXT_TEST", "PIXMAP_TEST",
    "SYMBOL_TEST", "EFFECT_TEST", "HYBRID_RENDER_TEST", "GPU_COMPOSER_TEST",
};

bool Fail(std::string& error, const std::string& message)
{
    error = message;
    return false;
}

std::string TestTypeToString(RSGraphicTestType type)
{
    const auto index = static_cast<size_t>(type);
    return index < std::size(TEST_TYPE_NAMES) ? std::string(TEST_TYPE_NAMES[index]) : std::string();
}

bool IsValidName(const std::string& value)
{
    if (value.empty() || !(std::isalpha(static_cast<unsigned char>(value.front())) || value.front() == '_')) {
        return false;
    }
    return std::all_of(value.begin(), value.end(), [](unsigned char ch) {
        return std::isalnum(ch) || ch == '_';
    });
}

bool IsKnownType(const std::string& type)
{
    return std::find(std::begin(TEST_TYPE_NAMES), std::end(TEST_TYPE_NAMES), type) != std::end(TEST_TYPE_NAMES);
}

bool ValidateAndSort(std::vector<GraphicTestCaseInfo>& cases, std::string& error)
{
    for (auto& info : cases) {
        if (!IsValidName(info.suite) || !IsValidName(info.name)) {
            return Fail(error, "invalid suite or case name");
        }
        if (!IsKnownType(info.type) || GraphicCaseModeToString(info.mode) == "unknown") {
            return Fail(error, "invalid test type or mode");
        }
    }
    std::sort(cases.begin(), cases.end(), [](const auto& lhs, const auto& rhs) {
        return std::tie(lhs.suite, lhs.name) < std::tie(rhs.suite, rhs.name);
    });
    const auto duplicate = std::adjacent_find(cases.begin(), cases.end(), [](const auto& lhs, const auto& rhs) {
        return lhs.suite == rhs.suite && lhs.name == rhs.name;
    });
    return duplicate == cases.end() || Fail(error, "duplicate suite.case: " + duplicate->suite + "." + duplicate->name);
}

} // namespace

bool TestCatalog::FromRegistry(TestCatalog& catalog, std::string& error)
{
    TestCatalog result;
    for (const TestDefInfo* info : TestDefManager::Instance().GetAllTestInfos()) {
        if (info == nullptr) {
            return Fail(error, "registry returned a null test definition");
        }
        GraphicTestCaseInfo item { info->testCaseName, info->testName, TestTypeToString(info->testType),
            GraphicCaseModeFromTestMode(static_cast<uint8_t>(info->testMode)), info->isMultiple, info->filePath };
        result.cases_.push_back(std::move(item));
    }
    if (!ValidateAndSort(result.cases_, error)) {
        return false;
    }
    catalog = std::move(result);
    error.clear();
    return true;
}

// Callers must treat a non-empty error as "do not use the returned catalog";
// the partially sorted result is returned only to keep the signature simple.
TestCatalog TestCatalog::FromCases(const std::vector<GraphicTestCaseInfo>& cases, std::string& error)
{
    TestCatalog catalog;
    catalog.cases_ = cases;
    ValidateAndSort(catalog.cases_, error);
    return catalog;
}

const std::vector<GraphicTestCaseInfo>& TestCatalog::Cases() const
{
    return cases_;
}

std::vector<std::string> TestCatalog::Suites() const
{
    std::vector<std::string> suites;
    for (const auto& info : cases_) {
        if (suites.empty() || suites.back() != info.suite) {
            suites.push_back(info.suite);
        }
    }
    return suites;
}

std::vector<GraphicTestCaseInfo> TestCatalog::CasesForSuite(const std::string& suite) const
{
    std::vector<GraphicTestCaseInfo> result;
    std::copy_if(cases_.begin(), cases_.end(), std::back_inserter(result),
        [&suite](const auto& info) { return info.suite == suite; });
    return result;
}

GraphicCatalogSummary TestCatalog::Summary() const
{
    GraphicCatalogSummary summary;
    summary.cases = cases_.size();
    summary.suites = Suites().size();
    for (const auto& info : cases_) {
        summary.automatic += info.mode == GraphicCaseMode::AUTOMATIC ? 1 : 0;
        summary.manual += info.mode == GraphicCaseMode::MANUAL ? 1 : 0;
        summary.dynamic += info.mode == GraphicCaseMode::DYNAMIC ? 1 : 0;
        summary.multiple += info.isMultiple ? 1 : 0;
    }
    return summary;
}

} // namespace Rosen
} // namespace OHOS
