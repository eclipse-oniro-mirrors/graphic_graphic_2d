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

#ifndef RS_GRAPHIC_TEST_CATALOG_H
#define RS_GRAPHIC_TEST_CATALOG_H

#include <string>
#include <vector>

#include "rs_graphic_test_types.h"

namespace OHOS {
namespace Rosen {

// The catalog is the compiled-in view of TestDefManager. Cases come from the registry, never from files.
class TestCatalog {
public:
    static bool FromRegistry(TestCatalog& catalog, std::string& error);
    // Test-only constructor: builds a catalog from an in-memory case list. Invalid or
    // duplicate entries are reported through error and dropped, not silently kept.
    static TestCatalog FromCases(const std::vector<GraphicTestCaseInfo>& cases, std::string& error);

    const std::vector<GraphicTestCaseInfo>& Cases() const;
    std::vector<std::string> Suites() const;
    std::vector<GraphicTestCaseInfo> CasesForSuite(const std::string& suite) const;
    GraphicCatalogSummary Summary() const;

private:
    std::vector<GraphicTestCaseInfo> cases_;
};

} // namespace Rosen
} // namespace OHOS

#endif // RS_GRAPHIC_TEST_CATALOG_H
