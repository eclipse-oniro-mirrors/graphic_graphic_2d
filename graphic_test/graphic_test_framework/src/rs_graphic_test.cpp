/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "rs_graphic_test.h"
#include "rs_graphic_test_director.h"
#include "rs_graphic_test_utils.h"
#include "rs_parameter_parse.h"
#include "ui/rs_root_node.h"
#include "ui/rs_surface_node.h"

#include <thread>
#include <chrono>
#include <filesystem>

namespace OHOS {
namespace Rosen {
namespace {
constexpr uint32_t SURFACE_COLOR = 0xffffffff;

bool ShouldRunCurrentTest()
{
    const ::testing::TestInfo* const testInfo =
        ::testing::UnitTest::GetInstance()->current_test_info();
    const auto& extInfo = ::OHOS::Rosen::TestDefManager::Instance().GetTestInfo(
        testInfo->test_case_name(), testInfo->name());
    const auto& params = RSParameterParse::Instance();
    if (!extInfo) {
        LOGE("RSGraphicTest no testinfo %{public}s-%{public}s",
            testInfo->test_case_name(), testInfo->name());
        return false;
    }
    if (!params.filterTestTypes.empty() && params.filterTestTypes.count(extInfo->testType) == 0) {
        return false;
    }

    if (params.runTestMode != RSGraphicTestMode::ALL && extInfo->testMode != params.runTestMode) {
        return false;
    }

    return true;
}
}

uint32_t RSGraphicTest::imageWriteId_ = 0;

void RSGraphicTest::SetUpTestCase()
{
    imageWriteId_ = 0;
}

void RSGraphicTest::TearDownTestCase()
{
    return;
}

void RSGraphicTest::SetUp()
{
    shouldRunTest_ = ShouldRunCurrentTest();
    if (!shouldRunTest_) {
        GTEST_SKIP();
        return;
    }

    RSSurfaceNodeConfig config;
    config.SurfaceNodeName = "TestSurface";
    auto testSurface = RSSurfaceNode::Create(config, false);

    testSurface->SetBounds({0, 0, GetScreenSize()[0], GetScreenSize()[1]});
    testSurface->SetFrame({0, 0, GetScreenSize()[0], GetScreenSize()[1]});
    testSurface->SetBackgroundColor(SURFACE_COLOR);
    GetRootNode()->SetTestSurface(testSurface);

    BeforeEach();
}

void RSGraphicTest::TearDown()
{
    if (!shouldRunTest_) {
        return;
    }

    RSGraphicTestDirector::Instance().FlushMessage();
    WaitTimeout(RSParameterParse::Instance().testCaseWaitTime);

    const ::testing::TestInfo* const testInfo =
        ::testing::UnitTest::GetInstance()->current_test_info();
    const auto& extInfo = ::OHOS::Rosen::TestDefManager::Instance().GetTestInfo(
        testInfo->test_case_name(), testInfo->name());
    bool isManualTest = false;
    if (extInfo) {
        isManualTest = (extInfo->testMode == RSGraphicTestMode::MANUAL);
    } else {
        LOGE("RSGraphicTest no testinfo %{public}s-%{public}s", testInfo->test_case_name(), testInfo->name());
    }

    if (isManualTest) {
        WaitTimeout(RSParameterParse::Instance().manualTestWaitTime);
    } else {
        auto pixelMap = RSGraphicTestDirector::Instance().TakeScreenCaptureAndWait(
            RSParameterParse::Instance().surfaceCaptureWaitTime);
        if (pixelMap) {
            std::string filename = RSParameterParse::Instance().imageSavePath;
            if (imageSavePath_ != "") {
                filename = imageSavePath_;
            }
            filename += testInfo->test_case_name() + std::string("_");
            filename += testInfo->name() + std::string(".png");
            if (std::filesystem::exists(filename)) {
                LOGW("RSGraphicTest file exists %{public}s", filename.c_str());
            }
            if (!WriteToPngWithPixelMap(filename, *pixelMap)) {
                LOGE("RSGraphicTest::TearDown write image failed %{public}s-%{public}s",
                    testInfo->test_case_name(), testInfo->name());
            }
        }
    }

    AfterEach();

    GetRootNode()->ResetTestSurface();
    RSGraphicTestDirector::Instance().FlushMessage();
    WaitTimeout(RSParameterParse::Instance().testCaseWaitTime);

    ++imageWriteId_;
}

void RSGraphicTest::RegisterNode(std::shared_ptr<RSNode> node)
{
    nodes_.push_back(node);
}

std::shared_ptr<RSGraphicRootNode> RSGraphicTest::GetRootNode() const
{
    return RSGraphicTestDirector::Instance().GetRootNode();
}

Vector2f RSGraphicTest::GetScreenSize() const
{
    return RSGraphicTestDirector::Instance().GetScreenSize();
}

void RSGraphicTest::SetSurfaceBounds(const Vector4f& bounds)
{
    RSGraphicTestDirector::Instance().SetSurfaceBounds(bounds);
}

void RSGraphicTest::SetSurfaceColor(const RSColor& color)
{
    RSGraphicTestDirector::Instance().SetSurfaceColor(color);
}

void RSGraphicTest::SetImageSavePath(const std::string path)
{
    namespace fs = std::filesystem;
    if (!fs::exists(path)) {
        if (!fs::create_directories(path)) {
            LOGE("RSGraphicTestDirector create dir failed");
        }
    } else {
        if (!fs::is_directory(path)) {
            LOGE("RSGraphicTestDirector path is not dir");
            return;
        }
    }
    imageSavePath_ = path;
}

} // namespace Rosen
} // namespace OHOS