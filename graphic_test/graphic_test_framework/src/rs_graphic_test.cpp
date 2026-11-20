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

#include "display_manager.h"
#include "rs_graphic_test_capture.h"
#include "rs_graphic_test.h"
#include "rs_graphic_test_director.h"
#include "rs_graphic_test_utils.h"
#include "rs_parameter_parse.h"
#include "rs_trace.h"
#include "transaction/rs_interfaces.h"
#include "ui/rs_root_node.h"
#include "ui/rs_surface_node.h"

#include <chrono>
#include <filesystem>
#include <iostream>
#include <thread>

using namespace std;
namespace OHOS {
namespace Rosen {
namespace {
constexpr uint32_t SURFACE_COLOR = 0xffffffff;
constexpr int64_t LOAD_TREE_WAIT_TIME = 3;
constexpr int PLAYBACK_PREPARE_WAIT_TIME = 5000;

void ReportEmulatorCaptureFailure(const std::string& message)
{
    LOGE("%{public}s", message.c_str());
    if (IsEmulatorCaptureModeEnabled()) {
        ADD_FAILURE() << message;
    }
}

void CheckFlushResultForEmulator(bool success, const char* stage)
{
    if (IsEmulatorCaptureModeEnabled()) {
        EXPECT_TRUE(success) << "RSGraphicTest flush timed out at " << stage;
    }
}

// Divided-render emulators never receive the transaction-data callback, so with a configured
// settle value send commands and wait briefly instead of blocking on the callback timeout.
bool FlushForStage(const char* stage)
{
    const uint32_t settleMs = GetEmulatorFlushSettleMs();
    if (settleMs > 0) {
        RSGraphicTestDirector::Instance().FlushMessageAndSettle(static_cast<int>(settleMs));
        return true;
    }
    const bool finished = RSGraphicTestDirector::Instance().FlushMessageAndWait(
        RSParameterParse::Instance().testCaseWaitTime);
    CheckFlushResultForEmulator(finished, stage);
    return finished;
}

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

UIPoint RSGraphicTest::GetScreenCapacity(const string testCase)
{
    int testCnt = ::OHOS::Rosen::TestDefManager::Instance().GetTestCaseCnt(testCase);
    int cl = 1;
    int num = 1;
    while (num < testCnt) {
        cl++;
        num = cl * cl;
    }
    int rl = ceil(static_cast<double>(testCnt) / cl);
    return {cl, rl};
}

UIPoint RSGraphicTest::GetPos(int id, int cl)
{
    if (cl > 0) {
        int x = id % cl;
        int y = id / cl;
        return {x, y};
    }

    return {0, 0};
}

void RSGraphicTest::SetUp()
{
    shouldRunTest_ = ShouldRunCurrentTest();
    if (!shouldRunTest_) {
        GTEST_SKIP();
        return;
    }

    if (IsDisplayCaptureFallbackEnabled()) {
        SetGraphicTestCaptureNativeToken();
    }

    RSSurfaceNodeConfig config;
    string surfaceNodeName = "TestSurface";
    config.SurfaceNodeName = surfaceNodeName.append(to_string(imageWriteId_));
    auto testSurface = RSSurfaceNode::Create(config, RSSurfaceNodeType::APP_WINDOW_NODE, true, false,
        RSGraphicTestDirector::Instance().GetRSUIContext());
    if (testSurface == nullptr) {
        return;
    }

    testSurface->SetBounds({0, 0, GetScreenSize()[0], GetScreenSize()[1]});
    testSurface->SetFrame({0, 0, GetScreenSize()[0], GetScreenSize()[1]});
    testSurface->SetBackgroundColor(SURFACE_COLOR);
    GetRootNode()->SetTestSurface(testSurface);

    BeforeEach();

    const ::testing::TestInfo* const testInfo =
        ::testing::UnitTest::GetInstance()->current_test_info();
    const auto& extInfo = ::OHOS::Rosen::TestDefManager::Instance().GetTestInfo(
        testInfo->test_case_name(), testInfo->name());

    if (extInfo == nullptr) {
        return;
    }

    auto size = GetScreenSize();
    cout << "SetUp:size:" << size.x_ << "*" << size.y_ << endl;
    if (!extInfo->isMultiple) {
        cout << "SetUp:isMultiple is false" << endl;
        SetScreenSurfaceBounds({0, 0, size.x_, size.y_});
        return;
    }

    cout << "SetUp:isMultiple is true" << endl;
    auto capacity = GetScreenCapacity(string(testInfo->test_case_name()));
    cout << "SetUp:capacity:" << capacity.x_ << "*" << capacity.y_ << endl;
    if (imageWriteId_ == 0) {
        SetScreenSurfaceBounds({0, 0, capacity.x_*size.x_, capacity.y_*size.y_});
        cout << "ScreenSurfaceBounds:[" << capacity.x_*size.x_ << "*" << capacity.y_*size.y_ << "]" << endl;
    }
    auto pos = GetPos(extInfo->testId, capacity.x_);
    cout << "pos:id:" << imageWriteId_ << "[" << pos.x_ << "." << pos.y_ << "]" << endl;

    testSurface->SetBounds({pos.x_*size.x_, pos.y_*size.y_, size.x_, size.y_});
    testSurface->SetFrame({pos.x_*size.x_, pos.y_*size.y_, size.x_, size.y_});
}

bool RSGraphicTest::WaitOtherTest()
{
    if (IsSingleTest()) {
        return false;
    }
    const ::testing::TestInfo* const testInfo =
        ::testing::UnitTest::GetInstance()->current_test_info();
    const auto& extInfo = ::OHOS::Rosen::TestDefManager::Instance().GetTestInfo(
        testInfo->test_case_name(), testInfo->name());
    int testCaseCnt = ::OHOS::Rosen::TestDefManager::Instance().GetTestCaseCnt(
        string(testInfo->test_case_name()));
    if (extInfo == nullptr) {
        return true;
    }
    if (!extInfo->isMultiple) {
        return false;
    }
    if (++imageWriteId_ < testCaseCnt) {
        return true;
    }
    return false;
}

void RSGraphicTest::TestCaseCapture(bool isScreenshot)
{
    const ::testing::TestInfo* const testInfo =
        ::testing::UnitTest::GetInstance()->current_test_info();
    const auto& extInfo = ::OHOS::Rosen::TestDefManager::Instance().GetTestInfo(
        testInfo->test_case_name(), testInfo->name());
    if (extInfo == nullptr) {
        LOGE("RSGraphicTest::TestCaseCapture no testinfo %{public}s-%{public}s",
            testInfo->test_case_name(), testInfo->name());
        return;
    }

    const bool useDisplayCapture = isScreenshot ||
        (captureScope_ == CaptureScope::FULL_DISPLAY) ||
        GetRootNode()->HasSubWindows();
    const int64_t captureStart = EmulatorMonotonicTimeMs();
    auto pixelMap = RSGraphicTestDirector::Instance().TakeScreenCaptureAndWait(
        RSParameterParse::Instance().surfaceCaptureWaitTime, useDisplayCapture);
    LogEmulatorTiming("capture", captureStart);
    if (!pixelMap) {
        if (IsEmulatorCaptureModeEnabled()) {
            ReportEmulatorCaptureFailure("RSGraphicTest capture returned no PixelMap");
        } else {
            std::cout << "png TakeScreenCaptureAndWait failed" << std::endl;
        }
        return;
    }
    if (hasCaptureCrop_) {
        const uint32_t cropResult = pixelMap->crop({
            static_cast<int32_t>(captureCrop_.x_), static_cast<int32_t>(captureCrop_.y_),
            static_cast<int32_t>(captureCrop_.z_), static_cast<int32_t>(captureCrop_.w_)});
        if (cropResult != 0 && IsEmulatorCaptureModeEnabled()) {
            ReportEmulatorCaptureFailure("RSGraphicTest capture crop failed");
            return;
        }
    }
    WriteCaptureFile(testInfo, extInfo, *pixelMap, useDisplayCapture);
}

std::pair<uint32_t, uint32_t> RSGraphicTest::GetExpectedCaptureSize(bool useDisplayCapture) const
{
    if (hasCaptureCrop_) {
        return {static_cast<uint32_t>(captureCrop_.z_), static_cast<uint32_t>(captureCrop_.w_)};
    }
    if (useDisplayCapture) {
        const auto display = DisplayManager::GetInstance().GetDefaultDisplay();
        if (display) {
            return {static_cast<uint32_t>(display->GetWidth()), static_cast<uint32_t>(display->GetHeight())};
        }
    }
    const auto rootNode = GetRootNode();
    if (rootNode && rootNode->screenSurfaceNode_) {
        const auto bounds = rootNode->screenSurfaceNode_->GetStagingProperties().GetBounds();
        if (bounds.z_ > 0 && bounds.w_ > 0) {
            return {static_cast<uint32_t>(bounds.z_), static_cast<uint32_t>(bounds.w_)};
        }
    }
    return {0, 0};
}

void RSGraphicTest::WriteCaptureFile(const ::testing::TestInfo* testInfo, const TestDefInfo* extInfo,
    Media::PixelMap& pixelMap, bool useDisplayCapture)
{
    std::string filename = GetImageSavePath(extInfo->filePath);
    if (filename.empty()) {
        ReportEmulatorCaptureFailure("RSGraphicTest invalid image save path");
        return;
    }
    filename += testInfo->test_case_name();
    if (!extInfo->isMultiple) {
        filename += std::string("_") + testInfo->name();
    }
    filename += std::string(".png");
    if (std::filesystem::exists(filename)) {
        LOGW("RSGraphicTest file exists %{public}s", filename.c_str());
    }
    uint32_t expectedWidth = 0;
    uint32_t expectedHeight = 0;
    if (IsEmulatorCaptureModeEnabled()) {
        const auto expected = GetExpectedCaptureSize(useDisplayCapture);
        expectedWidth = expected.first;
        expectedHeight = expected.second;
        if (expectedWidth == 0 || expectedHeight == 0) {
            ReportEmulatorCaptureFailure("RSGraphicTest cannot determine expected capture size");
            return;
        }
        std::cout << "RS_GRAPHIC_TEST_EXPECT_SIZE width=" << expectedWidth << " height=" << expectedHeight << std::endl;
        if (hasCaptureCrop_) {
            std::cout << "RS_GRAPHIC_TEST_CROP rect=" << captureCrop_.x_ << "," << captureCrop_.y_ << "," <<
                captureCrop_.z_ << "," << captureCrop_.w_ << std::endl;
        } else {
            std::cout << "RS_GRAPHIC_TEST_CROP rect=none" << std::endl;
        }
    }
    const int64_t writeStart = EmulatorMonotonicTimeMs();
    const bool writeSuccess = IsEmulatorCaptureModeEnabled() ?
        WriteToPngWithPixelMapAtomic(filename, pixelMap, expectedWidth, expectedHeight) :
        WriteToPngWithPixelMap(filename, pixelMap);
    LogEmulatorTiming("write", writeStart);
    if (!writeSuccess) {
        if (IsEmulatorCaptureModeEnabled()) {
            ReportEmulatorCaptureFailure("RSGraphicTest write image failed: " + filename);
            return;
        }
        LOGE("RSGraphicTest::TearDown write image failed %{public}s-%{public}s",
            testInfo->test_case_name(), testInfo->name());
    }
    if (!IsEmulatorCaptureModeEnabled() || writeSuccess) {
        std::cout << "png write to " << filename << std::endl;
    }
}

void RSGraphicTest::TearDown()
{
    if (!shouldRunTest_ || RSParameterParse::Instance().skipCapture_) {
        GetRootNode()->ResetSubWindows();
        GetRootNode()->ResetTestSurface();
        nodes_.clear();
        return;
    }

    const ::testing::TestInfo* const testInfo =
        ::testing::UnitTest::GetInstance()->current_test_info();
    const auto& extInfo = ::OHOS::Rosen::TestDefManager::Instance().GetTestInfo(
        testInfo->test_case_name(), testInfo->name());

    if (WaitOtherTest()) {
        return;
    }

    StartUIAnimation();
    FlushForStage("before capture");
    WaitTimeout(RSParameterParse::Instance().normalWaitTime);

    bool isManualTest = false;
    if (extInfo) {
        isManualTest = (extInfo->testMode == RSGraphicTestMode::MANUAL);
    } else {
        LOGE("RSGraphicTest no testinfo %{public}s-%{public}s", testInfo->test_case_name(), testInfo->name());
        return;
    }

    bool isDynamicTest = extInfo->testMode == RSGraphicTestMode::DYNAMIC;
    if (isManualTest) {
        WaitTimeout(RSParameterParse::Instance().manualTestWaitTime);
    } else {
        TestCaseCapture(isDynamicTest);
    }

    AfterEach();
    ClearCaptureCrop();

    if (isDynamicTest) {
        PlaybackStop();
    }

    GetRootNode()->ResetSubWindows();
    GetRootNode()->ResetTestSurface();
    nodes_.clear();
    RSGraphicTestDirector::Instance().SendProfilerCommand("rssubtree_clear");
    FlushForStage("during cleanup");
    WaitTimeout(RSParameterParse::Instance().normalWaitTime);
}

void RSGraphicTest::RegisterNode(std::shared_ptr<RSNode> node)
{
    nodes_.push_back(node);
    GetRootNode()->RegisterNode(node);
}

void RSGraphicTest::AddFileRenderNodeTreeToNode(std::shared_ptr<RSNode> node, const std::string& filePath)
{
    if (!shouldRunTest_ || RSParameterParse::Instance().skipCapture_) {
        return;
    }
    //need flush client node to rs firstly
    RSGraphicTestDirector::Instance().FlushMessage();
    WaitTimeout(RSParameterParse::Instance().testCaseWaitTime);

    std::cout << "load subbtree to node file path is " << filePath << std::endl;
    std::string command = "rssubtree_load " + std::to_string(node->GetId()) + " " + filePath;
    RSGraphicTestDirector::Instance().SendProfilerCommand(command);
    RSGraphicTestDirector::Instance().FlushMessage();
    WaitTimeout(LOAD_TREE_WAIT_TIME * RSParameterParse::Instance().testCaseWaitTime);
}

void RSGraphicTest::PlaybackRecover(const std::string& filePath, float pauseTimeStamp)
{
    if (!shouldRunTest_ || RSParameterParse::Instance().skipCapture_) {
        return;
    }
    // playback prepare
    int64_t pid = 0;
    std::string command =
        "rsrecord_replay_prepare " + std::to_string(pid) + " " + std::to_string(pauseTimeStamp) + " " + filePath;
    std::cout << "Playback Prepare: " << command << std::endl;
    RSGraphicTestDirector::Instance().SendProfilerCommand(command);
    WaitTimeout(PLAYBACK_PREPARE_WAIT_TIME);

    // playback start
    command = "rsrecord_replay";
    std::cout << "Playback Start: " << command << std::endl;
    RSGraphicTestDirector::Instance().SendProfilerCommand(command);
    WaitTimeout(static_cast<int>(pauseTimeStamp * UNIT_SEC_TO_MS) + RSParameterParse::Instance().testCaseWaitTime);
}

void RSGraphicTest::PlaybackStop()
{
    // playback stop
    std::string command = "rsrecord_replay_stop";
    std::cout << "Playback Stop: " << command << std::endl;
    RSGraphicTestDirector::Instance().SendProfilerCommand(command);
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

void RSGraphicTest::SetScreenSurfaceBounds(const Vector4f& bounds)
{
    RSGraphicTestDirector::Instance().SetScreenSurfaceBounds(bounds);
}

void RSGraphicTest::SetSurfaceColor(const RSColor& color)
{
    RSGraphicTestDirector::Instance().SetSurfaceColor(color);
}

void RSGraphicTest::SetScreenSize(float width, float height)
{
    RSGraphicTestDirector::Instance().SetScreenSize(width, height);
}

bool RSGraphicTest::IsSingleTest()
{
    return RSGraphicTestDirector::Instance().IsSingleTest();
}

std::string RSGraphicTest::GetImageSavePath(const std::string path)
{
    const size_t firstSlash = path.find('/');
    const size_t lastSlash = path.rfind('/');
    if (path.empty() || firstSlash == std::string::npos || lastSlash == std::string::npos ||
        lastSlash < firstSlash || lastSlash + 1 >= path.size()) {
        LOGE("RSGraphicTest invalid source path %{public}s", path.c_str());
        return {};
    }
    std::string imagePath = IsEmulatorCaptureModeEnabled() ? GetEmulatorCaptureConfig().outputDirectory :
        "/data/local/graphic_test";
    if (imagePath.empty()) {
        LOGE("RSGraphicTest image save root is empty");
        return {};
    }
    if (imagePath.back() != '/') {
        imagePath.push_back('/');
    }
    imagePath.append(path.substr(firstSlash + 1, lastSlash - firstSlash));

    namespace fs = std::filesystem;
    std::error_code errorCode;
    fs::create_directories(imagePath, errorCode);
    if (errorCode) {
        LOGE("RSGraphicTest create dir failed %{public}s, error=%{public}d",
            imagePath.c_str(), errorCode.value());
        return {};
    }
    const bool isDirectory = fs::is_directory(imagePath, errorCode);
    if (errorCode || !isDirectory) {
        LOGE("RSGraphicTest path is not dir %{public}s, error=%{public}d",
            imagePath.c_str(), errorCode.value());
        return {};
    }
    return imagePath;
}

void RSGraphicTest::StartUIAnimation()
{
    RSGraphicTestDirector::Instance().StartRunUIAnimation();
}

SubWindowId RSGraphicTest::CreateSubWindow(const SubWindowOptions& options)
{
    auto rootNode = GetRootNode();
    if (!rootNode) {
        return INVALID_SUB_WINDOW_ID;
    }
    return rootNode->CreateSubWindow(options);
}

std::shared_ptr<RSSurfaceNode> RSGraphicTest::GetSubWindow(SubWindowId id)
{
    auto rootNode = GetRootNode();
    if (!rootNode) {
        return nullptr;
    }
    return rootNode->GetSubWindow(id);
}

std::shared_ptr<RSSurfaceNode> RSGraphicTest::GetSubWindowTestSurface(SubWindowId id)
{
    auto rootNode = GetRootNode();
    if (!rootNode) {
        return nullptr;
    }
    return rootNode->GetSubWindowTestSurface(id);
}

bool RSGraphicTest::AddChildToSubWindow(
    SubWindowId id, std::shared_ptr<RSNode> child, int childIndex)
{
    auto rootNode = GetRootNode();
    if (!rootNode) {
        return false;
    }
    return rootNode->AddChildToSubWindow(id, child, childIndex);
}

bool RSGraphicTest::RemoveSubWindow(SubWindowId id)
{
    auto rootNode = GetRootNode();
    if (!rootNode) {
        return false;
    }
    return rootNode->RemoveSubWindow(id);
}

void RSGraphicTest::SetCaptureScope(CaptureScope scope)
{
    captureScope_ = scope;
}

void RSGraphicTest::SetCaptureCrop(const Vector4f& cropRect)
{
    captureCrop_ = cropRect;
    hasCaptureCrop_ = true;
}

void RSGraphicTest::ClearCaptureCrop()
{
    hasCaptureCrop_ = false;
    captureCrop_ = {0, 0, 0, 0};
}

void RSGraphicTest::SetCaptureScreenNativeToken()
{
    SetGraphicTestCaptureNativeToken();
}
} // namespace Rosen
} // namespace OHOS
