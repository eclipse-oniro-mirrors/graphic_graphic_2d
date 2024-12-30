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
#include "drawing_demo.h"

#include <sstream>

#include "accesstoken_kit.h"
#ifdef SUPPORT_ACCESS_TOKEN
#include "nativetoken_kit.h"
#include "token_setproc.h"
#endif
#include "display_manager.h"
#include "test_case_factory.h"
#include "test_case/test_common.h"

using namespace OHOS::Rosen;

namespace OHOS {
namespace Rosen {
DrawingDemo::DrawingDemo(int argc, char* argv[])
{
    argc_ = argc;
    for (int i = 0; i < argc_; i++) {
        std::string str = argv[i];
        argv_.emplace_back(str);
    }
};

DrawingDemo::~DrawingDemo()
{
    if (window_) {
        window_->Hide();
        window_->Destroy();
    }
};

int DrawingDemo::Test(TestDisplayCanvas* canvas)
{
    TestCommon::Log("eg: drawing_demo function [cpu | gpu] {caseName?} {displayTime?}");
    TestCommon::Log("eg: drawing_demo performance [cpu | gpu] caseName count {displayTime?}");
    if (argc_ <= INDEX_DRAWING_TYPE) {
        return RET_PARAM_ERR;
    }

    testType_ = argv_[INDEX_TEST_TYPE];
    drawingType_ = argv_[INDEX_DRAWING_TYPE];
    if (testType_ == "function") {
        if (drawingType_ == "cpu") {
            return TestFunction(FUNCTION_CPU);
        } else if (drawingType_ == "gpu") {
            return TestFunction(FUNCTION_GPU_UPSCREEN);
        }
    } else if (testType_ == "performance") {
        if (drawingType_ == "cpu") {
            return TestPerformance(canvas, PERFORMANCE_CPU);
        } else if (drawingType_ == "gpu") {
            return TestPerformance(canvas, PERFORMANCE_GPU_UPSCREEN);
        }
    }
    return RET_PARAM_ERR;
}

int DrawingDemo::InitWindow()
{
    rsUiDirector_ = RSUIDirector::Create();
    if (rsUiDirector_ == nullptr) {
        TestCommon::Log("Failed to create rsUiDirector_");
        return RET_FAILED;
    }
    rsUiDirector_->Init();
    RSTransaction::FlushImplicitTransaction();
    sleep(1);
    auto surfaceNode = window_->GetSurfaceNode();
    rsUiDirector_->SetRSSurfaceNode(surfaceNode);

    rootNode_ = RSRootNode::Create();
    if (rootNode_ == nullptr) {
        TestCommon::Log("Failed to create rootNode");
        return RET_FAILED;
    }
    rootNode_->SetBounds(0, 0, rect_.width_, rect_.height_);
    rootNode_->SetFrame(0, 0, rect_.width_, rect_.height_);
    rootNode_->SetBackgroundColor(Drawing::Color::COLOR_WHITE);
    rsUiDirector_->SetRoot(rootNode_->GetId());

    canvasNode_ = RSCanvasNode::Create();
    if (canvasNode_ == nullptr) {
        TestCommon::Log("Failed to create canvasNode");
        return RET_FAILED;
    }
    canvasNode_->SetFrame(0, 0, rect_.width_, rect_.height_);
    rootNode_->AddChild(canvasNode_, -1);
    rsUiDirector_->SendMessages();
    sleep(1);
    return RET_OK;
}

void InitNativeTokenInfo()
{
#ifdef SUPPORT_ACCESS_TOKEN
    uint64_t tokenId;
    const char *perms[1];
    perms[0] = "ohos.permission.SYSTEM_FLOAT_WINDOW";
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 1,
        .aclsNum = 0,
        .dcaps = NULL,
        .perms = perms,
        .acls = NULL,
        .processName = "drawing_demo",
        .aplStr = "system_basic",
    };
    tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
#endif
}

int DrawingDemo::CreateWindow()
{
#ifdef SUPPORT_ACCESS_TOKEN
    InitNativeTokenInfo();
    TestCommon::Log("create window start");
    sptr<Display> display = DisplayManager::GetInstance().GetDefaultDisplay();
    if (display == nullptr) {
        TestCommon::Log("Failed to get display!");
        return RET_FAILED;
    }
    int32_t defaultWidth = display->GetWidth();
    int32_t defaultHeight = display->GetHeight();
    std::ostringstream stream;
    stream << "display: " << defaultWidth << "*" << defaultHeight;
    TestCommon::Log(stream.str());

    std::string demoName = "drawing_demo";
    RSSystemProperties::GetUniRenderEnabled();
    sptr<WindowOption> option = new WindowOption();
    option->SetWindowType(WindowType::WINDOW_TYPE_FLOAT);
    option->SetWindowMode(WindowMode::WINDOW_MODE_FLOATING);
    option->SetWindowRect({ 0, 0, defaultWidth, defaultHeight });

    int count = 0;
    do {
        if (window_ != nullptr) {
            window_->Hide();
            window_->Destroy();
        }
        window_ = Window::Create(demoName, option);
        if (window_ == nullptr) {
            TestCommon::Log("Failed to create window");
            return RET_FAILED;
        }

        window_->Show();
        usleep(SLEEP_TIME);
        rect_ = window_->GetRect();
        count++;
    } while (rect_.width_ == 0 && rect_.height_ == 0 && count < MAX_TRY_NUMBER);

    if (rect_.width_ == 0 || rect_.height_ == 0) {
        TestCommon::Log("Failed to create window, rect is 0!");
        return RET_FAILED;
    }
    
    int ret = InitWindow();
    if (ret != RET_OK) {
        return ret;
    }
    stream.str("");
    stream << "create window success: " << rect_.width_ << " * " << rect_.height_;
    TestCommon::Log(stream.str());
    return RET_OK;
#endif
}

int DrawingDemo::GetFunctionalParam(std::unordered_map<std::string, std::function<std::shared_ptr<TestBase>()>>& map)
{
    // drawing_demo functional {cpu | gpu} {caseName?} {displayTime?}
    if (argc_ <= INDEX_CASE_NAME) {
        caseName_ = ALL_TAST_CASE;
        return RET_OK;
    }

    caseName_ = argv_[INDEX_CASE_NAME];
    if (map.find(caseName_) == map.end()) {
        TestCommon::Log("TestCase not exist, please try again. All testcase:");
        for (auto iter : map) {
            TestCommon::Log(iter.first);
        }
        return RET_PARAM_ERR;
    }

    if (argc_ > INDEX_FUNCTION_TIME) {
        std::string displayTimeStr = argv_[INDEX_FUNCTION_TIME];
        displayTime_ = std::stoi(displayTimeStr);
    }
    return RET_OK;
}

int DrawingDemo::TestFunction(int type)
{
    auto map = TestCaseFactory::GetFunctionCase();
    int ret = GetFunctionalParam(map);
    if (ret != RET_OK) {
        return ret;
    }

    TestCommon::Log("TestFunction start!");
    ret = CreateWindow();
    if (ret != RET_OK) {
        return ret;
    }
    for (auto iter : map) {
        if ((caseName_ != ALL_TAST_CASE) && (caseName_ != iter.first)) {
            continue;
        }

        auto canvas = canvasNode_->BeginRecording(rect_.width_, rect_.height_);
        auto testCase = iter.second();
        if (testCase == nullptr) {
            std::ostringstream stream;
            stream << "Failed to create testcase:" << iter.first;
            TestCommon::Log(stream.str());
            continue;
        }

        testCase->SetCanvas((TestDisplayCanvas*)(canvas));
        if (type == FUNCTION_CPU) {
            testCase->SetFileName(iter.first);
            testCase->TestFunctionCpu();
        } else if (type == FUNCTION_GPU_UPSCREEN) {
            testCase->TestFunctionGpuUpScreen();
        }
        canvasNode_->FinishRecording();
        rsUiDirector_->SendMessages();
        if (type == FUNCTION_GPU_UPSCREEN) {
            sleep(2); // Wait for 2 seconds to make the screen display normal
            (void)TestCommon::PackingPixmap(window_->Snapshot(), iter.first);
        }
    }
    
    int time = (caseName_ != ALL_TAST_CASE ? displayTime_ : 1);
    std::ostringstream stream;
    stream << "wait: " << time << "s";
    TestCommon::Log(stream.str());
    sleep(time);
    TestCommon::Log("TestFunction end!");
    return RET_OK;
}

int DrawingDemo::GetPerformanceParam(std::shared_ptr<TestBase>& testCase)
{
    // drawing_demo performance {cpu | gpu} caseName count {displaytime?}
    if (argc_ <= INDEX_COUNT) {
        return RET_PARAM_ERR;
    }

    caseName_ = argv_[INDEX_CASE_NAME];
    auto map = TestCaseFactory::GetPerformanceCase();
    auto iter = map.find(caseName_);
    if (iter == map.end()) {
        TestCommon::Log("TestCase not exist, please try again. All testcase:");
        for (auto iter : map) {
            TestCommon::Log(iter.first);
        }
        return RET_PARAM_ERR;
    }
    testCase = iter->second();
    if (testCase == nullptr) {
        TestCommon::Log("Failed to create testcase");
        return RET_FAILED;
    }

    std::string testCountStr = argv_[INDEX_COUNT];
    testCount_ = std::stoi(testCountStr);
    
    if (argc_ > INDEX_PERFORMANCE_TIME) {
        std::string displayTimeStr = argv_[INDEX_PERFORMANCE_TIME];
        displayTime_ = std::stoi(displayTimeStr);
    }
    return RET_OK;
}

int DrawingDemo::TestPerformance(TestDisplayCanvas* canvasExt, int type)
{
    std::shared_ptr<TestBase> testCase = nullptr;
    int ret = GetPerformanceParam(testCase);
    if (ret != RET_OK || testCase == nullptr) {
        return ret;
    }

    TestCommon::Log("TestPerformance start!");
    TestDisplayCanvas* canvas = nullptr;
    if (canvasExt == nullptr) {
        ret = CreateWindow();
        if (ret != RET_OK) {
            return ret;
        }
        canvas = reinterpret_cast<TestDisplayCanvas*>(canvasNode_->BeginRecording(rect_.width_, rect_.height_));
        if (canvas == nullptr) {
            TestCommon::Log("Failed to get canvas");
            return RET_FAILED;
        }
    } else {
        canvas = canvasExt;
    }

    testCase->SetCanvas((TestDisplayCanvas*)(canvas));
    testCase->SetTestCount(testCount_);

    if (type == PERFORMANCE_CPU) {
        testCase->TestPerformanceCpu();
    } else if (type == PERFORMANCE_GPU_UPSCREEN) {
        testCase->TestPerformanceGpuUpScreen();
    }

    if (canvasExt == nullptr) {
        canvasNode_->FinishRecording();
        rsUiDirector_->SendMessages();

        std::ostringstream stream;
        stream << "wait: " << displayTime_ << "s";
        TestCommon::Log(stream.str());
        sleep(displayTime_);
    }

    TestCommon::Log("TestPerformance end!");
    return RET_OK;
}
} // namespace Rosen
} // namespace OHOS

int main(int argc, char* argv[])
{
    std::shared_ptr<DrawingDemo> drawingDemo = std::make_shared<DrawingDemo>(argc, argv);
    if (drawingDemo == nullptr) {
        TestCommon::Log("Failed to create DrawingDemo");
        return 0;
    }
    int ret = drawingDemo->Test(nullptr);
    if (ret == RET_PARAM_ERR) {
        TestCommon::Log("Invalid parameter, please confirm");
    }
    return ret;
}

#ifdef __cplusplus
extern "C" {
#endif
int DrawingTest(void* canvas, int argc, char* argv[])
{
    if (canvas == nullptr) {
        TestCommon::Log("canvas is nullptr");
        return 0;
    }
    std::shared_ptr<DrawingDemo> drawingDemo = std::make_shared<DrawingDemo>(argc, argv);
    if (drawingDemo == nullptr) {
        TestCommon::Log("Failed to create DrawingDemo");
        return 0;
    }
    int ret = drawingDemo->Test((TestDisplayCanvas*)(canvas));
    if (ret == RET_PARAM_ERR) {
        TestCommon::Log("Invalid parameter, please confirm");
    }
    return ret;
}
#ifdef __cplusplus
}
#endif