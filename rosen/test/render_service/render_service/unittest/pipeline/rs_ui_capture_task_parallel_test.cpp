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

#include <gtest/gtest.h>
#include <hilog/log.h>
#include <memory>
#include <unistd.h>

#include "rs_test_util.h"
#include "surface_buffer_impl.h"
#include "pipeline/rs_surface_capture_task.h"
#include "pipeline/rs_ui_capture_task_parallel.h"
#include "pipeline/rs_base_render_node.h"
#include "pipeline/rs_display_render_node.h"
#include "pipeline/rs_root_render_node.h"
#include "pipeline/rs_render_node.h"
#include "pipeline/rs_surface_render_node.h"
#include "transaction/rs_interfaces.h"
#include "ui/rs_surface_extractor.h"
#include "ui/rs_canvas_node.h"
#include "ui/rs_canvas_drawing_node.h"
#include "ui/rs_proxy_node.h"
#include "pipeline/rs_main_thread.h"
#include "pipeline/rs_paint_filter_canvas.h"
#include "pipeline/rs_uni_render_judgement.h"
#include "pipeline/rs_uni_render_engine.h"
#include "platform/common/rs_system_properties.h"

using namespace testing::ext;

namespace OHOS {
namespace Rosen {
using namespace HiviewDFX;
using DisplayId = ScreenId;
namespace {
constexpr HiLogLabel LOG_LABEL = { LOG_CORE, 0xD001400, "RSUiCaptureTaskParallelTest" };
constexpr uint32_t MAX_TIME_WAITING_FOR_CALLBACK = 200;
constexpr uint32_t SLEEP_TIME_IN_US = 10000; // 10ms
constexpr uint32_t SLEEP_TIME_FOR_PROXY = 100000; // 100ms
constexpr float DEFAULT_BOUNDS_WIDTH = 100.f;
constexpr float DEFAULT_BOUNDS_HEIGHT = 200.f;
constexpr float HALF_BOUNDS_WIDTH = 50.0f;
constexpr float HALF_BOUNDS_HEIGHT = 100.0f;

class CustomizedSurfaceCapture : public SurfaceCaptureCallback {
public:
    void OnSurfaceCapture(std::shared_ptr<Media::PixelMap> pixelmap) override
    {
        captureSuccess_ = (pixelmap != nullptr);
        isCallbackCalled_ = true;
    }

    void Reset()
    {
        captureSuccess_ = false;
        isCallbackCalled_ = false;
    }

    bool captureSuccess_ = false;
    bool isCallbackCalled_ = false;
};
}

class RSUiCaptureTaskParallelTest : public testing::Test {
public:
    static void SetUpTestCase()
    {
        InitRenderContext();
        rsInterfaces_ = &RSInterfaces::GetInstance();

        ScreenId screenId = rsInterfaces_->GetDefaultScreenId();
        RSScreenModeInfo modeInfo = rsInterfaces_->GetScreenActiveMode(screenId);
        DisplayId virtualDisplayId = rsInterfaces_->CreateVirtualScreen("virtualDisplayTest",
            modeInfo.GetScreenWidth(), modeInfo.GetScreenHeight(), nullptr);
        mirrorConfig_.screenId = virtualDisplayId;
        mirrorConfig_.mirrorNodeId = screenId;
        displayNode_ = RSDisplayNode::Create(mirrorConfig_);

        RSTransactionProxy::GetInstance()->FlushImplicitTransaction();
        usleep(SLEEP_TIME_FOR_PROXY);
    }

    static void TearDownTestCase()
    {
        rsInterfaces_->RemoveVirtualScreen(mirrorConfig_.screenId);
        rsInterfaces_ = nullptr;
        renderContext_ = nullptr;
        displayNode_ = nullptr;
        RSTransactionProxy::GetInstance()->FlushImplicitTransaction();
        usleep(SLEEP_TIME_FOR_PROXY);
    }

    static void InitRenderContext()
    {
#ifdef ACE_ENABLE_GL
        if (renderContext_ == nullptr) {
            HiLog::Info(LOG_LABEL, "%s: init renderContext_", __func__);
            renderContext_ = RenderContextFactory::GetInstance().CreateEngine();
            renderContext_->InitializeEglContext();
        }
#endif // ACE_ENABLE_GL
    }

    void SetUp() override
    {
    }

    void TearDown() override
    {
        if (surfaceNode_) {
            displayNode_->RemoveChild(surfaceNode_);
            surfaceNode_ = nullptr;
            canvasNode_ = nullptr;

            RSTransactionProxy::GetInstance()->FlushImplicitTransaction();
            usleep(SLEEP_TIME_FOR_PROXY);
        }
    }

    std::shared_ptr<RSSurfaceNode> SetUpSurface()
    {
        RSSurfaceNodeConfig config;
        surfaceNode_ = RSSurfaceNode::Create(config);
        surfaceNode_->SetBounds(0.0f, 0.0f, DEFAULT_BOUNDS_WIDTH, DEFAULT_BOUNDS_HEIGHT);
        surfaceNode_->SetFrame(0.0f, 0.0f, DEFAULT_BOUNDS_WIDTH, DEFAULT_BOUNDS_HEIGHT);
        surfaceNode_->SetBackgroundColor(Drawing::Color::COLOR_RED);

        canvasNode_ = RSCanvasNode::Create();
        canvasNode_->SetBounds(0.0f, 0.0f, HALF_BOUNDS_WIDTH, HALF_BOUNDS_HEIGHT);
        canvasNode_->SetFrame(0.0f, 0.0f, HALF_BOUNDS_WIDTH, HALF_BOUNDS_HEIGHT);
        canvasNode_->SetBackgroundColor(Drawing::Color::COLOR_YELLOW);

        canvasDrawingNode_ = RSCanvasDrawingNode::Create();
        canvasDrawingNode_->SetBounds(0.0f, 0.0f, HALF_BOUNDS_WIDTH, HALF_BOUNDS_HEIGHT);
        canvasDrawingNode_->SetFrame(0.0f, 0.0f, HALF_BOUNDS_WIDTH, HALF_BOUNDS_HEIGHT);
        canvasDrawingNode_->SetBackgroundColor(Drawing::Color::COLOR_YELLOW);

        canvasNode_->AddChild(canvasDrawingNode_, -1);
        surfaceNode_->AddChild(canvasNode_, -1);
        displayNode_->AddChild(surfaceNode_, -1);
        RSTransactionProxy::GetInstance()->FlushImplicitTransaction();
        usleep(SLEEP_TIME_FOR_PROXY);

        return surfaceNode_;
    }

    bool CheckSurfaceCaptureCallback(std::shared_ptr<CustomizedSurfaceCapture> callback)
    {
        if (!callback) {
            return false;
        }

        uint32_t times = 0;
        while (times < MAX_TIME_WAITING_FOR_CALLBACK) {
            if (callback->isCallbackCalled_) {
                return true;
            }
            usleep(SLEEP_TIME_IN_US);
            ++times;
        }
        HiLog::Error(LOG_LABEL, "CheckSurfaceCaptureCallback timeout");
        return false;
    }

    static RSInterfaces* rsInterfaces_;
    static RenderContext* renderContext_;
    static RSDisplayNodeConfig mirrorConfig_;
    static std::shared_ptr<RSDisplayNode> displayNode_;

    std::shared_ptr<RSSurfaceNode> surfaceNode_;
    std::shared_ptr<RSCanvasNode> canvasNode_;
    std::shared_ptr<RSCanvasDrawingNode> canvasDrawingNode_;
};
RSInterfaces* RSUiCaptureTaskParallelTest::rsInterfaces_ = nullptr;
RenderContext* RSUiCaptureTaskParallelTest::renderContext_ = nullptr;
RSDisplayNodeConfig RSUiCaptureTaskParallelTest::mirrorConfig_ = {INVALID_SCREEN_ID, true, INVALID_SCREEN_ID};
std::shared_ptr<RSDisplayNode> RSUiCaptureTaskParallelTest::displayNode_ = nullptr;

/*
 * @tc.name: TakeSurfaceCaptureForUiInvalidSurface
 * @tc.desc: Test TakeSurfaceCaptureForUI with invalid surface
 * @tc.type: FUNC
 * @tc.require: issueIA6QID
*/
HWTEST_F(RSUiCaptureTaskParallelTest, TakeSurfaceCaptureForUiInvalidSurface, Function | SmallTest | Level2)
{
    RSSurfaceNodeConfig config;
    auto surfaceNode = RSSurfaceNode::Create(config);
    auto callback = std::make_shared<CustomizedSurfaceCapture>();

    bool ret = rsInterfaces_->TakeSurfaceCaptureForUI(surfaceNode, callback);
    ASSERT_EQ(ret, true);
    ASSERT_EQ(CheckSurfaceCaptureCallback(callback), true);
    ASSERT_EQ(callback->captureSuccess_, false);
}

/*
 * @tc.name: TakeSurfaceCaptureForUiSurfaceNode
 * @tc.desc: Test TakeSurfaceCaptureForUI with surface node
 * @tc.type: FUNC
 * @tc.require: issueIA6QID
*/
HWTEST_F(RSUiCaptureTaskParallelTest, TakeSurfaceCaptureForUiSurfaceNode, Function | SmallTest | Level2)
{
    SetUpSurface();

    auto callback = std::make_shared<CustomizedSurfaceCapture>();
    bool ret = rsInterfaces_->TakeSurfaceCaptureForUI(surfaceNode_, callback);
    ASSERT_EQ(ret, true);
    ASSERT_EQ(CheckSurfaceCaptureCallback(callback), true);
    ASSERT_EQ(callback->captureSuccess_, true);
}

/*
 * @tc.name: TakeSurfaceCaptureForUiCanvasNode001
 * @tc.desc: Test TakeSurfaceCaptureForUI with canvas node
 * @tc.type: FUNC
 * @tc.require: issueIA6QID
*/
HWTEST_F(RSUiCaptureTaskParallelTest, TakeSurfaceCaptureForUiCanvasNode001, Function | SmallTest | Level2)
{
    SetUpSurface();

    auto callback = std::make_shared<CustomizedSurfaceCapture>();
    bool ret = rsInterfaces_->TakeSurfaceCaptureForUI(canvasNode_, callback);
    ASSERT_EQ(ret, true);
    ASSERT_EQ(CheckSurfaceCaptureCallback(callback), true);
    ASSERT_EQ(callback->captureSuccess_, true);
}

/*
 * @tc.name: TakeSurfaceCaptureForUiCanvasNode002
 * @tc.desc: Test TakeSurfaceCaptureForUI with canvas node bounds inf
 * @tc.type: FUNC
 * @tc.require: issueIA6QID
*/
HWTEST_F(RSUiCaptureTaskParallelTest, TakeSurfaceCaptureForUiCanvasNode002, Function | SmallTest | Level2)
{
    auto canvasNode = RSCanvasNode::Create();
    canvasNode->SetBounds(0.0f, 0.0f, 10000, 10000);
    canvasNode->SetFrame(0.0f, 0.0f, 10000, 10000);
    RSTransactionProxy::GetInstance()->FlushImplicitTransaction();
    usleep(SLEEP_TIME_FOR_PROXY);

    auto callback = std::make_shared<CustomizedSurfaceCapture>();
    bool ret = rsInterfaces_->TakeSurfaceCaptureForUI(canvasNode, callback);
    ASSERT_EQ(ret, true);
    ASSERT_EQ(CheckSurfaceCaptureCallback(callback), true);
    ASSERT_EQ(callback->captureSuccess_, false);
}

/*
 * @tc.name: TakeSurfaceCaptureForUiCanvasDrawingNode
 * @tc.desc: Test TakeSurfaceCaptureForUI with canvasdrawing node
 * @tc.type: FUNC
 * @tc.require: issueIA6QID
*/
HWTEST_F(RSUiCaptureTaskParallelTest, TakeSurfaceCaptureForUiCanvasDrawingNode, Function | SmallTest | Level2)
{
    SetUpSurface();

    auto callback = std::make_shared<CustomizedSurfaceCapture>();
    bool ret = rsInterfaces_->TakeSurfaceCaptureForUI(canvasDrawingNode_, callback);
    ASSERT_EQ(ret, true);
    ASSERT_EQ(CheckSurfaceCaptureCallback(callback), true);
    ASSERT_EQ(callback->captureSuccess_, true);
}

/*
 * @tc.name: TakeSurfaceCaptureForUiProxyNode
 * @tc.desc: Test TakeSurfaceCaptureForUI with proxy node
 * @tc.type: FUNC
 * @tc.require: issueIA6QID
*/
HWTEST_F(RSUiCaptureTaskParallelTest, TakeSurfaceCaptureForUiProxyNode, Function | SmallTest | Level2)
{
    SetUpSurface();

    auto proxyNode = RSProxyNode::Create(canvasNode_->GetId());
    RSTransactionProxy::GetInstance()->FlushImplicitTransaction();

    auto callback = std::make_shared<CustomizedSurfaceCapture>();
    bool ret = rsInterfaces_->TakeSurfaceCaptureForUI(proxyNode, callback);
    ASSERT_EQ(ret, false);
    ASSERT_EQ(CheckSurfaceCaptureCallback(callback), false);
    ASSERT_EQ(callback->captureSuccess_, false);
}

/*
 * @tc.name: TakeSurfaceCaptureForUiSync001
 * @tc.desc: Test TakeSurfaceCaptureForUI sync is false
 * @tc.type: FUNC
 * @tc.require: issueIA6QID
*/
HWTEST_F(RSUiCaptureTaskParallelTest, TakeSurfaceCaptureForUiSync001, Function | SmallTest | Level2)
{
    auto canvasNode = RSCanvasNode::Create();
    canvasNode->SetBounds(0.0f, 0.0f, HALF_BOUNDS_WIDTH, HALF_BOUNDS_HEIGHT);
    canvasNode->SetFrame(0.0f, 0.0f, HALF_BOUNDS_WIDTH, HALF_BOUNDS_HEIGHT);
    canvasNode->SetBackgroundColor(Drawing::Color::COLOR_YELLOW);
    auto callback = std::make_shared<CustomizedSurfaceCapture>();
    bool ret = rsInterfaces_->TakeSurfaceCaptureForUI(canvasNode, callback);
    ASSERT_EQ(ret, true);
    ASSERT_EQ(CheckSurfaceCaptureCallback(callback), true);
    ASSERT_EQ(callback->captureSuccess_, false);
}

/*
 * @tc.name: TakeSurfaceCaptureForUiSync002
 * @tc.desc: Test TakeSurfaceCaptureForUI sync is true
 * @tc.type: FUNC
 * @tc.require: issueIA6QID
*/
HWTEST_F(RSUiCaptureTaskParallelTest, TakeSurfaceCaptureForUiSync002, Function | SmallTest | Level2)
{
    auto canvasNode = RSCanvasNode::Create();
    canvasNode->SetBounds(0.0f, 0.0f, HALF_BOUNDS_WIDTH, HALF_BOUNDS_HEIGHT);
    canvasNode->SetFrame(0.0f, 0.0f, HALF_BOUNDS_WIDTH, HALF_BOUNDS_HEIGHT);
    canvasNode->SetBackgroundColor(Drawing::Color::COLOR_YELLOW);
    auto callback = std::make_shared<CustomizedSurfaceCapture>();
    bool ret = rsInterfaces_->TakeSurfaceCaptureForUI(canvasNode, callback, 1.0, 1.0, true);
    ASSERT_EQ(ret, true);
    ASSERT_EQ(CheckSurfaceCaptureCallback(callback), true);
    ASSERT_EQ(callback->captureSuccess_, true);
}

/*
 * @tc.name: TakeSurfaceCaptureForUiScale001
 * @tc.desc: Test TakeSurfaceCaptureForUI scale
 * @tc.type: FUNC
 * @tc.require: issueIA6QID
*/
HWTEST_F(RSUiCaptureTaskParallelTest, TakeSurfaceCaptureForUiScale001, Function | SmallTest | Level2)
{
    SetUpSurface();

    auto callback = std::make_shared<CustomizedSurfaceCapture>();
    bool ret = rsInterfaces_->TakeSurfaceCaptureForUI(canvasNode_, callback, 0, 0);
    ASSERT_EQ(ret, true);
    ASSERT_EQ(CheckSurfaceCaptureCallback(callback), true);
    ASSERT_EQ(callback->captureSuccess_, false);
}

/*
 * @tc.name: TakeSurfaceCaptureForUiScale002
 * @tc.desc: Test TakeSurfaceCaptureForUI scale
 * @tc.type: FUNC
 * @tc.require: issueIA6QID
*/
HWTEST_F(RSUiCaptureTaskParallelTest, TakeSurfaceCaptureForUiScale002, Function | SmallTest | Level2)
{
    SetUpSurface();

    auto callback = std::make_shared<CustomizedSurfaceCapture>();
    bool ret = rsInterfaces_->TakeSurfaceCaptureForUI(canvasNode_, callback, -1, -1);
    ASSERT_EQ(ret, true);
    ASSERT_EQ(CheckSurfaceCaptureCallback(callback), true);
    ASSERT_EQ(callback->captureSuccess_, false);
}

/*
 * @tc.name: TakeSurfaceCaptureForUiScale003
 * @tc.desc: Test TakeSurfaceCaptureForUI scale
 * @tc.type: FUNC
 * @tc.require: issueIA6QID
*/
HWTEST_F(RSUiCaptureTaskParallelTest, TakeSurfaceCaptureForUiScale003, Function | SmallTest | Level2)
{
    SetUpSurface();

    auto callback = std::make_shared<CustomizedSurfaceCapture>();
    bool ret = rsInterfaces_->TakeSurfaceCaptureForUI(canvasNode_, callback, 10000, 10000);
    ASSERT_EQ(ret, true);
    ASSERT_EQ(CheckSurfaceCaptureCallback(callback), true);
    ASSERT_EQ(callback->captureSuccess_, false);
}

/*
 * @tc.name: TakeSurfaceCaptureForUiNotOnTree
 * @tc.desc: Test TakeSurfaceCaptureForUI with node not on tree
 * @tc.type: FUNC
 * @tc.require: issueIA6QID
*/
HWTEST_F(RSUiCaptureTaskParallelTest, TakeSurfaceCaptureForUiNotOnTree, Function | SmallTest | Level2)
{
    SetUpSurface();

    displayNode_->RemoveChild(surfaceNode_);
    RSTransactionProxy::GetInstance()->FlushImplicitTransaction();

    auto callback = std::make_shared<CustomizedSurfaceCapture>();
    bool ret = rsInterfaces_->TakeSurfaceCaptureForUI(canvasNode_, callback);
    ASSERT_EQ(ret, true);
    ASSERT_EQ(CheckSurfaceCaptureCallback(callback), true);
    ASSERT_EQ(callback->captureSuccess_, true);
}

/*
 * @tc.name: RSUiCaptureTaskParallel_CreateResources
 * @tc.desc: Test RSUiCaptureTaskParallel::CreateResources
 * @tc.type: FUNC
 * @tc.require: issueIA6QID
*/
HWTEST_F(RSUiCaptureTaskParallelTest, RSUiCaptureTaskParallel_CreateResources, Function | SmallTest | Level2)
{
    NodeId id = -1; // invalid id
    RSSurfaceCaptureConfig captureConfig;
    auto handle = std::make_shared<RSUiCaptureTaskParallel>(id, captureConfig);
    ASSERT_EQ(handle->CreateResources(), false);
    ASSERT_EQ(handle->captureConfig_.scaleX, 1.0f);
    ASSERT_EQ(handle->captureConfig_.scaleY, 1.0f);
    ASSERT_EQ(handle->pixelMap_, nullptr);
    ASSERT_EQ(handle->nodeDrawable_, nullptr);
}

/*
 * @tc.name: RSUiCaptureTaskParallel_CreatePixelMapByNode
 * @tc.desc: Test RSUiCaptureTaskParallel::CreatePixelMapByNode
 * @tc.type: FUNC
 * @tc.require: issueIA6QID
*/
HWTEST_F(RSUiCaptureTaskParallelTest, RSUiCaptureTaskParallel_CreatePixelMapByNode, Function | SmallTest | Level2)
{
    NodeId id = -1; // invalid id
    RSSurfaceCaptureConfig captureConfig;
    auto handle = std::make_shared<RSUiCaptureTaskParallel>(id, captureConfig);
    auto node = RSTestUtil::CreateSurfaceNode();
    ASSERT_EQ(handle->CreatePixelMapByNode(node), nullptr);
}
} // namespace Rosen
} // namespace OHOS
