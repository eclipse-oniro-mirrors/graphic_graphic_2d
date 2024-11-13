/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, Hardware
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "gtest/gtest.h"
#include "drawable/rs_canvas_render_node_drawable.h"
#include "pipeline/rs_canvas_render_node.h"
#include "pipeline/rs_uni_render_thread.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::Rosen::DrawableV2;

namespace OHOS::Rosen {
class RSCanvasRenderNodeDrawableTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void RSCanvasRenderNodeDrawableTest::SetUpTestCase() {}
void RSCanvasRenderNodeDrawableTest::TearDownTestCase() {}
void RSCanvasRenderNodeDrawableTest::SetUp() {}
void RSCanvasRenderNodeDrawableTest::TearDown() {}

/**
 * @tc.name: CreateCanvasRenderNodeDrawableTest
 * @tc.desc: Test If CanvasRenderNodeDrawable Can Be Created
 * @tc.type: FUNC
 * @tc.require: #I9NVOG
 */
HWTEST(RSCanvasRenderNodeDrawableTest, CreateCanvasRenderNodeDrawable, TestSize.Level1)
{
    NodeId nodeId = 1;
    auto canvasNode = std::make_shared<RSCanvasRenderNode>(nodeId);
    auto drawable = RSCanvasRenderNodeDrawable::OnGenerate(canvasNode);
    ASSERT_NE(drawable, nullptr);
}

/**
 * @tc.name: OnDrawTest
 * @tc.desc: Test If OnDraw Can Run
 * @tc.type: FUNC
 * @tc.require: issueIAEDYI
 */
HWTEST(RSCanvasRenderNodeDrawableTest, OnDrawTest, TestSize.Level1)
{
    NodeId nodeId = 0;
    auto node = std::make_shared<RSRenderNode>(nodeId);
    auto drawable = std::make_shared<RSCanvasRenderNodeDrawable>(std::move(node));
    ASSERT_NE(drawable, nullptr);
    Drawing::Canvas canvas;
    drawable->renderParams_ = std::make_unique<RSRenderParams>(nodeId);
    drawable->OnDraw(canvas);
    ASSERT_TRUE(drawable->GetRenderParams());

    drawable->isOpincDropNodeExt_ = false;
    drawable->renderParams_->isOpincStateChanged_ = false;
    drawable->renderParams_->startingWindowFlag_ = false;
    drawable->OnDraw(canvas);
    ASSERT_TRUE(drawable->GetRenderParams());

    drawable->isOpDropped_ = false;
    drawable->isDrawingCacheEnabled_ = true;
    drawable->autoCacheEnable_ = false;
    drawable->drawBlurForCache_ = false;
    drawable->OnDraw(canvas);
    ASSERT_TRUE(drawable->isDrawingCacheEnabled_);

    drawable->drawBlurForCache_ = true;
    drawable->OnDraw(canvas);
    ASSERT_TRUE(drawable->isDrawingCacheEnabled_);
}

/**
 * @tc.name: OnCaptureTest
 * @tc.desc: Test If OnCapture Can Run
 * @tc.type: FUNC
 * @tc.require: issueIAEDYI
 */
HWTEST(RSCanvasRenderNodeDrawableTest, OnCaptureTest001, TestSize.Level1)
{
    NodeId nodeId = 0;
    auto node = std::make_shared<RSRenderNode>(nodeId);
    auto drawable = std::make_shared<RSCanvasRenderNodeDrawable>(std::move(node));
    ASSERT_NE(drawable, nullptr);
    Drawing::Canvas drawingCanvas;
    RSPaintFilterCanvas canvas(&drawingCanvas);
    drawable->renderParams_ = std::make_unique<RSRenderParams>(nodeId);
    drawable->OnCapture(canvas);
    ASSERT_FALSE(drawable->ShouldPaint());
    drawable->renderParams_->shouldPaint_ = true;
    drawable->renderParams_->contentEmpty_ = false;
    ASSERT_TRUE(drawable->ShouldPaint());
    const auto& params = drawable->GetRenderParams();
    ASSERT_FALSE(drawable->EnableRecordingOptimization(*params));
    CaptureParam param;
    param.isMirror_ = false;
    RSUniRenderThread::SetCaptureParam(param);
    drawable->OnCapture(canvas);
    ASSERT_TRUE(drawable->ShouldPaint());
}

/**
 * @tc.name: OnCaptureTest
 * @tc.desc: Test If OnCapture Can Run
 * @tc.type: FUNC
 * @tc.require: issueIAEDYI
 */
HWTEST(RSCanvasRenderNodeDrawableTest, OnCaptureTest002, TestSize.Level1)
{
    NodeId nodeId = 0;
    auto node = std::make_shared<RSRenderNode>(nodeId);
    auto drawable = std::make_shared<RSCanvasRenderNodeDrawable>(std::move(node));
    ASSERT_NE(drawable, nullptr);
    Drawing::Canvas drawingCanvas;
    RSPaintFilterCanvas canvas(&drawingCanvas);
    RSUniRenderThread::GetCaptureParam().isMirror_ = true;
    drawable->isDrawingCacheEnabled_ = false;
    drawable->renderParams_ = std::make_unique<RSRenderParams>(nodeId);
    ASSERT_TRUE(drawable->GetRenderParams());
    drawable->renderParams_->shouldPaint_ = true;
    drawable->renderParams_->contentEmpty_ = false;
    ASSERT_FALSE(drawable->isDrawingCacheEnabled_);
    ASSERT_TRUE(drawable->GetRenderParams());
    drawable->OnCapture(canvas);
    ASSERT_TRUE(drawable->ShouldPaint());
}

/**
 * @tc.name: OnCaptureTest
 * @tc.desc: Test If OnCapture Can Run
 * @tc.type: FUNC
 * @tc.require: issueIAEDYI
 */
HWTEST(RSCanvasRenderNodeDrawableTest, OnCaptureTest003, TestSize.Level1)
{
    NodeId nodeId = 0;
    auto node = std::make_shared<RSRenderNode>(nodeId);
    auto drawable = std::make_shared<RSCanvasRenderNodeDrawable>(std::move(node));
    ASSERT_NE(drawable, nullptr);
    Drawing::Canvas drawingCanvas;
    RSPaintFilterCanvas canvas(&drawingCanvas);
    RSUniRenderThread::GetCaptureParam().isMirror_ = true;
    drawable->renderParams_ = std::make_unique<RSRenderParams>(nodeId);
    drawable->renderParams_->shouldPaint_ = true;
    drawable->renderParams_->contentEmpty_ = false;
    RSRenderThreadParamsManager::Instance().renderThreadParams_ = std::make_unique<RSRenderThreadParams>();
    ASSERT_TRUE(RSUniRenderThread::Instance().GetRSRenderThreadParams());
    RSUniRenderThread::Instance().GetRSRenderThreadParams()->SetRootIdOfCaptureWindow(1);
    RSUniRenderThread::Instance().GetRSRenderThreadParams()->SetHasCaptureImg(true);
    RSUniRenderThread::Instance().GetRSRenderThreadParams()->SetStartVisit(false);
    ASSERT_TRUE(drawable->GetRenderParams());
    drawable->OnCapture(canvas);
    ASSERT_TRUE(drawable->ShouldPaint());
    RSUniRenderThread::Instance().Sync(nullptr);
}
}
