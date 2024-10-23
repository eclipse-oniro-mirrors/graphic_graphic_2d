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
#include "drawable/dfx/rs_skp_capture_dfx.h"
#include "drawable/rs_display_render_node_drawable.h"
#include "params/rs_render_thread_params.h"
#include "pipeline/rs_display_render_node.h"
#include "pipeline/rs_render_node.h"
#include "pipeline/rs_uni_render_engine.h"
#include "pipeline/rs_uni_render_thread.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::Rosen::DrawableV2;

namespace OHOS::Rosen {
constexpr int32_t DEFAULT_CANVAS_SIZE = 100;

class RSSkpCaptureDFXTest : public testing::Test {
public:
    std::shared_ptr<RSSurfaceRenderNode> renderNode_;
    std::shared_ptr<RSDisplayRenderNode> displayRenderNode_;
    std::shared_ptr<RSSurfaceRenderNodeDrawable> surfaceDrawable_ = nullptr;
    std::shared_ptr<RSPaintFilterCanvas> canvas_;
    std::shared_ptr<Drawing::Canvas> drawingCanvas_;

    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void RSSkpCaptureDFXTest::SetUpTestCase() {}
void RSSkpCaptureDFXTest::TearDownTestCase() {}
void RSSkpCaptureDFXTest::SetUp() {}
void RSSkpCaptureDFXTest::TearDown() {}

/**
 * @tc.name: captureTest
 * @tc.desc: Test If capture Can Run
 * @tc.type: FUNC
 * @tc.require: #I9NVOG
 */
HWTEST_F(RSSkpCaptureDFXTest, captureTest001, TestSize.Level1)
{
    auto& rtThread = RSUniRenderThread::Instance();
    if (!rtThread.GetRSRenderThreadParams()) {
        rtThread.renderParamsManager_.renderThreadParams_ = std::make_unique<RSRenderThreadParams>();
    }
    rtThread.uniRenderEngine_ = std::make_shared<RSUniRenderEngine>();

    auto drawingCanvas = std::make_unique<Drawing::Canvas>(DEFAULT_CANVAS_SIZE, DEFAULT_CANVAS_SIZE);
    auto canvas = std::make_shared<RSPaintFilterCanvas>(drawingCanvas.get());
    
    ASSERT_NE(canvas, nullptr);
    {
        rtThread.uniRenderEngine_->renderContext_ = nullptr;
        RSSkpCaptureDfx capture(canvas);
        ASSERT_EQ(capture.recordingCanvas_, nullptr);
    }
    {
#if defined(NEW_RENDER_CONTEXT)
        rtThread.uniRenderEngine_->renderContext_ = std::shared_ptr<RenderContextBase>();
#else
        rtThread.uniRenderEngine_->renderContext_ = std::shared_ptr<RenderContext>();
#endif
        RSSkpCaptureDfx capture(canvas);
        ASSERT_EQ(capture.recordingCanvas_, nullptr);
    }
}
}
