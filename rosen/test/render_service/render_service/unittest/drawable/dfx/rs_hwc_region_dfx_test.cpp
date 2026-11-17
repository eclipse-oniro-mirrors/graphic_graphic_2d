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

#include "gtest/gtest.h"
#include "drawable/dfx/rs_hwc_region_dfx.h"
#include "drawable/rs_surface_render_node_drawable.h"
#include "parameters.h"
#include "params/rs_render_thread_params.h"
#include "params/rs_surface_render_params.h"
#include "pipeline/render_thread/rs_uni_render_thread.h"
#include "pipeline/rs_surface_render_node.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::Rosen::DrawableV2;

namespace OHOS::Rosen {
constexpr int32_t DEFAULT_CANVAS_SIZE = 100;

class RSHwcRegionDFXTest : public testing::Test {
public:
    std::shared_ptr<RSPaintFilterCanvas> canvas_;
    std::shared_ptr<Drawing::Canvas> drawingCanvas_;

    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void RSHwcRegionDFXTest::SetUpTestCase() {}
void RSHwcRegionDFXTest::TearDownTestCase() {}
void RSHwcRegionDFXTest::SetUp()
{
    drawingCanvas_ = std::make_unique<Drawing::Canvas>(DEFAULT_CANVAS_SIZE, DEFAULT_CANVAS_SIZE);
    if (drawingCanvas_) {
        canvas_ = std::make_shared<RSPaintFilterCanvas>(drawingCanvas_.get());
    }
    auto& rtThread = RSUniRenderThread::Instance();
    if (!rtThread.GetRSRenderThreadParams()) {
        RSRenderThreadParamsManager::Instance().renderThreadParams_ = std::make_unique<RSRenderThreadParams>();
    }
}
void RSHwcRegionDFXTest::TearDown() {}

/**
 * @tc.name: DrawHwcRegionForDFXTest
 * @tc.desc: Test DrawHwcRegionForDFX with different type drawables
 * @tc.type: FUNC
 * @tc.require: issueIB278U
 */
HWTEST_F(RSHwcRegionDFXTest, DrawHwcRegionForDFXTest, TestSize.Level1)
{
    system::SetParameter("persist.rosen.hwcRegionDfx.enabled", "1");
    auto params = std::make_unique<RSRenderThreadParams>();
    ASSERT_NE(params, nullptr);

    std::shared_ptr<RSSurfaceRenderNode> renderNode = std::make_shared<RSSurfaceRenderNode>(0);
    ASSERT_NE(renderNode, nullptr);
    auto drawable = RSSurfaceRenderNodeDrawable::OnGenerate(renderNode);
    drawable->renderParams_ = std::make_unique<RSSurfaceRenderParams>(0);
    auto surfaceParams = static_cast<RSSurfaceRenderParams*>(drawable->GetRenderParams().get());
    ASSERT_NE(surfaceParams, nullptr);
    surfaceParams->SetHardwareEnabled(true);
    params->hardwareEnabledTypeDrawables_.emplace_back(std::make_tuple(0, 0, drawable));

    std::shared_ptr<RSSurfaceRenderNode> renderNodeHardwareDisabled = std::make_shared<RSSurfaceRenderNode>(1);
    ASSERT_NE(renderNodeHardwareDisabled, nullptr);
    auto drawableHardwareDisabled = RSSurfaceRenderNodeDrawable::OnGenerate(renderNodeHardwareDisabled);
    drawableHardwareDisabled->renderParams_ = std::make_unique<RSSurfaceRenderParams>(1);
    auto surfaceParamsHardwareDisabled =
        static_cast<RSSurfaceRenderParams*>(drawableHardwareDisabled->GetRenderParams().get());
    ASSERT_NE(surfaceParamsHardwareDisabled, nullptr);
    surfaceParamsHardwareDisabled->SetHardwareEnabled(false);
    params->hardwareEnabledTypeDrawables_.emplace_back(std::make_tuple(1, 0, drawableHardwareDisabled));

    params->hardwareEnabledTypeDrawables_.emplace_back(std::make_tuple(1, 0, nullptr));

    std::shared_ptr<RSSurfaceRenderNode> renderNodeParamsNull = std::make_shared<RSSurfaceRenderNode>(2);
    ASSERT_NE(renderNodeParamsNull, nullptr);
    auto drawableParamsNull = RSSurfaceRenderNodeDrawable::OnGenerate(renderNodeParamsNull);
    drawableParamsNull->renderParams_ = nullptr;
    params->hardwareEnabledTypeDrawables_.emplace_back(std::make_tuple(2, 0, drawableParamsNull));

    RSUniRenderThread::Instance().Sync(move(params));
    ASSERT_NE(canvas_, nullptr);
    RSHwcRegionDfx::Draw(*canvas_);
}

/**
 * @tc.name: DrawHwcRegionForDFXDisabledTest
 * @tc.desc: Test DrawHwcRegionForDFX returns early when HwcRegionDfx is disabled
 * @tc.type: FUNC
 * @tc.require: issueIB278U
 */
HWTEST_F(RSHwcRegionDFXTest, DrawHwcRegionForDFXDisabledTest, TestSize.Level1)
{
    system::SetParameter("persist.rosen.hwcRegionDfx.enabled", "0");
    auto params = std::make_unique<RSRenderThreadParams>();
    ASSERT_NE(params, nullptr);

    std::shared_ptr<RSSurfaceRenderNode> renderNode = std::make_shared<RSSurfaceRenderNode>(0);
    ASSERT_NE(renderNode, nullptr);
    auto drawable = RSSurfaceRenderNodeDrawable::OnGenerate(renderNode);
    drawable->renderParams_ = std::make_unique<RSSurfaceRenderParams>(0);
    auto surfaceParams = static_cast<RSSurfaceRenderParams*>(drawable->GetRenderParams().get());
    ASSERT_NE(surfaceParams, nullptr);
    surfaceParams->SetHardwareEnabled(true);
    params->hardwareEnabledTypeDrawables_.emplace_back(std::make_tuple(0, 0, drawable));

    RSUniRenderThread::Instance().Sync(move(params));
    ASSERT_NE(canvas_, nullptr);
    RSHwcRegionDfx::Draw(*canvas_);
}
} // namespace OHOS::Rosen
