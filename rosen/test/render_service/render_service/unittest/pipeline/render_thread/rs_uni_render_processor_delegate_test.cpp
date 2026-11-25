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

#include "gtest/gtest.h"
#include "pipeline/render_thread/rs_uni_render_processor.h"
#include "params/rs_surface_render_params.h"
#include "screen_manager/rs_screen_info.h"
#include "rs_surface_layer.h"
#include "limit_number.h"
#include "surface_type.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::Rosen {
namespace {
constexpr NodeId DEFAULT_NODEID = 1;
constexpr float SRC_RECT_LEFT = 1.0f;
constexpr float SRC_RECT_TOP = 2.0f;
constexpr float SRC_RECT_WIDTH = 3.0f;
constexpr float SRC_RECT_HEIGHT = 4.0f;
constexpr int32_t EXPECTED_X = 1;
constexpr int32_t EXPECTED_Y = 2;
constexpr int32_t EXPECTED_W = 3;
constexpr int32_t EXPECTED_H = 4;
constexpr int32_t PRESET_X = 9;
constexpr int32_t PRESET_Y = 9;
constexpr int32_t PRESET_W = 9;
constexpr int32_t PRESET_H = 9;
}

class RSUniRenderProcessorDelegateTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;

    static inline std::shared_ptr<RSUniRenderProcessor> processor_ = nullptr;
    static inline ScreenId screenId_ = 0;
};

void RSUniRenderProcessorDelegateTest::SetUpTestCase()
{
    RSUniRenderThread::Instance().composerClientManager_ = std::make_shared<RSComposerClientManager>();
    processor_ = std::make_shared<RSUniRenderProcessor>(screenId_);
}

void RSUniRenderProcessorDelegateTest::TearDownTestCase() {}

void RSUniRenderProcessorDelegateTest::SetUp() {}

void RSUniRenderProcessorDelegateTest::TearDown() {}

/**
 * @tc.name: HandleDelegateComposerLayer_DelegateModeFalse_001
 * @tc.desc: Test condition !params.GetDelegateMode() returns true (delegateMode = false)
 *           Function should return immediately without processing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSUniRenderProcessorDelegateTest, HandleDelegateComposerLayer_DelegateModeFalse_001, TestSize.Level1)
{
    RSSurfaceRenderParams params(DEFAULT_NODEID);
    params.SetDelegateMode(false);

    RSLayerPtr layer = nullptr;

    processor_->HandleDelegateComposerLayer(layer, params);

    EXPECT_EQ(layer, nullptr);
}

/**
 * @tc.name: HandleDelegateComposerLayer_DelegateModeFalse_PreservesLayer_001
 * @tc.desc: When delegateMode is false, the layer's existing DelegateSrcRect must be unchanged.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSUniRenderProcessorDelegateTest, HandleDelegateComposerLayer_DelegateModeFalse_PreservesLayer_001,
    TestSize.Level1)
{
    RSSurfaceRenderParams params(DEFAULT_NODEID);
    params.SetDelegateMode(false);
    params.SetDelegateSrcRect(RectF(SRC_RECT_LEFT, SRC_RECT_TOP, SRC_RECT_WIDTH, SRC_RECT_HEIGHT));

    RSLayerPtr layer = std::make_shared<RSSurfaceLayer>(0, nullptr);
    ASSERT_NE(layer, nullptr);
    layer->SetDelegateSrcRect(GraphicIRect{PRESET_X, PRESET_Y, PRESET_W, PRESET_H});

    processor_->HandleDelegateComposerLayer(layer, params);

    auto result = layer->GetDelegateSrcRect();
    EXPECT_EQ(result.x, PRESET_X);
    EXPECT_EQ(result.y, PRESET_Y);
    EXPECT_EQ(result.w, PRESET_W);
    EXPECT_EQ(result.h, PRESET_H);
}

/**
 * @tc.name: HandleDelegateComposerLayer_DelegateModeTrue_SetsSrcRect_001
 * @tc.desc: When delegateMode is true, the layer's DelegateSrcRect is set from params.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSUniRenderProcessorDelegateTest, HandleDelegateComposerLayer_DelegateModeTrue_SetsSrcRect_001,
    TestSize.Level1)
{
    RSSurfaceRenderParams params(DEFAULT_NODEID);
    params.SetDelegateMode(true);
    params.SetDelegateSrcRect(RectF(SRC_RECT_LEFT, SRC_RECT_TOP, SRC_RECT_WIDTH, SRC_RECT_HEIGHT));

    RSLayerPtr layer = std::make_shared<RSSurfaceLayer>(0, nullptr);
    ASSERT_NE(layer, nullptr);

    processor_->HandleDelegateComposerLayer(layer, params);

    auto result = layer->GetDelegateSrcRect();
    EXPECT_EQ(result.x, EXPECTED_X);
    EXPECT_EQ(result.y, EXPECTED_Y);
    EXPECT_EQ(result.w, EXPECTED_W);
    EXPECT_EQ(result.h, EXPECTED_H);
}

/**
 * @tc.name: HandleDelegateComposerLayer_DstRectHeightZero_001
 * @tc.desc: New impl no longer early-returns on zero dst height; with a valid layer it still
 *           sets the src rect. DstRect height is not consulted by the current implementation.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSUniRenderProcessorDelegateTest, HandleDelegateComposerLayer_DstRectHeightZero_001, TestSize.Level1)
{
    RSSurfaceRenderParams params(DEFAULT_NODEID);
    params.SetDelegateMode(true);
    params.SetDelegateDstRect(RectF(0.0f, 0.0f, 100.0f, 0.0f));
    params.SetDelegateSrcRect(RectF(SRC_RECT_LEFT, SRC_RECT_TOP, SRC_RECT_WIDTH, SRC_RECT_HEIGHT));

    RSLayerPtr layer = std::make_shared<RSSurfaceLayer>(0, nullptr);
    ASSERT_NE(layer, nullptr);

    processor_->HandleDelegateComposerLayer(layer, params);

    auto result = layer->GetDelegateSrcRect();
    EXPECT_EQ(result.x, EXPECTED_X);
    EXPECT_EQ(result.y, EXPECTED_Y);
    EXPECT_EQ(result.w, EXPECTED_W);
    EXPECT_EQ(result.h, EXPECTED_H);
}

/**
 * @tc.name: HandleDelegateComposerLayer_DstRectHeightNegative_001
 * @tc.desc: New impl no longer early-returns on negative dst height; with a valid layer it
 *           still sets the src rect.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSUniRenderProcessorDelegateTest, HandleDelegateComposerLayer_DstRectHeightNegative_001, TestSize.Level1)
{
    RSSurfaceRenderParams params(DEFAULT_NODEID);
    params.SetDelegateMode(true);
    params.SetDelegateDstRect(RectF(0.0f, 0.0f, 100.0f, -10.0f));
    params.SetDelegateSrcRect(RectF(SRC_RECT_LEFT, SRC_RECT_TOP, SRC_RECT_WIDTH, SRC_RECT_HEIGHT));

    RSLayerPtr layer = std::make_shared<RSSurfaceLayer>(0, nullptr);
    ASSERT_NE(layer, nullptr);

    processor_->HandleDelegateComposerLayer(layer, params);

    auto result = layer->GetDelegateSrcRect();
    EXPECT_EQ(result.x, EXPECTED_X);
    EXPECT_EQ(result.y, EXPECTED_Y);
    EXPECT_EQ(result.w, EXPECTED_W);
    EXPECT_EQ(result.h, EXPECTED_H);
}

/**
 * @tc.name: HandleDelegateComposerLayer_SrcRectZeroDimensions_001
 * @tc.desc: New impl does not validate src rect dimensions; a zero-sized src rect is forwarded as-is.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSUniRenderProcessorDelegateTest, HandleDelegateComposerLayer_SrcRectZeroDimensions_001, TestSize.Level1)
{
    RSSurfaceRenderParams params(DEFAULT_NODEID);
    params.SetDelegateMode(true);
    params.SetDelegateSrcRect(RectF(0.0f, 0.0f, 0.0f, 0.0f));

    RSLayerPtr layer = std::make_shared<RSSurfaceLayer>(0, nullptr);
    ASSERT_NE(layer, nullptr);

    processor_->HandleDelegateComposerLayer(layer, params);

    auto result = layer->GetDelegateSrcRect();
    EXPECT_EQ(result.x, 0);
    EXPECT_EQ(result.y, 0);
    EXPECT_EQ(result.w, 0);
    EXPECT_EQ(result.h, 0);
}

/**
 * @tc.name: HandleDelegateComposerLayer_NegativeSrcRectValues_001
 * @tc.desc: New impl forwards negative left/top from DelegateSrcRect to the layer without validation.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSUniRenderProcessorDelegateTest, HandleDelegateComposerLayer_NegativeSrcRectValues_001, TestSize.Level1)
{
    RSSurfaceRenderParams params(DEFAULT_NODEID);
    params.SetDelegateMode(true);
    params.SetDelegateSrcRect(RectF(-10.0f, -20.0f, 100.0f, 200.0f));

    RSLayerPtr layer = std::make_shared<RSSurfaceLayer>(0, nullptr);
    ASSERT_NE(layer, nullptr);

    processor_->HandleDelegateComposerLayer(layer, params);

    auto result = layer->GetDelegateSrcRect();
    EXPECT_EQ(result.x, -10);
    EXPECT_EQ(result.y, -20);
    EXPECT_EQ(result.w, 100);
    EXPECT_EQ(result.h, 200);
}
} // namespace OHOS::Rosen
