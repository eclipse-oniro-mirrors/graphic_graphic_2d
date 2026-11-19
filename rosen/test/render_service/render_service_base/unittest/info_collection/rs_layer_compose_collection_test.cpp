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

#include "info_collection/rs_layer_compose_collection.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::Rosen {
namespace {
constexpr size_t UNIFORM_RENDER_LAYER_SIZE = 1;
constexpr size_t RCD_UNIFORM_RENDER_LAYER_SIZE = 3;
constexpr size_t OFFLINE_COMPOSE_LAYER_SIZE = 5;
constexpr size_t ZERO_LAYER_SIZE = 0;
constexpr int32_t EXPECTED_UNIFORM_COUNT_3 = 3;
constexpr int32_t EXPECTED_OFFLINE_COUNT_2 = 2;
constexpr int32_t EXPECTED_COUNT_1 = 1;
constexpr int32_t EXPECTED_COUNT_2 = 2;
constexpr int32_t EXPECTED_COUNT_0 = 0;
}
class RsLayerComposeCollectionTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void RsLayerComposeCollectionTest::SetUpTestCase() {}
void RsLayerComposeCollectionTest::TearDownTestCase() {}
void RsLayerComposeCollectionTest::SetUp()
{
    LayerComposeCollection::GetInstance().ResetLayerComposeInfo();
}
void RsLayerComposeCollectionTest::TearDown()
{
    LayerComposeCollection::GetInstance().ResetLayerComposeInfo();
}

/**
 * @tc.name: UpdateUniformOrOfflineComposeFrameNumberForDFX001
 * @tc.desc: No RCD layer, layerSize==1 -> uniformRenderFrameNumber++
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RsLayerComposeCollectionTest, UpdateUniformOrOfflineComposeFrameNumberForDFX001, TestSize.Level1)
{
    LayerComposeCollection::GetInstance().UpdateUniformOrOfflineComposeFrameNumberForDFX(
        UNIFORM_RENDER_LAYER_SIZE, false);
    auto info = LayerComposeCollection::GetInstance().GetLayerComposeInfo();
    EXPECT_EQ(info.uniformRenderFrameNumber, EXPECTED_COUNT_1);
    EXPECT_EQ(info.offlineComposeFrameNumber, EXPECTED_COUNT_0);
}

/**
 * @tc.name: UpdateUniformOrOfflineComposeFrameNumberForDFX002
 * @tc.desc: No RCD layer, layerSize!=1 -> offlineComposeFrameNumber++
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RsLayerComposeCollectionTest, UpdateUniformOrOfflineComposeFrameNumberForDFX002, TestSize.Level1)
{
    LayerComposeCollection::GetInstance().UpdateUniformOrOfflineComposeFrameNumberForDFX(
        OFFLINE_COMPOSE_LAYER_SIZE, false);
    auto info = LayerComposeCollection::GetInstance().GetLayerComposeInfo();
    EXPECT_EQ(info.uniformRenderFrameNumber, EXPECTED_COUNT_0);
    EXPECT_EQ(info.offlineComposeFrameNumber, EXPECTED_COUNT_1);
}

/**
 * @tc.name: UpdateUniformOrOfflineComposeFrameNumberForDFX003
 * @tc.desc: Has RCD layer, layerSize==3 -> UniformRenderFrameNumber++
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RsLayerComposeCollectionTest, UpdateUniformOrOfflineComposeFrameNumberForDFX003, TestSize.Level1)
{
    LayerComposeCollection::GetInstance().UpdateUniformOrOfflineComposeFrameNumberForDFX(
        RCD_UNIFORM_RENDER_LAYER_SIZE, true);
    auto info = LayerComposeCollection::GetInstance().GetLayerComposeInfo();
    EXPECT_EQ(info.uniformRenderFrameNumber, EXPECTED_COUNT_1);
    EXPECT_EQ(info.offlineComposeFrameNumber, EXPECTED_COUNT_0);
}

/**
 * @tc.name: UpdateUniformOrOfflineComposeFrameNumberForDFX004
 * @tc.desc: Has RCD layer, layerSize!=3 -> offlineComposeFrameNumber++
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RsLayerComposeCollectionTest, UpdateUniformOrOfflineComposeFrameNumberForDFX004, TestSize.Level1)
{
    LayerComposeCollection::GetInstance().UpdateUniformOrOfflineComposeFrameNumberForDFX(
       OFFLINE_COMPOSE_LAYER_SIZE, true);
    auto info = LayerComposeCollection::GetInstance().GetLayerComposeInfo();
    EXPECT_EQ(info.uniformRenderFrameNumber, EXPECTED_COUNT_0);
    EXPECT_EQ(info.offlineComposeFrameNumber, EXPECTED_COUNT_1);
}
/**
 * @tc.name: UpdateUniformOrOfflineComposeFrameNumberForDFX005
 * @tc.desc: Has RCD layer, layerSize==0 -> offlineComposeFrameNumber++ (boundary)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RsLayerComposeCollectionTest, UpdateUniformOrOfflineComposeFrameNumberForDFX005, TestSize.Level2)
{
    LayerComposeCollection::GetInstance().UpdateUniformOrOfflineComposeFrameNumberForDFX(
       ZERO_LAYER_SIZE, true);
    auto info = LayerComposeCollection::GetInstance().GetLayerComposeInfo();
    EXPECT_EQ(info.uniformRenderFrameNumber, EXPECTED_COUNT_0);
    EXPECT_EQ(info.offlineComposeFrameNumber, EXPECTED_COUNT_1);
}
/**
 * @tc.name: UpdateUniformOrOfflineComposeFrameNumberForDFX006
 * @tc.desc: No RCD layer, layerSize==0 -> offlineComposeFrameNumber++ (boundary)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RsLayerComposeCollectionTest, UpdateUniformOrOfflineComposeFrameNumberForDFX006, TestSize.Level2)
{
    LayerComposeCollection::GetInstance().UpdateUniformOrOfflineComposeFrameNumberForDFX(
       ZERO_LAYER_SIZE, false);
    auto info = LayerComposeCollection::GetInstance().GetLayerComposeInfo();
    EXPECT_EQ(info.uniformRenderFrameNumber, EXPECTED_COUNT_0);
    EXPECT_EQ(info.offlineComposeFrameNumber, EXPECTED_COUNT_1);
}
/**
 * @tc.name: UpdateUniformOrOfflineComposeFrameNumberForDFX007
 * @tc.desc: Default hasRCDLayer=false (backward compat), layerSize==1 -> uniform
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RsLayerComposeCollectionTest, UpdateUniformOrOfflineComposeFrameNumberForDFX007, TestSize.Level1)
{
    LayerComposeCollection::GetInstance().UpdateUniformOrOfflineComposeFrameNumberForDFX(
       UNIFORM_RENDER_LAYER_SIZE);
    auto info = LayerComposeCollection::GetInstance().GetLayerComposeInfo();
    EXPECT_EQ(info.uniformRenderFrameNumber, EXPECTED_COUNT_1);
    EXPECT_EQ(info.offlineComposeFrameNumber, EXPECTED_COUNT_0);
}
/**
 * @tc.name: UpdateUniformOrOfflineComposeFrameNumberForDFX008
 * @tc.desc: Multiple calls accumulate correctly
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RsLayerComposeCollectionTest, UpdateUniformOrOfflineComposeFrameNumberForDFX008, TestSize.Level1)
{
    LayerComposeCollection::GetInstance().UpdateUniformOrOfflineComposeFrameNumberForDFX(
        UNIFORM_RENDER_LAYER_SIZE, false);
    LayerComposeCollection::GetInstance().UpdateUniformOrOfflineComposeFrameNumberForDFX(
        UNIFORM_RENDER_LAYER_SIZE, false);
    LayerComposeCollection::GetInstance().UpdateUniformOrOfflineComposeFrameNumberForDFX(
        RCD_UNIFORM_RENDER_LAYER_SIZE, true);
    LayerComposeCollection::GetInstance().UpdateUniformOrOfflineComposeFrameNumberForDFX(
        OFFLINE_COMPOSE_LAYER_SIZE, true);
    LayerComposeCollection::GetInstance().UpdateUniformOrOfflineComposeFrameNumberForDFX(
        OFFLINE_COMPOSE_LAYER_SIZE, false);
    auto info = LayerComposeCollection::GetInstance().GetLayerComposeInfo();
    EXPECT_EQ(info.uniformRenderFrameNumber, EXPECTED_UNIFORM_COUNT_3);
    EXPECT_EQ(info.offlineComposeFrameNumber, EXPECTED_OFFLINE_COUNT_2);
}
/**
 * @tc.name: UpdateRedrawFrameNumberForDFX001
 * @tc.desc: UpdateRedrawFrameNumberForDFX decrements offline and increments redraw
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RsLayerComposeCollectionTest, UpdateRedrawFrameNumberForDFX001, TestSize.Level1)
{
    LayerComposeCollection::GetInstance().UpdateUniformOrOfflineComposeFrameNumberForDFX(
       OFFLINE_COMPOSE_LAYER_SIZE, false);
    LayerComposeCollection::GetInstance().UpdateRedrawFrameNumberForDFX();
    auto info = LayerComposeCollection::GetInstance().GetLayerComposeInfo();
    EXPECT_EQ(info.offlineComposeFrameNumber, EXPECTED_COUNT_0);
    EXPECT_EQ(info.redrawFrameNumber, EXPECTED_COUNT_1);
}

/**
 * @tc.name: UpdateDrawImageNumberForDFX001
 * @tc.desc: UpdateDrawImageNumberForDFX increments drawImageNumber
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RsLayerComposeCollectionTest, UpdateDrawImageNumberForDFX001, TestSize.Level1)
{
    LayerComposeCollection::GetInstance().UpdateDrawImageNumberForDFX();
    LayerComposeCollection::GetInstance().UpdateDrawImageNumberForDFX();
    auto info = LayerComposeCollection::GetInstance().GetLayerComposeInfo();
    EXPECT_EQ(info.drawImageNumber, EXPECTED_COUNT_2);
}

/**
 * @tc.name: ResetLayerComposeInfo001
 * @tc.desc: ResetLayerComposeInfo resets all counters to zero
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RsLayerComposeCollectionTest, ResetLayerComposeInfo001, TestSize.Level1)
{
    LayerComposeCollection::GetInstance().UpdateUniformOrOfflineComposeFrameNumberForDFX(
       OFFLINE_COMPOSE_LAYER_SIZE, false);
    LayerComposeCollection::GetInstance().UpdateDrawImageNumberForDFX();
    LayerComposeCollection::GetInstance().ResetLayerComposeInfo();
    auto info = LayerComposeCollection::GetInstance().GetLayerComposeInfo();
    EXPECT_EQ(info.uniformRenderFrameNumber, EXPECTED_COUNT_0);
    EXPECT_EQ(info.offlineComposeFrameNumber, EXPECTED_COUNT_0);
    EXPECT_EQ(info.redrawFrameNumber, EXPECTED_COUNT_0);
    EXPECT_EQ(info.drawImageNumber, EXPECTED_COUNT_0);
}

/**
 * @tc.name: GetLayerComposeInfo001
 * @tc.desc: GetLayerComposeInfo returns current state
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RsLayerComposeCollectionTest, GetLayerComposeInfo001, TestSize.Level1)
{
    auto info = LayerComposeCollection::GetInstance().GetLayerComposeInfo();
    EXPECT_EQ(info.uniformRenderFrameNumber, EXPECTED_COUNT_0);
    EXPECT_EQ(info.offlineComposeFrameNumber, EXPECTED_COUNT_0);
    EXPECT_EQ(info.redrawFrameNumber, EXPECTED_COUNT_0);
    EXPECT_EQ(info.drawImageNumber, EXPECTED_COUNT_0);
}

/**
 * @tc.name: UpdateDirectCompositionFrameNumberForDFX001
 * @tc.desc: UpdateDirectCompositionFrameNumberForDFX increments directCompositionFrameNumber
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RsLayerComposeCollectionTest, UpdateDirectCompositionFrameNumberForDFX001, TestSize.Level1)
{
    LayerComposeCollection::GetInstance().UpdateDirectCompositionFrameNumberForDFX();
    auto info = LayerComposeCollection::GetInstance().GetLayerComposeInfo();
    EXPECT_EQ(info.directCompositionFrameNumber, EXPECTED_COUNT_1);

    LayerComposeCollection::GetInstance().UpdateDirectCompositionFrameNumberForDFX();
    info = LayerComposeCollection::GetInstance().GetLayerComposeInfo();
    EXPECT_EQ(info.directCompositionFrameNumber, EXPECTED_COUNT_2);
}

/**
 * @tc.name: UpdateDirectCompositionFrameNumberForDFX002
 * @tc.desc: UpdateDirectCompositionFrameNumberForDFX does not affect other counters
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RsLayerComposeCollectionTest, UpdateDirectCompositionFrameNumberForDFX002, TestSize.Level1)
{
    LayerComposeCollection::GetInstance().UpdateDirectCompositionFrameNumberForDFX();
    auto info = LayerComposeCollection::GetInstance().GetLayerComposeInfo();
    EXPECT_EQ(info.directCompositionFrameNumber, EXPECTED_COUNT_1);
    EXPECT_EQ(info.uniformRenderFrameNumber, EXPECTED_COUNT_0);
    EXPECT_EQ(info.offlineComposeFrameNumber, EXPECTED_COUNT_0);
    EXPECT_EQ(info.redrawFrameNumber, EXPECTED_COUNT_0);
    EXPECT_EQ(info.drawImageNumber, EXPECTED_COUNT_0);
}

/**
 * @tc.name: ResetLayerComposeInfo002
 * @tc.desc: ResetLayerComposeInfo resets directCompositionFrameNumber to zero
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RsLayerComposeCollectionTest, ResetLayerComposeInfo002, TestSize.Level1)
{
    LayerComposeCollection::GetInstance().UpdateDirectCompositionFrameNumberForDFX();
    LayerComposeCollection::GetInstance().UpdateDirectCompositionFrameNumberForDFX();
    LayerComposeCollection::GetInstance().ResetLayerComposeInfo();
    auto info = LayerComposeCollection::GetInstance().GetLayerComposeInfo();
    EXPECT_EQ(info.directCompositionFrameNumber, EXPECTED_COUNT_0);
}

/**
 * @tc.name: LayerComposeInfoOperatorAdd001
 * @tc.desc: LayerComposeInfo operator+= accumulates directCompositionFrameNumber and other fields
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RsLayerComposeCollectionTest, LayerComposeInfoOperatorAdd001, TestSize.Level1)
{
    constexpr int32_t UNIFORM_1 = 1;
    constexpr int32_t UNIFORM_2 = 2;
    constexpr int32_t OFFLINE_1 = 3;
    constexpr int32_t OFFLINE_2 = 4;
    constexpr int32_t REDRAW_1 = 5;
    constexpr int32_t REDRAW_2 = 6;
    constexpr int32_t DRAW_1 = 7;
    constexpr int32_t DRAW_2 = 8;
    constexpr int32_t DIRECT_1 = 9;
    constexpr int32_t DIRECT_2 = 10;

    LayerComposeInfo lhs(UNIFORM_1, OFFLINE_1, REDRAW_1, DRAW_1, DIRECT_1);
    LayerComposeInfo rhs(UNIFORM_2, OFFLINE_2, REDRAW_2, DRAW_2, DIRECT_2);
    lhs += rhs;

    EXPECT_EQ(lhs.uniformRenderFrameNumber, UNIFORM_1 + UNIFORM_2);
    EXPECT_EQ(lhs.offlineComposeFrameNumber, OFFLINE_1 + OFFLINE_2);
    EXPECT_EQ(lhs.redrawFrameNumber, REDRAW_1 + REDRAW_2);
    EXPECT_EQ(lhs.drawImageNumber, DRAW_1 + DRAW_2);
    EXPECT_EQ(lhs.directCompositionFrameNumber, DIRECT_1 + DIRECT_2);
}
} // namespace OHOS::Rosen