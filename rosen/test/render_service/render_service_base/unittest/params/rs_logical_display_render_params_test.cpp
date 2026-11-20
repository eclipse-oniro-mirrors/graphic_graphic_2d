/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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
#include "drawable/rs_render_node_drawable_adapter.h"
#include "params/rs_logical_display_render_params.h"
#include "pipeline/rs_render_node.h"
#include "limit_number.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::Rosen {
namespace {
class LogicalDisplayParamsDrawableAdapterMock : public DrawableV2::RSRenderNodeDrawableAdapter {
public:
    explicit LogicalDisplayParamsDrawableAdapterMock(std::shared_ptr<const RSRenderNode> node)
        : RSRenderNodeDrawableAdapter(std::move(node))
    {}
    void Draw(Drawing::Canvas&) override {}
};
}

class RSLogicalDisplayRenderParamsTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
    static void DisplayTestInfo();
};

void RSLogicalDisplayRenderParamsTest::SetUpTestCase() {}
void RSLogicalDisplayRenderParamsTest::TearDownTestCase() {}
void RSLogicalDisplayRenderParamsTest::SetUp() {}
void RSLogicalDisplayRenderParamsTest::TearDown() {}
void RSLogicalDisplayRenderParamsTest::DisplayTestInfo()
{
    return;
}

/**
 * @tc.name: HasCaptureWindow
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSLogicalDisplayRenderParamsTest, HasCaptureWindow, TestSize.Level1)
{
    constexpr NodeId id = TestSrc::limitNumber::Uint64[3];
    RSLogicalDisplayRenderParams params(id);
    EXPECT_FALSE(params.HasCaptureWindow());

    params.hasCaptureWindow_ = true;
    EXPECT_TRUE(params.HasCaptureWindow());
}

/**
 * @tc.name: IsRecordSessionActiveTruthTable
 * @tc.desc: Verify record activity requires a non-empty config, a virtual screen, and MIRROR mode
 * @tc.type: FUNC
 * @tc.require: issues/26744
 */
HWTEST_F(RSLogicalDisplayRenderParamsTest, IsRecordSessionActiveTruthTable, TestSize.Level1)
{
    constexpr NodeId id = TestSrc::limitNumber::Uint64[4];
    RSWindowRecordConfig recordConfig;
    recordConfig.surfaceNodeIds = { TestSrc::limitNumber::Uint64[5] };

    RSLogicalDisplayRenderParams emptyPhysical(id);
    EXPECT_FALSE(emptyPhysical.IsRecordSessionActive());

    RSLogicalDisplayRenderParams emptyVirtual(id);
    emptyVirtual.SetOnVirtualScreen(true);
    EXPECT_FALSE(emptyVirtual.IsRecordSessionActive());

    RSLogicalDisplayRenderParams recordPhysical(id);
    recordPhysical.SetWindowRecordConfig(recordConfig);
    EXPECT_FALSE(recordPhysical.IsRecordSessionActive());
    EXPECT_EQ(recordPhysical.GetWindowRecordConfig(), recordConfig);

    RSLogicalDisplayRenderParams recordVirtual(id);
    recordVirtual.SetWindowRecordConfig(recordConfig);
    recordVirtual.SetOnVirtualScreen(true);
    recordVirtual.displayMode_ = DisplayMode::EXPAND;
    EXPECT_FALSE(recordVirtual.IsRecordSessionActive());
    recordVirtual.displayMode_ = DisplayMode::MIRROR;
    EXPECT_TRUE(recordVirtual.IsRecordSessionActive());
    EXPECT_EQ(recordVirtual.GetWindowRecordConfig(), recordConfig);
}

/**
 * @tc.name: WindowRecordSyncOptimization
 * @tc.desc: Verify unchanged record config and virtual-screen state skip needSync_, while real changes,
 *     an empty-config clear, and an active snapshot rebuild still request a sync
 * @tc.type: FUNC
 * @tc.require: issues/26744
 */
HWTEST_F(RSLogicalDisplayRenderParamsTest, WindowRecordSyncOptimization, TestSize.Level1)
{
    constexpr NodeId id = TestSrc::limitNumber::Uint64[6];
    constexpr NodeId recordId = TestSrc::limitNumber::Uint64[7];
    RSWindowRecordConfig recordConfig;
    recordConfig.surfaceNodeIds = { recordId };

    RSLogicalDisplayRenderParams params(id);
    EXPECT_FALSE(params.NeedSync());

    // Default empty config and unchanged virtual-screen state must not request a sync.
    params.SetWindowRecordConfig(RSWindowRecordConfig{});
    EXPECT_FALSE(params.NeedSync());
    params.SetOnVirtualScreen(false);
    EXPECT_FALSE(params.NeedSync());

    // A real config change requests a sync; repeating the same config does not.
    params.SetWindowRecordConfig(recordConfig);
    EXPECT_TRUE(params.NeedSync());
    EXPECT_EQ(params.GetWindowRecordConfig(), recordConfig);
    params.SetNeedSync(false);
    params.SetWindowRecordConfig(recordConfig);
    EXPECT_FALSE(params.NeedSync());

    // The virtual-screen transition requests a sync; repeating it does not.
    params.SetOnVirtualScreen(true);
    EXPECT_TRUE(params.NeedSync());
    params.SetNeedSync(false);
    params.SetOnVirtualScreen(true);
    EXPECT_FALSE(params.NeedSync());

    // Clearing an active config is a real change and must publish.
    params.SetNeedSync(false);
    params.SetWindowRecordConfig(RSWindowRecordConfig{});
    EXPECT_TRUE(params.NeedSync());
    EXPECT_TRUE(params.GetWindowRecordConfig().surfaceNodeIds.empty());

    // An active record snapshot rebuild always publishes, independent of the raw config.
    params.SetNeedSync(false);
    params.MarkWindowRecordSnapshotSynced();
    EXPECT_TRUE(params.NeedSync());
}

/**
 * @tc.name: WindowRecordFieldsOnSync
 * @tc.desc: Verify OnSync copies the window record config and resolved snapshot to the target params
 * @tc.type: FUNC
 * @tc.require: issues/26744
 */
HWTEST_F(RSLogicalDisplayRenderParamsTest, WindowRecordFieldsOnSync, TestSize.Level1)
{
    constexpr NodeId id = 800;
    constexpr NodeId drawableNodeId = 801;
    constexpr NodeId whiteListId = 802;
    RSWindowRecordConfig recordConfig;
    recordConfig.surfaceNodeIds = { whiteListId };
    auto drawable = std::make_shared<LogicalDisplayParamsDrawableAdapterMock>(
        std::make_shared<RSRenderNode>(drawableNodeId));

    RSLogicalDisplayRenderParams source(id);
    source.SetWindowRecordConfig(recordConfig);
    source.SetOnVirtualScreen(true);
    source.displayMode_ = DisplayMode::MIRROR;
    source.recordSurfaceDrawables_.push_back(drawable);
    source.recordWhiteListIds_ = { whiteListId };
    source.recordSourceDisplayDrawable_ = drawable;
    source.hasPaintableRecordSurface_ = true;

    std::unique_ptr<RSRenderParams> target = std::make_unique<RSLogicalDisplayRenderParams>(id);
    source.OnSync(target);
    auto targetParams = static_cast<RSLogicalDisplayRenderParams*>(target.get());
    EXPECT_EQ(targetParams->GetWindowRecordConfig(), recordConfig);
    EXPECT_TRUE(targetParams->IsRecordSessionActive());
    ASSERT_EQ(targetParams->GetRecordSurfaceDrawables().size(), 1u);
    EXPECT_EQ(targetParams->GetRecordSurfaceDrawables()[0].lock(), drawable);
    EXPECT_EQ(targetParams->GetRecordWhiteListIds(), source.GetRecordWhiteListIds());
    EXPECT_EQ(targetParams->GetRecordSourceDisplayDrawable().lock(), drawable);
    EXPECT_TRUE(targetParams->HasPaintableRecordSurface());
}
} // namespace OHOS::Rosen