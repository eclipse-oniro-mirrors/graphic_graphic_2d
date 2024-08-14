/*
 * Copyright (c) 2024-2024 Huawei Device Co., Ltd.
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
#include "params/rs_surface_render_params.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::Rosen {
class RSSurfaceRenderParamsTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};
void RSSurfaceRenderParamsTest::SetUpTestCase() {}
void RSSurfaceRenderParamsTest::TearDownTestCase() {}
void RSSurfaceRenderParamsTest::SetUp() {}
void RSSurfaceRenderParamsTest::TearDown() {}

/**
 * @tc.name: SetOccludedByFilterCache
 * @tc.desc:
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSSurfaceRenderParamsTest, SetOccludedByFilterCache, TestSize.Level1)
{
    RSSurfaceRenderParams params(100);
    params.SetOccludedByFilterCache(false);
    EXPECT_EQ(params.needSync_, false);

    params.SetOccludedByFilterCache(true);
    EXPECT_EQ(params.needSync_, true);
}

/**
 * @tc.name: SetHardwareEnabled
 * @tc.desc:
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSSurfaceRenderParamsTest, SetHardwareEnabled, TestSize.Level1)
{
    RSSurfaceRenderParams params(101);
    params.SetHardwareEnabled(false);
    EXPECT_EQ(params.needSync_, false);

    params.SetHardwareEnabled(true);
    EXPECT_EQ(params.needSync_, true);
}

/**
 * @tc.name: SetLastFrameHardwareEnabled
 * @tc.desc:
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSSurfaceRenderParamsTest, SetLastFrameHardwareEnabled, TestSize.Level1)
{
    RSSurfaceRenderParams params(102);
    params.SetLastFrameHardwareEnabled(false);
    EXPECT_EQ(params.needSync_, false);

    params.SetLastFrameHardwareEnabled(true);
    EXPECT_EQ(params.needSync_, true);
}

/**
 * @tc.name: SetLayerSourceTuning
 * @tc.desc:
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSSurfaceRenderParamsTest, SetLayerSourceTuning, TestSize.Level1)
{
    RSSurfaceRenderParams params(103);
    params.SetLayerSourceTuning(false);
    EXPECT_EQ(params.needSync_, false);

    params.SetLayerSourceTuning(true);
    EXPECT_EQ(params.needSync_, true);
}

/**
 * @tc.name: SetForceHardwareByUser
 * @tc.desc:
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSSurfaceRenderParamsTest, SetForceHardwareByUser, TestSize.Level1)
{
    RSSurfaceRenderParams params(104);
    params.SetForceHardwareByUser(false);
    EXPECT_EQ(params.needSync_, false);

    params.SetForceHardwareByUser(true);
    EXPECT_EQ(params.needSync_, true);
}


/**
 * @tc.name: SetSurfaceCacheContentStatic
 * @tc.desc:
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSSurfaceRenderParamsTest, SetSurfaceCacheContentStatic, TestSize.Level1)
{
    RSSurfaceRenderParams params(105);
    params.SetSurfaceCacheContentStatic(false, false);
    EXPECT_EQ(params.needSync_, false);

    params.SetSurfaceCacheContentStatic(true, false);
    EXPECT_EQ(params.needSync_, false);

    params.SetSurfaceCacheContentStatic(true, true);
    EXPECT_EQ(params.needSync_, true);

    RSSurfaceRenderParams paramsAno(106);
    paramsAno.surfaceCacheContentStatic_ = true;
    params.SetSurfaceCacheContentStatic(false, true);
    EXPECT_EQ(params.needSync_, true);

    params.SetSurfaceCacheContentStatic(false, false);
    EXPECT_EQ(params.needSync_, true);
}

/**
 * @tc.name: SetSurfaceSubTreeDirty
 * @tc.desc:
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSSurfaceRenderParamsTest, SetSurfaceSubTreeDirty, TestSize.Level1)
{
    RSSurfaceRenderParams params(107);
    params.SetSurfaceSubTreeDirty(false);
    EXPECT_EQ(params.needSync_, false);

    params.SetSurfaceSubTreeDirty(true);
    EXPECT_EQ(params.needSync_, true);
}

/**
* @tc.name: SetGpuOverDrawBufferOptimizeNode
* @tc.desc:
* @tc.type:FUNC
* @tc.require:
*/
HWTEST_F(RSSurfaceRenderParamsTest, SetGpuOverDrawBufferOptimizeNode, TestSize.Level1)
{
    RSSurfaceRenderParams params(108);
    params.SetGpuOverDrawBufferOptimizeNode(false);
    EXPECT_EQ(params.needSync_, false);

    params.SetGpuOverDrawBufferOptimizeNode(true);
    EXPECT_EQ(params.needSync_, true);
}

/**
 * @tc.name: SetOverDrawBufferNodeCornerRadius
 * @tc.desc:
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSSurfaceRenderParamsTest, SetOverDrawBufferNodeCornerRadius, TestSize.Level1)
{
    RSSurfaceRenderParams params(109);
    params.SetOverDrawBufferNodeCornerRadius(false);
    EXPECT_EQ(params.needSync_, false);

    params.SetOverDrawBufferNodeCornerRadius(true);
    EXPECT_EQ(params.needSync_, true);
}

/**
* @tc.name: SetRootIdOfCaptureWindow
* @tc.desc:
* @tc.type:FUNC
* @tc.require:
*/
HWTEST_F(RSSurfaceRenderParamsTest, SetRootIdOfCaptureWindow, TestSize.Level1)
{
    RSSurfaceRenderParams params(110);
    params.SetRootIdOfCaptureWindow(false);
    EXPECT_EQ(params.needSync_, false);

    params.SetRootIdOfCaptureWindow(true);
    EXPECT_EQ(params.needSync_, true);
}

/**
 * @tc.name: IsVisibleDirtyRegionEmpty
 * @tc.desc:
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RSSurfaceRenderParamsTest, IsVisibleDirtyRegionEmpty, TestSize.Level1)
{
    RSSurfaceRenderParams params(111);
    Drawing::Region region;
    params.windowInfo_.isMainWindowType_ = true;
    ASSERT_TRUE(params.IsVisibleDirtyRegionEmpty(region));

    params.windowInfo_.isMainWindowType_ = false;
    params.windowInfo_.isLeashWindow_ = true;
    ASSERT_FALSE(params.IsVisibleDirtyRegionEmpty(region));

    params.windowInfo_.isMainWindowType_ = false;
    params.windowInfo_.isLeashWindow_ = false;
    ASSERT_FALSE(params.IsVisibleDirtyRegionEmpty(region));
}
}