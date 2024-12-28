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
#include "pipeline/rs_uni_hwc_prevalidate_util.h"
#include "rs_test_util.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::Rosen {
constexpr uint64_t DEFAULT_FPS = 120;
constexpr uint32_t DEFAULT_Z_ORDER = 0;
constexpr int DEFAULT_POSITION = 0;
constexpr int DEFAULT_WIDTH = 100;
constexpr int DEFAULT_HEIGHT = 100;
class RSUniPrevalidateUtilTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void RSUniPrevalidateUtilTest::SetUpTestCase()
{
    RSTestUtil::InitRenderNodeGC();
}
void RSUniPrevalidateUtilTest::TearDownTestCase() {}
void RSUniPrevalidateUtilTest::SetUp() {}
void RSUniPrevalidateUtilTest::TearDown() {}

/**
 * @tc.name: CreateSurfaceNodeLayerInfo001
 * @tc.desc: CreateSurfaceNodeLayerInfo, input nullptr
 * @tc.type: FUNC
 * @tc.require: issueIAZAWR
 */
HWTEST_F(RSUniPrevalidateUtilTest, CreateSurfaceNodeLayerInfo001, TestSize.Level1)
{
    auto& uniHwcPrevalidateUtil = RSUniHwcPrevalidateUtil::GetInstance();
    RequestLayerInfo info;
    bool ret = uniHwcPrevalidateUtil.CreateSurfaceNodeLayerInfo(
        DEFAULT_Z_ORDER, nullptr, GraphicTransformType::GRAPHIC_ROTATE_180, DEFAULT_FPS, info);
    ASSERT_EQ(info.fps, DEFAULT_FPS);
    ASSERT_EQ(ret, false);
}

/**
 * @tc.name: CreateSurfaceNodeLayerInfo002
 * @tc.desc: CreateSurfaceNodeLayerInfo, input surfaceNode
 * @tc.type: FUNC
 * @tc.require: issueIAZAWR
 */
HWTEST_F(RSUniPrevalidateUtilTest, CreateSurfaceNodeLayerInfo002, TestSize.Level1)
{
    auto& uniHwcPrevalidateUtil = RSUniHwcPrevalidateUtil::GetInstance();
    auto surfaceNode = RSTestUtil::CreateSurfaceNodeWithBuffer();
    ASSERT_NE(surfaceNode, nullptr);

    RequestLayerInfo info;
    bool ret = uniHwcPrevalidateUtil.CreateSurfaceNodeLayerInfo(
        DEFAULT_Z_ORDER, surfaceNode, GraphicTransformType::GRAPHIC_ROTATE_180, DEFAULT_FPS, info);
    ASSERT_EQ(info.fps, DEFAULT_FPS);
    ASSERT_EQ(ret, true);
}

/**
 * @tc.name: IsYUVBufferFormat001
 * @tc.desc: IsYUVBufferFormat, buffer is nullptr && format is invalid
 * @tc.type: FUNC
 * @tc.require: issueIAZAWR
 */
HWTEST_F(RSUniPrevalidateUtilTest, IsYUVBufferFormat001, TestSize.Level1)
{
    auto& uniHwcPrevalidateUtil = RSUniHwcPrevalidateUtil::GetInstance();
    auto surfaceNode1 = RSTestUtil::CreateSurfaceNodeWithBuffer();
    auto surfaceHandler = surfaceNode1->surfaceHandler_;
    ASSERT_NE(surfaceHandler, nullptr);
    surfaceHandler->buffer_.buffer = nullptr;
    bool ret = uniHwcPrevalidateUtil.IsYUVBufferFormat(surfaceNode1);
    ASSERT_EQ(ret, false);

    auto surfaceNode2 = RSTestUtil::CreateSurfaceNodeWithBuffer();
    auto bufferHandle = surfaceNode2->surfaceHandler_->buffer_.buffer->GetBufferHandle();
    ASSERT_NE(bufferHandle, nullptr);
    bufferHandle->format = GraphicPixelFormat::GRAPHIC_PIXEL_FMT_RGBA_1010102;
    ret = uniHwcPrevalidateUtil.IsYUVBufferFormat(surfaceNode2);
    ASSERT_EQ(ret, false);
}

/**
 * @tc.name: IsYUVBufferFormat002
 * @tc.desc: IsYUVBufferFormat, format is valid
 * @tc.type: FUNC
 * @tc.require: issueIAZAWR
 */
HWTEST_F(RSUniPrevalidateUtilTest, IsYUVBufferFormat002, TestSize.Level1)
{
    auto& uniHwcPrevalidateUtil = RSUniHwcPrevalidateUtil::GetInstance();
    auto surfaceNode = RSTestUtil::CreateSurfaceNodeWithBuffer();
    auto bufferHandle = surfaceNode->surfaceHandler_->buffer_.buffer->GetBufferHandle();
    ASSERT_NE(bufferHandle, nullptr);
    bufferHandle->format = GraphicPixelFormat::GRAPHIC_PIXEL_FMT_YUV_422_I;
    bool ret = uniHwcPrevalidateUtil.IsYUVBufferFormat(surfaceNode);
    ASSERT_EQ(ret, true);
}

/**
 * @tc.name: CreateDisplayNodeLayerInfo001
 * @tc.desc: CreateDisplayNodeLayerInfo, node is nullptr
 * @tc.type: FUNC
 * @tc.require: issueI60QXK
 */
HWTEST_F(RSUniPrevalidateUtilTest, CreateDisplayNodeLayerInfo001, TestSize.Level1)
{
    auto& uniHwcPrevalidateUtil = RSUniHwcPrevalidateUtil::GetInstance();
    ScreenInfo screenInfo;
    RequestLayerInfo info;
    bool ret = uniHwcPrevalidateUtil.CreateDisplayNodeLayerInfo(
        DEFAULT_Z_ORDER, nullptr, screenInfo, DEFAULT_FPS, info);
    ASSERT_EQ(info.fps, DEFAULT_FPS);
    ASSERT_EQ(ret, false);
}

/**
 * @tc.name: CreateDisplayNodeLayerInfo002
 * @tc.desc: CreateDisplayNodeLayerInfo, input displayNode
 * @tc.type: FUNC
 * @tc.require: issueI60QXK
 */
HWTEST_F(RSUniPrevalidateUtilTest, CreateDisplayNodeLayerInfo002, TestSize.Level1)
{
    auto& uniHwcPrevalidateUtil = RSUniHwcPrevalidateUtil::GetInstance();
    ScreenInfo screenInfo;
    RSDisplayNodeConfig config;
    NodeId id = 0;
    auto displayNode = std::make_shared<RSDisplayRenderNode>(id, config);
    ASSERT_NE(displayNode, nullptr);
    RequestLayerInfo info;
    bool ret = uniHwcPrevalidateUtil.CreateDisplayNodeLayerInfo(
        DEFAULT_Z_ORDER, displayNode, screenInfo, DEFAULT_FPS, info);
    ASSERT_EQ(info.fps, DEFAULT_FPS);
    ASSERT_EQ(ret, false);
}

/**
 * @tc.name: CreateRCDLayerInfo001
 * @tc.desc: CreateRCDLayerInfo, input nullptr
 * @tc.type: FUNC
 * @tc.require: issueI60QXK
 */
HWTEST_F(RSUniPrevalidateUtilTest, CreateRCDLayerInfo001, TestSize.Level1)
{
    auto& uniHwcPrevalidateUtil = RSUniHwcPrevalidateUtil::GetInstance();
    ScreenInfo screenInfo;
    RequestLayerInfo info;
    bool ret = uniHwcPrevalidateUtil.CreateRCDLayerInfo(nullptr, screenInfo, DEFAULT_FPS, info);
    ASSERT_EQ(info.fps, DEFAULT_FPS);
    ASSERT_EQ(ret, false);
}

/**
 * @tc.name: CreateRCDLayerInfo002
 * @tc.desc: CreateRCDLayerInfo, input RCDSurfaceNode
 * @tc.type: FUNC
 * @tc.require: issueI60QXK
 */
HWTEST_F(RSUniPrevalidateUtilTest, CreateRCDLayerInfo002, TestSize.Level1)
{
    auto& uniHwcPrevalidateUtil = RSUniHwcPrevalidateUtil::GetInstance();
    NodeId id = 1;
    auto node = std::make_shared<RSRcdSurfaceRenderNode>(id, RCDSurfaceType::BOTTOM);
    ASSERT_NE(node, nullptr);
    ScreenInfo screenInfo;
    RequestLayerInfo info;
    bool ret = uniHwcPrevalidateUtil.CreateRCDLayerInfo(node, screenInfo, DEFAULT_FPS, info);
    ASSERT_EQ(info.fps, DEFAULT_FPS);
    ASSERT_EQ(ret, false);
}

/**
 * @tc.name: IsPrevalidateEnable001
 * @tc.desc: IsPrevalidateEnable, input screen 0 and load success/fail
 * @tc.type: FUNC
 * @tc.require: issueIATEBN
 */
HWTEST_F(RSUniPrevalidateUtilTest, IsPrevalidateEnable001, TestSize.Level1)
{
    auto& uniHwcPrevalidateUtil = RSUniHwcPrevalidateUtil::GetInstance();
    uniHwcPrevalidateUtil.isPrevalidateHwcNodeEnable_ = true;
    uniHwcPrevalidateUtil.loadSuccess_ = false;
    bool ret = uniHwcPrevalidateUtil.IsPrevalidateEnable();
    EXPECT_EQ(ret, false);
    uniHwcPrevalidateUtil.loadSuccess_ = true;
    ret = uniHwcPrevalidateUtil.IsPrevalidateEnable();
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: CheckHwcNodeAndGetPointerWindow001
 * @tc.desc: CheckHwcNodeAndGetPointerWindow, input nullptr or hwcNode not on the tree
 * @tc.type: FUNC
 * @tc.require: issueIATEBN
 */
HWTEST_F(RSUniPrevalidateUtilTest, CheckHwcNodeAndGetPointerWindow001, TestSize.Level1)
{
    std::shared_ptr<RSSurfaceRenderNode> hwcNode = nullptr;
    std::shared_ptr<RSSurfaceRenderNode> pointerWindow = nullptr;
    bool ret = RSUniHwcPrevalidateUtil::CheckHwcNodeAndGetPointerWindow(hwcNode, pointerWindow);
    EXPECT_EQ(ret, false);
    hwcNode = RSTestUtil::CreateSurfaceNode();
    hwcNode->isOnTheTree_ = false;
    ret = RSUniHwcPrevalidateUtil::CheckHwcNodeAndGetPointerWindow(hwcNode, pointerWindow);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: CheckHwcNodeAndGetPointerWindow002
 * @tc.desc: CheckHwcNodeAndGetPointerWindow, input pointerWindow
 * @tc.type: FUNC
 * @tc.require: issueIATEBN
 */
HWTEST_F(RSUniPrevalidateUtilTest, CheckHwcNodeAndGetPointerWindow002, TestSize.Level1)
{
    std::shared_ptr<RSSurfaceRenderNode> hwcNode = RSTestUtil::CreateSurfaceNode();
    std::shared_ptr<RSSurfaceRenderNode> pointerWindow = nullptr;
    hwcNode->isOnTheTree_ = true;
    hwcNode->nodeType_ = RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE;
    hwcNode->name_ = "pointer window";
    bool ret = RSUniHwcPrevalidateUtil::CheckHwcNodeAndGetPointerWindow(hwcNode, pointerWindow);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: CheckHwcNodeAndGetPointerWindow003
 * @tc.desc: CheckHwcNodeAndGetPointerWindow, input normal hwcNode
 * @tc.type: FUNC
 * @tc.require: issueIATEBN
 */
HWTEST_F(RSUniPrevalidateUtilTest, CheckHwcNodeAndGetPointerWindow003, TestSize.Level1)
{
    std::shared_ptr<RSSurfaceRenderNode> hwcNode = RSTestUtil::CreateSurfaceNode();
    std::shared_ptr<RSSurfaceRenderNode> pointerWindow = nullptr;
    hwcNode->isOnTheTree_ = true;
    hwcNode->dstRect_ = { DEFAULT_POSITION, DEFAULT_POSITION, DEFAULT_WIDTH, DEFAULT_HEIGHT };
    bool ret = RSUniHwcPrevalidateUtil::CheckHwcNodeAndGetPointerWindow(hwcNode, pointerWindow);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: ClearCldInfo
 * @tc.desc: Test ClearCldInfo
 * @tc.type: FUNC
 * @tc.require: issueIBA4NP
 */
HWTEST_F(RSUniPrevalidateUtilTest, ClearCldInfo001, TestSize.Level2)
{
    NodeId id = 1;
    auto node = std::make_shared<RSRcdSurfaceRenderNode>(id, RCDSurfaceType::BOTTOM);
    ASSERT_NE(node, nullptr);

    RequestLayerInfo info;
    RSUniHwcPrevalidateUtil::GetInstance().CopyCldInfo(node->GetCldInfo(), info);

    std::vector<RequestLayerInfo> infos;
    infos.push_back(info);
    RSUniHwcPrevalidateUtil::GetInstance().ClearCldInfo(infos);
    ASSERT_EQ(infos[0].cldInfo, nullptr);
}

/**
 * @tc.name: CreateUIFirstLayerInfo001
 * @tc.desc: CreateUIFirstLayerInfo, input normal hwcNode
 * @tc.type: FUNC
 * @tc.require: issueIBA6PF
 */
HWTEST_F(RSUniPrevalidateUtilTest, CreateUIFirstLayerInfo001, TestSize.Level1)
{
    auto& uniHwcPrevalidateUtil = RSUniHwcPrevalidateUtil::GetInstance();
    auto surfaceNode = RSTestUtil::CreateSurfaceNodeWithBuffer();
    ASSERT_NE(surfaceNode, nullptr);
    RequestLayerInfo info;
    bool ret = uniHwcPrevalidateUtil.CreateUIFirstLayerInfo(
        surfaceNode, GraphicTransformType::GRAPHIC_ROTATE_180, DEFAULT_FPS, info);
    ASSERT_EQ(ret, true);
}

/**
 * @tc.name: CreateUIFirstLayerInfo002
 * @tc.desc: CreateUIFirstLayerInfo, input nullptr
 * @tc.type: FUNC
 * @tc.require: issueIBA6PF
 */
HWTEST_F(RSUniPrevalidateUtilTest, CreateUIFirstLayerInfo002, TestSize.Level1)
{
    auto& uniHwcPrevalidateUtil = RSUniHwcPrevalidateUtil::GetInstance();
    RequestLayerInfo info;
    bool ret = uniHwcPrevalidateUtil.CreateUIFirstLayerInfo(
        nullptr, GraphicTransformType::GRAPHIC_ROTATE_180, DEFAULT_FPS, info);
    ASSERT_EQ(info.fps, DEFAULT_FPS);
    ASSERT_EQ(ret, false);
}

/**
 * @tc.name: CheckIfDoArsrPre001
 * @tc.desc: CheckIfDoArsrPre, input normal surfacenode
 * @tc.type: FUNC
 * @tc.require: issueIBA6PF
 */
HWTEST_F(RSUniPrevalidateUtilTest, CheckIfDoArsrPre001, TestSize.Level1)
{
    auto& uniHwcPrevalidateUtil = RSUniHwcPrevalidateUtil::GetInstance();
    auto surfaceNode = RSTestUtil::CreateSurfaceNodeWithBuffer();
    ASSERT_NE(surfaceNode, nullptr);
    auto bufferHandle = surfaceNode->surfaceHandler_->buffer_.buffer->GetBufferHandle();
    ASSERT_NE(bufferHandle, nullptr);
    bufferHandle->format = GraphicPixelFormat::GRAPHIC_PIXEL_FMT_YUV_422_I;
    bool ret = uniHwcPrevalidateUtil.CheckIfDoArsrPre(surfaceNode);
    ASSERT_EQ(ret, true);
}

/**
 * @tc.name: CopyCldInfo001
 * @tc.desc: CopyCldInfo
 * @tc.type: FUNC
 * @tc.require: issueIBA6PF
 */
HWTEST_F(RSUniPrevalidateUtilTest, CopyCldInfo001, TestSize.Level1)
{
    auto& uniHwcPrevalidateUtil = RSUniHwcPrevalidateUtil::GetInstance();
    NodeId id = 1;
    auto node = std::make_shared<RSRcdSurfaceRenderNode>(id, RCDSurfaceType::BOTTOM);
    ASSERT_NE(node, nullptr);
    RequestLayerInfo info;
    uniHwcPrevalidateUtil.CopyCldInfo(node->GetCldInfo(), info);
}

/**
 * @tc.name: LayerRotate001
 * @tc.desc: LayerRotate
 * @tc.type: FUNC
 * @tc.require: issueIBA6PF
 */
HWTEST_F(RSUniPrevalidateUtilTest, LayerRotate001, TestSize.Level1)
{
    auto& uniHwcPrevalidateUtil = RSUniHwcPrevalidateUtil::GetInstance();
    RequestLayerInfo info;
    info.dstRect = {50, 50, 100, 200};
    ScreenInfo screenInfo;
    sptr<IConsumerSurface> cSurface = nullptr;
    uniHwcPrevalidateUtil.LayerRotate(info, cSurface, screenInfo);
    ASSERT_EQ(info.dstRect.w, 100);
    ASSERT_EQ(info.dstRect.h, 200);
    
    cSurface = IConsumerSurface::Create();
    uniHwcPrevalidateUtil.LayerRotate(info, cSurface, screenInfo);
    ASSERT_EQ(info.dstRect.w, 100);
    ASSERT_EQ(info.dstRect.h, 200);

    screenInfo.rotation = ScreenRotation::ROTATION_90;
    uniHwcPrevalidateUtil.LayerRotate(info, cSurface, screenInfo);
    ASSERT_EQ(info.dstRect.w, 200);
    ASSERT_EQ(info.dstRect.h, 100);

    screenInfo.rotation = ScreenRotation::ROTATION_180;
    uniHwcPrevalidateUtil.LayerRotate(info, cSurface, screenInfo);
    ASSERT_EQ(info.dstRect.w, 200);
    ASSERT_EQ(info.dstRect.h, 100);

    screenInfo.rotation = ScreenRotation::ROTATION_270;
    uniHwcPrevalidateUtil.LayerRotate(info, cSurface, screenInfo);
    ASSERT_EQ(info.dstRect.w, 100);
    ASSERT_EQ(info.dstRect.h, 200);
}

/**
 * @tc.name: EmplaceSurfaceNodeLayer001
 * @tc.desc: EmplaceSurfaceNodeLayer
 * @tc.type: FUNC
 * @tc.require: issueIBA6PF
 */
HWTEST_F(RSUniPrevalidateUtilTest, EmplaceSurfaceNodeLayer001, TestSize.Level1)
{
    auto& uniHwcPrevalidateUtil = RSUniHwcPrevalidateUtil::GetInstance();
    std::vector<RequestLayerInfo> prevalidLayers;
    auto surfaceNode = RSTestUtil::CreateSurfaceNodeWithBuffer();
    ASSERT_NE(surfaceNode, nullptr);
    ScreenInfo screenInfo;
    uint32_t zOrder = DEFAULT_Z_ORDER;
    uniHwcPrevalidateUtil.EmplaceSurfaceNodeLayer(prevalidLayers, surfaceNode, DEFAULT_FPS, zOrder, screenInfo);
    ASSERT_EQ(prevalidLayers.size(), 1);
}

/**
 * @tc.name: CollectUIFirstLayerInfo001
 * @tc.desc: CollectUIFirstLayerInfo
 * @tc.type: FUNC
 * @tc.require: issueIBA6PF
 */
HWTEST_F(RSUniPrevalidateUtilTest, CollectUIFirstLayerInfo001, TestSize.Level1)
{
    auto& uniHwcPrevalidateUtil = RSUniHwcPrevalidateUtil::GetInstance();
    std::vector<RequestLayerInfo> uiFirstLayers;
    ScreenInfo screenInfo;
    uniHwcPrevalidateUtil.CollectUIFirstLayerInfo(uiFirstLayers, DEFAULT_FPS, DEFAULT_Z_ORDER, screenInfo);
    ASSERT_EQ(uiFirstLayers.size(), 0);
}

/**
 * @tc.name: CollectSurfaceNodeLayerInfo001
 * @tc.desc: CollectSurfaceNodeLayerInfo
 * @tc.type: FUNC
 * @tc.require: issueIBA6PF
 */
HWTEST_F(RSUniPrevalidateUtilTest, CollectSurfaceNodeLayerInfo001, TestSize.Level1)
{
    auto& uniHwcPrevalidateUtil = RSUniHwcPrevalidateUtil::GetInstance();
    std::vector<RequestLayerInfo> prevalidLayers;
    std::vector<RSBaseRenderNode::SharedPtr> surfaceNodes;
    surfaceNodes.push_back(nullptr);
    auto surfaceNode = RSTestUtil::CreateSurfaceNodeWithBuffer();
    ASSERT_NE(surfaceNode, nullptr);
    surfaceNodes.push_back(surfaceNode);
    ScreenInfo screenInfo;
    uint32_t zOrder = DEFAULT_Z_ORDER;
    uniHwcPrevalidateUtil.CollectSurfaceNodeLayerInfo(prevalidLayers, surfaceNodes, DEFAULT_FPS, zOrder, screenInfo);
}
}