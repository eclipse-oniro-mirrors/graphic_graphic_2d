/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "common/rs_common_def.h"
#include "gtest/gtest.h"
#include "feature/hdr/rs_hdr_util.h"
#include "pipeline/render_thread/rs_render_engine.h"
#include "pipeline/rs_screen_render_node.h"
#include "pipeline/rs_test_util.h"
#include "v2_2/cm_color_space.h"
#ifdef USE_VIDEO_PROCESSING_ENGINE
#include "colorspace_converter_display.h"
#endif

using namespace testing;
using namespace testing::ext;

namespace OHOS::Rosen {
class RSHdrUtilTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void RSHdrUtilTest::SetUpTestCase()
{
    RSTestUtil::InitRenderNodeGC();
}
void RSHdrUtilTest::TearDownTestCase() {}
void RSHdrUtilTest::SetUp() {}
void RSHdrUtilTest::TearDown() {}

/**
 * @tc.name: CheckIsHdrSurface
 * @tc.desc: Test CheckIsHdrSurface
 * @tc.type: FUNC
 * @tc.require: issueI6QM6E
 */
HWTEST_F(RSHdrUtilTest, CheckIsHdrSurfaceTest, TestSize.Level1)
{
    auto node = RSTestUtil::CreateSurfaceNodeWithBuffer();
    ASSERT_TRUE(node->GetRSSurfaceHandler() != nullptr);
    auto buffer = node->GetRSSurfaceHandler()->GetBuffer();
    ASSERT_TRUE(buffer != nullptr);
    ASSERT_TRUE(buffer->GetBufferHandle() != nullptr);
    node->SetIsOnTheTree(false);
    HdrStatus ret = RSHdrUtil::CheckIsHdrSurface(*node);
    ASSERT_EQ(ret, HdrStatus::NO_HDR);
    node->SetIsOnTheTree(true);
    ret = RSHdrUtil::CheckIsHdrSurface(*node);
    ASSERT_EQ(ret, HdrStatus::NO_HDR);
}

/**
 * @tc.name: CheckIsHdrSurfaceBuffer
 * @tc.desc: Test CheckIsHdrSurfaceBuffer
 * @tc.type: FUNC
 * @tc.require: issueI6QM6E
 */
HWTEST_F(RSHdrUtilTest, CheckIsHdrSurfaceBufferTest, TestSize.Level1)
{
    auto node = RSTestUtil::CreateSurfaceNodeWithBuffer();
    ASSERT_TRUE(node->GetRSSurfaceHandler() != nullptr);
    sptr<SurfaceBuffer> buffer = nullptr;
    HdrStatus ret = RSHdrUtil::CheckIsHdrSurfaceBuffer(buffer);
    ASSERT_EQ(ret, HdrStatus::NO_HDR);
    buffer = node->GetRSSurfaceHandler()->GetBuffer();
    ASSERT_TRUE(buffer != nullptr);
    ASSERT_TRUE(buffer->GetBufferHandle() != nullptr);
    buffer->GetBufferHandle()->format = GraphicPixelFormat::GRAPHIC_PIXEL_FMT_YCBCR_420_SP;
    ret = RSHdrUtil::CheckIsHdrSurfaceBuffer(buffer);
    ASSERT_EQ(ret, HdrStatus::NO_HDR);
    buffer->GetBufferHandle()->format = GraphicPixelFormat::GRAPHIC_PIXEL_FMT_YCBCR_P010;
    ret = RSHdrUtil::CheckIsHdrSurfaceBuffer(buffer);
    ASSERT_EQ(ret, HdrStatus::NO_HDR);

    uint32_t hdrType = HDI::Display::Graphic::Common::V2_2::CM_VIDEO_AI_HDR;
    std::vector<uint8_t> metadataType;
    metadataType.resize(sizeof(hdrType));
    memcpy_s(metadataType.data(), metadataType.size(), &hdrType, sizeof(hdrType));
    buffer->SetMetadata(HDI::Display::Graphic::Common::V1_0::ATTRKEY_HDR_METADATA_TYPE, metadataType);
    ret = RSHdrUtil::CheckIsHdrSurfaceBuffer(buffer);
    ASSERT_EQ(ret, HdrStatus::AI_HDR_VIDEO);
 
    hdrType = HDI::Display::Graphic::Common::V2_2::CM_VIDEO_AI_HDR_HIGH_LIGHT;
    memcpy_s(metadataType.data(), metadataType.size(), &hdrType, sizeof(hdrType));
    buffer->SetMetadata(HDI::Display::Graphic::Common::V1_0::ATTRKEY_HDR_METADATA_TYPE, metadataType);
    ret = RSHdrUtil::CheckIsHdrSurfaceBuffer(buffer);
    ASSERT_EQ(ret, HdrStatus::AI_HDR_VIDEO);
 
    hdrType = HDI::Display::Graphic::Common::V2_2::CM_VIDEO_AI_HDR_COLOR_ENHANCE;
    memcpy_s(metadataType.data(), metadataType.size(), &hdrType, sizeof(hdrType));
    buffer->SetMetadata(HDI::Display::Graphic::Common::V1_0::ATTRKEY_HDR_METADATA_TYPE, metadataType);
    ret = RSHdrUtil::CheckIsHdrSurfaceBuffer(buffer);
    ASSERT_EQ(ret, HdrStatus::AI_HDR_VIDEO);
}

/**
 * @tc.name: CheckIsSurfaceWithMetadata
 * @tc.desc: Test CheckIsSurfaceWithMetadata
 * @tc.type: FUNC
 * @tc.require: issueI6QM6E
 */
HWTEST_F(RSHdrUtilTest, CheckIsSurfaceWithMetadataTest, TestSize.Level1)
{
    auto node = RSTestUtil::CreateSurfaceNodeWithBuffer();
    ASSERT_TRUE(node->GetRSSurfaceHandler() != nullptr);
    auto buffer = node->GetRSSurfaceHandler()->GetBuffer();
    ASSERT_TRUE(buffer != nullptr);
    ASSERT_TRUE(buffer->GetBufferHandle() != nullptr);
    node->SetIsOnTheTree(false);
    bool ret = RSHdrUtil::CheckIsSurfaceWithMetadata(*node);
    ASSERT_EQ(ret, false);
    node->SetIsOnTheTree(true);
    ret = RSHdrUtil::CheckIsSurfaceWithMetadata(*node);
    ASSERT_EQ(ret, false);
}

/**
 * @tc.name: CheckIsSurfaceBufferWithMetadata
 * @tc.desc: Test CheckIsSurfaceBufferWithMetadata
 * @tc.type: FUNC
 * @tc.require: issueI6QM6E
 */
HWTEST_F(RSHdrUtilTest, CheckIsSurfaceBufferWithMetadataTest, TestSize.Level1)
{
    auto node = RSTestUtil::CreateSurfaceNodeWithBuffer();
    ASSERT_TRUE(node->GetRSSurfaceHandler() != nullptr);
    auto buffer = node->GetRSSurfaceHandler()->GetBuffer();
    ASSERT_TRUE(buffer != nullptr);
    ASSERT_TRUE(buffer->GetBufferHandle() != nullptr);
    bool ret = RSHdrUtil::CheckIsSurfaceBufferWithMetadata(buffer);
    ASSERT_EQ(ret, false);
}

/**
 * @tc.name: UpdateSurfaceNodeNit
 * @tc.desc: Test UpdateSurfaceNodeNit
 * @tc.type: FUNC
 * @tc.require: issueI6QM6E
 */
HWTEST_F(RSHdrUtilTest, UpdateSurfaceNodeNitTest, TestSize.Level1)
{
    auto node = RSTestUtil::CreateSurfaceNode();
    ASSERT_NE(node, nullptr);
    RSHdrUtil::UpdateSurfaceNodeNit(*node, 0);
    node = RSTestUtil::CreateSurfaceNodeWithBuffer();
    ASSERT_NE(node, nullptr);
    node->SetVideoHdrStatus(HdrStatus::HDR_VIDEO);
    RSHdrUtil::UpdateSurfaceNodeNit(*node, 0);
}

/**
 * @tc.name: GetRGBA1010108Enabled
 * @tc.desc: Test GetRGBA1010108Enabled
 * @tc.type: FUNC
 * @tc.require: issueI6QM6E
 */
HWTEST_F(RSHdrUtilTest, GetRGBA1010108EnabledTest, TestSize.Level1)
{
    EXPECT_FALSE(RSHdrUtil::GetRGBA1010108Enabled());
}

/**
 * @tc.name: UpdateSurfaceNodeNit001
 * @tc.desc: Test UpdateSurfaceNodeNit
 * @tc.type: FUNC
 * @tc.require: issueI6QM6E
 */
HWTEST_F(RSHdrUtilTest, UpdateSurfaceNodeNitTest001, TestSize.Level1)
{
    auto node = RSTestUtil::CreateSurfaceNodeWithBuffer();
    ASSERT_NE(node, nullptr);
    node->SetVideoHdrStatus(HdrStatus::HDR_VIDEO);
    EXPECT_EQ(node->GetVideoHdrStatus(), HdrStatus::HDR_VIDEO);
    RSHdrUtil::UpdateSurfaceNodeNit(*node, 0);
}

/**
 * @tc.name: UpdateSurfaceNodeNit002
 * @tc.desc: Test UpdateSurfaceNodeNit
 * @tc.type: FUNC
 * @tc.require: issueI6QM6E
 */
HWTEST_F(RSHdrUtilTest, UpdateSurfaceNodeNitTest002, TestSize.Level1)
{
    auto node = RSTestUtil::CreateSurfaceNodeWithBuffer();
    ASSERT_NE(node, nullptr);
    std::shared_ptr<RSContext> context = std::make_shared<RSContext>();
    node->OnRegister(context);
    node->SetVideoHdrStatus(HdrStatus::HDR_VIDEO);
    EXPECT_EQ(node->GetVideoHdrStatus(), HdrStatus::HDR_VIDEO);
    RSHdrUtil::UpdateSurfaceNodeNit(*node, 0);

    auto& nodeMap = context->GetMutableNodeMap();
    NodeId screenRenderNodeId = 1;
    ScreenId screenId = 1;
    auto screenRenderNode = std::make_shared<RSScreenRenderNode>(screenRenderNodeId, screenId, context);
    bool res = nodeMap.RegisterRenderNode(screenRenderNode);
    ASSERT_EQ(res, true);
    RSHdrUtil::UpdateSurfaceNodeNit(*node, 0); // displayNode is nullptr
    node->screenNodeId_ = screenRenderNodeId;
    auto screenNode = context->GetNodeMap().GetRenderNode<RSScreenRenderNode>(node->GetScreenNodeId());
    ASSERT_NE(screenNode, nullptr);
    RSHdrUtil::UpdateSurfaceNodeNit(*node, 0); // displayNode is not nullptr
    screenNode->GetMutableRenderProperties().SetHDRBrightnessFactor(0.5f);
    RSHdrUtil::UpdateSurfaceNodeNit(*node, 0); // update surfaceNode HDRBrightnessFactor
    RSHdrUtil::UpdateSurfaceNodeNit(*node, 0); // not update surfaceNode HDRBrightnessFactor
    EXPECT_EQ(node->GetHDRBrightnessFactor(), 0.5f);
}

/**
 * @tc.name: UpdateSurfaceNodeLayerLinearMatrix
 * @tc.desc: Test UpdateSurfaceNodeLayerLinearMatrix
 * @tc.type: FUNC
 * @tc.require: issueI6QM6E
 */
HWTEST_F(RSHdrUtilTest, UpdateSurfaceNodeLayerLinearMatrixTest, TestSize.Level1)
{
    auto node = RSTestUtil::CreateSurfaceNode();
    ASSERT_NE(node, nullptr);
    RSHdrUtil::UpdateSurfaceNodeLayerLinearMatrix(*node, 0);
    node = RSTestUtil::CreateSurfaceNodeWithBuffer();
    ASSERT_NE(node, nullptr);
    node->SetVideoHdrStatus(HdrStatus::HDR_VIDEO);
    RSHdrUtil::UpdateSurfaceNodeLayerLinearMatrix(*node, 0);
}

/**
 * @tc.name: UpdatePixelFormatAfterHwcCalc
 * @tc.desc: Test UpdatePixelFormatAfterHwcCalc
 * @tc.type: FUNC
 * @tc.require: issueI6QM6E
 */
HWTEST_F(RSHdrUtilTest, UpdatePixelFormatAfterHwcCalcTest, TestSize.Level1)
{
    auto selfDrawingNode = RSTestUtil::CreateSurfaceNodeWithBuffer();
    ASSERT_NE(selfDrawingNode, nullptr);
    NodeId id = 0;
    ScreenId screenId = 1;
    std::shared_ptr<RSContext> context = std::make_shared<RSContext>();
    auto screenNode = std::make_shared<RSScreenRenderNode>(id, screenId, context);
    ASSERT_NE(screenNode, nullptr);
    selfDrawingNode->SetAncestorScreenNode(screenNode);
    selfDrawingNode->SetIsOnTheTree(true);
    selfDrawingNode->SetHardwareForcedDisabledState(true);
    screenNode->SetIsOnTheTree(true);

    ASSERT_NE(selfDrawingNode->GetRSSurfaceHandler(), nullptr);
    auto bufferHandle = selfDrawingNode->GetRSSurfaceHandler()->buffer_.buffer->GetBufferHandle();
    ASSERT_NE(bufferHandle, nullptr);
    bufferHandle->format = GraphicPixelFormat::GRAPHIC_PIXEL_FMT_RGBA_1010102;
    RSHdrUtil::UpdatePixelFormatAfterHwcCalc(*screenNode);
}

/**
 * @tc.name: CheckPixelFormatWithSelfDrawingNode
 * @tc.desc: Test CheckPixelFormatWithSelfDrawingNode
 * @tc.type: FUNC
 * @tc.require: issueI6QM6E
 */
HWTEST_F(RSHdrUtilTest, CheckPixelFormatWithSelfDrawingNodeTest, TestSize.Level1)
{
    NodeId id = 1;
    ScreenId screenId = 1;
    std::shared_ptr<RSContext> context = std::make_shared<RSContext>();
    auto screenNode = std::make_shared<RSScreenRenderNode>(id, screenId, context);
    ASSERT_NE(screenNode, nullptr);
    screenNode->SetIsLuminanceStatusChange(true);
    auto surfaceNode = RSTestUtil::CreateSurfaceNodeWithBuffer();
    ASSERT_NE(surfaceNode, nullptr);
    surfaceNode->SetVideoHdrStatus(HdrStatus::HDR_VIDEO);
    surfaceNode->SetIsOnTheTree(false);
    RSHdrUtil::CheckPixelFormatWithSelfDrawingNode(*surfaceNode, *screenNode);
    surfaceNode->SetIsOnTheTree(true);
    RSHdrUtil::CheckPixelFormatWithSelfDrawingNode(*surfaceNode, *screenNode);
    surfaceNode->SetHardwareForcedDisabledState(false);
    RSHdrUtil::CheckPixelFormatWithSelfDrawingNode(*surfaceNode, *screenNode);
    surfaceNode->SetHardwareForcedDisabledState(true);
    RSHdrUtil::CheckPixelFormatWithSelfDrawingNode(*surfaceNode, *screenNode);
}

/**
 * @tc.name: SetHDRParam
 * @tc.desc: Test SetHDRParam
 * @tc.type: FUNC
 * @tc.require: issueI6QM6E
 */
HWTEST_F(RSHdrUtilTest, SetHDRParamTest, TestSize.Level1)
{
    NodeId id = 0;
    auto parentNode = std::make_shared<RSSurfaceRenderNode>(id);
    ASSERT_NE(parentNode, nullptr);
    parentNode->SetSurfaceNodeType(RSSurfaceNodeType::LEASH_WINDOW_NODE);
    id = 1;
    auto childNode = std::make_shared<RSSurfaceRenderNode>(id);
    ASSERT_NE(childNode, nullptr);
    ScreenId screenId = 0;
    std::shared_ptr<RSContext> context = std::make_shared<RSContext>();
    auto screenNode = std::make_shared<RSScreenRenderNode>(3, screenId, context);
    ASSERT_NE(screenNode, nullptr);
    childNode->SetSurfaceNodeType(RSSurfaceNodeType::APP_WINDOW_NODE);
    parentNode->AddChild(childNode);
    parentNode->SetIsOnTheTree(true);
    childNode->SetIsOnTheTree(true);
    screenNode->GetMutableRenderProperties().SetHDRBrightnessFactor(0.5f); // GetForceCloseHdr false
    RSHdrUtil::SetHDRParam(*screenNode, *childNode, true);
    screenNode->GetMutableRenderProperties().SetHDRBrightnessFactor(0.0f); // GetForceCloseHdr true
    RSHdrUtil::SetHDRParam(*screenNode, *childNode, true);
}
} // namespace OHOS::Rosen