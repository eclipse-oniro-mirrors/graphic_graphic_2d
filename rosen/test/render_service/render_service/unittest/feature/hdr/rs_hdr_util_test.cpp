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

#include "feature/hdr/rs_hdr_util.h"

#include <parameter.h>
#include <parameters.h>

#include "common/rs_common_def.h"
#include "ibuffer_consumer_listener.h"
#include "gtest/gtest.h"
#include "pipeline/main_thread/rs_main_thread.h"
#include "pipeline/render_thread/rs_render_engine.h"
#include "pipeline/rs_screen_render_node.h"
#include "pipeline/rs_paint_filter_canvas.h"
#include "pipeline/rs_test_util.h"
#include "platform/ohos/backend/rs_surface_frame_ohos_vulkan.h"
#include "screen_manager/rs_screen.h"
#include "system/rs_system_parameters.h"
#include "utils/system_properties.h"
#include "v2_2/buffer_handle_meta_key_type.h"
#include "v2_2/cm_color_space.h"
#ifdef USE_VIDEO_PROCESSING_ENGINE
#include "colorspace_converter_display.h"
#include "render/rs_colorspace_convert.h"
#endif

using namespace testing;
using namespace testing::ext;

namespace OHOS::Rosen {
namespace {
constexpr int32_t DEFAULT_CANVAS_SIZE = 100;
BufferRequestConfig requestConfig = {
    .width = 0x100,
    .height = 0x100,
    .strideAlignment = 0x8,
    .format = GRAPHIC_PIXEL_FMT_RGBA_8888,
    .usage = BUFFER_USAGE_CPU_READ | BUFFER_USAGE_CPU_WRITE | BUFFER_USAGE_MEM_DMA,
    .timeout = 0,
};
}

class BufferConsumerListener : public ::OHOS::IBufferConsumerListener {
public:
    void OnBufferAvailable() override
    {
    }
};

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
    HDI::Display::Graphic::Common::V1_0::CM_ColorSpaceInfo colorSpaceInfo = {
        .transfunc = HDI::Display::Graphic::Common::V1_0::TRANSFUNC_HLG
    };
    EXPECT_EQ(MetadataHelper::SetColorSpaceInfo(buffer, colorSpaceInfo), GSERROR_OK);
    ret = RSHdrUtil::CheckIsHdrSurfaceBuffer(buffer);
    EXPECT_EQ(ret, HdrStatus::HDR_VIDEO);
#ifdef USE_VIDEO_PROCESSING_ENGINE
    uint32_t hdrType = HDI::Display::Graphic::Common::V2_2::CM_VIDEO_AI_HDR;
    std::vector<uint8_t> metadataType;
    metadataType.resize(sizeof(hdrType));
    memcpy_s(metadataType.data(), metadataType.size(), &hdrType, sizeof(hdrType));
    buffer->SetMetadata(HDI::Display::Graphic::Common::V1_0::ATTRKEY_HDR_METADATA_TYPE, metadataType);
    ret = RSHdrUtil::CheckIsHdrSurfaceBuffer(buffer);
    ASSERT_EQ(ret, HdrStatus::AI_HDR_VIDEO_GTM);
 
    hdrType = HDI::Display::Graphic::Common::V2_2::CM_VIDEO_AI_HDR_HIGH_LIGHT;
    metadataType.resize(sizeof(hdrType));
    memcpy_s(metadataType.data(), metadataType.size(), &hdrType, sizeof(hdrType));
    buffer->SetMetadata(Media::VideoProcessingEngine::ATTRKEY_HDR_METADATA_TYPE, metadataType);
    ret = RSHdrUtil::CheckIsHdrSurfaceBuffer(buffer);
    ASSERT_EQ(ret, HdrStatus::AI_HDR_VIDEO_GAINMAP);

    hdrType = HDI::Display::Graphic::Common::V2_2::CM_VIDEO_AI_HDR_COLOR_ENHANCE;
    metadataType.resize(sizeof(hdrType));
    memcpy_s(metadataType.data(), metadataType.size(), &hdrType, sizeof(hdrType));
    buffer->SetMetadata(Media::VideoProcessingEngine::ATTRKEY_HDR_METADATA_TYPE, metadataType);
    ret = RSHdrUtil::CheckIsHdrSurfaceBuffer(buffer);
    ASSERT_EQ(ret, HdrStatus::AI_HDR_VIDEO_GAINMAP);
#endif
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
#ifdef USE_VIDEO_PROCESSING_ENGINE
    using namespace OHOS::HDI::Display::Graphic::Common::V1_0;
    CM_ColorSpaceInfo infoSet = {
        .primaries = COLORPRIMARIES_P3_D65,
    };
    auto retSet = MetadataHelper::SetColorSpaceInfo(buffer, infoSet);
    EXPECT_EQ(retSet, GSERROR_OK);
    std::vector<uint8_t> metadata = {1.0f, 1.0f, 1.0f};
    buffer->SetMetadata(OHOS::HDI::Display::Graphic::Common::V2_0::ATTRKEY_EXTERNAL_METADATA_002, metadata);
    ret = RSHdrUtil::CheckIsSurfaceBufferWithMetadata(buffer);
    ASSERT_EQ(ret, true);
#endif
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
    bool isDDGR = Drawing::SystemProperties::GetSystemGraphicGpuType() == GpuApiType::DDGR;
    bool rgba1010108 = system::GetBoolParameter("const.graphics.rgba_1010108_supported", false);
    bool debugSwitch = system::GetBoolParameter("persist.sys.graphic.rgba_1010108.enabled", true);
    bool result = isDDGR && rgba1010108 && debugSwitch;
    EXPECT_EQ(RSHdrUtil::GetRGBA1010108Enabled(), result);
    system::SetParameter("persist.sys.graphic.rgba_1010108.enabled", "false");
    EXPECT_EQ(RSHdrUtil::GetRGBA1010108Enabled(), false);
    system::SetParameter("persist.sys.graphic.rgba_1010108.enabled", debugSwitch ? "true" : "false");
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
    RSHdrUtil::UpdateSurfaceNodeNit(*node, 0); // screenNode is nullptr
    node->screenNodeId_ = screenRenderNodeId;
    auto screenNode = context->GetNodeMap().GetRenderNode<RSScreenRenderNode>(node->GetScreenNodeId());
    ASSERT_NE(screenNode, nullptr);
    RSHdrUtil::UpdateSurfaceNodeNit(*node, 0); // screenNode is not nullptr
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
    RSMainThread::Instance()->AddSelfDrawingNodes(selfDrawingNode);
    std::shared_ptr<RSSurfaceRenderNode> selfDrawingNode2 = nullptr;
    RSMainThread::Instance()->AddSelfDrawingNodes(selfDrawingNode2);
    std::shared_ptr<RSSurfaceRenderNode> selfDrawingNode3 = RSTestUtil::CreateSurfaceNodeWithBuffer();
    ASSERT_NE(selfDrawingNode3, nullptr);
    selfDrawingNode3->SetAncestorScreenNode(screenNode);
    RSHdrUtil::UpdatePixelFormatAfterHwcCalc(*screenNode);
    auto screenNode2 = std::make_shared<RSScreenRenderNode>(3, 4, context);
    ASSERT_NE(screenNode2, nullptr);
    selfDrawingNode->SetAncestorScreenNode(screenNode2);
    RSHdrUtil::UpdatePixelFormatAfterHwcCalc(*screenNode);
    auto renderNode = std::make_shared<RSBaseRenderNode>(0, context);
    selfDrawingNode->SetAncestorScreenNode(renderNode);
    RSHdrUtil::UpdatePixelFormatAfterHwcCalc(*screenNode);
    selfDrawingNode->SetHardwareForcedDisabledState(false);
    selfDrawingNode->SetAncestorScreenNode(screenNode);
    screenNode->stagingRenderParams_ = std::make_unique<RSScreenRenderParams>(screenNode->GetId());
    ASSERT_NE(screenNode->stagingRenderParams_, nullptr);
    RSHdrUtil::UpdatePixelFormatAfterHwcCalc(*screenNode);
    EXPECT_EQ(screenNode->GetExistHWCNode(), true);
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
 * @tc.name: LuminanceChangeSetDirty
 * @tc.desc: Test LuminanceChangeSetDirty
 * @tc.type: FUNC
 * @tc.require: issueI6QM6E
 */
HWTEST_F(RSHdrUtilTest, LuminanceChangeSetDirtyTest, TestSize.Level1)
{
    NodeId screenRenderNodeId = 2;
    ScreenId screenId = 0;
    auto context = std::make_shared<RSContext>();
    auto screenRenderNode = std::make_shared<RSScreenRenderNode>(screenRenderNodeId, screenId, context);

    RSHdrUtil::LuminanceChangeSetDirty(*screenRenderNode);
    screenRenderNode->SetIsLuminanceStatusChange(true);
    screenRenderNode->InsertHDRNode(screenRenderNodeId);
    EXPECT_NE(screenRenderNode->hdrNodeList_.find(screenRenderNodeId), screenRenderNode->hdrNodeList_.end());
    RSHdrUtil::LuminanceChangeSetDirty(*screenRenderNode);
    
    NodeId nodeId1 = 0;
    auto node1 = std::make_shared<RSRenderNode>(nodeId1);
    pid_t pid1 = ExtractPid(nodeId1);
    context->GetMutableNodeMap().renderNodeMap_[pid1][nodeId1] = node1;
    screenRenderNode->InsertHDRNode(nodeId1);
    RSHdrUtil::LuminanceChangeSetDirty(*screenRenderNode);
    
    pid_t pid = ExtractPid(screenRenderNodeId);
    context->GetMutableNodeMap().renderNodeMap_[pid][screenRenderNodeId] = screenRenderNode;
    RSHdrUtil::LuminanceChangeSetDirty(*screenRenderNode);
    
    ScreenId screenId2 = 1;
    std::shared_ptr<RSContext> context2;
    auto screenNode2 = std::make_shared<RSScreenRenderNode>(3, screenId2, context2);
    screenRenderNode->InsertHDRNode(3);
    RSHdrUtil::LuminanceChangeSetDirty(*screenRenderNode);
    EXPECT_NE(screenRenderNode->hdrNodeList_.find(3), screenRenderNode->hdrNodeList_.end());
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

/**
 * @tc.name: UpdateHDRCastPropertiesTest
 * @tc.desc: Test UpdateHDRCastProperties
 * @tc.type: FUNC
 * @tc.require: issueI6QM6E
 */
HWTEST_F(RSHdrUtilTest, UpdateHDRCastPropertiesTest, TestSize.Level1)
{
    auto rsContext = std::make_shared<RSContext>();
    auto screenNode = std::make_shared<RSScreenRenderNode>(0, 0, rsContext->weak_from_this());
    screenNode->stagingRenderParams_ = std::make_unique<RSScreenRenderParams>(screenNode->GetId());
    auto param = static_cast<RSScreenRenderParams*>(screenNode->stagingRenderParams_.get());
    ASSERT_NE(param, nullptr);
    screenNode->SetFixVirtualBuffer10Bit(false);
    RSHdrUtil::UpdateHDRCastProperties(*screenNode, true, true);
    screenNode->SetFixVirtualBuffer10Bit(true);
    RSHdrUtil::UpdateHDRCastProperties(*screenNode, true, true);
    EXPECT_EQ(param->GetHDRPresent(), true);
}

/**
 * @tc.name: GetScreenColorGamut
 * @tc.desc: Test GetScreenColorGamut
 * @tc.type: FUNC
 * @tc.require: issueI6QM6E
 */
HWTEST_F(RSHdrUtilTest, GetScreenColorGamutTest, TestSize.Level1)
{
    sptr<RSScreenManager> screenManager = CreateOrGetScreenManager();
    ASSERT_NE(screenManager, nullptr);
    auto virtualScreenId = screenManager->CreateVirtualScreen("virtual screen 001", 0, 0, nullptr);
    ASSERT_NE(INVALID_SCREEN_ID, virtualScreenId);
    auto rsContext = std::make_shared<RSContext>();
    auto screenNode = std::make_shared<RSScreenRenderNode>(0, 0, rsContext->weak_from_this());

    EXPECT_EQ(RSHdrUtil::GetScreenColorGamut(*screenNode, screenManager), COLOR_GAMUT_INVALID);
    screenNode->screenId_ = virtualScreenId; // pass GetScreenColorGamut
    // COLOR_GAMUT_BT2100_HLG index in supportedVirtualColorGamuts_ is 4
    screenManager->SetScreenColorGamut(virtualScreenId, 4);
    EXPECT_EQ(RSHdrUtil::GetScreenColorGamut(*screenNode, screenManager), COLOR_GAMUT_BT2100_HLG);
}

/**
 * @tc.name: NeedUseF16Capture
 * @tc.desc: Test NeedUseF16Capture
 * @tc.type: FUNC
 * @tc.require: issueI6QM6E
 */
HWTEST_F(RSHdrUtilTest, NeedUseF16CaptureTest, TestSize.Level1)
{
    NodeId nodeId = 1;
    std::shared_ptr<RSSurfaceRenderNode> surfaceNode = std::make_shared<RSSurfaceRenderNode>(nodeId);
    ASSERT_NE(surfaceNode, nullptr);
    NodeId id = 0;
    ScreenId screenId = 1;
    std::shared_ptr<RSContext> context = std::make_shared<RSContext>();
    auto screenNode = std::make_shared<RSScreenRenderNode>(id, screenId, context);
    ASSERT_NE(screenNode, nullptr);

    EXPECT_EQ(surfaceNode->GetAncestorScreenNode().lock(), nullptr);
    EXPECT_FALSE(RSHdrUtil::NeedUseF16Capture(nullptr));
    EXPECT_FALSE(RSHdrUtil::NeedUseF16Capture(surfaceNode));

    surfaceNode->SetAncestorScreenNode(screenNode);
    EXPECT_NE(surfaceNode->GetAncestorScreenNode().lock(), nullptr);
    EXPECT_FALSE(RSHdrUtil::NeedUseF16Capture(surfaceNode));
    screenNode->InitRenderParams();
    auto param = screenNode->GetStagingRenderParams().get();
    EXPECT_NE(param, nullptr);
    EXPECT_FALSE(RSHdrUtil::NeedUseF16Capture(surfaceNode));

    surfaceNode->nodeType_ = RSSurfaceNodeType::LEASH_WINDOW_NODE;
    EXPECT_FALSE(RSHdrUtil::NeedUseF16Capture(surfaceNode));
}

/**
 * @tc.name: HandleVirtualScreenHDRStatus
 * @tc.desc: Test HandleVirtualScreenHDRStatus
 * @tc.type: FUNC
 * @tc.require: issueI6QM6E
 */
HWTEST_F(RSHdrUtilTest, HandleVirtualScreenHDRStatusTest, TestSize.Level1)
{
    sptr<RSScreenManager> screenManager = CreateOrGetScreenManager();
    ASSERT_NE(screenManager, nullptr);
    auto virtualScreenId = screenManager->CreateVirtualScreen("virtual screen 001", 0, 0, nullptr);
    ASSERT_NE(INVALID_SCREEN_ID, virtualScreenId);
    auto rsContext = std::make_shared<RSContext>();
    auto screenNode = std::make_shared<RSScreenRenderNode>(0, 0, rsContext->weak_from_this());

    screenNode->SetCompositeType(CompositeType::UNI_RENDER_MIRROR_COMPOSITE);
    RSHdrUtil::HandleVirtualScreenHDRStatus(*screenNode, screenManager); // failed GetScreenColorGamut

    screenNode->screenId_ = virtualScreenId; // pass GetScreenColorGamut
    // COLOR_GAMUT_BT2100_HLG index in supportedVirtualColorGamuts_ is 4
    screenManager->SetScreenColorGamut(virtualScreenId, 4);
    RSHdrUtil::HandleVirtualScreenHDRStatus(*screenNode, screenManager); // mirror node is null

    screenNode->SetIsMirrorScreen(true);
    NodeId id = 1;
    auto mirrorSourceNode = std::make_shared<RSScreenRenderNode>(id, 0);
    screenNode->SetMirrorSource(mirrorSourceNode);
    mirrorSourceNode->CollectHdrStatus(HdrStatus::HDR_VIDEO);
    RSHdrUtil::HandleVirtualScreenHDRStatus(*screenNode, screenManager); // mirror node is not null

    ScreenColorGamut colorGamut;
    EXPECT_EQ(screenManager->GetScreenColorGamut(screenNode->GetScreenId(), colorGamut), StatusCode::SUCCESS);
    EXPECT_NE(screenNode->GetMirrorSource().lock(), nullptr);
    EXPECT_EQ(static_cast<GraphicColorGamut>(colorGamut), GRAPHIC_COLOR_GAMUT_BT2100_HLG);
}

/**
 * @tc.name: HandleVirtualScreenHDRStatus
 * @tc.desc: Test HandleVirtualScreenHDRStatus
 * @tc.type: FUNC
 * @tc.require: issueI6QM6E
 */
HWTEST_F(RSHdrUtilTest, HandleVirtualScreenHDRStatusTest002, TestSize.Level1)
{
    sptr<RSScreenManager> screenManager = CreateOrGetScreenManager();
    ASSERT_NE(screenManager, nullptr);
    auto virtualScreenId = screenManager->CreateVirtualScreen("virtual screen 001", 0, 0, nullptr);
    ASSERT_NE(INVALID_SCREEN_ID, virtualScreenId);
    auto screenNode = std::make_shared<RSScreenRenderNode>(0, 0);

    screenNode->SetCompositeType(CompositeType::UNI_RENDER_COMPOSITE);
    RSHdrUtil::HandleVirtualScreenHDRStatus(*screenNode, screenManager);
    screenNode->SetCompositeType(CompositeType::UNI_RENDER_EXPAND_COMPOSITE);
    ScreenColorGamut colorGamut;
    EXPECT_NE(screenManager->GetScreenColorGamut(screenNode->GetScreenId(), colorGamut), StatusCode::SUCCESS);
    RSHdrUtil::HandleVirtualScreenHDRStatus(*screenNode, screenManager); // failed GetScreenColorGamut

    screenNode->screenId_ = virtualScreenId; // pass GetScreenColorGamut
    // COLOR_GAMUT_BT2100_HLG index in supportedVirtualColorGamuts_ is 4
    screenManager->SetScreenColorGamut(virtualScreenId, 4);
    RSHdrUtil::HandleVirtualScreenHDRStatus(*screenNode, screenManager);
    EXPECT_EQ(screenManager->GetScreenColorGamut(screenNode->GetScreenId(), colorGamut), StatusCode::SUCCESS);
    EXPECT_EQ(static_cast<GraphicColorGamut>(colorGamut), GRAPHIC_COLOR_GAMUT_BT2100_HLG);
}

#ifdef USE_VIDEO_PROCESSING_ENGINE
/**
 * @tc.name: HDRCastProcess001
 * @tc.desc: Test HDRCastProcess
 * @tc.type: FUNC
 * @tc.require: issueIBCH1W
 */
HWTEST_F(RSHdrUtilTest, HDRCastProcess001, TestSize.Level2)
{
    auto image = std::make_shared<Drawing::Image>();
    Drawing::Brush brush;
    Drawing::SamplingOptions sampling;
    std::shared_ptr<RSPaintFilterCanvas> filterCanvas = nullptr;
    std::shared_ptr<Drawing::Surface> surface = nullptr;
    EXPECT_FALSE(RSHdrUtil::HDRCastProcess(image, brush, sampling, surface, nullptr)); // null canvas
    auto canvas = std::make_shared<Drawing::Canvas>(DEFAULT_CANVAS_SIZE, DEFAULT_CANVAS_SIZE);
    filterCanvas = std::make_shared<RSPaintFilterCanvas>(canvas.get());
    EXPECT_FALSE(RSHdrUtil::HDRCastProcess(image, brush, sampling, surface, filterCanvas.get())); // null surface
    surface = std::make_shared<Drawing::Surface>();
    EXPECT_FALSE(RSHdrUtil::HDRCastProcess(image, brush, sampling, surface, filterCanvas.get())); // null GPUContext
    filterCanvas->surface_ = nullptr;
    EXPECT_FALSE(RSHdrUtil::HDRCastProcess(image, brush, sampling, surface, filterCanvas.get())); // null canvasSurface
}

/**
 * @tc.name: HDRCastProcess002
 * @tc.desc: Test HDRCastProcess
 * @tc.type: FUNC
 * @tc.require: issueIBCH1W
 */
HWTEST_F(RSHdrUtilTest, HDRCastProcess002, TestSize.Level2)
{
    auto image = std::make_shared<Drawing::Image>();
    Drawing::Brush brush;
    Drawing::SamplingOptions sampling;
    auto canvas = std::make_shared<Drawing::Canvas>(DEFAULT_CANVAS_SIZE, DEFAULT_CANVAS_SIZE);
    canvas->gpuContext_ = std::make_shared<Drawing::GPUContext>();
    auto filterCanvas = std::make_shared<RSPaintFilterCanvas>(canvas.get());
    auto surface = std::make_shared<Drawing::Surface>();
    auto surface2 = std::make_shared<Drawing::Surface>();
    filterCanvas->surface_ = surface2.get();
    ASSERT_TRUE(canvas->GetGPUContext());
    ASSERT_TRUE(RSHdrUtil::HDRCastProcess(image, brush, sampling, surface, filterCanvas.get()));
}

/**
 * @tc.name: SetHDRCastShader001
 * @tc.desc: Test SetHDRCastShader
 * @tc.type: FUNC
 * @tc.require: issueIBCH1W
 */
HWTEST_F(RSHdrUtilTest, SetHDRCastShader001, TestSize.Level2)
{
    std::shared_ptr<Drawing::Image> image = nullptr;
    Drawing::Brush brush;
    Drawing::SamplingOptions sampling;
    EXPECT_FALSE(RSHdrUtil::SetHDRCastShader(image, brush, sampling));
    image = std::make_shared<Drawing::Image>();
    ASSERT_TRUE(RSHdrUtil::SetHDRCastShader(image, brush, sampling));
}

/**
 * @tc.name: SetMetadata001
 * @tc.desc: SetMetadata test.
 * @tc.type:FUNC
 * @tc.require:issuesIBKZFK
 */
HWTEST_F(RSHdrUtilTest, SetMetadata001, TestSize.Level2)
{
    std::unique_ptr<RSRenderFrame> renderFrame = nullptr;
    auto res = RSHdrUtil::SetMetadata(RSHDRUtilConst::HDR_CAST_OUT_COLORSPACE, renderFrame);
    EXPECT_EQ(GSERROR_INVALID_ARGUMENTS, res);

    renderFrame = std::make_unique<RSRenderFrame>(nullptr, nullptr);
    res = RSHdrUtil::SetMetadata(RSHDRUtilConst::HDR_CAST_OUT_COLORSPACE, renderFrame);
    EXPECT_EQ(GSERROR_INVALID_ARGUMENTS, res);

    sptr<OHOS::IConsumerSurface> cSurface = IConsumerSurface::Create();
    sptr<IBufferConsumerListener> listener = new BufferConsumerListener();
    cSurface->RegisterConsumerListener(listener);
    sptr<OHOS::IBufferProducer> producer2 = cSurface->GetProducer();
    sptr<OHOS::Surface> pSurface2 = Surface::CreateSurfaceAsProducer(producer2);
    int32_t fence;
    sptr<OHOS::SurfaceBuffer> sBuffer = nullptr;

    pSurface2->RequestBuffer(sBuffer, fence, requestConfig);
    NativeWindowBuffer* nativeWindowBuffer = OH_NativeWindow_CreateNativeWindowBufferFromSurfaceBuffer(&sBuffer);
    ASSERT_NE(nativeWindowBuffer, nullptr);
    res = RSHdrUtil::SetMetadata(RSHDRUtilConst::HDR_CAST_OUT_COLORSPACE, renderFrame);
    EXPECT_EQ(GSERROR_OK, res);
}

/**
 * @tc.name: SetMetadata002
 * @tc.desc: SetMetadata test.
 * @tc.type:FUNC
 * @tc.require:issuesIBKZFK
 */
HWTEST_F(RSHdrUtilTest, SetMetadata002, TestSize.Level2)
{
    auto res = RSHdrUtil::SetMetadata(nullptr, RSHDRUtilConst::HDR_CAPTURE_HDR_COLORSPACE,
        HDI::Display::Graphic::Common::V1_0::CM_HDR_Metadata_Type::CM_IMAGE_HDR_VIVID_SINGLE);
    EXPECT_EQ(GSERROR_INVALID_ARGUMENTS, res);

    sptr<OHOS::IConsumerSurface> cSurface = IConsumerSurface::Create();
    sptr<IBufferConsumerListener> listener = new BufferConsumerListener();
    cSurface->RegisterConsumerListener(listener);
    sptr<OHOS::IBufferProducer> producer = cSurface->GetProducer();
    sptr<OHOS::Surface> pSurface = Surface::CreateSurfaceAsProducer(producer);
    int32_t fence;
    sptr<OHOS::SurfaceBuffer> sBuffer = nullptr;

    pSurface->RequestBuffer(sBuffer, fence, requestConfig);

    res = RSHdrUtil::SetMetadata(sBuffer.GetRefPtr(), RSHDRUtilConst::HDR_CAPTURE_HDR_COLORSPACE,
        HDI::Display::Graphic::Common::V1_0::CM_HDR_Metadata_Type::CM_IMAGE_HDR_VIVID_SINGLE);
    EXPECT_EQ(GSERROR_OK, res);
}
#endif

/**
 * @tc.name: IsHDRCast
 * @tc.desc: IsHDRCast test.
 * @tc.type:FUNC
 * @tc.require:issuesIBKZFK
 */
HWTEST_F(RSHdrUtilTest, IsHDRCastTest, TestSize.Level2)
{
    std::shared_ptr<RSScreenRenderParams> params = nullptr;
    bool ret = RSHdrUtil::IsHDRCast(nullptr, requestConfig);
    EXPECT_EQ(ret, false);

    params = std::make_shared<RSScreenRenderParams>(0);
    params->SetFixVirtualBuffer10Bit(true);
    ret = RSHdrUtil::IsHDRCast(params.get(), requestConfig);
    EXPECT_EQ(ret, false);

    params->SetHDRPresent(true);
    ret = RSHdrUtil::IsHDRCast(params.get(), requestConfig);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: SetColorSpaceConverterDisplayParameter
 * @tc.desc: test SetColorSpaceConverterDisplayParameter with different screenshotType
 * @tc.type:FUNC
 * @tc.require: issueI9NLRF
 */
HWTEST_F(RSHdrUtilTest, SetColorSpaceConverterDisplayParameter, TestSize.Level1)
{
    GraphicColorGamut targetColorSpace = GRAPHIC_COLOR_GAMUT_DISPLAY_P3;
    ScreenId screenId = 0;
    uint32_t dynamicRangeMode = 1;

    sptr<OHOS::IConsumerSurface> cSurface = IConsumerSurface::Create();
    sptr<IBufferConsumerListener> listener = new BufferConsumerListener();
    cSurface->RegisterConsumerListener(listener);
    sptr<OHOS::IBufferProducer> producer = cSurface->GetProducer();
    sptr<OHOS::Surface> pSurface = Surface::CreateSurfaceAsProducer(producer);
    int32_t fence;
    sptr<OHOS::SurfaceBuffer> sBuffer = nullptr;
    pSurface->RequestBuffer(sBuffer, fence, requestConfig);
    auto res = RSHdrUtil::SetMetadata(sBuffer.GetRefPtr(),
        RSHDRUtilConst::HDR_CAPTURE_HDR_COLORSPACE,
        HDI::Display::Graphic::Common::V1_0::CM_HDR_Metadata_Type::CM_IMAGE_HDR_VIVID_SINGLE);
    EXPECT_EQ(GSERROR_OK, res);

    VPEParameter parameter;
    RSPaintFilterCanvas::HDRProperties hdrProperties = RSPaintFilterCanvas::HDRProperties{};
    hdrProperties.screenshotType = RSPaintFilterCanvas::ScreenshotType::HDR_SCREENSHOT;
    bool ret = RSColorSpaceConvert::Instance().SetColorSpaceConverterDisplayParameter(sBuffer, parameter,
        targetColorSpace, screenId, dynamicRangeMode, hdrProperties);
    EXPECT_EQ(parameter.tmoNits, RSLuminanceConst::DEFAULT_CAPTURE_HDR_NITS);
    EXPECT_EQ(ret, true);

    hdrProperties.screenshotType = RSPaintFilterCanvas::ScreenshotType::HDR_WINDOWSHOT;
    ret = RSColorSpaceConvert::Instance().SetColorSpaceConverterDisplayParameter(sBuffer, parameter,
        targetColorSpace, screenId, dynamicRangeMode, hdrProperties);
    EXPECT_EQ(parameter.tmoNits, parameter.currentDisplayNits);
    EXPECT_EQ(ret, true);

    hdrProperties.screenshotType = RSPaintFilterCanvas::ScreenshotType::SDR_SCREENSHOT;
    ret = RSColorSpaceConvert::Instance().SetColorSpaceConverterDisplayParameter(sBuffer, parameter,
        targetColorSpace, screenId, dynamicRangeMode, hdrProperties);
    EXPECT_EQ(parameter.tmoNits, RSLuminanceConst::DEFAULT_CAPTURE_HDR_NITS);
    EXPECT_EQ(ret, true);
}

} // namespace OHOS::Rosen