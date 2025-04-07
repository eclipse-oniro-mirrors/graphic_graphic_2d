/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

 #include "common/rs_common_hook.h"
 #include "gtest/gtest.h"
 #include "limit_number.h"
 #include "pipeline/rs_test_util.h"
 #include "system/rs_system_parameters.h"
  
 #include "consumer_surface.h"
 #include "draw/color.h"
 #include "monitor/self_drawing_node_monitor.h"
 #include "pipeline/hardware_thread/rs_realtime_refresh_rate_manager.h"
 #include "pipeline/hwc/rs_uni_hwc_visitor.h"
 #include "pipeline/render_thread/rs_uni_render_engine.h"
 #include "pipeline/render_thread/rs_uni_render_thread.h"
 #include "pipeline/render_thread/rs_uni_render_util.h"
 #include "pipeline/rs_base_render_node.h"
 #include "pipeline/rs_context.h"
 #include "pipeline/rs_display_render_node.h"
 #include "pipeline/rs_effect_render_node.h"
 #include "pipeline/main_thread/rs_main_thread.h"
 #include "pipeline/rs_processor_factory.h"
 #include "pipeline/rs_proxy_render_node.h"
 #include "pipeline/rs_render_node.h"
 #include "pipeline/rs_render_thread.h"
 #include "pipeline/rs_root_render_node.h"
 #include "pipeline/rs_surface_render_node.h"
 #include "pipeline/rs_uni_render_judgement.h"
 #include "feature/round_corner_display/rs_round_corner_display.h"
 #include "feature/round_corner_display/rs_round_corner_display_manager.h"
  
 using namespace testing;
 using namespace testing::ext;
  
 namespace OHOS::Rosen {
 class RSUniHwcVisitorTest : public testing::Test {
 public:
     static void SetUpTestCase();
     static void TearDownTestCase();
     void SetUp() override;
     void TearDown() override;
 };
  
 void RSUniHwcVisitorTest::SetUpTestCase()
 {
     RSTestUtil::InitRenderNodeGC();
 }
 void RSUniHwcVisitorTest::TearDownTestCase() {}
 void RSUniHwcVisitorTest::SetUp()
 {
     if (RSUniRenderJudgement::IsUniRender()) {
         auto& uniRenderThread = RSUniRenderThread::Instance();
         uniRenderThread.uniRenderEngine_ = std::make_shared<RSUniRenderEngine>();
     }
 }
 void RSUniHwcVisitorTest::TearDown() {}
 
 /**
  * @tc.name: UpdateSrcRect001
  * @tc.desc: Test UpdateSrcRect with empty matrix
  * @tc.type: FUNC
  * @tc.require: issuesIBT79X
  */
 HWTEST_F(RSUniHwcVisitorTest, UpdateSrcRect001, TestSize.Level2)
 {
     NodeId id = 1;
     RSSurfaceRenderNode node1(id);
     node1.GetRSSurfaceHandler()->buffer_.buffer = OHOS::SurfaceBuffer::Create();
     node1.GetRSSurfaceHandler()->buffer_.buffer->SetSurfaceBufferTransform(GraphicTransformType::GRAPHIC_ROTATE_NONE);
     node1.GetRSSurfaceHandler()->buffer_.buffer->SetSurfaceBufferWidth(1080);
     node1.GetRSSurfaceHandler()->buffer_.buffer->SetSurfaceBufferHeight(1653);
     node1.GetRSSurfaceHandler()->consumer_ = OHOS::IConsumerSurface::Create();
     node1.renderContent_->renderProperties_.SetBoundsWidth(2440);
     node1.renderContent_->renderProperties_.SetBoundsHeight(1080);
     node1.renderContent_->renderProperties_.frameGravity_ = Gravity::TOP_LEFT;
     node1.SetDstRect({0, 1000, 2440, 1080});
     node1.isFixRotationByUser_ = false;
     Drawing::Matrix totalMatrix = Drawing::Matrix();
     totalMatrix.SetMatrix(1, 0, 0, 0, 0, 0, 0, 0, 1);
     auto rsUniRenderVisitor = std::make_shared<RSUniRenderVisitor>();
     ASSERT_NE(rsUniRenderVisitor, nullptr);
     auto rsUniHwcVisitor = std::make_shared<RSUniHwcVisitor>(*rsUniRenderVisitor);
     ASSERT_NE(rsUniHwcVisitor, nullptr);
     ScreenInfo screenInfo;
     screenInfo.width = 1440;
     screenInfo.height = 1080;
     rsUniRenderVisitor->screenInfo_ = screenInfo;
     rsUniHwcVisitor->UpdateSrcRect(node1, totalMatrix);
     RectI expectedSrcRect = {0, 0, 1440, 1080};
     EXPECT_TRUE(node1.GetSrcRect() == expectedSrcRect);
 }
 
 /**
  * @tc.name: UpdateSrcRect002
  * @tc.desc: Test UpdateSrcRect after applying valid clipRects to the boundary of a surface node
  * @tc.type: FUNC
  * @tc.require: issuesIBT79X
  */
 HWTEST_F(RSUniHwcVisitorTest, UpdateSrcRect002, TestSize.Level2)
 {
     NodeId id = 1;
     RSSurfaceRenderNode node1(id);
     node1.GetRSSurfaceHandler()->buffer_.buffer = OHOS::SurfaceBuffer::Create();
     node1.GetRSSurfaceHandler()->buffer_.buffer->SetSurfaceBufferTransform(GraphicTransformType::GRAPHIC_ROTATE_NONE);
     node1.GetRSSurfaceHandler()->buffer_.buffer->SetSurfaceBufferWidth(1080);
     node1.GetRSSurfaceHandler()->buffer_.buffer->SetSurfaceBufferHeight(1653);
     node1.GetRSSurfaceHandler()->consumer_ = OHOS::IConsumerSurface::Create();
     node1.renderContent_->renderProperties_.SetBoundsWidth(2440);
     node1.renderContent_->renderProperties_.SetBoundsHeight(1080);
     node1.renderContent_->renderProperties_.frameGravity_ = Gravity::TOP_LEFT;
     node1.SetDstRect({0, 1000, 1440, 880});
     node1.isFixRotationByUser_ = false;
     Drawing::Matrix totalMatrix = Drawing::Matrix();
     totalMatrix.SetMatrix(1, 0, 0, 0, 1, 800, 0, 0, 1);
     auto rsUniRenderVisitor = std::make_shared<RSUniRenderVisitor>();
     ASSERT_NE(rsUniRenderVisitor, nullptr);
     auto rsUniHwcVisitor = std::make_shared<RSUniHwcVisitor>(*rsUniRenderVisitor);
     ASSERT_NE(rsUniHwcVisitor, nullptr);
     ScreenInfo screenInfo;
     screenInfo.width = 1440;
     screenInfo.height = 1080;
     rsUniRenderVisitor->screenInfo_ = screenInfo;
     rsUniHwcVisitor->UpdateSrcRect(node1, totalMatrix);
     RectI expectedSrcRect = {0, 306, 638, 1347};
     EXPECT_TRUE(node1.GetSrcRect() == expectedSrcRect);
 }
 
 /**
  * @tc.name: UpdateSrcRect003
  * @tc.desc: Test UpdateSrcRect when we use the full boundary of a surface node
  * @tc.type: FUNC
  * @tc.require: issuesIBT79X
  */
 HWTEST_F(RSUniHwcVisitorTest, UpdateSrcRect003, TestSize.Level2)
 {
     NodeId id = 1;
     RSSurfaceRenderNode node1(id);
     node1.GetRSSurfaceHandler()->buffer_.buffer = OHOS::SurfaceBuffer::Create();
     node1.GetRSSurfaceHandler()->buffer_.buffer->SetSurfaceBufferTransform(GraphicTransformType::GRAPHIC_ROTATE_NONE);
     node1.GetRSSurfaceHandler()->buffer_.buffer->SetSurfaceBufferWidth(1080);
     node1.GetRSSurfaceHandler()->buffer_.buffer->SetSurfaceBufferHeight(1653);
     node1.GetRSSurfaceHandler()->consumer_ = OHOS::IConsumerSurface::Create();
     node1.renderContent_->renderProperties_.SetBoundsWidth(2440);
     node1.renderContent_->renderProperties_.SetBoundsHeight(1080);
     node1.renderContent_->renderProperties_.frameGravity_ = Gravity::RESIZE;
     node1.SetDstRect({0, 1000, 2440, 1080});
     node1.isFixRotationByUser_ = false;
     Drawing::Matrix totalMatrix = Drawing::Matrix();
     totalMatrix.SetMatrix(1, 0, 0, 0, 1, 1000, 0, 0, 1);
     auto rsUniRenderVisitor = std::make_shared<RSUniRenderVisitor>();
     ASSERT_NE(rsUniRenderVisitor, nullptr);
     auto rsUniHwcVisitor = std::make_shared<RSUniHwcVisitor>(*rsUniRenderVisitor);
     ASSERT_NE(rsUniHwcVisitor, nullptr);
     rsUniHwcVisitor->UpdateSrcRect(node1, totalMatrix);
     RectI expectedSrcRect = {0, 0, 1080, 1653};
     EXPECT_TRUE(node1.GetSrcRect() == expectedSrcRect);
 }
 
 /**
  * @tc.name: UpdateDstRect001
  * @tc.desc: Test UpdateDstRect with empty rect
  * @tc.type: FUNC
  * @tc.require: issuesIBT79X
  */
 HWTEST_F(RSUniHwcVisitorTest, UpdateDstRect001, TestSize.Level2)
 {
     auto rsContext = std::make_shared<RSContext>();
     RSSurfaceRenderNodeConfig config;
     RSDisplayNodeConfig displayConfig;
     config.id = 10;
     auto rsSurfaceRenderNode = std::make_shared<RSSurfaceRenderNode>(config, rsContext->weak_from_this());
     ASSERT_NE(rsSurfaceRenderNode, nullptr);
     config.id = 11;
     auto rsSurfaceRenderNode2 = std::make_shared<RSSurfaceRenderNode>(config, rsContext->weak_from_this());
     ASSERT_NE(rsSurfaceRenderNode2, nullptr);
     rsSurfaceRenderNode->InitRenderParams();
     rsSurfaceRenderNode2->InitRenderParams();
     rsSurfaceRenderNode2->SetNodeName("testNode");
     rsSurfaceRenderNode2->SetLayerTop(true);
     // 11 non-zero node id
     auto rsDisplayRenderNode = std::make_shared<RSDisplayRenderNode>(12, displayConfig, rsContext->weak_from_this());
     rsDisplayRenderNode->InitRenderParams();
     ASSERT_NE(rsDisplayRenderNode, nullptr);
     auto rsUniRenderVisitor = std::make_shared<RSUniRenderVisitor>();
     auto rsUniHwcVisitor = std::make_shared<RSUniHwcVisitor>(*rsUniRenderVisitor);
     rsUniRenderVisitor->InitDisplayInfo(*rsDisplayRenderNode);
 
     RectI absRect(0, 0, 0, 0);
     RectI clipRect(0, 0, 0, 0);
     rsUniRenderVisitor->curSurfaceNode_ = rsSurfaceRenderNode2;
     ASSERT_NE(rsUniRenderVisitor, nullptr);
     rsUniHwcVisitor->UpdateDstRect(*rsSurfaceRenderNode, absRect, clipRect);
     ASSERT_NE(rsUniHwcVisitor, nullptr);
     ASSERT_EQ(rsSurfaceRenderNode->GetDstRect().left_, 0);
     rsUniHwcVisitor->UpdateDstRect(*rsSurfaceRenderNode2, absRect, clipRect);
     ASSERT_EQ(rsSurfaceRenderNode2->GetDstRect().left_, 0);
 }
 
 /**
  * @tc.name: UpdateHwcNodeByTransform_001
  * @tc.desc: UpdateHwcNodeByTransform Test, buffer of RSSurfaceHandler is not nullptr, and
  * consumer_ of of RSSurfaceHandler is nullptr, expect return directly
  * @tc.type:FUNC
  * @tc.require: issuesIBT79X
  */
 HWTEST_F(RSUniHwcVisitorTest, UpdateHwcNodeByTransform_001, TestSize.Level2)
 {
     auto rsUniRenderVisitor = std::make_shared<RSUniRenderVisitor>();
     ASSERT_NE(rsUniRenderVisitor, nullptr);
     auto rsUniHwcVisitor = std::make_shared<RSUniHwcVisitor>(*rsUniRenderVisitor);
     ASSERT_NE(rsUniHwcVisitor, nullptr);
 
     auto node = RSTestUtil::CreateSurfaceNodeWithBuffer();
     ASSERT_NE(node, nullptr);
     ASSERT_FALSE(!node->GetRSSurfaceHandler() || !node->GetRSSurfaceHandler()->GetBuffer());
 
     node->surfaceHandler_->consumer_ = nullptr;
     ASSERT_EQ(node->GetRSSurfaceHandler()->GetConsumer(), nullptr);
 
     Drawing::Matrix matrix = Drawing::Matrix();
     matrix.SetMatrix(1, 2, 3, 4, 5, 6, 7, 8, 9);
     rsUniHwcVisitor->UpdateHwcNodeByTransform(*node, matrix);
 }
 
 /**
  * @tc.name: UpdateHwcNodeByTransform_002
  * @tc.desc: UpdateHwcNodeByTransform Test, buffer of RSSurfaceHandler is not nullptr, and
  * consumer_ of of RSSurfaceHandler is not nullptr, and GetScalingMode is GSERROR_OK
  * scalingMode == ScalingMode::SCALING_MODE_SCALE_TO_WINDOW, expect neither LayerScaleDown nor LayerScaleFit
  * @tc.type:FUNC
  * @tc.require: issuesIBT79X
  */
 HWTEST_F(RSUniHwcVisitorTest, UpdateHwcNodeByTransform_002, TestSize.Level2)
 {
     auto rsUniRenderVisitor = std::make_shared<RSUniRenderVisitor>();
     ASSERT_NE(rsUniRenderVisitor, nullptr);
     auto rsUniHwcVisitor = std::make_shared<RSUniHwcVisitor>(*rsUniRenderVisitor);
     ASSERT_NE(rsUniHwcVisitor, nullptr);
 
     auto node = RSTestUtil::CreateSurfaceNodeWithBuffer();
     ASSERT_NE(node, nullptr);
     ASSERT_FALSE(!node->GetRSSurfaceHandler() || !node->GetRSSurfaceHandler()->GetBuffer());
 
     const auto& surface = node->GetRSSurfaceHandler()->GetConsumer();
     ASSERT_NE(node->GetRSSurfaceHandler()->GetConsumer(), nullptr);
 
     const auto& buffer = node->GetRSSurfaceHandler()->GetBuffer();
     Drawing::Matrix matrix = Drawing::Matrix();
     matrix.SetMatrix(1, 2, 3, 4, 5, 6, 7, 8, 9);
     rsUniHwcVisitor->UpdateHwcNodeByTransform(*node, matrix);
     ASSERT_EQ(node->GetRSSurfaceHandler()->GetBuffer()->GetSurfaceBufferScalingMode(), SCALING_MODE_SCALE_TO_WINDOW);
 }
 
 /**
  * @tc.name: UpdateHwcNodeByTransform_003
  * @tc.desc: UpdateHwcNodeByTransform Test, buffer of RSSurfaceHandler is not nullptr, and
  * consumer_ of of RSSurfaceHandler is not nullptr, and GetScalingMode is GSERROR_INVALID_ARGUMENTS
  * scalingMode == ScalingMode::SCALING_MODE_SCALE_CROP, expect LayerScaleDown
  * @tc.type:FUNC
  * @tc.require: issuesIBT79X
  */
 HWTEST_F(RSUniHwcVisitorTest, UpdateHwcNodeByTransform_003, TestSize.Level2)
 {
     auto rsUniRenderVisitor = std::make_shared<RSUniRenderVisitor>();
     ASSERT_NE(rsUniRenderVisitor, nullptr);
     auto rsUniHwcVisitor = std::make_shared<RSUniHwcVisitor>(*rsUniRenderVisitor);
     ASSERT_NE(rsUniHwcVisitor, nullptr);
 
     auto node = RSTestUtil::CreateSurfaceNodeWithBuffer();
     ASSERT_NE(node, nullptr);
     ASSERT_FALSE(!node->GetRSSurfaceHandler() || !node->GetRSSurfaceHandler()->GetBuffer());
     ASSERT_NE(node->GetRSSurfaceHandler()->GetConsumer(), nullptr);
 
     auto nodeParams = static_cast<RSSurfaceRenderParams*>(node->GetStagingRenderParams().get());
     ASSERT_NE(nodeParams, nullptr);
 
     ScalingMode scalingMode = ScalingMode::SCALING_MODE_SCALE_CROP;
     auto& buffer = node->surfaceHandler_->buffer_.buffer;
     auto surface = static_cast<ConsumerSurface*>(node->surfaceHandler_->consumer_.refs_);
     ASSERT_NE(surface, nullptr);
 
     surface->consumer_ = nullptr;
     ASSERT_EQ(surface->GetScalingMode(buffer->GetSeqNum(), scalingMode), GSERROR_INVALID_ARGUMENTS);
 
     Drawing::Matrix matrix = Drawing::Matrix();
     matrix.SetMatrix(1, 2, 3, 4, 5, 6, 7, 8, 9);
     rsUniHwcVisitor->UpdateHwcNodeByTransform(*node, matrix);
 }
 
 /**
  * @tc.name: UpdateHwcNodeByTransform_004
  * @tc.desc: UpdateHwcNodeByTransform Test, buffer of RSSurfaceHandler is not nullptr, and
  * consumer_ of of RSSurfaceHandler is not nullptr, and GetScalingMode is GSERROR_INVALID_ARGUMENTS
  * scalingMode == ScalingMode::SCALING_MODE_SCALE_FIT, expect LayerScaleFit
  * @tc.type:FUNC
  * @tc.require: issuesIBT79X
  */
 HWTEST_F(RSUniHwcVisitorTest, UpdateHwcNodeByTransform_004, TestSize.Level2)
 {
     auto rsUniRenderVisitor = std::make_shared<RSUniRenderVisitor>();
     ASSERT_NE(rsUniRenderVisitor, nullptr);
     auto rsUniHwcVisitor = std::make_shared<RSUniHwcVisitor>(*rsUniRenderVisitor);
     ASSERT_NE(rsUniHwcVisitor, nullptr);
 
     auto node = RSTestUtil::CreateSurfaceNodeWithBuffer();
     ASSERT_NE(node, nullptr);
     ASSERT_FALSE(!node->GetRSSurfaceHandler() || !node->GetRSSurfaceHandler()->GetBuffer());
     ASSERT_NE(node->GetRSSurfaceHandler()->GetConsumer(), nullptr);
 
     auto nodeParams = static_cast<RSSurfaceRenderParams*>(node->GetStagingRenderParams().get());
     ASSERT_NE(nodeParams, nullptr);
 
     ScalingMode scalingMode = ScalingMode::SCALING_MODE_SCALE_FIT;
     auto& buffer = node->surfaceHandler_->buffer_.buffer;
     auto surface = static_cast<ConsumerSurface*>(node->surfaceHandler_->consumer_.refs_);
     ASSERT_NE(surface, nullptr);
 
     surface->consumer_ = nullptr;
     ASSERT_EQ(surface->GetScalingMode(buffer->GetSeqNum(), scalingMode), GSERROR_INVALID_ARGUMENTS);
 
     Drawing::Matrix matrix = Drawing::Matrix();
     matrix.SetMatrix(1, 2, 3, 4, 5, 6, 7, 8, 9);
     rsUniHwcVisitor->UpdateHwcNodeByTransform(*node, matrix);
 }
 
 /**
  * @tc.name: UpdateHwcNodeEnableByBufferSize
  * @tc.desc: Test UpdateHwcNodeEnableByBufferSize with rosen-web node / non-rosen-web node.
  * @tc.type: FUNC
  * @tc.require: IAHFXD
  */
 HWTEST_F(RSUniHwcVisitorTest, UpdateHwcNodeEnableByBufferSize, TestSize.Level1)
 {
     // create input args.
     auto node1 = RSTestUtil::CreateSurfaceNodeWithBuffer();
     auto node2 = RSTestUtil::CreateSurfaceNodeWithBuffer();
     node1->name_ = "RosenWeb_test";
 
     auto rsUniRenderVisitor = std::make_shared<RSUniRenderVisitor>();
     ASSERT_NE(rsUniRenderVisitor, nullptr);
     auto rsUniHwcVisitor = std::make_shared<RSUniHwcVisitor>(*rsUniRenderVisitor);
     ASSERT_NE(rsUniHwcVisitor, nullptr);
 
     rsUniHwcVisitor->UpdateHwcNodeEnableByBufferSize(*node1);
     rsUniHwcVisitor->UpdateHwcNodeEnableByBufferSize(*node2);
 }
 
 /*
  * @tc.name: UpdateHwcNodeEnableBySrcRect_001
  * @tc.desc: Test UpdateHwcNodeEnableBySrcRect when node is hardware forced disabled.
  * @tc.type: FUNC
  * @tc.require: issueIAJY2P
  */
 HWTEST_F(RSUniHwcVisitorTest, UpdateHwcNodeEnableBySrcRect_001, TestSize.Level2)
 {
     auto rsUniRenderVisitor = std::make_shared<RSUniRenderVisitor>();
     ASSERT_NE(rsUniRenderVisitor, nullptr);
     auto rsUniHwcVisitor = std::make_shared<RSUniHwcVisitor>(*rsUniRenderVisitor);
     ASSERT_NE(rsUniHwcVisitor, nullptr);
 
     auto surfaceNode = RSTestUtil::CreateSurfaceNodeWithBuffer();
     ASSERT_NE(surfaceNode, nullptr);
 
     ASSERT_TRUE(surfaceNode->IsHardwareForcedDisabled());
     rsUniHwcVisitor->UpdateHwcNodeEnableBySrcRect(*surfaceNode);
 }
 
 /*
  * @tc.name: UpdateHwcNodeEnableBySrcRect_002
  * @tc.desc: Test UpdateHwcNodeEnableBySrcRect when consumer is not nullptr.
  * @tc.type: FUNC
  * @tc.require: issueIAJY2P
  */
 HWTEST_F(RSUniHwcVisitorTest, UpdateHwcNodeEnableBySrcRect_002, TestSize.Level2)
 {
     auto rsUniRenderVisitor = std::make_shared<RSUniRenderVisitor>();
     ASSERT_NE(rsUniRenderVisitor, nullptr);
     auto rsUniHwcVisitor = std::make_shared<RSUniHwcVisitor>(*rsUniRenderVisitor);
     ASSERT_NE(rsUniHwcVisitor, nullptr);
 
     auto surfaceNode = RSTestUtil::CreateSurfaceNodeWithBuffer();
     ASSERT_NE(surfaceNode, nullptr);
 
     surfaceNode->GetMultableSpecialLayerMgr().Set(SpecialLayerType::PROTECTED, true);
     surfaceNode->isOnTheTree_ = true;
     ASSERT_FALSE(surfaceNode->IsHardwareForcedDisabled());
     ASSERT_NE(surfaceNode->GetRSSurfaceHandler()->GetConsumer(), nullptr);
 
     rsUniHwcVisitor->UpdateHwcNodeEnableBySrcRect(*surfaceNode);
 }
 
 /*
  * @tc.name: UpdateHwcNodeEnableBySrcRect_003
  * @tc.desc: Test UpdateHwcNodeEnableBySrcRect when node is hardware disabled by src rect.
  * @tc.type: FUNC
  * @tc.require: issueIAJY2P
  */
 HWTEST_F(RSUniHwcVisitorTest, UpdateHwcNodeEnableBySrcRect_003, TestSize.Level2)
 {
     auto rsUniRenderVisitor = std::make_shared<RSUniRenderVisitor>();
     ASSERT_NE(rsUniRenderVisitor, nullptr);
     auto rsUniHwcVisitor = std::make_shared<RSUniHwcVisitor>(*rsUniRenderVisitor);
     ASSERT_NE(rsUniHwcVisitor, nullptr);
 
     auto surfaceNode = RSTestUtil::CreateSurfaceNodeWithBuffer();
     ASSERT_NE(surfaceNode, nullptr);
 
     surfaceNode->GetMultableSpecialLayerMgr().Set(SpecialLayerType::PROTECTED, true);
     surfaceNode->isOnTheTree_ = true;
     ASSERT_FALSE(surfaceNode->IsHardwareForcedDisabled());
     surfaceNode->isHardwareForcedDisabledBySrcRect_ = true;
     ASSERT_TRUE(surfaceNode->IsHardwareDisabledBySrcRect());
 
     rsUniHwcVisitor->UpdateHwcNodeEnableBySrcRect(*surfaceNode);
 }
 
 /*
  * @tc.name: UpdateHwcNodeEnable_001
  * @tc.desc: Test UpdateHwcNodeEnable when surfaceNode is nullptr.
  * @tc.type: FUNC
  * @tc.require: issueIAJY2P
  */
 HWTEST_F(RSUniHwcVisitorTest, UpdateHwcNodeEnable_001, TestSize.Level2)
 {
     auto rsUniRenderVisitor = std::make_shared<RSUniRenderVisitor>();
     ASSERT_NE(rsUniRenderVisitor, nullptr);
     auto rsUniHwcVisitor = std::make_shared<RSUniHwcVisitor>(*rsUniRenderVisitor);
     ASSERT_NE(rsUniHwcVisitor, nullptr);
 
     auto surfaceNode = RSTestUtil::CreateSurfaceNodeWithBuffer();
     ASSERT_NE(surfaceNode, nullptr);
 
     NodeId displayNodeId = 1;
     RSDisplayNodeConfig config;
     auto displayNode = std::make_shared<RSDisplayRenderNode>(displayNodeId, config);
     displayNode->curMainAndLeashSurfaceNodes_.push_back(nullptr);
     rsUniRenderVisitor->curDisplayNode_ = displayNode;
 
     rsUniHwcVisitor->UpdateHwcNodeEnable();
 }
 
 /*
  * @tc.name: UpdateHwcNodeEnable_002
  * @tc.desc: Test UpdateHwcNodeEnable when hwcNodes is empty.
  * @tc.type: FUNC
  * @tc.require: issueIAJY2P
  */
 HWTEST_F(RSUniHwcVisitorTest, UpdateHwcNodeEnable_002, TestSize.Level2)
 {
     auto rsUniRenderVisitor = std::make_shared<RSUniRenderVisitor>();
     ASSERT_NE(rsUniRenderVisitor, nullptr);
     auto rsUniHwcVisitor = std::make_shared<RSUniHwcVisitor>(*rsUniRenderVisitor);
     ASSERT_NE(rsUniHwcVisitor, nullptr);
 
     auto surfaceNode = RSTestUtil::CreateSurfaceNodeWithBuffer();
     ASSERT_NE(surfaceNode, nullptr);
 
     surfaceNode->ResetChildHardwareEnabledNodes();
     ASSERT_EQ(surfaceNode->GetChildHardwareEnabledNodes().size(), 0);
     NodeId displayNodeId = 1;
     RSDisplayNodeConfig config;
     auto displayNode = std::make_shared<RSDisplayRenderNode>(displayNodeId, config);
     displayNode->curMainAndLeashSurfaceNodes_.push_back(surfaceNode);
     rsUniRenderVisitor->curDisplayNode_ = displayNode;
 
     rsUniHwcVisitor->UpdateHwcNodeEnable();
 }
 
 /*
  * @tc.name: UpdateHwcNodeEnable_003
  * @tc.desc: Test UpdateHwcNodeEnable when hwcNodePtr is not on the tree.
  * @tc.type: FUNC
  * @tc.require: issueIAJY2P
  */
 HWTEST_F(RSUniHwcVisitorTest, UpdateHwcNodeEnable_003, TestSize.Level2)
 {
     auto rsUniRenderVisitor = std::make_shared<RSUniRenderVisitor>();
     ASSERT_NE(rsUniRenderVisitor, nullptr);
     auto rsUniHwcVisitor = std::make_shared<RSUniHwcVisitor>(*rsUniRenderVisitor);
     ASSERT_NE(rsUniHwcVisitor, nullptr);
 
     auto surfaceNode = RSTestUtil::CreateSurfaceNodeWithBuffer();
     ASSERT_NE(surfaceNode, nullptr);
 
     NodeId displayNodeId = 1;
     RSDisplayNodeConfig config;
     auto displayNode = std::make_shared<RSDisplayRenderNode>(displayNodeId, config);
     NodeId childId = 2;
     auto childNode = std::make_shared<RSSurfaceRenderNode>(childId);
     childNode->SetIsOnTheTree(false);
     ASSERT_FALSE(childNode->IsOnTheTree());
     surfaceNode->AddChildHardwareEnabledNode(childNode);
     displayNode->curMainAndLeashSurfaceNodes_.push_back(surfaceNode);
     rsUniRenderVisitor->curDisplayNode_ = displayNode;
 
     rsUniHwcVisitor->UpdateHwcNodeEnable();
 }
 
 /*
  * @tc.name: UpdateHwcNodeEnableByHwcNodeBelowSelf_001
  * @tc.desc: Test UpdateHwcNodeEnableByHwcNodeBelowSelf when hwcNode is hardware forced disabled.
  * @tc.type: FUNC
  * @tc.require: issueIAJY2P
  */
 HWTEST_F(RSUniHwcVisitorTest, UpdateHwcNodeEnableByHwcNodeBelowSelf_001, TestSize.Level2)
 {
     auto rsUniRenderVisitor = std::make_shared<RSUniRenderVisitor>();
     ASSERT_NE(rsUniRenderVisitor, nullptr);
     auto rsUniHwcVisitor = std::make_shared<RSUniHwcVisitor>(*rsUniRenderVisitor);
     ASSERT_NE(rsUniHwcVisitor, nullptr);
 
     auto surfaceNode = RSTestUtil::CreateSurfaceNodeWithBuffer();
     ASSERT_NE(surfaceNode, nullptr);
     ASSERT_TRUE(surfaceNode->IsHardwareForcedDisabled());
 
     std::vector<RectI> hwcRects;
     NodeId displayNodeId = 1;
     RSDisplayNodeConfig config;
     rsUniRenderVisitor->curDisplayNode_ = std::make_shared<RSDisplayRenderNode>(displayNodeId, config);
     rsUniHwcVisitor->UpdateHwcNodeEnableByHwcNodeBelowSelf(hwcRects, surfaceNode, true);
     EXPECT_EQ(hwcRects.size(), 0);
 }
 
 /*
  * @tc.name: UpdateHwcNodeEnableByHwcNodeBelowSelf_002
  * @tc.desc: Test UpdateHwcNodeEnableByHwcNodeBelowSelf when hwcNode has corner radius and anco force do direct.
  * @tc.type: FUNC
  * @tc.require: issueIAJY2P
  */
 HWTEST_F(RSUniHwcVisitorTest, UpdateHwcNodeEnableByHwcNodeBelowSelf_002, TestSize.Level2)
 {
     auto rsUniRenderVisitor = std::make_shared<RSUniRenderVisitor>();
     ASSERT_NE(rsUniRenderVisitor, nullptr);
     auto rsUniHwcVisitor = std::make_shared<RSUniHwcVisitor>(*rsUniRenderVisitor);
     ASSERT_NE(rsUniHwcVisitor, nullptr);
 
     auto surfaceNode = RSTestUtil::CreateSurfaceNodeWithBuffer();
     ASSERT_NE(surfaceNode, nullptr);
 
     surfaceNode->GetMultableSpecialLayerMgr().Set(SpecialLayerType::PROTECTED, true);
     surfaceNode->isOnTheTree_ = true;
     ASSERT_FALSE(surfaceNode->IsHardwareForcedDisabled());
     surfaceNode->SetAncoForceDoDirect(true);
     surfaceNode->SetAncoFlags(static_cast<uint32_t>(0x0001));
     ASSERT_TRUE(surfaceNode->GetAncoForceDoDirect());
 
     std::vector<RectI> hwcRects;
     NodeId displayNodeId = 1;
     RSDisplayNodeConfig config;
     rsUniRenderVisitor->curDisplayNode_ = std::make_shared<RSDisplayRenderNode>(displayNodeId, config);
     rsUniHwcVisitor->UpdateHwcNodeEnableByHwcNodeBelowSelf(hwcRects, surfaceNode, false);
     EXPECT_EQ(hwcRects.size(), 1);
 }
 
 /*
  * @tc.name: UpdateHwcNodeEnableByHwcNodeBelowSelf_003
  * @tc.desc: Test UpdateHwcNodeEnableByHwcNodeBelowSelf when hwcNode intersects with hwcRects.
  * @tc.type: FUNC
  * @tc.require: issueIAJY2P
  */
 HWTEST_F(RSUniHwcVisitorTest, UpdateHwcNodeEnableByHwcNodeBelowSelf_003, TestSize.Level2)
 {
     auto rsUniRenderVisitor = std::make_shared<RSUniRenderVisitor>();
     ASSERT_NE(rsUniRenderVisitor, nullptr);
     auto rsUniHwcVisitor = std::make_shared<RSUniHwcVisitor>(*rsUniRenderVisitor);
     ASSERT_NE(rsUniHwcVisitor, nullptr);
 
     auto surfaceNode = RSTestUtil::CreateSurfaceNodeWithBuffer();
     ASSERT_NE(surfaceNode, nullptr);
 
     surfaceNode->GetMultableSpecialLayerMgr().Set(SpecialLayerType::PROTECTED, true);
     surfaceNode->isOnTheTree_ = true;
     ASSERT_FALSE(surfaceNode->IsHardwareForcedDisabled());
     surfaceNode->SetAncoForceDoDirect(false);
     ASSERT_FALSE(surfaceNode->GetAncoForceDoDirect());
 
     surfaceNode->SetDstRect(RectI(0, 0, 100, 100));
     std::vector<RectI> hwcRects;
     hwcRects.emplace_back(RectI(50, 50, 100, 100));
     ASSERT_TRUE(surfaceNode->GetDstRect().Intersect(RectI(50, 50, 100, 100)));
 
     NodeId displayNodeId = 1;
     RSDisplayNodeConfig config;
     rsUniRenderVisitor->curDisplayNode_ = std::make_shared<RSDisplayRenderNode>(displayNodeId, config);
     rsUniHwcVisitor->UpdateHwcNodeEnableByHwcNodeBelowSelf(hwcRects, surfaceNode, true);
     EXPECT_EQ(hwcRects.size(), 2);
 }
 
 /*
  * @tc.name: UpdateHwcNodeEnableByHwcNodeBelowSelf_004
  * @tc.desc: Test UpdateHwcNodeEnableByHwcNodeBelowSelf when hwcNode does not intersect with hwcRects.
  * @tc.type: FUNC
  * @tc.require: issueIAJY2P
  */
 HWTEST_F(RSUniHwcVisitorTest, UpdateHwcNodeEnableByHwcNodeBelowSelf_004, TestSize.Level2)
 {
     auto rsUniRenderVisitor = std::make_shared<RSUniRenderVisitor>();
     ASSERT_NE(rsUniRenderVisitor, nullptr);
     auto rsUniHwcVisitor = std::make_shared<RSUniHwcVisitor>(*rsUniRenderVisitor);
     ASSERT_NE(rsUniHwcVisitor, nullptr);
     
     auto surfaceNode = RSTestUtil::CreateSurfaceNodeWithBuffer();
     ASSERT_NE(surfaceNode, nullptr);
 
     surfaceNode->GetMultableSpecialLayerMgr().Set(SpecialLayerType::PROTECTED, true);
     surfaceNode->isOnTheTree_ = true;
     ASSERT_FALSE(surfaceNode->IsHardwareForcedDisabled());
     surfaceNode->SetAncoForceDoDirect(false);
     ASSERT_FALSE(surfaceNode->GetAncoForceDoDirect());
 
     surfaceNode->SetDstRect(RectI());
     std::vector<RectI> hwcRects;
     hwcRects.emplace_back(RectI(50, 50, 100, 100));
     ASSERT_FALSE(surfaceNode->GetDstRect().Intersect(RectI(50, 50, 100, 100)));
 
     NodeId displayNodeId = 1;
     RSDisplayNodeConfig config;
     rsUniRenderVisitor->curDisplayNode_ = std::make_shared<RSDisplayRenderNode>(displayNodeId, config);
     rsUniHwcVisitor->UpdateHwcNodeEnableByHwcNodeBelowSelf(hwcRects, surfaceNode, true);
     EXPECT_EQ(hwcRects.size(), 2);
 }
 
 /*
  * @tc.name: UpdateHwcNodeEnableByNodeBelow
  * @tc.desc: Test RSUniRenderVistorTest.UpdateHwcNodeEnableByNodeBelow
  * @tc.type: FUNC
  * @tc.require: issuesI8MQCS
  */
 HWTEST_F(RSUniHwcVisitorTest, UpdateHwcNodeEnableByNodeBelow, TestSize.Level2)
 {
     auto rsUniRenderVisitor = std::make_shared<RSUniRenderVisitor>();
     ASSERT_NE(rsUniRenderVisitor, nullptr);
     auto rsUniHwcVisitor = std::make_shared<RSUniHwcVisitor>(*rsUniRenderVisitor);
     ASSERT_NE(rsUniHwcVisitor, nullptr);
 
     auto surfaceNode = RSTestUtil::CreateSurfaceNodeWithBuffer();
     ASSERT_NE(surfaceNode, nullptr);
 
     NodeId displayNodeId = 1;
     RSDisplayNodeConfig config;
     auto displayNode = std::make_shared<RSDisplayRenderNode>(displayNodeId, config);
 
     RSSurfaceRenderNodeConfig surfaceConfig;
     surfaceConfig.id = 1;
     auto hwcNode1 = std::make_shared<RSSurfaceRenderNode>(surfaceConfig);
     ASSERT_NE(hwcNode1, nullptr);
     surfaceConfig.id = 2;
     auto hwcNode2 = std::make_shared<RSSurfaceRenderNode>(surfaceConfig);
     ASSERT_NE(hwcNode2, nullptr);
     hwcNode1->SetIsOnTheTree(true);
     hwcNode2->SetIsOnTheTree(false);
     surfaceNode->AddChildHardwareEnabledNode(hwcNode1);
     surfaceNode->AddChildHardwareEnabledNode(hwcNode2);
 
     displayNode->curMainAndLeashSurfaceNodes_.push_back(surfaceNode);
     rsUniRenderVisitor->curDisplayNode_ = displayNode;
     rsUniHwcVisitor->UpdateHwcNodeEnableByNodeBelow();
 }
 
 /**
  * @tc.name: UpdateHwcNodeEnableByRotateAndAlpha001
  * @tc.desc: Test UpdateHwcNodeEnableByRotateAndAlpha for empty node
  * @tc.type: FUNC
  * @tc.require: issueI9RR2Y
  */
 HWTEST_F(RSUniHwcVisitorTest, UpdateHwcNodeEnableByRotateAndAlpha001, TestSize.Level2)
 {
     auto node = RSTestUtil::CreateSurfaceNode();
 
     auto rsUniRenderVisitor = std::make_shared<RSUniRenderVisitor>();
     ASSERT_NE(rsUniRenderVisitor, nullptr);
     auto rsUniHwcVisitor = std::make_shared<RSUniHwcVisitor>(*rsUniRenderVisitor);
     ASSERT_NE(rsUniHwcVisitor, nullptr);
 
     rsUniHwcVisitor->UpdateHwcNodeEnableByRotateAndAlpha(node);
     ASSERT_FALSE(node->isHardwareForcedDisabled_);
 }
 
 /**
  * @tc.name: UpdateHwcNodeEnableBySrcRect001
  * @tc.desc: Test UpdateHwcNodeEnableBySrcRect with empty node
  * @tc.type: FUNC
  * @tc.require: issueI9RR2Y
  */
 HWTEST_F(RSUniHwcVisitorTest, UpdateHwcNodeEnableBySrcRect001, TestSize.Level2)
 {
     auto node = RSTestUtil::CreateSurfaceNode();
 
     auto rsUniRenderVisitor = std::make_shared<RSUniRenderVisitor>();
     ASSERT_NE(rsUniRenderVisitor, nullptr);
     auto rsUniHwcVisitor = std::make_shared<RSUniHwcVisitor>(*rsUniRenderVisitor);
     ASSERT_NE(rsUniHwcVisitor, nullptr);
 
     rsUniHwcVisitor->UpdateHwcNodeEnableBySrcRect(*node);
     ASSERT_FALSE(node->isHardwareForcedDisabledBySrcRect_);
 }
 
 /**
  * @tc.name: UpdateHardwareStateByHwcNodeBackgroundAlpha001
  * @tc.desc: Test RSUniHwcVisitorTest.UpdateHardwareStateByHwcNodeBackgroundAlpha
  * @tc.type: FUNC
  * @tc.require: IAHFXD
  */
 HWTEST_F(RSUniHwcVisitorTest, UpdateHardwareStateByHwcNodeBackgroundAlpha001, TestSize.Level1)
 {
     RSSurfaceRenderNodeConfig surfaceConfig;
     surfaceConfig.id = 1;
     auto surfaceNode = std::make_shared<RSSurfaceRenderNode>(surfaceConfig);
     ASSERT_NE(surfaceNode, nullptr);
 
     std::vector<std::weak_ptr<RSSurfaceRenderNode>> hwcNodes;
     hwcNodes.push_back(std::weak_ptr<RSSurfaceRenderNode>(surfaceNode));
     auto rsUniRenderVisitor = std::make_shared<RSUniRenderVisitor>();
     ASSERT_NE(rsUniRenderVisitor, nullptr);
     auto rsUniHwcVisitor = std::make_shared<RSUniHwcVisitor>(*rsUniRenderVisitor);
     ASSERT_NE(rsUniHwcVisitor, nullptr);
 
     RectI rect;
     bool isHardwareEnableByBackgroundAlpha = false;
     rsUniHwcVisitor->UpdateHardwareStateByHwcNodeBackgroundAlpha(hwcNodes, rect, isHardwareEnableByBackgroundAlpha);
 }
 
 /**
  * @tc.name: UpdateHardwareStateByHwcNodeBackgroundAlpha002
  * @tc.desc: Test RSUniHwcVisitorTest.UpdateHardwareStateByHwcNodeBackgroundAlpha
  * @tc.type: FUNC
  * @tc.require: IAHFXD
  */
 HWTEST_F(RSUniHwcVisitorTest, UpdateHardwareStateByHwcNodeBackgroundAlpha002, TestSize.Level1)
 {
     RSSurfaceRenderNodeConfig surfaceConfig;
     surfaceConfig.id = 1;
     auto surfaceNode = std::make_shared<RSSurfaceRenderNode>(surfaceConfig);
     ASSERT_NE(surfaceNode, nullptr);
     surfaceNode->SetNodeHasBackgroundColorAlpha(true);
     surfaceNode->SetHardwareForcedDisabledState(true);
 
     std::vector<std::weak_ptr<RSSurfaceRenderNode>> hwcNodes;
     hwcNodes.push_back(std::weak_ptr<RSSurfaceRenderNode>(surfaceNode));
     auto rsUniRenderVisitor = std::make_shared<RSUniRenderVisitor>();
     ASSERT_NE(rsUniRenderVisitor, nullptr);
     auto rsUniHwcVisitor = std::make_shared<RSUniHwcVisitor>(*rsUniRenderVisitor);
     ASSERT_NE(rsUniHwcVisitor, nullptr);
 
     RectI rect;
     bool isHardwareEnableByBackgroundAlpha = false;
     rsUniHwcVisitor->UpdateHardwareStateByHwcNodeBackgroundAlpha(hwcNodes, rect, isHardwareEnableByBackgroundAlpha);
 }
 
 /**
  * @tc.name: UpdateHardwareStateByHwcNodeBackgroundAlpha003
  * @tc.desc: Test RSUniHwcVisitorTest.UpdateHardwareStateByHwcNodeBackgroundAlpha
  * @tc.type: FUNC
  * @tc.require: IAHFXD
  */
 HWTEST_F(RSUniHwcVisitorTest, UpdateHardwareStateByHwcNodeBackgroundAlpha003, TestSize.Level1)
 {
     RSSurfaceRenderNodeConfig surfaceConfig;
     surfaceConfig.id = 1;
     auto surfaceNode1 = std::make_shared<RSSurfaceRenderNode>(surfaceConfig);
     ASSERT_NE(surfaceNode1, nullptr);
 
     auto surfaceNode2 = std::make_shared<RSSurfaceRenderNode>(surfaceConfig);
     ASSERT_NE(surfaceNode2, nullptr);
     surfaceNode2->SetNodeHasBackgroundColorAlpha(true);
 
     std::vector<std::weak_ptr<RSSurfaceRenderNode>> hwcNodes;
     hwcNodes.push_back(std::weak_ptr<RSSurfaceRenderNode>(surfaceNode1));
     hwcNodes.push_back(std::weak_ptr<RSSurfaceRenderNode>(surfaceNode2));
 }
 
     RectI rect;
     bool isHardwareEnableByBackgroundAlpha = false;
     rsUniHwcVisitor->UpdateHardwareStateByHwcNodeBackgroundAlpha(hwcNodes, rect, isHardwareEnableByBackgroundAlpha);
 }
 
 /**
  * @tc.name: UpdateHardwareStateByHwcNodeBackgroundAlpha004
  * @tc.desc: Test RSUniHwcVisitorTest.UpdateHardwareStateByHwcNodeBackgroundAlpha
  * @tc.type: FUNC
  * @tc.require: IAHFXD
  */
 HWTEST_F(RSUniHwcVisitorTest, UpdateHardwareStateByHwcNodeBackgroundAlpha004, TestSize.Level1)
 {
     RSSurfaceRenderNodeConfig surfaceConfig;
     surfaceConfig.id = 1;
     auto surfaceNode = std::make_shared<RSSurfaceRenderNode>(surfaceConfig);
     ASSERT_NE(surfaceNode, nullptr);
     surfaceNode->SetNodeHasBackgroundColorAlpha(true);
 
     std::vector<std::weak_ptr<RSSurfaceRenderNode>> hwcNodes;
     hwcNodes.push_back(std::weak_ptr<RSSurfaceRenderNode>(surfaceNode));
     auto rsUniRenderVisitor = std::make_shared<RSUniRenderVisitor>();
     ASSERT_NE(rsUniRenderVisitor, nullptr);
     auto rsUniHwcVisitor = std::make_shared<RSUniHwcVisitor>(*rsUniRenderVisitor);
     ASSERT_NE(rsUniHwcVisitor, nullptr);
 
     RectI rect;
     bool isHardwareEnableByBackgroundAlpha = false;
     rsUniHwcVisitor->UpdateHardwareStateByHwcNodeBackgroundAlpha(hwcNodes, rect, isHardwareEnableByBackgroundAlpha);
 }
 
 /**
  * @tc.name: UpdateHardwareStateByHwcNodeBackgroundAlpha005
  * @tc.desc: Test RSUniHwcVisitorTest.UpdateHardwareStateByHwcNodeBackgroundAlpha
  * @tc.type: FUNC
  * @tc.require: IAHFXD
  */
 HWTEST_F(RSUniHwcVisitorTest, UpdateHardwareStateByHwcNodeBackgroundAlpha005, TestSize.Level1)
 {
     std::vector<std::weak_ptr<RSSurfaceRenderNode>> hwcNodes;
     std::weak_ptr<RSSurfaceRenderNode> hwcNode;
     hwcNodes.push_back(hwcNode);
     auto rsUniRenderVisitor = std::make_shared<RSUniRenderVisitor>();
     ASSERT_NE(rsUniRenderVisitor, nullptr);
     auto rsUniHwcVisitor = std::make_shared<RSUniHwcVisitor>(*rsUniRenderVisitor);
     ASSERT_NE(rsUniHwcVisitor, nullptr);
 
     RectI rect;
     bool isHardwareEnableByBackgroundAlpha = false;
     rsUniHwcVisitor->UpdateHardwareStateByHwcNodeBackgroundAlpha(hwcNodes, rect, isHardwareEnableByBackgroundAlpha);
 }
 
 /**
  * @tc.name: UpdateHardwareStateByHwcNodeBackgroundAlpha006
  * @tc.desc: Test RSUniHwcVisitorTest.UpdateHardwareStateByHwcNodeBackgroundAlpha
  * @tc.type: FUNC
  * @tc.require: IAHFXD
  */
 HWTEST_F(RSUniHwcVisitorTest, UpdateHardwareStateByHwcNodeBackgroundAlpha006, TestSize.Level1)
 {
     RSSurfaceRenderNodeConfig surfaceConfig;
     surfaceConfig.id = 1;
     auto surfaceNode1 = std::make_shared<RSSurfaceRenderNode>(surfaceConfig);
     ASSERT_NE(surfaceNode1, nullptr);
     auto surfaceNode2 = std::make_shared<RSSurfaceRenderNode>(surfaceConfig);
     ASSERT_NE(surfaceNode2, nullptr);
     surfaceNode2->SetNodeHasBackgroundColorAlpha(true);
     ASSERT_NE(surfaceNode2->GetRenderProperties().GetBoundsGeometry(), nullptr);
     RectI absRect1 = RectI{0, 0, 200, 200};
     surfaceNode2->GetRenderProperties().GetBoundsGeometry()->absRect_ = absRect1;
     auto surfaceNode3 = std::make_shared<RSSurfaceRenderNode>(surfaceConfig);
     ASSERT_NE(surfaceNode3, nullptr);
     ASSERT_NE(surfaceNode3->GetRenderProperties().GetBoundsGeometry(), nullptr);
     RectI absRect2 = RectI{100, 100, 50, 50};
     surfaceNode3->GetRenderProperties().GetBoundsGeometry()->absRect_ = absRect2;
 
     std::vector<std::weak_ptr<RSSurfaceRenderNode>> hwcNodes1;
     hwcNodes1.push_back(std::weak_ptr<RSSurfaceRenderNode>(surfaceNode1));
     hwcNodes1.push_back(std::weak_ptr<RSSurfaceRenderNode>(surfaceNode2));
     std::vector<std::weak_ptr<RSSurfaceRenderNode>> hwcNodes2;
     hwcNodes2.push_back(std::weak_ptr<RSSurfaceRenderNode>(surfaceNode3));
 
     auto rsUniRenderVisitor = std::make_shared<RSUniRenderVisitor>();
     ASSERT_NE(rsUniRenderVisitor, nullptr);
     auto rsUniHwcVisitor = std::make_shared<RSUniHwcVisitor>(*rsUniRenderVisitor);
     ASSERT_NE(rsUniHwcVisitor, nullptr);
 
     RectI rect;
     bool isHardwareEnableByBackgroundAlpha = false;
     rsUniHwcVisitor->UpdateHardwareStateByHwcNodeBackgroundAlpha(hwcNodes1, rect, isHardwareEnableByBackgroundAlpha);
     rsUniHwcVisitor->UpdateHardwareStateByHwcNodeBackgroundAlpha(hwcNodes2, rect, isHardwareEnableByBackgroundAlpha);
 }
 
 /**
  * @tc.name: UpdateTransparentHwcNodeEnable001
  * @tc.desc: Test RSUniHwcVisitorTest.UpdateTransparentHwcNodeEnable
  * @tc.type: FUNC
  * @tc.require: IAHFXD
  */
 HWTEST_F(RSUniHwcVisitorTest, UpdateTransparentHwcNodeEnable001, TestSize.Level1)
 {
     RSSurfaceRenderNodeConfig surfaceConfig;
     surfaceConfig.id = 1;
     auto surfaceNode = std::make_shared<RSSurfaceRenderNode>(surfaceConfig);
     ASSERT_NE(surfaceNode, nullptr);
     surfaceNode->SetDstRect({0, 0, 100, 100});
 
     std::vector<std::weak_ptr<RSSurfaceRenderNode>> hwcNodes;
     hwcNodes.push_back(std::weak_ptr<RSSurfaceRenderNode>(surfaceNode));
     auto rsUniRenderVisitor = std::make_shared<RSUniRenderVisitor>();
     ASSERT_NE(rsUniRenderVisitor, nullptr);
     auto rsUniHwcVisitor = std::make_shared<RSUniHwcVisitor>(*rsUniRenderVisitor);
     ASSERT_NE(rsUniHwcVisitor, nullptr);
 
     ASSERT_FALSE(surfaceNode->IsHardwareForcedDisabled());
 
     surfaceNode->SetNodeHasBackgroundColorAlpha(true);
     surfaceNode->SetHardwareEnableHint(true);
     rsUniHwcVisitor->UpdateTransparentHwcNodeEnable(hwcNodes);
     ASSERT_FALSE(surfaceNode->IsHardwareForcedDisabled());
 }
 
 /**
  * @tc.name: UpdateTransparentHwcNodeEnable002
  * @tc.desc: Test RSUniHwcVisitorTest.UpdateTransparentHwcNodeEnable
  * @tc.type: FUNC
  * @tc.require: IAHFXD
  */
 HWTEST_F(RSUniHwcVisitorTest, UpdateTransparentHwcNodeEnable002, TestSize.Level1)
 {
     RSSurfaceRenderNodeConfig surfaceConfig;
     surfaceConfig.id = 1;
     auto surfaceNode = std::make_shared<RSSurfaceRenderNode>(surfaceConfig);
     ASSERT_NE(surfaceNode, nullptr);
     surfaceConfig.id = 2;
     auto opacitySurfaceNode = std::make_shared<RSSurfaceRenderNode>(surfaceConfig);
     ASSERT_NE(opacitySurfaceNode, nullptr);
     // set transparent
     surfaceNode->SetNodeHasBackgroundColorAlpha(true);
     surfaceNode->SetHardwareEnableHint(true);
     surfaceNode->SetDstRect({0, 0, 100, 100});
     opacitySurfaceNode->SetDstRect({100, 0, 100, 100});
     opacitySurfaceNode->SetHardwareForcedDisabledState(true);
 
     std::vector<std::weak_ptr<RSSurfaceRenderNode>> hwcNodes;
     hwcNodes.push_back(std::weak_ptr<RSSurfaceRenderNode>(opacitySurfaceNode));
     hwcNodes.push_back(std::weak_ptr<RSSurfaceRenderNode>(surfaceNode));
     auto rsUniRenderVisitor = std::make_shared<RSUniRenderVisitor>();
     ASSERT_NE(rsUniRenderVisitor, nullptr);
     auto rsUniHwcVisitor = std::make_shared<RSUniHwcVisitor>(*rsUniRenderVisitor);
     ASSERT_NE(rsUniHwcVisitor, nullptr);
 
     ASSERT_FALSE(surfaceNode->IsHardwareForcedDisabled());
     // A transparent HWC node is NOT intersected with another opacity disabled-HWC node below it.
     rsUniHwcVisitor->UpdateTransparentHwcNodeEnable(hwcNodes);
     ASSERT_FALSE(surfaceNode->IsHardwareForcedDisabled());
 
     // A transparent HWC node is intersected with another opacity disabled-HWC node below it.
     opacitySurfaceNode->SetDstRect({50, 0, 100, 100});
     rsUniHwcVisitor->UpdateTransparentHwcNodeEnable(hwcNodes);
     ASSERT_TRUE(surfaceNode->IsHardwareForcedDisabled());
 }
 
 /*
  * @tc.name: UpdateChildHwcNodeEnabledByHwcNodeBelow
  * @tc.desc: Test RSUniRenderVistorTest.UpdateChildHwcNodeEnableByHwcNodeBelow
  * @tc.type: FUNC
  * @tc.require: issuesI8MQCS
  */
 HWTEST_F(RSUniHwcVisitorTest, UpdateChildHwcNodeEnableByHwcNodeBelow, TestSize.Level2)
 {
     auto appNode = RSTestUtil::CreateSurfaceNode();
     RSSurfaceRenderNodeConfig surfaceConfig;
     surfaceConfig.id = 1;
     auto hwcNode1 = std::make_shared<RSSurfaceRenderNode>(surfaceConfig);
     ASSERT_NE(hwcNode1, nullptr);
     surfaceConfig.id = 2;
     auto hwcNode2 = std::make_shared<RSSurfaceRenderNode>(surfaceConfig);
     ASSERT_NE(hwcNode2, nullptr);
     std::weak_ptr<RSSurfaceRenderNode> hwcNode3;
     hwcNode1->SetIsOnTheTree(true);
     hwcNode2->SetIsOnTheTree(false);
     appNode->AddChildHardwareEnabledNode(hwcNode1);
     appNode->AddChildHardwareEnabledNode(hwcNode2);
     appNode->AddChildHardwareEnabledNode(hwcNode3);
     std::vector<RectI> hwcRects;
     hwcRects.emplace_back(0, 0, 0, 0);
     auto rsUniRenderVisitor = std::make_shared<RSUniRenderVisitor>();
     ASSERT_NE(rsUniRenderVisitor, nullptr);
     auto rsUniHwcVisitor = std::make_shared<RSUniHwcVisitor>(*rsUniRenderVisitor);
     ASSERT_NE(rsUniHwcVisitor, nullptr);
     rsUniHwcVisitor->UpdateChildHwcNodeEnableByHwcNodeBelow(hwcRects, appNode);
 }
 
 /*
  * @tc.name: UpdateHwcNodeEnableByFilterRect
  * @tc.desc: Test RSUniHwcVisitorTest.UpdateHwcNodeEnableByFilterRect with intersect rect
  * @tc.type: FUNC
  * @tc.require: issuesI9V0N7
  */
 HWTEST_F(RSUniHwcVisitorTest, UpdateHwcNodeEnableByFilterRect001, TestSize.Level2)
 {
     auto rsUniRenderVisitor = std::make_shared<RSUniRenderVisitor>();
     ASSERT_NE(rsUniRenderVisitor, nullptr);
     auto rsUniHwcVisitor = std::make_shared<RSUniHwcVisitor>(*rsUniRenderVisitor);
     ASSERT_NE(rsUniHwcVisitor, nullptr);
 
     RSSurfaceRenderNodeConfig surfaceConfig;
     surfaceConfig.id = 1;
     auto surfaceNode1 = std::make_shared<RSSurfaceRenderNode>(surfaceConfig);
     ASSERT_NE(surfaceNode1, nullptr);
     surfaceConfig.id = 2;
     auto surfaceNode2 = std::make_shared<RSSurfaceRenderNode>(surfaceConfig);
     ASSERT_NE(surfaceNode2, nullptr);
 
     uint32_t left = 0;
     uint32_t top = 0;
     uint32_t width = 300;
     uint32_t height = 300;
     RectI rect{left, top, width, height};
     surfaceNode2->SetDstRect(rect);
     surfaceNode1->AddChildHardwareEnabledNode(surfaceNode2);
 
     ASSERT_NE(rsUniHwcVisitor, nullptr);
     rsUniHwcVisitor->UpdateHwcNodeEnableByFilterRect(surfaceNode1, rect, 1, false, 0);
     ASSERT_TRUE(surfaceNode2->IsHardwareForcedDisabled());
 }
 
 /*
  * @tc.name: UpdateHwcNodeEnableByFilterRect
  * @tc.desc: Test RSUniHwcVisitorTest.UpdateHwcNodeEnableByFilterRect with empty rect
  * @tc.type: FUNC
  * @tc.require: issuesI9V0N7
  */
 HWTEST_F(RSUniHwcVisitorTest, UpdateHwcNodeEnableByFilterRect002, TestSize.Level2)
 {
     auto rsUniRenderVisitor = std::make_shared<RSUniRenderVisitor>();
     ASSERT_NE(rsUniRenderVisitor, nullptr);
     auto rsUniHwcVisitor = std::make_shared<RSUniHwcVisitor>(*rsUniRenderVisitor);
     ASSERT_NE(rsUniHwcVisitor, nullptr);
 
     RSSurfaceRenderNodeConfig surfaceConfig;
     surfaceConfig.id = 1;
     auto surfaceNode1 = std::make_shared<RSSurfaceRenderNode>(surfaceConfig);
     ASSERT_NE(surfaceNode1, nullptr);
 
     uint32_t left = 0;
     uint32_t top = 0;
     uint32_t width = 0;
     uint32_t height = 0;
     RectI rect{left, top, width, height};
     ASSERT_NE(rsUniHwcVisitor, nullptr);
     rsUniHwcVisitor->UpdateHwcNodeEnableByFilterRect(surfaceNode1, rect, 1, false, 0);
 }
 
 /*
  * @tc.name: UpdateHwcNodeEnableByFilterRect
  * @tc.desc: Test RSUniHwcVisitorTest.UpdateHwcNodeEnableByFilterRect with no hwcNode
  * @tc.type: FUNC
  * @tc.require: issuesI9V0N7
  */
 HWTEST_F(RSUniHwcVisitorTest, UpdateHwcNodeEnableByFilterRect003, TestSize.Level2)
 {
     auto rsUniRenderVisitor = std::make_shared<RSUniRenderVisitor>();
     ASSERT_NE(rsUniRenderVisitor, nullptr);
     auto rsUniHwcVisitor = std::make_shared<RSUniHwcVisitor>(*rsUniRenderVisitor);
     ASSERT_NE(rsUniHwcVisitor, nullptr);
 
     RSSurfaceRenderNodeConfig surfaceConfig;
     surfaceConfig.id = 1;
     auto surfaceNode = std::make_shared<RSSurfaceRenderNode>(surfaceConfig);
     ASSERT_NE(surfaceNode, nullptr);
 
     uint32_t left = 0;
     uint32_t top = 0;
     uint32_t width = 300;
     uint32_t height = 300;
     RectI rect{left, top, width, height};
     ASSERT_NE(rsUniHwcVisitor, nullptr);
     rsUniHwcVisitor->UpdateHwcNodeEnableByFilterRect(surfaceNode, rect, 1, false, 0);
 }
 
 /*
  * @tc.name: UpdateHwcNodeEnableByGlobalCleanFilter_001
  * @tc.desc: Test UpdateHwcNodeEnableByGlobalCleanFilter when Intersect return false.
  * @tc.type: FUNC
  * @tc.require: issueIAJY2P
  */
 HWTEST_F(RSUniHwcVisitorTest, UpdateHwcNodeEnableByGlobalCleanFilter_001, TestSize.Level2)
 {
     auto rsUniRenderVisitor = std::make_shared<RSUniRenderVisitor>();
     ASSERT_NE(rsUniRenderVisitor, nullptr);
     auto rsUniHwcVisitor = std::make_shared<RSUniHwcVisitor>(*rsUniRenderVisitor);
     ASSERT_NE(rsUniHwcVisitor, nullptr);
   
     auto surfaceNode = RSTestUtil::CreateSurfaceNodeWithBuffer();
     ASSERT_NE(surfaceNode, nullptr);
 
     std::vector<std::pair<NodeId, RectI>> cleanFilter;
     auto& properties = surfaceNode->GetMutableRenderProperties();
     auto offset = std::nullopt;
     auto matrix = Drawing::Matrix();
     properties.UpdateGeometryByParent(&matrix, offset);
     cleanFilter.emplace_back(NodeId(0), RectI(50, 50, 100, 100));
     ASSERT_TRUE(surfaceNode->GetRenderProperties().GetBoundsGeometry()->GetAbsRect()
         .IntersectRect(cleanFilter[0].second).IsEmpty());
 
     rsUniHwcVisitor->UpdateHwcNodeEnableByGlobalCleanFilter(cleanFilter, *surfaceNode);
     EXPECT_FALSE(surfaceNode->isHardwareForcedDisabled_);
 }
 
 /*
  * @tc.name: UpdateHwcNodeEnableByGlobalCleanFilter_002
  * @tc.desc: Test UpdateHwcNodeEnableByGlobalCleanFilter when rendernode is nullptr.
  * @tc.type: FUNC
  * @tc.require: issueIAJY2P
  */
 HWTEST_F(RSUniHwcVisitorTest, UpdateHwcNodeEnableByGlobalCleanFilter_002, TestSize.Level2)
 {
     auto rsUniRenderVisitor = std::make_shared<RSUniRenderVisitor>();
     ASSERT_NE(rsUniRenderVisitor, nullptr);
     auto rsUniHwcVisitor = std::make_shared<RSUniHwcVisitor>(*rsUniRenderVisitor);
     ASSERT_NE(rsUniHwcVisitor, nullptr);
 
     auto surfaceNode = RSTestUtil::CreateSurfaceNodeWithBuffer();
     ASSERT_NE(surfaceNode, nullptr);
 
     std::vector<std::pair<NodeId, RectI>> cleanFilter;
     auto& properties = surfaceNode->GetMutableRenderProperties();
     auto offset = std::nullopt;
     auto matrix = Drawing::Matrix();
     matrix.SetScale(100, 100);
     properties.UpdateGeometryByParent(&matrix, offset);
     cleanFilter.emplace_back(NodeId(0), RectI(50, 50, 100, 100));
     auto& nodeMap = RSMainThread::Instance()->GetContext().GetMutableNodeMap();
     constexpr NodeId id = 0;
     pid_t pid = ExtractPid(id);
     nodeMap.renderNodeMap_[pid][id] = nullptr;
 
     rsUniHwcVisitor->UpdateHwcNodeEnableByGlobalCleanFilter(cleanFilter, *surfaceNode);
     EXPECT_FALSE(surfaceNode->isHardwareForcedDisabled_);
 }
 
 /*
  * @tc.name: UpdateHwcNodeEnableByGlobalCleanFilter_003
  * @tc.desc: Test UpdateHwcNodeEnableByGlobalCleanFilter when rendernode is not null and AIBarFilterCache is not valid.
  * @tc.type: FUNC
  * @tc.require: issueIAJY2P
  */
 HWTEST_F(RSUniHwcVisitorTest, UpdateHwcNodeEnableByGlobalCleanFilter_003, TestSize.Level2)
 {
     auto rsUniRenderVisitor = std::make_shared<RSUniRenderVisitor>();
     ASSERT_NE(rsUniRenderVisitor, nullptr);
     auto rsUniHwcVisitor = std::make_shared<RSUniHwcVisitor>(*rsUniRenderVisitor);
     ASSERT_NE(rsUniHwcVisitor, nullptr);
 
     auto surfaceNode = RSTestUtil::CreateSurfaceNodeWithBuffer();
     ASSERT_NE(surfaceNode, nullptr);
 
     std::vector<std::pair<NodeId, RectI>> cleanFilter;
     auto& properties = surfaceNode->GetMutableRenderProperties();
     auto offset = std::nullopt;
     auto matrix = Drawing::Matrix();
     matrix.SetScale(100, 100);
     properties.UpdateGeometryByParent(&matrix, offset);
     cleanFilter.emplace_back(NodeId(1), RectI(50, 50, 100, 100));
     auto& nodeMap = RSMainThread::Instance()->GetContext().GetMutableNodeMap();
     constexpr NodeId id = 1;
     pid_t pid = ExtractPid(id);
     auto node = std::make_shared<RSRenderNode>(id);
     nodeMap.renderNodeMap_[pid][id] = node;
     ASSERT_NE(node, nullptr);
     ASSERT_FALSE(node->IsAIBarFilterCacheValid());
 
     rsUniHwcVisitor->UpdateHwcNodeEnableByGlobalCleanFilter(cleanFilter, *surfaceNode);
     EXPECT_FALSE(surfaceNode->isHardwareForcedDisabled_);
 }
 
 /*
  * @tc.name: UpdateHwcNodeEnableByGlobalDirtyFilter_001
  * @tc.desc: Test UpdateHwcNodeEnableByGlobalDirtyFilter when Intersect return false.
  * @tc.type: FUNC
  * @tc.require: issueIAJY2P
  */
 HWTEST_F(RSUniHwcVisitorTest, UpdateHwcNodeEnableByGlobalDirtyFilter_001, TestSize.Level2)
 {
     auto rsUniRenderVisitor = std::make_shared<RSUniRenderVisitor>();
     ASSERT_NE(rsUniRenderVisitor, nullptr);
     auto rsUniHwcVisitor = std::make_shared<RSUniHwcVisitor>(*rsUniRenderVisitor);
     ASSERT_NE(rsUniHwcVisitor, nullptr);
 
     auto surfaceNode = RSTestUtil::CreateSurfaceNodeWithBuffer();
     ASSERT_NE(surfaceNode, nullptr);
 
     std::vector<std::pair<NodeId, RectI>> dirtyFilter;
     auto& properties = surfaceNode->GetMutableRenderProperties();
     auto offset = std::nullopt;
     auto matrix = Drawing::Matrix();
     properties.UpdateGeometryByParent(&matrix, offset);
     dirtyFilter.emplace_back(NodeId(0), RectI(50, 50, 100, 100));
     auto geo = surfaceNode->GetRenderProperties().GetBoundsGeometry();
     ASSERT_TRUE(geo->GetAbsRect().IntersectRect(dirtyFilter[0].second).IsEmpty());
 
     rsUniHwcVisitor->UpdateHwcNodeEnableByGlobalDirtyFilter(dirtyFilter, *surfaceNode);
     EXPECT_FALSE(surfaceNode->isHardwareForcedDisabled_);
 }
 
 /*
  * @tc.name: UpdateHwcNodeEnableByGlobalDirtyFilter_002
  * @tc.desc: Test UpdateHwcNodeEnableByGlobalDirtyFilter when rendernode is nullptr.
  * @tc.type: FUNC
  * @tc.require: issueIAJY2P
  */
 HWTEST_F(RSUniHwcVisitorTest, UpdateHwcNodeEnableByGlobalDirtyFilter_002, TestSize.Level2)
 {
     auto rsUniRenderVisitor = std::make_shared<RSUniRenderVisitor>();
     ASSERT_NE(rsUniRenderVisitor, nullptr);
     auto rsUniHwcVisitor = std::make_shared<RSUniHwcVisitor>(*rsUniRenderVisitor);
     ASSERT_NE(rsUniHwcVisitor, nullptr);
 
     auto surfaceNode = RSTestUtil::CreateSurfaceNodeWithBuffer();
     ASSERT_NE(surfaceNode, nullptr);
 
     std::vector<std::pair<NodeId, RectI>> dirtyFilter;
     auto& properties = surfaceNode->GetMutableRenderProperties();
     auto offset = std::nullopt;
     auto matrix = Drawing::Matrix();
     matrix.SetScale(100, 100);
     properties.UpdateGeometryByParent(&matrix, offset);
     dirtyFilter.emplace_back(NodeId(0), RectI(50, 50, 100, 100));
     auto geo = surfaceNode->GetRenderProperties().GetBoundsGeometry();
     ASSERT_FALSE(geo->GetAbsRect().IntersectRect(dirtyFilter[0].second).IsEmpty());
 
     rsUniHwcVisitor->UpdateHwcNodeEnableByGlobalDirtyFilter(dirtyFilter, *surfaceNode);
     EXPECT_TRUE(surfaceNode->isHardwareForcedDisabled_);
 }
 }