/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "drawable/rs_display_render_node_drawable.h"

#include "gtest/gtest.h"
#include "limit_number.h"
#include "foundation/graphic/graphic_2d/rosen/test/render_service/render_service/unittest/pipeline/rs_test_util.h"

#include "drawable/rs_display_render_node_drawable.h"
#include "params/rs_display_render_params.h"
#include "feature/round_corner_display/rs_rcd_surface_render_node.h"
#include "feature/round_corner_display/rs_rcd_surface_render_node_drawable.h"
#include "pipeline/render_thread/rs_uni_render_engine.h"
#include "pipeline/render_thread/rs_uni_render_processor.h"
#include "pipeline/render_thread/rs_render_engine.h"
#include "pipeline/rs_processor_factory.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::Rosen {
class RSUniRenderProcessorTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void RSUniRenderProcessorTest::SetUpTestCase() {}
void RSUniRenderProcessorTest::TearDownTestCase() {}
void RSUniRenderProcessorTest::SetUp() {}
void RSUniRenderProcessorTest::TearDown() {}

/**
 * @tc.name: ProcessorInit001
 * @tc.desc: test ProcessorInit func with renderEngine nullptr
 * @tc.type: FUNC
 * @tc.require: issueI6QM6E
 */
HWTEST(RSUniRenderProcessorTest, ProcessorInit001, TestSize.Level1)
{
    if (!RSUniRenderJudgement::IsUniRender()) {
        return;
    }
    auto processor = RSProcessorFactory::CreateProcessor(RSDisplayRenderNode::CompositeType::UNI_RENDER_COMPOSITE);
    RSDisplayNodeConfig config;
    RSDisplayRenderNode node(1, config);
    EXPECT_EQ(processor->Init(node, 0, 0, 0, nullptr), false);
}

/**
 * @tc.name: ProcessSurface001
 * @tc.desc: test ProcessSurface func with invalid layer info
 * @tc.type: FUNC
 * @tc.require: issueI6QM6E
 */
HWTEST(RSUniRenderProcessorTest, ProcessSurface001, TestSize.Level1)
{
    if (!RSUniRenderJudgement::IsUniRender()) {
        return;
    }
    auto processor = RSProcessorFactory::CreateProcessor(RSDisplayRenderNode::CompositeType::UNI_RENDER_COMPOSITE);
    ASSERT_NE(processor, nullptr);
    RSDisplayNodeConfig config;
    RSDisplayRenderNode node(1, config);
    auto uniRenderEngine = std::make_shared<RSUniRenderEngine>();
    processor->Init(node, 0, 0, 0, uniRenderEngine);
    RSSurfaceRenderNode surfaceNode(2);
    processor->ProcessSurface(surfaceNode);
}

/**
 * @tc.name: InitTest
 * @tc.desc: Verify function Init
 * @tc.type:FUNC
 * @tc.require:issuesI9KRF1
 */
HWTEST(RSUniRenderProcessorTest, InitTest, TestSize.Level1)
{
    if (!RSUniRenderJudgement::IsUniRender()) {
        return;
    }
    auto renderProcessor = std::make_shared<RSUniRenderProcessor>();
    RSDisplayNodeConfig config;
    RSDisplayRenderNode node(1, config);
    auto renderEngine = std::make_shared<RSUniRenderEngine>();
    EXPECT_EQ(renderProcessor->Init(node, 0, 0, 0, renderEngine), false);
}

/**
 * @tc.name: ProcessSurfaceTest
 * @tc.desc: Verify function ProcessSurface
 * @tc.type:FUNC
 * @tc.require:issuesI9KRF1
 */
HWTEST(RSUniRenderProcessorTest, ProcessSurfaceTest, TestSize.Level1)
{
    if (!RSUniRenderJudgement::IsUniRender()) {
        return;
    }
    auto renderProcessor = std::make_shared<RSUniRenderProcessor>();
    ASSERT_NE(renderProcessor, nullptr);
    RSDisplayNodeConfig config;
    RSDisplayRenderNode node(1, config);
    auto uniRenderEngine = std::make_shared<RSUniRenderEngine>();
    renderProcessor->Init(node, 0, 0, 0, uniRenderEngine);
    // for test
    RSSurfaceRenderNode surfaceNode(2);
    renderProcessor->ProcessSurface(surfaceNode);
}

/**
 * @tc.name: PostProcessTest
 * @tc.desc: Verify function PostProcess
 * @tc.type:FUNC
 * @tc.require:issuesI9KRF1
 */
HWTEST(RSUniRenderProcessorTest, PostProcessTest, TestSize.Level1)
{
    if (!RSUniRenderJudgement::IsUniRender()) {
        return;
    }
    auto renderProcessor = std::make_shared<RSUniRenderProcessor>();
    renderProcessor->PostProcess();
    EXPECT_EQ(renderProcessor->layers_.size(), 0);
}

/**
 * @tc.name: CreateLayerTest
 * @tc.desc: Verify function CreateLayer
 * @tc.type:FUNC
 * @tc.require:issuesI9KRF1
 */
HWTEST(RSUniRenderProcessorTest, CreateLayerTest, TestSize.Level1)
{
    if (!RSUniRenderJudgement::IsUniRender()) {
        return;
    }
    auto renderProcessor = std::make_shared<RSUniRenderProcessor>();
    HdiBackend hdiBackend;
    auto output = std::make_shared<HdiOutput>(1);
    renderProcessor->uniComposerAdapter_->hdiBackend_ = &hdiBackend;
    renderProcessor->uniComposerAdapter_->output_ = output;
    RSSurfaceRenderNode node(0);
    auto iConsumerSurface = IConsumerSurface::Create();
    node.GetRSSurfaceHandler()->SetConsumer(iConsumerSurface);
    RSSurfaceRenderParams params(0);
    RSLayerInfo layerInfo;
    sptr<SurfaceBuffer> bufferTest = OHOS::SurfaceBuffer::Create();
    sptr<SurfaceBuffer> preBufferTest = OHOS::SurfaceBuffer::Create();
    params.SetBuffer(bufferTest, {});
    params.SetPreBuffer(preBufferTest);
    layerInfo.zOrder = 0;
    params.SetLayerInfo(layerInfo);
    renderProcessor->CreateLayer(node, params);
    EXPECT_EQ(params.GetLayerInfo().zOrder, 0);
}

/**
 * @tc.name: ProcessDisplaySurfaceTest
 * @tc.desc: Verify function ProcessDisplaySurface
 * @tc.type:FUNC
 * @tc.require:issuesI9KRF1
 */
HWTEST(RSUniRenderProcessorTest, ProcessDisplaySurfaceTest, TestSize.Level1)
{
    if (!RSUniRenderJudgement::IsUniRender()) {
        return;
    }
    auto renderProcessor = std::make_shared<RSUniRenderProcessor>();
    constexpr NodeId nodeId = TestSrc::limitNumber::Uint64[0];
    RSDisplayNodeConfig config;
    RSDisplayRenderNode node(nodeId, config);
    renderProcessor->ProcessDisplaySurface(node);
    EXPECT_FALSE(renderProcessor->uniComposerAdapter_->CreateLayer(node));
}

/**
 * @tc.name: ProcessRcdSurfaceTest
 * @tc.desc: Verify function ProcessRcdSurface
 * @tc.type:FUNC
 * @tc.require:issuesI9KRF1
 */
HWTEST(RSUniRenderProcessorTest, ProcessRcdSurfaceTest, TestSize.Level1)
{
    if (!RSUniRenderJudgement::IsUniRender()) {
        return;
    }
    auto renderProcessor = std::make_shared<RSUniRenderProcessor>();
    constexpr NodeId nodeId = TestSrc::limitNumber::Uint64[0];
    RCDSurfaceType type = RCDSurfaceType::INVALID;
    auto node = std::make_shared<RSRcdSurfaceRenderNode>(nodeId, type);
    renderProcessor->ProcessRcdSurface(*node);
    EXPECT_FALSE(renderProcessor->uniComposerAdapter_->CreateLayer(*node));
    DrawableV2::RSRcdSurfaceRenderNodeDrawable drawable(node);
    renderProcessor->ProcessRcdSurfaceForRenderThread(drawable);
    EXPECT_FALSE(renderProcessor->uniComposerAdapter_->CreateLayer(drawable));
}

/**
 * @tc.name: InitForRenderThread001
 * @tc.desc: Test RSUniRenderProcessorTest.InitForRenderThread when renderEngine is nullptr
 * @tc.type:FUNC
 * @tc.require: issueIAJ1RT
 */
HWTEST(RSUniRenderProcessorTest, InitForRenderThread001, TestSize.Level1)
{
    if (!RSUniRenderJudgement::IsUniRender()) {
        return;
    }
    NodeId nodeId = 1;
    auto node = std::make_shared<RSRenderNode>(nodeId);
    DrawableV2::RSDisplayRenderNodeDrawable drawable(node);
    drawable.renderParams_ = std::make_unique<RSRenderParams>(nodeId);
    ASSERT_NE(drawable.renderParams_, nullptr);
    ScreenId mirroredId = 1;

    auto renderProcessor = std::make_shared<RSUniRenderProcessor>();
    ASSERT_NE(renderProcessor, nullptr);
    renderProcessor->InitForRenderThread(drawable, mirroredId, nullptr);
}

/**
 * @tc.name: InitForRenderThread002
 * @tc.desc: Test RSUniRenderProcessorTest.InitForRenderThread with not nullptr
 * @tc.type:FUNC
 * @tc.require: issueIAJ1RT
 */
HWTEST(RSUniRenderProcessorTest, InitForRenderThread002, TestSize.Level1)
{
    if (!RSUniRenderJudgement::IsUniRender()) {
        return;
    }

    NodeId nodeId = 1;
    auto node = std::make_shared<RSRenderNode>(nodeId);
    DrawableV2::RSDisplayRenderNodeDrawable drawable(node);
    drawable.renderParams_ = nullptr;
    ASSERT_EQ(drawable.renderParams_, nullptr);
    ScreenId mirroredId = 1;
    auto renderEngine = std::make_shared<RSRenderEngine>();
    ASSERT_NE(renderEngine, nullptr);
    
    auto renderProcessor = std::make_shared<RSUniRenderProcessor>();
    ASSERT_NE(renderProcessor, nullptr);
    renderProcessor->InitForRenderThread(drawable, mirroredId, renderEngine);
}

/**
 * @tc.name: ProcessDisplaySurfaceForRenderThread001
 * @tc.desc: Test RSUniRenderProcessorTest.ProcessDisplaySurfaceForRenderThread when layer is nullptr
 * @tc.type:FUNC
 * @tc.require: issueIAJ1RT
 */
HWTEST(RSUniRenderProcessorTest, ProcessDisplaySurfaceForRenderThread001, TestSize.Level1)
{
    if (!RSUniRenderJudgement::IsUniRender()) {
        return;
    }
    NodeId nodeId = 1;
    auto node = std::make_shared<RSRenderNode>(nodeId);
    DrawableV2::RSDisplayRenderNodeDrawable drawable(node);
    
    auto renderProcessor = std::make_shared<RSUniRenderProcessor>();
    ASSERT_NE(renderProcessor, nullptr);
    renderProcessor->ProcessDisplaySurfaceForRenderThread(drawable);
}

/**
 * @tc.name: ProcessDisplaySurfaceForRenderThread002
 * @tc.desc: Test RSUniRenderProcessorTest.ProcessDisplaySurfaceForRenderThread when params is nullptr
 * @tc.type:FUNC
 * @tc.require: issueIAJ1RT
 */
HWTEST(RSUniRenderProcessorTest, ProcessDisplaySurfaceForRenderThread002, TestSize.Level1)
{
    if (!RSUniRenderJudgement::IsUniRender()) {
        return;
    }
    NodeId nodeId = 1;
    auto node = std::make_shared<RSRenderNode>(nodeId);
    DrawableV2::RSDisplayRenderNodeDrawable drawable(node);
    drawable.renderParams_= nullptr;
    
    auto renderProcessor = std::make_shared<RSUniRenderProcessor>();
    ASSERT_NE(renderProcessor, nullptr);
    auto output = std::make_shared<HdiOutput>(1);
    renderProcessor->uniComposerAdapter_->output_ = output;
    renderProcessor->ProcessDisplaySurfaceForRenderThread(drawable);
}

/**
 * @tc.name: ProcessDisplaySurfaceForRenderThread003
 * @tc.desc: Test RSUniRenderProcessorTest.ProcessDisplaySurfaceForRenderThread when Fingerprint_ is false
 * @tc.type:FUNC
 * @tc.require: issueIAJ1RT
 */
HWTEST(RSUniRenderProcessorTest, ProcessDisplaySurfaceForRenderThread003, TestSize.Level1)
{
    if (!RSUniRenderJudgement::IsUniRender()) {
        return;
    }
    NodeId nodeId = 1;
    auto node = std::make_shared<RSRenderNode>(nodeId);
    DrawableV2::RSDisplayRenderNodeDrawable drawable(node);
    drawable.renderParams_= std::make_unique<RSRenderParams>(0);

    auto renderProcessor = std::make_shared<RSUniRenderProcessor>();
    ASSERT_NE(renderProcessor, nullptr);
    auto output = std::make_shared<HdiOutput>(1);
    ASSERT_NE(output, nullptr);
    renderProcessor->uniComposerAdapter_->output_ = output;
    renderProcessor->ProcessDisplaySurfaceForRenderThread(drawable);
}

/**
 * @tc.name: ProcessDisplaySurfaceForRenderThread004
 * @tc.desc: Test RSUniRenderProcessorTest.ProcessDisplaySurfaceForRenderThread when Fingerprint_ is true
 * @tc.type:FUNC
 * @tc.require: issueIAJ1RT
 */
HWTEST(RSUniRenderProcessorTest, ProcessDisplaySurfaceForRenderThread004, TestSize.Level1)
{
    if (!RSUniRenderJudgement::IsUniRender()) {
        return;
    }
    NodeId nodeId = 1;
    auto node = std::make_shared<RSRenderNode>(nodeId);
    DrawableV2::RSDisplayRenderNodeDrawable drawable(node);
    drawable.renderParams_= std::make_unique<RSRenderParams>(0);
    drawable.renderParams_->SetFingerprint(true);
    drawable.surfaceHandler_ = std::make_shared<RSSurfaceHandler>(0);
    ASSERT_NE(drawable.surfaceHandler_, nullptr);
    
    auto renderProcessor = std::make_shared<RSUniRenderProcessor>();
    ASSERT_NE(renderProcessor, nullptr);
    auto output = std::make_shared<HdiOutput>(1);
    ASSERT_NE(output, nullptr);
    renderProcessor->uniComposerAdapter_->output_ = output;
    renderProcessor->ProcessDisplaySurfaceForRenderThread(drawable);
}

/**
 * @tc.name: ProcessSurfaceForRenderThread001
 * @tc.desc: Test RSUniRenderProcessorTest.ProcessSurfaceForRenderThread with not nullptr
 * @tc.type:FUNC
 * @tc.require: issueIAIT5Z
 */
HWTEST(RSUniRenderProcessorTest, ProcessSurfaceForRenderThread001, TestSize.Level1)
{
    if (!RSUniRenderJudgement::IsUniRender()) {
        return;
    }
    NodeId id = 0;
    auto node = std::make_shared<RSSurfaceRenderNode>(id);
    ASSERT_NE(node, nullptr);
    auto surfaceDrawable = std::make_shared<DrawableV2::RSSurfaceRenderNodeDrawable>(node);
    ASSERT_NE(surfaceDrawable, nullptr);
    auto renderProcessor = std::make_shared<RSUniRenderProcessor>();
    ASSERT_NE(renderProcessor, nullptr);
    renderProcessor->ProcessSurfaceForRenderThread(*surfaceDrawable);
}

/**
 * @tc.name: CreateLayerForRenderThread001
 * @tc.desc: Test RSUniRenderProcessorTest.CreateLayerForRenderThread with nullptr
 * @tc.type:FUNC
 * @tc.require: issueIAIT5Z
 */
HWTEST(RSUniRenderProcessorTest, CreateLayerForRenderThread001, TestSize.Level1)
{
    if (!RSUniRenderJudgement::IsUniRender()) {
        return;
    }
    NodeId id = 0;
    auto node = std::make_shared<RSSurfaceRenderNode>(id);
    ASSERT_NE(node, nullptr);
    auto surfaceDrawable = std::make_shared<DrawableV2::RSSurfaceRenderNodeDrawable>(node);
    ASSERT_NE(surfaceDrawable, nullptr);

    surfaceDrawable->renderParams_ = nullptr;
    auto renderProcessor = std::make_shared<RSUniRenderProcessor>();
    ASSERT_NE(renderProcessor, nullptr);
    renderProcessor->CreateLayerForRenderThread(*surfaceDrawable);
    surfaceDrawable->renderParams_= std::make_unique<RSRenderParams>(0);
    renderProcessor->CreateLayerForRenderThread(*surfaceDrawable);
}

/**
 * @tc.name: CreateLayerForRenderThread002
 * @tc.desc: Test RSUniRenderProcessorTest.CreateLayerForRenderThread with not nullptr
 * @tc.type:FUNC
 * @tc.require: issueIAIT5Z
 */
HWTEST(RSUniRenderProcessorTest, CreateLayerForRenderThread002, TestSize.Level1)
{
    if (!RSUniRenderJudgement::IsUniRender()) {
        return;
    }
    RSSurfaceRenderParams params(0);
    sptr<SurfaceBuffer> bufferTest = OHOS::SurfaceBuffer::Create();
    params.SetBuffer(bufferTest, {});
    NodeId id = 1;
    auto node = std::make_shared<RSSurfaceRenderNode>(id);
    ASSERT_NE(node, nullptr);
    auto surfaceDrawable = std::make_shared<DrawableV2::RSSurfaceRenderNodeDrawable>(node);
    ASSERT_EQ(surfaceDrawable->renderParams_, nullptr);
    surfaceDrawable->renderParams_ = std::make_unique<RSRenderParams>(1);

    auto renderProcessor = std::make_shared<RSUniRenderProcessor>();
    ASSERT_NE(renderProcessor, nullptr);
    renderProcessor->CreateLayerForRenderThread(*surfaceDrawable);
}

/**
 * @tc.name: CreateUIFirstLayer001
 * @tc.desc: Test RSUniRenderProcessorTest.CreateUIFirstLayer while params is null
 * @tc.type:FUNC
 * @tc.require: issueIAIT5Z
 */
HWTEST(RSUniRenderProcessorTest, CreateUIFirstLayer001, TestSize.Level1)
{
    if (!RSUniRenderJudgement::IsUniRender()) {
        return;
    }
    RSSurfaceRenderParams params(0);
    NodeId id = 1;
    auto node = std::make_shared<RSSurfaceRenderNode>(id);
    ASSERT_NE(node, nullptr);
    auto surfaceDrawable = std::make_shared<DrawableV2::RSSurfaceRenderNodeDrawable>(node);
    ASSERT_NE(surfaceDrawable, nullptr);
    surfaceDrawable->surfaceHandlerUiFirst_ = std::make_shared<RSSurfaceHandler>(0);
    ASSERT_NE(surfaceDrawable->surfaceHandlerUiFirst_, nullptr);

    auto renderProcessor = std::make_shared<RSUniRenderProcessor>();
    ASSERT_NE(renderProcessor, nullptr);
    renderProcessor->CreateUIFirstLayer(*surfaceDrawable, params);
}

/**
 * @tc.name: CreateUIFirstLayer002
 * @tc.desc: Test RSUniRenderProcessorTest.CreateUIFirstLayer when params has Buffer
 * @tc.type:FUNC
 * @tc.require: issueIAIT5Z
 */
HWTEST(RSUniRenderProcessorTest, CreateUIFirstLayer002, TestSize.Level1)
{
    if (!RSUniRenderJudgement::IsUniRender()) {
        return;
    }
    RSSurfaceRenderParams params(0);
    sptr<SurfaceBuffer> buffer = OHOS::SurfaceBuffer::Create();
    params.SetBuffer(buffer, {});
    NodeId id = 1;
    auto node = std::make_shared<RSSurfaceRenderNode>(id);
    ASSERT_NE(node, nullptr);
    auto surfaceDrawable = std::make_shared<DrawableV2::RSSurfaceRenderNodeDrawable>(node);
    ASSERT_NE(surfaceDrawable, nullptr);
    surfaceDrawable->surfaceHandlerUiFirst_ = std::make_shared<RSSurfaceHandler>(0);
    ASSERT_NE(surfaceDrawable->surfaceHandlerUiFirst_, nullptr);

    auto renderProcessor = std::make_shared<RSUniRenderProcessor>();
    ASSERT_NE(renderProcessor, nullptr);
    renderProcessor->CreateUIFirstLayer(*surfaceDrawable, params);
}

/**
 * @tc.name: GetForceClientForDRM001
 * @tc.desc: Test RSUniRenderProcessorTest.GetForceClientForDRM
 * @tc.type:FUNC
 * @tc.require: issueIAIT5Z
 */
HWTEST(RSUniRenderProcessorTest, GetForceClientForDRM001, TestSize.Level1)
{
    if (!RSUniRenderJudgement::IsUniRender()) {
        return;
    }
    auto renderProcessor = std::make_shared<RSUniRenderProcessor>();
    ASSERT_NE(renderProcessor, nullptr);
    RSSurfaceRenderParams params(0);
    params.GetMultableSpecialLayerMgr().Set(SpecialLayerType::PROTECTED, false);
    ASSERT_FALSE(renderProcessor->GetForceClientForDRM(params));
}

/**
 * @tc.name: GetForceClientForDRM002
 * @tc.desc: Test RSUniRenderProcessorTest.GetForceClientForDRM
 * @tc.type:FUNC
 * @tc.require: issueIAIT5Z
 */
HWTEST(RSUniRenderProcessorTest, GetForceClientForDRM002, TestSize.Level1)
{
    if (!RSUniRenderJudgement::IsUniRender()) {
        return;
    }
    auto renderProcessor = std::make_shared<RSUniRenderProcessor>();
    ASSERT_NE(renderProcessor, nullptr);
    RSSurfaceRenderParams params(0);
    params.GetMultableSpecialLayerMgr().Set(SpecialLayerType::PROTECTED, true);
    params.animateState_ = true;
    ASSERT_TRUE(renderProcessor->GetForceClientForDRM(params));
}

/**
 * @tc.name: GetForceClientForDRM003
 * @tc.desc: Test RSUniRenderProcessorTest.GetForceClientForDRM
 * @tc.type:FUNC
 * @tc.require: issueIAIT5Z
 */
HWTEST(RSUniRenderProcessorTest, GetForceClientForDRM003, TestSize.Level1)
{
    if (!RSUniRenderJudgement::IsUniRender()) {
        return;
    }
    auto renderProcessor = std::make_shared<RSUniRenderProcessor>();
    ASSERT_NE(renderProcessor, nullptr);
    RSSurfaceRenderParams params(0);
    params.GetMultableSpecialLayerMgr().Set(SpecialLayerType::PROTECTED, true);
    params.animateState_ = false;
    ASSERT_FALSE(renderProcessor->GetForceClientForDRM(params));
    // set totalMatrix to 30 degrees
    params.totalMatrix_.PostRotate(30.0f);
    ASSERT_TRUE(renderProcessor->GetForceClientForDRM(params));
}

/**
 * @tc.name: GetForceClientForDRM004
 * @tc.desc: Test RSUniRenderProcessorTest.GetForceClientForDRM
 * @tc.type:FUNC
 * @tc.require: issueIAIT5Z
 */
HWTEST(RSUniRenderProcessorTest, GetForceClientForDRM004, TestSize.Level1)
{
    if (!RSUniRenderJudgement::IsUniRender()) {
        return;
    }
    auto renderProcessor = std::make_shared<RSUniRenderProcessor>();
    ASSERT_NE(renderProcessor, nullptr);
    RSSurfaceRenderParams params(0);
    params.GetMultableSpecialLayerMgr().Set(SpecialLayerType::PROTECTED, true);
    params.animateState_ = false;
    RSDisplayNodeConfig config;
    NodeId id = 1;
    auto node = std::make_shared<RSDisplayRenderNode>(id, config);
    std::shared_ptr<DrawableV2::RSDisplayRenderNodeDrawable> displayDrawable(
        static_cast<DrawableV2::RSDisplayRenderNodeDrawable*>(
        DrawableV2::RSDisplayRenderNodeDrawable::OnGenerate(node)));
    ASSERT_NE(displayDrawable, nullptr);
    params.ancestorDisplayDrawable_ = displayDrawable;
    displayDrawable->renderParams_ = std::make_unique<RSDisplayRenderParams>(id);
    ASSERT_NE(displayDrawable->GetRenderParams(), nullptr);
    ASSERT_FALSE(renderProcessor->GetForceClientForDRM(params));
}

/**
 * @tc.name: GetForceClientForDRM005
 * @tc.desc: Test RSUniRenderProcessorTest.GetForceClientForDRM
 * @tc.type:FUNC
 * @tc.require: issueIAIT5Z
 */
HWTEST(RSUniRenderProcessorTest, GetForceClientForDRM005, TestSize.Level1)
{
    if (!RSUniRenderJudgement::IsUniRender()) {
        return;
    }
    auto renderProcessor = std::make_shared<RSUniRenderProcessor>();
    ASSERT_NE(renderProcessor, nullptr);
    RSSurfaceRenderParams params(0);
    params.GetMultableSpecialLayerMgr().Set(SpecialLayerType::PROTECTED, true);
    params.animateState_ = false;
    ASSERT_FALSE(renderProcessor->GetForceClientForDRM(params));
    // set drm out of screen
    params.isOutOfScreen_ = false;
    ASSERT_FALSE(renderProcessor->GetForceClientForDRM(params));
    params.isOutOfScreen_ = true;
    ASSERT_TRUE(renderProcessor->GetForceClientForDRM(params));
}
}