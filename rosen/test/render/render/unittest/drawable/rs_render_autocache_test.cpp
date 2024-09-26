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
#include "drawable/rs_render_node_drawable.h"
#include "params/rs_render_params.h"
#include <parameters.h>

using namespace testing;
using namespace testing::ext;
using namespace OHOS::Rosen::DrawableV2;

namespace OHOS::Rosen {
class RSRenderAutoCacheTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void RSRenderAutoCacheTest::SetUpTestCase() {}
void RSRenderAutoCacheTest::TearDownTestCase() {}
void RSRenderAutoCacheTest::SetUp() {}
void RSRenderAutoCacheTest::TearDown() {}

/**
 * @tc.name: OpincCalculateAfterExtTest
 * @tc.desc: Test If OpincCalculateAfter Can Run
 * @tc.type: FUNC
 * @tc.require: issueIAFM3H
 */
HWTEST(RSRenderAutoCacheTest, OpincCalculateAfterExtTest, TestSize.Level1)
{
    NodeId nodeId = 0;
    auto node = std::make_shared<RSRenderNode>(nodeId);
    auto drawable = std::make_shared<RSRenderNodeDrawable>(std::move(node));
    ASSERT_NE(drawable, nullptr);
    Drawing::Canvas canvas;
    bool isOpincDropNodeExt = true;
    drawable->isOpincCaculateStart_ = true;
    drawable->OpincCalculateAfter(canvas, isOpincDropNodeExt);
    ASSERT_FALSE(drawable->IsOpListDrawAreaEnable());
}

/**
 * @tc.name: OpincCalculateBeforeExtTest
 * @tc.desc: Test If OpincCalculateBefore Can Run
 * @tc.type: FUNC
 * @tc.require: issueIAFM3H
 */
HWTEST(RSRenderAutoCacheTest, OpincCalculateBeforeExtTest, TestSize.Level1)
{
    NodeId nodeId = 0;
    auto node = std::make_shared<RSRenderNode>(nodeId);
    auto drawable = std::make_shared<RSRenderNodeDrawable>(std::move(node));
    ASSERT_NE(drawable, nullptr);
    Drawing::Canvas canvas;
    RSRenderParams params(nodeId);
    bool isOpincDropNodeExt = true;
    drawable->OpincCalculateBefore(canvas, params, isOpincDropNodeExt);
    ASSERT_TRUE(drawable->IsOpincRealDrawCacheEnable());
    ASSERT_FALSE(drawable->IsOpListDrawAreaEnable());

    drawable->rootNodeStragyType_ = NodeStrategyType::OPINC_AUTOCACHE;
    drawable->recordState_ = NodeRecordState::RECORD_CALCULATE;
    drawable->OpincCalculateBefore(canvas, params, isOpincDropNodeExt);
    ASSERT_TRUE(drawable->IsOpincRealDrawCacheEnable());
    ASSERT_TRUE(drawable->IsOpListDrawAreaEnable());
}

/**
 * @tc.name: OpincCanvasUnionTranslateExtTest
 * @tc.desc: Test If OpincCanvasUnionTranslate Can Run
 * @tc.type: FUNC
 * @tc.require: issueIAFM3H
 */
HWTEST(RSRenderAutoCacheTest, OpincCanvasUnionTranslateExtTest, TestSize.Level1)
{
    NodeId nodeId = 0;
    auto node = std::make_shared<RSRenderNode>(nodeId);
    auto drawable = std::make_shared<RSRenderNodeDrawable>(std::move(node));
    ASSERT_NE(drawable, nullptr);
    Drawing::Canvas drawingCanvas;
    RSPaintFilterCanvas canvas(&drawingCanvas);
    drawable->OpincCanvasUnionTranslate(canvas);
    ASSERT_FALSE(drawable->IsComputeDrawAreaSucc());

    drawable->isDrawAreaEnable_ = DrawAreaEnableState::DRAW_AREA_ENABLE;
    drawable->OpincCanvasUnionTranslate(canvas);
    ASSERT_TRUE(drawable->IsComputeDrawAreaSucc());
}

/**
 * @tc.name: PreDrawableCacheStateExtTest
 * @tc.desc: Test If PreDrawableCacheState Can Run
 * @tc.type: FUNC
 * @tc.require: issueIAFM3H
 */
HWTEST(RSRenderAutoCacheTest, PreDrawableCacheStateExtTest, TestSize.Level1)
{
    NodeId nodeId = 0;
    auto node = std::make_shared<RSRenderNode>(nodeId);
    auto drawable = std::make_shared<RSRenderNodeDrawable>(std::move(node));
    ASSERT_NE(drawable, nullptr);
    RSRenderParams params(nodeId);
    bool isOpincDropNodeExt = true;
    bool res = drawable->PreDrawableCacheState(params, isOpincDropNodeExt);
    ASSERT_TRUE(res);

    params.isOpincStateChanged_ = true;
    res = drawable->PreDrawableCacheState(params, isOpincDropNodeExt);
    ASSERT_TRUE(res);
}

/**
 * @tc.name: NodeCacheStateDisableExtTest
 * @tc.desc: Test If NodeCacheStateDisable Can Run
 * @tc.type: FUNC
 * @tc.require: issueIAFM3H
 */
HWTEST(RSRenderAutoCacheTest, NodeCacheStateDisableExtTest, TestSize.Level1)
{
    NodeId nodeId = 0;
    auto node = std::make_shared<RSRenderNode>(nodeId);
    auto drawable = std::make_shared<RSRenderNodeDrawable>(std::move(node));
    ASSERT_NE(drawable, nullptr);
    drawable->opCanCache_ = true;
    drawable->NodeCacheStateDisable();
    ASSERT_FALSE(drawable->opCanCache_);
    drawable->NodeCacheStateDisable();
    ASSERT_FALSE(drawable->opCanCache_);
}

/**
 * @tc.name: ResumeOpincCanvasTranslateExtTest
 * @tc.desc: Test If ResumeOpincCanvasTranslate Can Run
 * @tc.type: FUNC
 * @tc.require: issueIAFM3H
 */
HWTEST(RSRenderAutoCacheTest, ResumeOpincCanvasTranslateExtTest, TestSize.Level1)
{
    NodeId nodeId = 0;
    auto node = std::make_shared<RSRenderNode>(nodeId);
    auto drawable = std::make_shared<RSRenderNodeDrawable>(std::move(node));
    ASSERT_NE(drawable, nullptr);
    Drawing::Canvas drawingCanvas;
    RSPaintFilterCanvas canvas(&drawingCanvas);
    drawable->ResumeOpincCanvasTranslate(canvas);
    ASSERT_FALSE(drawable->IsComputeDrawAreaSucc());

    drawable->isDrawAreaEnable_ = DrawAreaEnableState::DRAW_AREA_ENABLE;
    drawable->ResumeOpincCanvasTranslate(canvas);
    ASSERT_TRUE(drawable->IsComputeDrawAreaSucc());
}

/**
 * @tc.name: BeforeDrawCacheFindRootNodeSingleTest
 * @tc.desc: Test If BeforeDrawCacheFindRootNode Can Run
 * @tc.type: FUNC
 * @tc.require: issueIAFM3H
 */
HWTEST(RSRenderAutoCacheTest, BeforeDrawCacheFindRootNodeSingleTest, TestSize.Level1)
{
    NodeId nodeId = 0;
    auto node = std::make_shared<RSRenderNode>(nodeId);
    auto drawable = std::make_shared<RSRenderNodeDrawable>(std::move(node));
    ASSERT_NE(drawable, nullptr);
    Drawing::Canvas canvas;
    RSRenderParams params(nodeId);
    bool isOpincDropNodeExt = true;
    params.isOpincRootFlag_ = true;
    params.cacheSize_.x_ = 51; // for test
    params.cacheSize_.y_ = 51; // for test
    drawable->BeforeDrawCacheFindRootNode(canvas, params, isOpincDropNodeExt);
    ASSERT_TRUE(params.OpincGetRootFlag());

    params.cacheSize_.y_ = 0; // for test
    drawable->BeforeDrawCacheFindRootNode(canvas, params, isOpincDropNodeExt);
    ASSERT_FALSE(params.cacheSize_.y_);

    params.cacheSize_.x_ = 0; // for test
    drawable->BeforeDrawCacheFindRootNode(canvas, params, isOpincDropNodeExt);
    ASSERT_FALSE(params.cacheSize_.x_);

    params.isOpincRootFlag_ = false;
    drawable->BeforeDrawCacheFindRootNode(canvas, params, isOpincDropNodeExt);
    ASSERT_FALSE(params.OpincGetRootFlag());
}

/**
 * @tc.name: BeforeDrawCacheProcessChildNodeSingleTest
 * @tc.desc: Test If BeforeDrawCacheProcessChildNode Can Run
 * @tc.type: FUNC
 * @tc.require: issueIAFM3H
 */
HWTEST(RSRenderAutoCacheTest, BeforeDrawCacheProcessChildNodeSingleTest, TestSize.Level1)
{
    NodeId nodeId = 0;
    auto node = std::make_shared<RSRenderNode>(nodeId);
    auto drawable = std::make_shared<RSRenderNodeDrawable>(std::move(node));
    ASSERT_NE(drawable, nullptr);
    RSRenderParams params(nodeId);
    NodeStrategyType cacheStragy = NodeStrategyType::CACHE_NONE;
    params.isOpincRootFlag_ = true;
    bool res = drawable->BeforeDrawCacheProcessChildNode(cacheStragy, params);
    ASSERT_TRUE(res);

    params.isOpincRootFlag_ = false;
    drawable->recordState_ = NodeRecordState::RECORD_CACHED;
    drawable->rootNodeStragyType_ = NodeStrategyType::OPINC_AUTOCACHE;
    res = drawable->BeforeDrawCacheProcessChildNode(cacheStragy, params);
    ASSERT_FALSE(res);

    cacheStragy = NodeStrategyType::CACHE_DISABLE;
    drawable->recordState_ = NodeRecordState::RECORD_CACHED;
    drawable->rootNodeStragyType_ = NodeStrategyType::CACHE_DISABLE;
    res = drawable->BeforeDrawCacheProcessChildNode(cacheStragy, params);
    ASSERT_FALSE(res);

    drawable->recordState_ = NodeRecordState::RECORD_CALCULATE;
    res = drawable->BeforeDrawCacheProcessChildNode(cacheStragy, params);
    ASSERT_FALSE(res);
}

/**
 * @tc.name: AfterDrawCacheSingleTest
 * @tc.desc: Test If AfterDrawCache Can Run
 * @tc.type: FUNC
 * @tc.require: issueIAFM3H
 */
HWTEST(RSRenderAutoCacheTest, AfterDrawCacheSingleTest, TestSize.Level1)
{
    NodeId nodeId = 0;
    auto node = std::make_shared<RSRenderNode>(nodeId);
    auto drawable = std::make_shared<RSRenderNodeDrawable>(std::move(node));
    ASSERT_NE(drawable, nullptr);
    NodeStrategyType cacheStragy = NodeStrategyType::CACHE_NONE;
    Drawing::Canvas canvas;
    RSRenderParams params(nodeId);
    bool isOpincDropNodeExt = true;
    int opincRootTotalCount = 0;
    drawable->autoCacheEnable_ = false;
    drawable->AfterDrawCache(cacheStragy, canvas, params, isOpincDropNodeExt, opincRootTotalCount);
    ASSERT_FALSE(drawable->autoCacheEnable_);
    drawable->autoCacheEnable_ = true;
    drawable->rootNodeStragyType_ = NodeStrategyType::OPINC_AUTOCACHE;
    drawable->AfterDrawCache(cacheStragy, canvas, params, isOpincDropNodeExt, opincRootTotalCount);
    drawable->recordState_ = NodeRecordState::RECORD_CALCULATE;
    drawable->AfterDrawCache(cacheStragy, canvas, params, isOpincDropNodeExt, opincRootTotalCount);
    ASSERT_TRUE(drawable->recordState_ == NodeRecordState::RECORD_CALCULATE);

    drawable->isDrawAreaEnable_ = DrawAreaEnableState::DRAW_AREA_ENABLE;
    drawable->AfterDrawCache(cacheStragy, canvas, params, isOpincDropNodeExt, opincRootTotalCount);
    ASSERT_FALSE(drawable->isDrawAreaEnable_ == DrawAreaEnableState::DRAW_AREA_DISABLE);
    drawable->isDrawAreaEnable_ = DrawAreaEnableState::DRAW_AREA_DISABLE;
    drawable->AfterDrawCache(cacheStragy, canvas, params, isOpincDropNodeExt, opincRootTotalCount);
    ASSERT_FALSE(drawable->isDrawAreaEnable_ == DrawAreaEnableState::DRAW_AREA_ENABLE);
    drawable->recordState_ = NodeRecordState::RECORD_CACHING;
    drawable->rootNodeStragyType_ = NodeStrategyType::OPINC_AUTOCACHE;
    drawable->AfterDrawCache(cacheStragy, canvas, params, isOpincDropNodeExt, opincRootTotalCount);
    ASSERT_FALSE(drawable->OpincGetCachedMark());

    opincRootTotalCount = 0;
    drawable->isOpincMarkCached_ = true;
    ASSERT_TRUE(drawable->OpincGetCachedMark());
    drawable->AfterDrawCache(cacheStragy, canvas, params, isOpincDropNodeExt, opincRootTotalCount);
    opincRootTotalCount = 2;
    drawable->isOpincMarkCached_ = true;
    drawable->AfterDrawCache(cacheStragy, canvas, params, isOpincDropNodeExt, opincRootTotalCount);
    ASSERT_TRUE(drawable->OpincGetCachedMark());
}

/**
 * @tc.name: BeforeDrawCacheSingleTest
 * @tc.desc: Test If BeforeDrawCache Can Run
 * @tc.type: FUNC
 * @tc.require: issueIAFM3H
 */
HWTEST(RSRenderAutoCacheTest, BeforeDrawCacheSingleTest, TestSize.Level1)
{
    NodeId nodeId = 0;
    auto node = std::make_shared<RSRenderNode>(nodeId);
    auto drawable = std::make_shared<RSRenderNodeDrawable>(std::move(node));
    ASSERT_NE(drawable, nullptr);
    NodeStrategyType cacheStragy = NodeStrategyType::CACHE_NONE;
    Drawing::Canvas canvas;
    RSRenderParams params(nodeId);
    bool isOpincDropNodeExt = true;
    drawable->BeforeDrawCache(cacheStragy, canvas, params, isOpincDropNodeExt);
    ASSERT_FALSE(drawable->autoCacheEnable_);

    drawable->autoCacheEnable_ = true;
    params.isOpincRootFlag_ = true;
    drawable->recordState_ = NodeRecordState::RECORD_NONE;
    drawable->BeforeDrawCache(cacheStragy, canvas, params, isOpincDropNodeExt);
    ASSERT_TRUE(drawable->autoCacheEnable_);
    ASSERT_TRUE(drawable->BeforeDrawCacheProcessChildNode(cacheStragy, params));
    drawable->recordState_ = NodeRecordState::RECORD_CALCULATE;
    drawable->BeforeDrawCache(cacheStragy, canvas, params, isOpincDropNodeExt);
    drawable->recordState_ = NodeRecordState::RECORD_CACHING;
    drawable->BeforeDrawCache(cacheStragy, canvas, params, isOpincDropNodeExt);
    drawable->recordState_ = NodeRecordState::RECORD_CACHED;
    drawable->BeforeDrawCache(cacheStragy, canvas, params, isOpincDropNodeExt);
    ASSERT_EQ(drawable->reuseCount_, 0);
    drawable->recordState_ = NodeRecordState::RECORD_DISABLE;
    drawable->BeforeDrawCache(cacheStragy, canvas, params, isOpincDropNodeExt);

    cacheStragy = NodeStrategyType::CACHE_DISABLE;
    drawable->BeforeDrawCache(cacheStragy, canvas, params, isOpincDropNodeExt);
    ASSERT_FALSE(drawable->BeforeDrawCacheProcessChildNode(cacheStragy, params));
}

/**
 * @tc.name: DrawAutoCacheDfxExtTest
 * @tc.desc: Test If DrawAutoCacheDfx Can Run
 * @tc.type: FUNC
 * @tc.require: issueIAFM3H
 */
HWTEST(RSRenderAutoCacheTest, DrawAutoCacheDfxExtTest, TestSize.Level1)
{
    NodeId nodeId = 0;
    auto node = std::make_shared<RSRenderNode>(nodeId);
    auto drawable = std::make_shared<RSRenderNodeDrawable>(std::move(node));
    ASSERT_NE(drawable, nullptr);
    Drawing::Canvas drawingCanvas;
    RSPaintFilterCanvas canvas(&drawingCanvas);
    std::vector<std::pair<RectI, std::string>> autoCacheRenderNodeInfos;
    drawable->DrawAutoCacheDfx(canvas, autoCacheRenderNodeInfos);
    ASSERT_FALSE(drawable->IsAutoCacheDebugEnable());
    auto debugtype = system::GetParameter("persist.rosen.ddgr.opinctype.debugtype", "0");
    system::SetParameter("persist.rosen.ddgr.opinctype.debugtype", "1");
#ifdef DDGR_ENABLE_FEATURE_OPINC_DFX
    drawable->DrawAutoCacheDfx(canvas, autoCacheRenderNodeInfos);
    drawable->opListDrawAreas_.opInfo_.unionRect = { 0.f, 0.f, 1.f, 1.f };
    drawable->DrawAutoCacheDfx(canvas, autoCacheRenderNodeInfos);
    Drawing::RectF rect(1.f, 1.f, 1.f, 1.f);
    drawable->opListDrawAreas_.opInfo_.drawAreaRects.push_back(rect);
#endif
    drawable->DrawAutoCacheDfx(canvas, autoCacheRenderNodeInfos);
    system::SetParameter("persist.rosen.ddgr.opinctype.debugtype", debugtype);
}

/**
 * @tc.name: DrawAutoCacheExtTest
 * @tc.desc: Test If DrawAutoCache Can Run
 * @tc.type: FUNC
 * @tc.require: issueIAFM3H
 */
HWTEST(RSRenderAutoCacheTest, DrawAutoCacheExtTest, TestSize.Level1)
{
    NodeId nodeId = 0;
    auto node = std::make_shared<RSRenderNode>(nodeId);
    auto drawable = std::make_shared<RSRenderNodeDrawable>(std::move(node));
    ASSERT_NE(drawable, nullptr);
    Drawing::Canvas drawingCanvas;
    RSPaintFilterCanvas canvas(&drawingCanvas);
    Drawing::Image image;
    Drawing::SamplingOptions samplingOption;
    Drawing::SrcRectConstraint constraint = Drawing::SrcRectConstraint::FAST_SRC_RECT_CONSTRAINT;
    bool res = drawable->DrawAutoCache(canvas, image, samplingOption, constraint);
    ASSERT_FALSE(res);

    drawable->isDrawAreaEnable_ = DrawAreaEnableState::DRAW_AREA_ENABLE;
    res = drawable->DrawAutoCache(canvas, image, samplingOption, constraint);
    ASSERT_FALSE(res);

    drawable->opCanCache_ = true;
    res = drawable->DrawAutoCache(canvas, image, samplingOption, constraint);
    ASSERT_FALSE(res);

    drawable->opListDrawAreas_.opInfo_.unionRect = { 0.f, 0.f, 1.f, 1.f }; // for test
    res = drawable->DrawAutoCache(canvas, image, samplingOption, constraint);
    ASSERT_FALSE(res);

    Drawing::RectF rect(1.f, 1.f, 1.f, 1.f); // for test
    drawable->opListDrawAreas_.opInfo_.drawAreaRects.push_back(rect);
    res = drawable->DrawAutoCache(canvas, image, samplingOption, constraint);
    ASSERT_TRUE(res);
}

/**
 * @tc.name: GetNodeDebugInfoSingleTest
 * @tc.desc: Test If GetNodeDebugInfo Can Run
 * @tc.type: FUNC
 * @tc.require: issueIAFM3H
 */
HWTEST(RSRenderAutoCacheTest, GetNodeDebugInfoSingleTest, TestSize.Level1)
{
    NodeId nodeId = 0;
    auto node = std::make_shared<RSRenderNode>(nodeId);
    auto drawable = std::make_shared<RSRenderNodeDrawable>(std::move(node));
    ASSERT_NE(drawable, nullptr);
#ifdef DDGR_ENABLE_FEATURE_OPINC_DFX
    std::string res = drawable->GetNodeDebugInfo();
    ASSERT_TRUE(res.empty());
    drawable->renderParams_ = std::make_unique<RSRenderParams>(0);
    res = drawable->GetNodeDebugInfo();
    ASSERT_FALSE(res.empty());
#endif
    std::string result = drawable->GetNodeDebugInfo();
    ASSERT_TRUE(result.empty());
}
}
