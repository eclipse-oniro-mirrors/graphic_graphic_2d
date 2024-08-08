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

#include "drawable/rs_misc_drawable.h"
#include "drawable/rs_render_node_drawable.h"
#include "params/rs_render_params.h"
#include "pipeline/rs_canvas_drawing_render_node.h"
#include "pipeline/rs_context.h"
#include "pipeline/rs_display_render_node.h"
#include "pipeline/rs_effect_render_node.h"
#include "pipeline/rs_render_node.h"
#include "pipeline/rs_surface_render_node.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::Rosen::DrawableV2;

namespace OHOS::Rosen {
class RSChildrenDrawableBrotherAdapter : public RSDrawable {
public:
    RSChildrenDrawableBrotherAdapter() = default;
    ~RSChildrenDrawableBrotherAdapter() override = default;
    bool OnUpdate(const RSRenderNode& content) override
    {
        return true;
    }
    void OnSync() override {}
    Drawing::RecordingCanvas::DrawFunc CreateDrawFunc() const override
    {
        auto ptr = std::static_pointer_cast<const RSChildrenDrawableBrotherAdapter>(shared_from_this());
        return [ptr](Drawing::Canvas* canvas, const Drawing::Rect* rect) {
            for (const auto& drawable : ptr->childrenDrawableVec_) {
                drawable->Draw(*canvas);
            }
        };
    }

private:
    bool needSync_ = false;
    std::vector<std::shared_ptr<RSRenderNodeDrawableAdapter>> childrenDrawableVec_;
    std::vector<std::shared_ptr<RSRenderNodeDrawableAdapter>> stagingChildrenDrawableVec_;

    // Shared Transition related
    bool childrenHasSharedTransition_ = false;
    bool OnSharedTransition(const std::shared_ptr<RSRenderNode>& node)
    {
        return true;
    }
    friend class RSRenderNode;
    friend class RSRenderNodeDrawableAdapter;
};
class RSRenderNodeDrawableAdapterTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void RSRenderNodeDrawableAdapterTest::SetUpTestCase() {}
void RSRenderNodeDrawableAdapterTest::TearDownTestCase() {}
void RSRenderNodeDrawableAdapterTest::SetUp() {}
void RSRenderNodeDrawableAdapterTest::TearDown() {}

/**
 * @tc.name: OnGenerateTest
 * @tc.desc: Test OnGenerateTree
 * @tc.type: FUNC
 * @tc.require: issueI9UTMA
 */
HWTEST(RSRenderNodeDrawableAdapterTest, OnGenerateTest, TestSize.Level1)
{
    NodeId id = 0;
    std::shared_ptr<RSRenderNode> renderNode;
    auto retAdapter = RSRenderNodeDrawableAdapter::OnGenerate(renderNode);
    EXPECT_TRUE(retAdapter == nullptr);

    renderNode = std::make_shared<RSRenderNode>(id);
    retAdapter = RSRenderNodeDrawableAdapter::OnGenerate(renderNode);
    EXPECT_NE(retAdapter, nullptr);
    EXPECT_TRUE(!RSRenderNodeDrawableAdapter::RenderNodeDrawableCache_.empty());

    RSRenderNodeDrawableAdapter::WeakPtr wNode;
    renderNode->renderDrawable_ = nullptr;
    RSRenderNodeDrawableAdapter::RenderNodeDrawableCache_.clear();
    RSRenderNodeDrawableAdapter::RenderNodeDrawableCache_.emplace(id, wNode);
    auto tmpGeneratorMap = RSRenderNodeDrawableAdapter::GeneratorMap;
    RSRenderNodeDrawableAdapter::GeneratorMap.clear();
    retAdapter = RSRenderNodeDrawableAdapter::OnGenerate(renderNode);
    EXPECT_EQ(retAdapter, nullptr);
    EXPECT_TRUE(RSRenderNodeDrawableAdapter::RenderNodeDrawableCache_.empty());
    RSRenderNodeDrawableAdapter::GeneratorMap = tmpGeneratorMap;
    EXPECT_TRUE(!RSRenderNodeDrawableAdapter::GeneratorMap.empty());

    auto adapterNode = std::make_shared<RSRenderNode>(id + 1);
    auto adapter = std::make_shared<RSRenderNodeDrawable>(std::move(adapterNode));
    wNode = adapter;
    RSRenderNodeDrawableAdapter::RenderNodeDrawableCache_.emplace(id, wNode);
    retAdapter = RSRenderNodeDrawableAdapter::OnGenerate(renderNode);
    EXPECT_NE(retAdapter, nullptr);
    RSRenderNodeDrawableAdapter::RenderNodeDrawableCache_.clear();

    auto otherNode = std::make_shared<RSRenderNode>(id + 2);
    renderNode->renderDrawable_ = std::make_shared<RSRenderNodeDrawable>(otherNode);
    retAdapter = RSRenderNodeDrawableAdapter::OnGenerate(renderNode);
    EXPECT_NE(retAdapter, nullptr);
}

/**
 * @tc.name: GetDrawableByIdTest
 * @tc.desc: Test GetDrawableByIdTree
 * @tc.type: FUNC
 * @tc.require: issueI9UTMA
 */
HWTEST(RSRenderNodeDrawableAdapterTest, GetDrawableByIdTest, TestSize.Level1)
{
    NodeId id = 1;
    auto retAdapter = RSRenderNodeDrawableAdapter::GetDrawableById(id);
    EXPECT_EQ(retAdapter, nullptr);

    auto adapterNode = std::make_shared<RSRenderNode>(id + 1);
    auto adapter = std::make_shared<RSRenderNodeDrawable>(std::move(adapterNode));
    RSRenderNodeDrawableAdapter::WeakPtr wNode = adapter;
    RSRenderNodeDrawableAdapter::RenderNodeDrawableCache_.emplace(id, wNode);
    retAdapter = RSRenderNodeDrawableAdapter::GetDrawableById(id);
    EXPECT_NE(retAdapter, nullptr);
    RSRenderNodeDrawableAdapter::RenderNodeDrawableCache_.clear();
}

/**
 * @tc.name: OnGenerateShadowDrawableTest
 * @tc.desc: Test OnGenerateShadowDrawableTree
 * @tc.type: FUNC
 * @tc.require: issueI9UTMA
 */
HWTEST(RSRenderNodeDrawableAdapterTest, OnGenerateShadowDrawableTest, TestSize.Level1)
{
    std::shared_ptr<RSRenderNode> node;
    std::shared_ptr<RSRenderNodeDrawableAdapter> drawable;
    auto retAdapter = RSRenderNodeDrawableAdapter::OnGenerateShadowDrawable(node, drawable);
    EXPECT_EQ(retAdapter, nullptr);

    NodeId id = 2;
    node = std::make_shared<RSRenderNode>(id);
    auto adapterNode = std::make_shared<RSRenderNode>(id + 1);
    drawable = std::make_shared<RSRenderNodeDrawable>(std::move(adapterNode));
    retAdapter = RSRenderNodeDrawableAdapter::OnGenerateShadowDrawable(node, drawable);
    EXPECT_NE(retAdapter, nullptr);

    // for cache
    retAdapter = RSRenderNodeDrawableAdapter::OnGenerateShadowDrawable(node, drawable);
    EXPECT_NE(retAdapter, nullptr);
}

/**
 * @tc.name: GetRenderParamsAndGetUifirstRenderParamsTest
 * @tc.desc: Test GetRenderParamsAndGetUifirstRenderParams
 * @tc.type: FUNC
 * @tc.require: issueI9UTMA
 */
HWTEST(RSRenderNodeDrawableAdapterTest, GetRenderParamsAndGetUifirstRenderParamsTest, TestSize.Level1)
{
    NodeId id = 4;
    auto node = std::make_shared<RSRenderNode>(id);
    auto adapter = std::make_shared<RSRenderNodeDrawable>(std::move(node));
    const auto& retParams = adapter->GetRenderParams();
    EXPECT_EQ(retParams, nullptr);
    const auto& retUifirstParams = adapter->GetUifirstRenderParams();
    EXPECT_EQ(retUifirstParams, nullptr);
}

/**
 * @tc.name: QuickRejectTest
 * @tc.desc: Test QuickReject
 * @tc.type: FUNC
 * @tc.require: issueI9UTMA
 */
HWTEST(RSRenderNodeDrawableAdapterTest, QuickRejectTest, TestSize.Level1)
{
    NodeId id = 6;
    auto node = std::make_shared<RSRenderNode>(id);
    auto adapter = std::make_shared<RSRenderNodeDrawable>(std::move(node));
    Drawing::Canvas drawingCanvas;
    RSPaintFilterCanvas canvas(&drawingCanvas);
    RectF rectF;
    rectF.SetRight(1.0f);
    auto ret = adapter->QuickReject(canvas, rectF);
    EXPECT_FALSE(ret);
    EXPECT_TRUE(canvas.IsDirtyRegionStackEmpty());
    EXPECT_FALSE(canvas.GetIsParallelCanvas());

    canvas.dirtyRegionStack_.emplace(Drawing::Region());
    auto mainCanvas = std::make_shared<Drawing::Canvas>();
    canvas.storeMainCanvas_ = mainCanvas.get();
    std::shared_ptr<Drawing::Surface> offscreenSurface = std::make_shared<Drawing::Surface>();
    std::shared_ptr<RSPaintFilterCanvas> offscreenCanvas = std::make_shared<RSPaintFilterCanvas>(&drawingCanvas);
    RSPaintFilterCanvas::OffscreenData offscreenData = { offscreenSurface, offscreenCanvas };
    canvas.offscreenDataList_.emplace(offscreenData);
    EXPECT_TRUE(canvas.GetOriginalCanvas() != nullptr);
    EXPECT_TRUE(!canvas.GetOffscreenDataList().empty());
    EXPECT_TRUE(!canvas.IsDirtyRegionStackEmpty() && !canvas.GetIsParallelCanvas());
    ret = adapter->QuickReject(canvas, rectF);
}

/**
 * @tc.name: HasFilterOrEffectTest
 * @tc.desc: Test HasFilterOrEffect
 * @tc.type: FUNC
 * @tc.require: issueI9UTMA
 */
HWTEST(RSRenderNodeDrawableAdapterTest, HasFilterOrEffectTest, TestSize.Level1)
{
    NodeId id = 7;
    auto node = std::make_shared<RSRenderNode>(id);
    auto adapter = std::make_shared<RSRenderNodeDrawable>(std::move(node));
    auto ret = adapter->HasFilterOrEffect();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: DrawRangeImplAndRelatedTest
 * @tc.desc: Test DrawRangeImplAndRelated
 * @tc.type: FUNC
 * @tc.require: issueI9UTMA
 */
HWTEST(RSRenderNodeDrawableAdapterTest, DrawRangeImplAndRelatedTest, TestSize.Level1)
{
    NodeId id = 8;
    auto node = std::make_shared<RSRenderNode>(id);
    auto adapter = std::make_shared<RSRenderNodeDrawable>(std::move(node));
    Drawing::Canvas drawingCanvas;
    Drawing::Rect rect;
    adapter->DrawForeground(drawingCanvas, rect);
    adapter->DrawBackground(drawingCanvas, rect);
    adapter->DrawBeforeCacheWithForegroundFilter(drawingCanvas, rect);
    adapter->DrawCacheWithForegroundFilter(drawingCanvas, rect);
    adapter->DrawAfterCacheWithForegroundFilter(drawingCanvas, rect);
    adapter->DrawCacheWithProperty(drawingCanvas, rect);
    adapter->DrawBeforeCacheWithProperty(drawingCanvas, rect);
    adapter->DrawAfterCacheWithProperty(drawingCanvas, rect);
    adapter->DrawAll(drawingCanvas, rect);
    EXPECT_TRUE(adapter->drawCmdList_.empty());

    Drawing::RecordingCanvas::DrawFunc drawFuncCallBack = [](Drawing::Canvas* canvas, const Drawing::Rect* rect) {
        printf("DrawRangeImplTest drawFuncCallBack\n");
    };
    adapter->drawCmdList_.emplace_back(drawFuncCallBack);
    adapter->drawCmdList_.emplace_back(drawFuncCallBack);
    adapter->drawCmdList_.emplace_back(drawFuncCallBack);
    adapter->drawCmdList_.emplace_back(drawFuncCallBack);
    auto start = 0;
    auto end = adapter->drawCmdList_.size();
    EXPECT_FALSE(adapter->drawCmdList_.empty() || start < 0 || end < 0 || start > end);
    EXPECT_TRUE(adapter->skipType_ == SkipType::NONE);
    adapter->DrawRangeImpl(drawingCanvas, rect, start, end);

    adapter->skipType_ = SkipType::SKIP_BACKGROUND_COLOR;
    adapter->drawCmdIndex_.backgroundColorIndex_ = end - 2;
    auto skipIndex = adapter->GetSkipIndex();
    EXPECT_LE(start, skipIndex);
    EXPECT_GT(end, skipIndex);
    adapter->DrawRangeImpl(drawingCanvas, rect, start, end);

    std::vector<Drawing::RecordingCanvas::DrawFunc> drawCmdList;
    adapter->drawCmdList_.swap(drawCmdList);
}

/**
 * @tc.name: DrawUifirstContentChildrenTest
 * @tc.desc: Test DrawUifirstContentChildren
 * @tc.type: FUNC
 * @tc.require: issueI9UTMA
 */
HWTEST(RSRenderNodeDrawableAdapterTest, DrawUifirstContentChildrenTest, TestSize.Level1)
{
    NodeId id = 9;
    auto node = std::make_shared<RSRenderNode>(id);
    auto adapter = std::make_shared<RSRenderNodeDrawable>(std::move(node));
    Drawing::Canvas canvas;
    Drawing::Rect rect;
    adapter->DrawUifirstContentChildren(canvas, rect);
    EXPECT_TRUE(adapter->uifirstDrawCmdList_.empty());

    Drawing::RecordingCanvas::DrawFunc drawuIFuncCallBack = [](Drawing::Canvas* canvas, const Drawing::Rect* rect) {
        printf("DrawUifirstContentChildrenTest drawuIFuncCallBack\n");
    };
    adapter->uifirstDrawCmdList_.emplace_back(drawuIFuncCallBack);
    EXPECT_TRUE(!adapter->uifirstDrawCmdList_.empty());
    adapter->uifirstDrawCmdIndex_.contentIndex_ = 0;
    adapter->uifirstDrawCmdIndex_.childrenIndex_ = 0;
    adapter->DrawUifirstContentChildren(canvas, rect);
    std::vector<Drawing::RecordingCanvas::DrawFunc> uifirstDrawCmdIndex;
    adapter->uifirstDrawCmdList_.swap(uifirstDrawCmdIndex);
}

/**
 * @tc.name: DrawContentTest
 * @tc.desc: Test DrawContent
 * @tc.type: FUNC
 * @tc.require: issueI9UTMA
 */
HWTEST(RSRenderNodeDrawableAdapterTest, DrawContentTest, TestSize.Level1)
{
    NodeId id = 10;
    auto node = std::make_shared<RSRenderNode>(id);
    auto adapter = std::make_shared<RSRenderNodeDrawable>(std::move(node));
    Drawing::Rect rect;
    Drawing::Canvas canvas;
    EXPECT_TRUE(adapter->drawCmdList_.empty());
    adapter->DrawContent(canvas, rect);

    Drawing::RecordingCanvas::DrawFunc drawFuncCallBack = [](Drawing::Canvas* canvas, const Drawing::Rect* rect) {
        printf("DrawContentTest drawFuncCallBack\n");
    };
    adapter->drawCmdList_.emplace_back(drawFuncCallBack);
    EXPECT_EQ(adapter->drawCmdIndex_.contentIndex_, -1);
    adapter->DrawContent(canvas, rect);

    adapter->drawCmdIndex_.contentIndex_ = 0;
    adapter->DrawContent(canvas, rect);
}

/**
 * @tc.name: DrawChildrenTest
 * @tc.desc: Test DrawChildren
 * @tc.type: FUNC
 * @tc.require: issueI9UTMA
 */
HWTEST(RSRenderNodeDrawableAdapterTest, DrawChildrenTest, TestSize.Level1)
{
    NodeId id = 11;
    auto node = std::make_shared<RSRenderNode>(id);
    auto adapter = std::make_shared<RSRenderNodeDrawable>(std::move(node));
    Drawing::Rect rect;
    Drawing::Canvas canvas;
    adapter->DrawChildren(canvas, rect);
    EXPECT_TRUE(adapter->drawCmdList_.empty());

    Drawing::RecordingCanvas::DrawFunc drawFuncCallBack = [](Drawing::Canvas* canvas, const Drawing::Rect* rect) {
        printf("DrawChildrenTest drawFuncCallBack\n");
    };
    adapter->drawCmdList_.emplace_back(drawFuncCallBack);
    adapter->DrawContent(canvas, rect);
    EXPECT_EQ(adapter->drawCmdIndex_.contentIndex_, -1);

    adapter->drawCmdIndex_.contentIndex_ = 0;
    adapter->DrawContent(canvas, rect);
}

/**
 * @tc.name: DrawImplTest
 * @tc.desc: Test DrawImpl
 * @tc.type: FUNC
 * @tc.require: issueI9UTMA
 */
HWTEST(RSRenderNodeDrawableAdapterTest, DrawImplTest, TestSize.Level1)
{
    NodeId id = 12;
    auto node = std::make_shared<RSRenderNode>(id);
    auto adapter = std::make_shared<RSRenderNodeDrawable>(std::move(node));
    int8_t index = -1;
    Drawing::Rect rect;
    Drawing::Canvas canvas;
    adapter->DrawImpl(canvas, rect, index);
    EXPECT_TRUE(adapter->drawCmdList_.empty());

    index = 0;
    Drawing::RecordingCanvas::DrawFunc drawFuncCallBack = [](Drawing::Canvas* canvas, const Drawing::Rect* rect) {
        printf("DrawChildrenTest drawFuncCallBack\n");
    };
    adapter->drawCmdList_.emplace_back(drawFuncCallBack);
    EXPECT_FALSE(
        adapter->drawCmdList_.empty() || index < 0 || index >= static_cast<int8_t>(adapter->drawCmdList_.size()));
    adapter->DrawImpl(canvas, rect, index);

    adapter->skipType_ = SkipType::SKIP_SHADOW;
    adapter->drawCmdIndex_.shadowIndex_ = index;
    EXPECT_TRUE(adapter->GetSkipIndex() == index);
    adapter->DrawImpl(canvas, rect, index);
}

/**
 * @tc.name: InitRenderParamsTest
 * @tc.desc: Test InitRenderParams
 * @tc.type: FUNC
 * @tc.require: issueI9UTMA
 */
HWTEST(RSRenderNodeDrawableAdapterTest, InitRenderParamsTest, TestSize.Level1)
{
    NodeId id = 13;
    auto node = std::make_shared<RSRenderNode>(id);
    auto adapter =
        std::dynamic_pointer_cast<RSRenderNodeDrawableAdapter>(std::make_shared<RSRenderNodeDrawable>(std::move(node)));

    auto rSSurfaceRenderNode = std::make_shared<const RSSurfaceRenderNode>(id);
    EXPECT_TRUE(adapter->renderParams_ == nullptr);
    RSRenderNodeDrawableAdapter::InitRenderParams(rSSurfaceRenderNode, adapter);
    EXPECT_TRUE(adapter->renderParams_ != nullptr);
    adapter->renderParams_.reset(nullptr);

    RSDisplayNodeConfig config;
    auto rSDisplayRenderNode = std::make_shared<const RSDisplayRenderNode>(id, config);
    EXPECT_TRUE(adapter->renderParams_ == nullptr);
    RSRenderNodeDrawableAdapter::InitRenderParams(rSDisplayRenderNode, adapter);
    EXPECT_TRUE(adapter->renderParams_ != nullptr);
    adapter->renderParams_.reset(nullptr);

    auto rSEffectRenderNode = std::make_shared<const RSEffectRenderNode>(id);
    EXPECT_TRUE(adapter->renderParams_ == nullptr);
    RSRenderNodeDrawableAdapter::InitRenderParams(rSEffectRenderNode, adapter);
    EXPECT_TRUE(adapter->renderParams_ != nullptr);
    adapter->renderParams_.reset(nullptr);

    auto rSCanvasDrawingRenderNode = std::make_shared<const RSCanvasDrawingRenderNode>(id);
    EXPECT_TRUE(adapter->renderParams_ == nullptr);
    RSRenderNodeDrawableAdapter::InitRenderParams(rSCanvasDrawingRenderNode, adapter);
    EXPECT_TRUE(adapter->renderParams_ != nullptr);
    adapter->renderParams_.reset(nullptr);

    auto defaultRenderNode = std::make_shared<const RSRenderNode>(id);
    EXPECT_TRUE(adapter->renderParams_ == nullptr);
    RSRenderNodeDrawableAdapter::InitRenderParams(defaultRenderNode, adapter);
    EXPECT_TRUE(adapter->renderParams_ != nullptr);
    adapter->renderParams_.reset(nullptr);
}

/**
 * @tc.name: GetSkipIndexTest
 * @tc.desc: Test GetSkipIndex
 * @tc.type: FUNC
 * @tc.require: issueI9UTMA
 */
HWTEST(RSRenderNodeDrawableAdapterTest, GetSkipIndexTest, TestSize.Level1)
{
    NodeId id = 14;
    auto node = std::make_shared<RSRenderNode>(id);
    auto adapter = std::make_shared<RSRenderNodeDrawable>(std::move(node));
    adapter->drawCmdIndex_.backgroundColorIndex_ = 1;
    adapter->drawCmdIndex_.shadowIndex_ = 2;
    auto ret = adapter->GetSkipIndex();
    EXPECT_EQ(ret, -1);

    adapter->skipType_ = SkipType::SKIP_BACKGROUND_COLOR;
    ret = adapter->GetSkipIndex();
    EXPECT_EQ(ret, adapter->drawCmdIndex_.backgroundColorIndex_);

    adapter->skipType_ = SkipType::SKIP_SHADOW;
    ret = adapter->GetSkipIndex();
    EXPECT_EQ(ret, adapter->drawCmdIndex_.shadowIndex_);
}
} // namespace OHOS::Rosen
