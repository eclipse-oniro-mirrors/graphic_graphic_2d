/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "rs_test_util.h"
#include "surface_buffer_impl.h"
#include "surface_type.h"

#include "drawable/rs_display_render_node_drawable.h"
#include "drawable/rs_surface_render_node_drawable.h"
#include "params/rs_surface_render_params.h"
#include "pipeline/rs_main_thread.h"
#include "pipeline/rs_surface_capture_task_parallel.h"
#include "pipeline/rs_uni_render_util.h"
#include "pixel_map.h"
#include "property/rs_properties_def.h"
#include "render/rs_material_filter.h"
#include "render/rs_shadow.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::Rosen::DrawableV2;

namespace OHOS::Rosen {
class RSUniRenderUtilTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;

private:
    static std::shared_ptr<Drawing::Image> CreateSkImage();
};

std::shared_ptr<Drawing::Image> CreateSkImage()
{
    const Drawing::ImageInfo info =
    Drawing::ImageInfo{200, 200, Drawing::COLORTYPE_N32, Drawing::ALPHATYPE_OPAQUE };
    auto surface = Drawing::Surface::MakeRaster(info);
    auto canvas = surface->GetCanvas();
    canvas->Clear(Drawing::Color::COLOR_YELLOW);
    Drawing::Brush paint;
    paint.SetColor(Drawing::Color::COLOR_RED);
    canvas->AttachBrush(paint);
    canvas->DrawRect(Drawing::Rect(50, 50, 100, 100));
    canvas->DetachBrush();
    return surface->GetImageSnapshot();
}

void RSUniRenderUtilTest::SetUpTestCase()
{
    RSTestUtil::InitRenderNodeGC();
}
void RSUniRenderUtilTest::TearDownTestCase() {}
void RSUniRenderUtilTest::SetUp() {}
void RSUniRenderUtilTest::TearDown() {}

/*
 * @tc.name: SrcRectScaleDown_001
 * @tc.desc: default value
 * @tc.type: FUNC
 * @tc.require:
*/
HWTEST_F(RSUniRenderUtilTest, SrcRectScaleDown_001, Function | SmallTest | Level2)
{
    auto rsSurfaceRenderNode = RSTestUtil::CreateSurfaceNode();
    ASSERT_NE(rsSurfaceRenderNode, nullptr);
    RSSurfaceRenderNode& node = static_cast<RSSurfaceRenderNode&>(*(rsSurfaceRenderNode.get()));
    BufferDrawParam params;
    RectF localBounds;
    RSUniRenderUtil::SrcRectScaleDown(
        params, node.GetRSSurfaceHandler()->GetBuffer(), node.GetRSSurfaceHandler()->GetConsumer(), localBounds);
}

/*
 * @tc.name: SrcRectScaleDown_002
 * @tc.desc: default value
 * @tc.type: FUNC
 * @tc.require:
*/
HWTEST_F(RSUniRenderUtilTest, SrcRectScaleDown_002, Function | SmallTest | Level2)
{
    auto rsSurfaceRenderNode = RSTestUtil::CreateSurfaceNodeWithBuffer();
    ASSERT_NE(rsSurfaceRenderNode, nullptr);
    RSSurfaceRenderNode& node = static_cast<RSSurfaceRenderNode&>(*(rsSurfaceRenderNode.get()));
    BufferDrawParam params;
    RectF localBounds;
    RSUniRenderUtil::SrcRectScaleDown(
        params, node.GetRSSurfaceHandler()->GetBuffer(), node.GetRSSurfaceHandler()->GetConsumer(), localBounds);
}

/*
 * @tc.name: SrcRectScaleDown_003
 * @tc.desc: Test SrcRectScaleDown when srcRect is multiple
 * @tc.type: FUNC
 * @tc.require: issueIAJOWI
*/
HWTEST_F(RSUniRenderUtilTest, SrcRectScaleDown_003, Function | SmallTest | Level2)
{
    auto node = RSTestUtil::CreateSurfaceNodeWithBuffer();
    ASSERT_NE(node, nullptr);
    BufferDrawParam params;
    int32_t left = 0;
    int32_t top = 0;
    int32_t right = 1;
    int32_t bottom = 2;
    params.srcRect = Drawing::Rect(left, top, right, bottom);
    right = 2;
    bottom = 1;
    RectF localBounds = RectF(left, top, right, bottom);
    RSUniRenderUtil::SrcRectScaleDown(
        params, node->GetRSSurfaceHandler()->GetBuffer(), node->GetRSSurfaceHandler()->GetConsumer(), localBounds);
   
    params.srcRect.SetRight(right);
    params.srcRect.SetBottom(bottom);
    right = 1;
    bottom = 2;
    localBounds.SetRight(right);
    localBounds.SetBottom(bottom);
    RSUniRenderUtil::SrcRectScaleDown(
        params, node->GetRSSurfaceHandler()->GetBuffer(), node->GetRSSurfaceHandler()->GetConsumer(), localBounds);
}

/*
 * @tc.name: SrcRectScaleFit_001
 * @tc.desc: default value
 * @tc.type: FUNC
 * @tc.require:
*/
HWTEST_F(RSUniRenderUtilTest, SrcRectScaleFit_001, Function | SmallTest | Level2)
{
    auto rsSurfaceRenderNode = RSTestUtil::CreateSurfaceNode();
    ASSERT_NE(rsSurfaceRenderNode, nullptr);
    RSSurfaceRenderNode& node = static_cast<RSSurfaceRenderNode&>(*(rsSurfaceRenderNode.get()));
    BufferDrawParam params;
    RectF localBounds;
    RSUniRenderUtil::SrcRectScaleFit(
        params, node.GetRSSurfaceHandler()->GetBuffer(), node.GetRSSurfaceHandler()->GetConsumer(), localBounds);
}

/*
 * @tc.name: SrcRectScaleFit_002
 * @tc.desc: default value
 * @tc.type: FUNC
 * @tc.require:
*/
HWTEST_F(RSUniRenderUtilTest, SrcRectScaleFit_002, Function | SmallTest | Level2)
{
    auto rsSurfaceRenderNode = RSTestUtil::CreateSurfaceNodeWithBuffer();
    ASSERT_NE(rsSurfaceRenderNode, nullptr);
    RSSurfaceRenderNode& node = static_cast<RSSurfaceRenderNode&>(*(rsSurfaceRenderNode.get()));
    BufferDrawParam params;
    RectF localBounds;
    RSUniRenderUtil::SrcRectScaleFit(
        params, node.GetRSSurfaceHandler()->GetBuffer(), node.GetRSSurfaceHandler()->GetConsumer(), localBounds);
}

/*
 * @tc.name: SrcRectScaleFit_003
 * @tc.desc: Test SrcRectScaleFit when srcRect is multiple
 * @tc.type: FUNC
 * @tc.require: issueIAJOWI
*/
HWTEST_F(RSUniRenderUtilTest, SrcRectScaleFit_003, Function | SmallTest | Level2)
{
    auto node = RSTestUtil::CreateSurfaceNodeWithBuffer();
    ASSERT_NE(node, nullptr);
    BufferDrawParam params;
    int32_t left = 0;
    int32_t top = 0;
    int32_t right = 1;
    int32_t bottom = 2;
    params.srcRect = Drawing::Rect(left, top, right, bottom);
    right = 2;
    bottom = 1;
    RectF localBounds = RectF(left, top, right, bottom);
    RSUniRenderUtil::SrcRectScaleFit(
        params, node->GetRSSurfaceHandler()->GetBuffer(), node->GetRSSurfaceHandler()->GetConsumer(), localBounds);
   
    params.srcRect.SetRight(right);
    params.srcRect.SetBottom(bottom);
    right = 1;
    bottom = 2;
    localBounds.SetRight(right);
    localBounds.SetBottom(bottom);
    RSUniRenderUtil::SrcRectScaleFit(
        params, node->GetRSSurfaceHandler()->GetBuffer(), node->GetRSSurfaceHandler()->GetConsumer(), localBounds);
}

/*
 * @tc.name: GetMatrixOfBufferToRelRect_001
 * @tc.desc: test GetMatrixOfBufferToRelRect with surfaceNode without buffer
 * @tc.type: FUNC
 * @tc.require: #I9E60C
 */
HWTEST_F(RSUniRenderUtilTest, GetMatrixOfBufferToRelRect_001, Function | SmallTest | Level2)
{
    auto rsSurfaceRenderNode = RSTestUtil::CreateSurfaceNode();
    ASSERT_NE(rsSurfaceRenderNode, nullptr);
    RSSurfaceRenderNode& node = static_cast<RSSurfaceRenderNode&>(*(rsSurfaceRenderNode.get()));
    RSUniRenderUtil::GetMatrixOfBufferToRelRect(node);
}

/*
 * @tc.name: GetMatrixOfBufferToRelRect_002
 * @tc.desc: test GetMatrixOfBufferToRelRect with surfaceNode with buffer
 * @tc.type: FUNC
 * @tc.require: #I9E60C
 */
HWTEST_F(RSUniRenderUtilTest, GetMatrixOfBufferToRelRect_002, Function | SmallTest | Level2)
{
    auto rsSurfaceRenderNode = RSTestUtil::CreateSurfaceNodeWithBuffer();
    ASSERT_NE(rsSurfaceRenderNode, nullptr);
    RSSurfaceRenderNode& node = static_cast<RSSurfaceRenderNode&>(*(rsSurfaceRenderNode.get()));
    RSUniRenderUtil::GetMatrixOfBufferToRelRect(node);
}

/*
 * @tc.name: CreateLayerBufferDrawParam_001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSUniRenderUtilTest, CreateLayerBufferDrawParam_001, Function | SmallTest | Level2)
{
    bool forceCPU = false;
    LayerInfoPtr layer = HdiLayerInfo::CreateHdiLayerInfo();
    RSUniRenderUtil::CreateLayerBufferDrawParam(layer, forceCPU);
}

/*
 * @tc.name: CreateLayerBufferDrawParam_002
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSUniRenderUtilTest, CreateLayerBufferDrawParam_002, Function | SmallTest | Level2)
{
    bool forceCPU = false;
    auto surfaceNode = RSTestUtil::CreateSurfaceNodeWithBuffer();
    ASSERT_NE(surfaceNode, nullptr);
    auto buffer = surfaceNode->GetRSSurfaceHandler()->GetBuffer();
    LayerInfoPtr layer = HdiLayerInfo::CreateHdiLayerInfo();
    layer->SetBuffer(buffer, surfaceNode->GetRSSurfaceHandler()->GetAcquireFence());
    RSUniRenderUtil::CreateLayerBufferDrawParam(layer, forceCPU);
}

/*
 * @tc.name: CreateLayerBufferDrawParam_003
 * @tc.desc: Test CreateLayerBufferDrawParam when buffer is nullptr
 * @tc.type: FUNC
 * @tc.require: issueIAJOWI
 */
HWTEST_F(RSUniRenderUtilTest, CreateLayerBufferDrawParam_003, Function | SmallTest | Level2)
{
    bool forceCPU = false;
    auto surfaceNode = RSTestUtil::CreateSurfaceNode();
    ASSERT_NE(surfaceNode, nullptr);
    LayerInfoPtr layer = HdiLayerInfo::CreateHdiLayerInfo();
    layer->SetBuffer(nullptr, surfaceNode->GetRSSurfaceHandler()->GetAcquireFence());
    RSUniRenderUtil::CreateLayerBufferDrawParam(layer, forceCPU);
}

/*
 * @tc.name: CreateLayerBufferDrawParam_004
 * @tc.desc: Test CreateLayerBufferDrawParam when surface is not nullptr
 * @tc.type: FUNC
 * @tc.require: issueIAJOWI
 */
HWTEST_F(RSUniRenderUtilTest, CreateLayerBufferDrawParam_004, Function | SmallTest | Level2)
{
    bool forceCPU = false;
    auto surfaceNode = RSTestUtil::CreateSurfaceNode();
    ASSERT_NE(surfaceNode, nullptr);
    LayerInfoPtr layer = HdiLayerInfo::CreateHdiLayerInfo();
    layer->SetBuffer(nullptr, surfaceNode->GetRSSurfaceHandler()->GetAcquireFence());
    auto csurface = IConsumerSurface::Create();
    layer->SetSurface(csurface);
    RSUniRenderUtil::CreateLayerBufferDrawParam(layer, forceCPU);
}

/*
 * @tc.name: GetRotationFromMatrix
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSUniRenderUtilTest, GetRotationFromMatrix, Function | SmallTest | Level2)
{
    int angle;
    Drawing::Matrix matrix = Drawing::Matrix();
    matrix.SetMatrix(1, 0, 0, 0, 1, 0, 0, 0, 1);
    angle = RSUniRenderUtil::GetRotationFromMatrix(matrix);
    ASSERT_EQ(angle, 0);
}

/*
 * @tc.name: GetRotationDegreeFromMatrix
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSUniRenderUtilTest, GetRotationDegreeFromMatrix, Function | SmallTest | Level2)
{
    int angle;
    Drawing::Matrix matrix = Drawing::Matrix();
    matrix.SetMatrix(1, 0, 0, 0, 1, 0, 0, 0, 1);
    angle = RSUniRenderUtil::GetRotationDegreeFromMatrix(matrix);
    ASSERT_EQ(angle, 0);
}

/*
 * @tc.name: Is3DRotation_001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSUniRenderUtilTest, Is3DRotation_001, Function | SmallTest | Level2)
{
    bool is3DRotation;
    Drawing::Matrix matrix = Drawing::Matrix();
    matrix.SetMatrix(1, 0, 0, 0, 1, 0, 0, 0, 1);
    is3DRotation = RSUniRenderUtil::Is3DRotation(matrix);
    ASSERT_FALSE(is3DRotation);
}

/*
 * @tc.name: Is3DRotation_002
 * @tc.desc: test Is3DRotation with ScaleX and ScaleY have same sign
 * @tc.type: FUNC
 * @tc.require: #IANUEG
 */
HWTEST_F(RSUniRenderUtilTest, Is3DRotation_002, Function | SmallTest | Level2)
{
    bool is3DRotation;
    Drawing::Matrix matrix = Drawing::Matrix();
    matrix.SetMatrix(-1, 0, 0, 0, -1, 0, 0, 0, 1);
    is3DRotation = RSUniRenderUtil::Is3DRotation(matrix);
    ASSERT_FALSE(is3DRotation);
}

/*
 * @tc.name: Is3DRotation_003
 * @tc.desc: Test Is3DRotation when ScaleX and ScaleY have different sign
 * @tc.type: FUNC
 * @tc.require: issueIAJOWI
 */
HWTEST_F(RSUniRenderUtilTest, Is3DRotation_003, Function | SmallTest | Level2)
{
    bool is3DRotation;
    Drawing::Matrix matrix = Drawing::Matrix();
    matrix.SetMatrix(-1, 0, 0, 0, 1, 0, 0, 0, 1);
    is3DRotation = RSUniRenderUtil::Is3DRotation(matrix);
    ASSERT_TRUE(is3DRotation);
}

/*
 * @tc.name: AssignWindowNodes
 * @tc.desc: Test AssignWindowNodes when displaynode is nullptr, or has no child.
 * @tc.type: FUNC
 * @tc.require: issueIATLPV
 */
HWTEST_F(RSUniRenderUtilTest, AssignWindowNodes, Function | SmallTest | Level2)
{
    std::list<std::shared_ptr<RSSurfaceRenderNode>> mainThreadNodes;
    std::list<std::shared_ptr<RSSurfaceRenderNode>> subThreadNodes;
    RSUniRenderUtil::AssignWindowNodes(nullptr, mainThreadNodes, subThreadNodes);
    ASSERT_TRUE(mainThreadNodes.empty());
    ASSERT_TRUE(subThreadNodes.empty());
    NodeId id = 0;
    RSDisplayNodeConfig config;
    auto node = std::make_shared<RSDisplayRenderNode>(id, config);
    RSUniRenderUtil::AssignWindowNodes(node, mainThreadNodes, subThreadNodes);
    ASSERT_TRUE(mainThreadNodes.empty());
    ASSERT_TRUE(subThreadNodes.empty());
}

/*
 * @tc.name: AssignWindowNodes002
 * @tc.desc: Test AssignWindowNodes when mainThreadNodes and subThreadNodes is not empty
 * @tc.type: FUNC
 * @tc.require: issueIAKA4Y
 */
HWTEST_F(RSUniRenderUtilTest, AssignWindowNodes002, Function | SmallTest | Level2)
{
    std::list<std::shared_ptr<RSSurfaceRenderNode>> mainThreadNodes;
    std::list<std::shared_ptr<RSSurfaceRenderNode>> subThreadNodes;
    NodeId id = 1;
    RSDisplayNodeConfig config;
    auto displayNode = std::make_shared<RSDisplayRenderNode>(id, config);
    ASSERT_NE(displayNode, nullptr);
    std::shared_ptr<RSSurfaceRenderNode> node1 = std::make_shared<RSSurfaceRenderNode>(1);
    ASSERT_NE(node1, nullptr);
    std::shared_ptr<RSSurfaceRenderNode> node2 = std::make_shared<RSSurfaceRenderNode>(2);
    ASSERT_NE(node2, nullptr);
    mainThreadNodes.push_back(node1);
    mainThreadNodes.push_back(node2);
    subThreadNodes.push_back(node1);
    subThreadNodes.push_back(node2);
    RSUniRenderUtil::AssignWindowNodes(displayNode, mainThreadNodes, subThreadNodes);
}

/*
 * @tc.name: ClearSurfaceIfNeed
 * @tc.desc: Test ClearSurfaceIfNeed with various displayNode
 * @tc.type: FUNC
 * @tc.require: issueIAKA4Y
 */
HWTEST_F(RSUniRenderUtilTest, ClearSurfaceIfNeed, Function | SmallTest | Level2)
{
    RSRenderNodeMap map;
    std::set<std::shared_ptr<RSBaseRenderNode>> oldChildren;
    RSUniRenderUtil::ClearSurfaceIfNeed(map, nullptr, oldChildren);
    NodeId id = 1;
    RSDisplayNodeConfig config;
    auto displayNode = std::make_shared<RSDisplayRenderNode>(id, config);
    ASSERT_NE(displayNode, nullptr);
    RSUniRenderUtil::ClearSurfaceIfNeed(map, displayNode, oldChildren);
}

/*
 * @tc.name: ClearSurfaceIfNeed002
 * @tc.desc: Test ClearSurfaceIfNeed when oldChildren.size > 0
 * @tc.type: FUNC
 * @tc.require: issueIAKA4Y
 */
HWTEST_F(RSUniRenderUtilTest, ClearSurfaceIfNeed002, Function | SmallTest | Level2)
{
    RSRenderNodeMap map;
    NodeId id = 1;
    RSDisplayNodeConfig config;
    auto displayNode = std::make_shared<RSDisplayRenderNode>(id, config);
    ASSERT_NE(displayNode, nullptr);
    std::set<std::shared_ptr<RSBaseRenderNode>> oldChildren;
    std::shared_ptr<RSBaseRenderNode> node1 = std::make_shared<RSBaseRenderNode>(1);
    ASSERT_NE(node1, nullptr);
    std::shared_ptr<RSBaseRenderNode> node2 = std::make_shared<RSBaseRenderNode>(2);
    ASSERT_NE(node2, nullptr);
    oldChildren.insert(node1);
    oldChildren.insert(node2);
    DeviceType deviceType = DeviceType::PHONE;
    RSUniRenderUtil::ClearSurfaceIfNeed(map, displayNode, oldChildren, deviceType);
}

/*
 * @tc.name: ClearCacheSurface
 * @tc.desc: Test ClearCacheSurface when threadIndex = 0
 * @tc.type: FUNC
 * @tc.require: issueIAKA4Y
 */
HWTEST_F(RSUniRenderUtilTest, ClearCacheSurface, Function | SmallTest | Level2)
{
    NodeId id = 1;
    std::shared_ptr<RSRenderNode> node = std::make_shared<RSRenderNode>(id);
    ASSERT_NE(node, nullptr);
    uint32_t threadIndex = 0;
    RSUniRenderUtil::ClearCacheSurface(*node, threadIndex);
}

/*
 * @tc.name: ClearCacheSurface002
 * @tc.desc: Test ClearCacheSurface reset cacheSurfaceThreadIndex_ and completedSurfaceThreadIndex_
 * @tc.type: FUNC
 * @tc.require: issueIAKA4Y
 */
HWTEST_F(RSUniRenderUtilTest, ClearCacheSurface002, Function | SmallTest | Level2)
{
    NodeId id = 1;
    std::shared_ptr<RSRenderNode> node = std::make_shared<RSRenderNode>(id);
    ASSERT_NE(node, nullptr);
    uint32_t threadIndex = UNI_MAIN_THREAD_INDEX;
    RSUniRenderUtil::ClearCacheSurface(*node, threadIndex);
    node->cacheSurfaceThreadIndex_ = UNI_RENDER_THREAD_INDEX;
    node->completedSurfaceThreadIndex_ = UNI_RENDER_THREAD_INDEX;
    RSUniRenderUtil::ClearCacheSurface(*node, threadIndex);
}

/*
 * @tc.name: PostReleaseSurfaceTask001
 * @tc.desc: Test PostReleaseSurfaceTask when surface is not nullptr
 * @tc.type: FUNC
 * @tc.require: issueIAJOWI
 */
HWTEST_F(RSUniRenderUtilTest, PostReleaseSurfaceTask001, Function | SmallTest | Level2)
{
    int width = 200;
    int height = 200;
    const Drawing::ImageInfo info =
        Drawing::ImageInfo { width, height, Drawing::COLORTYPE_N32, Drawing::ALPHATYPE_OPAQUE };
    auto surface(Drawing::Surface::MakeRaster(info));
    ASSERT_NE(surface, nullptr);
    uint32_t threadIndex = UNI_MAIN_THREAD_INDEX;
    RSUniRenderUtil::PostReleaseSurfaceTask(std::move(surface), threadIndex);
    threadIndex = UNI_RENDER_THREAD_INDEX;
    RSUniRenderUtil::PostReleaseSurfaceTask(std::move(surface), threadIndex);
}

/*
 * @tc.name: PostReleaseSurfaceTask002
 * @tc.desc: Test PostReleaseSurfaceTask when surface is nullptr and change threadIndex
 * @tc.type: FUNC
 * @tc.require: issueIAKA4Y
 */
HWTEST_F(RSUniRenderUtilTest, PostReleaseSurfaceTask002, Function | SmallTest | Level2)
{
    int width = 200;
    int height = 200;
    const Drawing::ImageInfo info =
        Drawing::ImageInfo { width, height, Drawing::COLORTYPE_N32, Drawing::ALPHATYPE_OPAQUE };
    uint32_t threadIndex = INVALID_NODEID;
    RSUniRenderUtil::PostReleaseSurfaceTask(nullptr, threadIndex);
    auto surface(Drawing::Surface::MakeRaster(info));
    ASSERT_NE(surface, nullptr);
    RSUniRenderUtil::PostReleaseSurfaceTask(std::move(surface), threadIndex);
}

/*
 * @tc.name: ClearNodeCacheSurface
 * @tc.desc: Test ClearNodeCacheSurface
 * @tc.type: FUNC
 * @tc.require: issueIATLPV
 */
HWTEST_F(RSUniRenderUtilTest, ClearNodeCacheSurface, Function | SmallTest | Level2)
{
    uint32_t threadIndex = 1;
    RSUniRenderUtil::ClearNodeCacheSurface(nullptr, nullptr, threadIndex, 0);
    NodeId id = 0;
    RSDisplayNodeConfig config;
    auto node = std::make_shared<RSDisplayRenderNode>(id, config);
    ASSERT_NE(node, nullptr);
    threadIndex = UNI_MAIN_THREAD_INDEX;
    auto cacheSurface = node->GetCacheSurface(threadIndex, false);
    auto completedSurface= node->GetCompletedCacheSurface(0, true);
    RSUniRenderUtil::ClearNodeCacheSurface(std::move(cacheSurface), std::move(completedSurface), threadIndex, 0);
    threadIndex = 1;
    auto cacheSurface1 = node->GetCacheSurface(threadIndex, false);
    auto completedSurface1= node->GetCompletedCacheSurface(0, true);
    RSUniRenderUtil::ClearNodeCacheSurface(std::move(cacheSurface1), std::move(completedSurface1), threadIndex, 0);
}

/*
 * @tc.name: HandleCaptureNode001
 * @tc.desc: Test RSUniRenderUtil::HandleCaptureNode api when sufaceNode is nullptr
 * @tc.type: FUNC
 * @tc.require: issueIAKDJI
 */
HWTEST_F(RSUniRenderUtilTest, HandleCaptureNode001, Function | SmallTest | Level2)
{
    Drawing::Canvas drawingCanvas;
    RSPaintFilterCanvas canvas(&drawingCanvas);
    auto surfaceNode = RSTestUtil::CreateSurfaceNode();
    ASSERT_NE(surfaceNode, nullptr);
    RSUniRenderUtil::HandleCaptureNode(*surfaceNode, canvas);
}

/*
 * @tc.name: HandleCaptureNode002
 * @tc.desc: Test RSUniRenderUtil::HandleCaptureNode api when node should not paint
 * @tc.type: FUNC
 * @tc.require: issueIAKDJI
 */
HWTEST_F(RSUniRenderUtilTest, HandleCaptureNode002, Function | SmallTest | Level2)
{
    Drawing::Canvas drawingCanvas;
    RSPaintFilterCanvas canvas(&drawingCanvas);
    auto surfaceNode = RSTestUtil::CreateSurfaceNode();
    auto node = RSTestUtil::CreateSurfaceNode();
    auto drawable = std::make_shared<DrawableV2::RSSurfaceRenderNodeDrawable>(node);
    auto param = std::make_unique<RSSurfaceRenderParams>(node->id_);
    param->shouldPaint_ = false;
    param->contentEmpty_ = false;
    param->isMainWindowType_ = true;
    param->isLeashWindow_ = false;
    param->isAppWindow_ = false;
    drawable->renderParams_ = std::move(param);
    surfaceNode->renderDrawable_ = drawable;
    ASSERT_NE(surfaceNode, nullptr);
    RSUniRenderUtil::HandleCaptureNode(*surfaceNode, canvas);
}

/*
 * @tc.name: HandleCaptureNode003
 * @tc.desc: Test RSUniRenderUtil::HandleCaptureNode api when node is on the tree
 * @tc.type: FUNC
 * @tc.require: issueIAKDJI
 */
HWTEST_F(RSUniRenderUtilTest, HandleCaptureNode003, Function | SmallTest | Level2)
{
    Drawing::Canvas drawingCanvas;
    RSPaintFilterCanvas canvas(&drawingCanvas);
    auto surfaceNode = RSTestUtil::CreateSurfaceNode();
    surfaceNode->isOnTheTree_ = true;
    auto node = RSTestUtil::CreateSurfaceNode();
    auto drawable = std::make_shared<DrawableV2::RSSurfaceRenderNodeDrawable>(node);
    auto param = std::make_unique<RSSurfaceRenderParams>(node->id_);
    param->shouldPaint_ = true;
    param->contentEmpty_ = true;
    param->isMainWindowType_ = true;
    param->isLeashWindow_ = false;
    param->isAppWindow_ = false;
    drawable->renderParams_ = std::move(param);
    surfaceNode->renderDrawable_ = drawable;
    ASSERT_NE(surfaceNode, nullptr);
    RSUniRenderUtil::HandleCaptureNode(*surfaceNode, canvas);
}

/*
 * @tc.name: HandleCaptureNode004
 * @tc.desc: Test RSUniRenderUtil::HandleCaptureNode api when node is not on the tree
 * @tc.type: FUNC
 * @tc.require: issueIAKDJI
 */
HWTEST_F(RSUniRenderUtilTest, HandleCaptureNode004, Function | SmallTest | Level2)
{
    Drawing::Canvas drawingCanvas;
    RSPaintFilterCanvas canvas(&drawingCanvas);
    auto surfaceNode = RSTestUtil::CreateSurfaceNode();
    surfaceNode->isOnTheTree_ = false;
    auto node = RSTestUtil::CreateSurfaceNode();
    auto drawable = std::make_shared<DrawableV2::RSSurfaceRenderNodeDrawable>(node);
    auto param = std::make_unique<RSSurfaceRenderParams>(node->id_);
    param->shouldPaint_ = true;
    param->contentEmpty_ = true;
    param->isMainWindowType_ = true;
    param->isLeashWindow_ = false;
    param->isAppWindow_ = false;
    drawable->renderParams_ = std::move(param);
    surfaceNode->renderDrawable_ = drawable;
    ASSERT_NE(surfaceNode, nullptr);
    RSUniRenderUtil::HandleCaptureNode(*surfaceNode, canvas);
}

/*
 * @tc.name: AssignMainThreadNode
 * @tc.desc:Test RSUniRenderUtilTest.AssignMainThreadNode
 * @tc.type: FUNC
 * @tc.require:issueI7KK3I
 */
HWTEST_F(RSUniRenderUtilTest, AssignMainThreadNode, Function | SmallTest | Level2)
{
    std::list<std::shared_ptr<RSSurfaceRenderNode>> mainThreadNodes;
    RSUniRenderUtil::AssignMainThreadNode(mainThreadNodes, nullptr);
    ASSERT_EQ(0, mainThreadNodes.size());
    auto node = RSTestUtil::CreateSurfaceNode();
    RSUniRenderUtil::AssignMainThreadNode(mainThreadNodes, node);
    ASSERT_EQ(1, mainThreadNodes.size());
}

/*
 * @tc.name: AssignMainThreadNode002
 * @tc.desc:Test AssignMainThreadNode002 when node.isMainThreadNode_ is false
 * @tc.type: FUNC
 * @tc.require: issueIAJOWI
 */
HWTEST_F(RSUniRenderUtilTest, AssignMainThreadNode002, Function | SmallTest | Level2)
{
    std::list<std::shared_ptr<RSSurfaceRenderNode>> mainThreadNodes;
    ASSERT_EQ(0, mainThreadNodes.size());
    auto node = RSTestUtil::CreateSurfaceNode();
    node->isMainThreadNode_ = false;
    RSUniRenderUtil::AssignMainThreadNode(mainThreadNodes, node);
    ASSERT_EQ(1, mainThreadNodes.size());
}

/*
 * @tc.name: AssignSubThreadNode
 * @tc.desc:Test RSUniRenderUtilTest.AssignSubThreadNode
 * @tc.type: FUNC
 * @tc.require:issueI7KK3I
 */
HWTEST_F(RSUniRenderUtilTest, AssignSubThreadNode, Function | SmallTest | Level2)
{
    std::list<std::shared_ptr<RSSurfaceRenderNode>> subThreadNodes;
    RSUniRenderUtil::AssignSubThreadNode(subThreadNodes, nullptr);
    ASSERT_EQ(0, subThreadNodes.size());
    auto node = RSTestUtil::CreateSurfaceNode();
    RSUniRenderUtil::AssignSubThreadNode(subThreadNodes, node);
    ASSERT_EQ(1, subThreadNodes.size());
}

/*
 * @tc.name: AssignSubThreadNode002
 * @tc.desc:Test RSUniRenderUtilTest.AssignSubThreadNode when reset node.cacheProcessStatus_
 * @tc.type: FUNC
 * @tc.require: issueIAKA4Y
 */
HWTEST_F(RSUniRenderUtilTest, AssignSubThreadNode002, Function | SmallTest | Level2)
{
    std::list<std::shared_ptr<RSSurfaceRenderNode>> subThreadNodes;
    auto node = RSTestUtil::CreateSurfaceNode();
    node->cacheProcessStatus_ = CacheProcessStatus::DONE;
    RSUniRenderUtil::AssignSubThreadNode(subThreadNodes, node);
    ASSERT_EQ(1, subThreadNodes.size());
}

/*
 * @tc.name: IsNodeAssignSubThread001
 * @tc.desc: test IsNodeAssignSubThread for non focus node
 * @tc.type: FUNC
 * @tc.require: issueI904G4
 */
HWTEST_F(RSUniRenderUtilTest, IsNodeAssignSubThread001, Function | SmallTest | Level2)
{
    NodeId id = 0;
    RSDisplayNodeConfig config;
    auto displayNode = std::make_shared<RSDisplayRenderNode>(id, config);
    auto surfaceNode = RSTestUtil::CreateSurfaceNode();
    ASSERT_NE(displayNode, nullptr);
    ASSERT_NE(surfaceNode, nullptr);
    displayNode->AddChild(surfaceNode);

    auto mainThread = RSMainThread::Instance();
    if (mainThread->GetDeviceType() == DeviceType::PC) {
        ASSERT_EQ(RSUniRenderUtil::IsNodeAssignSubThread(surfaceNode, displayNode->IsRotationChanged()),
            surfaceNode->QuerySubAssignable(displayNode->IsRotationChanged()));
    }
}

/*
 * @tc.name: IsNodeAssignSubThread002
 * @tc.desc: test IsNodeAssignSubThread for focus node which has shared transition
 * @tc.type: FUNC
 * @tc.require: issueI904G4
 */
HWTEST_F(RSUniRenderUtilTest, IsNodeAssignSubThread002, Function | SmallTest | Level2)
{
    NodeId id = 0;
    RSDisplayNodeConfig config;
    auto displayNode = std::make_shared<RSDisplayRenderNode>(id, config);
    auto surfaceNode = RSTestUtil::CreateSurfaceNode();
    ASSERT_NE(displayNode, nullptr);
    ASSERT_NE(surfaceNode, nullptr);
    displayNode->AddChild(surfaceNode);
    surfaceNode->SetHasSharedTransitionNode(true);
    
    auto mainThread = RSMainThread::Instance();
    std::string str = "";
    mainThread->SetFocusAppInfo(-1, -1, str, str, surfaceNode->GetId());
    if (mainThread->GetDeviceType() == DeviceType::PC) {
        ASSERT_FALSE(RSUniRenderUtil::IsNodeAssignSubThread(surfaceNode, displayNode->IsRotationChanged()));
    }
}

/*
 * @tc.name: IsNodeAssignSubThread003
 * @tc.desc: test IsNodeAssignSubThread for focus node which don't have shared transition
 * @tc.type: FUNC
 * @tc.require: issueI904G4
 */
HWTEST_F(RSUniRenderUtilTest, IsNodeAssignSubThread003, Function | SmallTest | Level2)
{
    NodeId id = 0;
    RSDisplayNodeConfig config;
    auto displayNode = std::make_shared<RSDisplayRenderNode>(id, config);
    auto surfaceNode = RSTestUtil::CreateSurfaceNode();
    ASSERT_NE(displayNode, nullptr);
    ASSERT_NE(surfaceNode, nullptr);
    displayNode->AddChild(surfaceNode);
    surfaceNode->SetHasSharedTransitionNode(false);
    
    auto mainThread = RSMainThread::Instance();
    std::string str = "";
    mainThread->SetFocusAppInfo(-1, -1, str, str, surfaceNode->GetId());
    if (mainThread->GetDeviceType() == DeviceType::PC) {
        ASSERT_EQ(RSUniRenderUtil::IsNodeAssignSubThread(surfaceNode, displayNode->IsRotationChanged()),
            surfaceNode->QuerySubAssignable(displayNode->IsRotationChanged()));
    }
}

/*
 * @tc.name: IsNodeAssignSubThread004
 * @tc.desc: test IsNodeAssignSubThread for self drawing node & self drawing window node
 * @tc.type: FUNC
 * @tc.require: issueI98VTC
 */
HWTEST_F(RSUniRenderUtilTest, IsNodeAssignSubThread004, Function | SmallTest | Level2)
{
    NodeId id = 0;
    RSDisplayNodeConfig config;
    auto displayNode = std::make_shared<RSDisplayRenderNode>(id, config);
    auto selfDrawingNode = RSTestUtil::CreateSurfaceNode();
    auto selfDrawingWindowNode = RSTestUtil::CreateSurfaceNode();
    ASSERT_NE(displayNode, nullptr);
    ASSERT_NE(selfDrawingNode, nullptr);
    ASSERT_NE(selfDrawingWindowNode, nullptr);
    displayNode->AddChild(selfDrawingNode);
    displayNode->AddChild(selfDrawingWindowNode);
    selfDrawingNode->SetSurfaceNodeType(RSSurfaceNodeType::SELF_DRAWING_NODE);
    selfDrawingWindowNode->SetSurfaceNodeType(RSSurfaceNodeType::SELF_DRAWING_WINDOW_NODE);
    
    ASSERT_EQ(RSUniRenderUtil::IsNodeAssignSubThread(selfDrawingNode, displayNode->IsRotationChanged()), false);
    ASSERT_EQ(RSUniRenderUtil::IsNodeAssignSubThread(selfDrawingWindowNode, displayNode->IsRotationChanged()), false);
}

/*
 * @tc.name: IsNodeAssignSubThread005
 * @tc.desc: test IsNodeAssignSubThread while cache is waiting for process
 * @tc.type: FUNC
 * @tc.require: issueI98VTC
 */
HWTEST_F(RSUniRenderUtilTest, IsNodeAssignSubThread005, Function | SmallTest | Level2)
{
    NodeId id = 0;
    RSDisplayNodeConfig config;
    auto displayNode = std::make_shared<RSDisplayRenderNode>(id, config);
    auto surfaceNode = RSTestUtil::CreateSurfaceNode();
    ASSERT_NE(displayNode, nullptr);
    ASSERT_NE(surfaceNode, nullptr);
    displayNode->AddChild(surfaceNode);
    surfaceNode->SetCacheSurfaceProcessedStatus(CacheProcessStatus::WAITING);
    
    ASSERT_EQ(RSUniRenderUtil::IsNodeAssignSubThread(surfaceNode, displayNode->IsRotationChanged()), false);
}

/*
 * @tc.name: IsNodeAssignSubThread006
 * @tc.desc: test IsNodeAssignSubThread when nodeType_ is reset
 * @tc.type: FUNC
 * @tc.require: issueIAJOWI
 */
HWTEST_F(RSUniRenderUtilTest, IsNodeAssignSubThread006, Function | SmallTest | Level2)
{
    NodeId id = 1;
    RSDisplayNodeConfig config;
    auto displayNode = std::make_shared<RSDisplayRenderNode>(id, config);
    auto surfaceNode = RSTestUtil::CreateSurfaceNode();
    surfaceNode->nodeType_ = RSSurfaceNodeType::SELF_DRAWING_NODE;
    ASSERT_NE(displayNode, nullptr);
    ASSERT_NE(surfaceNode, nullptr);
    displayNode->AddChild(surfaceNode);
    surfaceNode->SetCacheSurfaceProcessedStatus(CacheProcessStatus::WAITING);
    
    ASSERT_EQ(RSUniRenderUtil::IsNodeAssignSubThread(surfaceNode, displayNode->IsRotationChanged()), false);
}

/**
 * @tc.name: IsNeedClientsTest
 * @tc.desc: Verify function IsNeedClient
 * @tc.type:FUNC
 * @tc.require:issuesI9KRF1
 */
HWTEST_F(RSUniRenderUtilTest, IsNeedClientsTest, Function | SmallTest | Level2)
{
    auto rsSurfaceRenderNode = RSTestUtil::CreateSurfaceNode();
    ASSERT_NE(rsSurfaceRenderNode, nullptr);
    RSSurfaceRenderNode& node = static_cast<RSSurfaceRenderNode&>(*(rsSurfaceRenderNode.get()));
    ComposeInfo info;
    EXPECT_FALSE(RSUniRenderUtil::IsNeedClient(node, info));
}

/**
 * @tc.name: IsNeedClientTest002
 * @tc.desc: Test IsNeedClient with modify params such as Rotation
 * @tc.type:FUNC
 * @tc.require: issueIAJOWI
 */
HWTEST_F(RSUniRenderUtilTest, IsNeedClientTest002, Function | SmallTest | Level2)
{
    std::shared_ptr<RSSurfaceRenderNode> node = std::make_shared<RSSurfaceRenderNode>(1);
    ASSERT_NE(node, nullptr);
    ComposeInfo info;
    node->renderContent_->renderProperties_.SetRotation(1.0f);
    EXPECT_TRUE(RSUniRenderUtil::IsNeedClient(*node, info));
    node->renderContent_->renderProperties_.SetRotationX(1.0f);
    EXPECT_TRUE(RSUniRenderUtil::IsNeedClient(*node, info));
    node->renderContent_->renderProperties_.SetRotationY(1.0f);
    EXPECT_TRUE(RSUniRenderUtil::IsNeedClient(*node, info));
    Quaternion quaternion(90.0f, 90.0f, 90.0f, 90.0f);
    node->renderContent_->renderProperties_.SetQuaternion(quaternion);
    EXPECT_TRUE(RSUniRenderUtil::IsNeedClient(*node, info));
}

/*
 * @tc.name: DrawRectForDfxTest
 * @tc.desc: Verify function DrawRectForDfx
 * @tc.type: FUNC
 * @tc.require: issuesI9KRF1
 */
HWTEST_F(RSUniRenderUtilTest, DrawRectForDfxTest, Function | SmallTest | Level2)
{
    Drawing::Canvas canvas;
    RSPaintFilterCanvas filterCanvas(&canvas);
    RectI rect(1, 1, -1, -1);
    Drawing::Color color;
    float alpha = 1.f;
    std::string extraInfo = "";
    RSUniRenderUtil::DrawRectForDfx(filterCanvas, rect, color, alpha, extraInfo);
    EXPECT_TRUE(rect.width_ <= 0);

    rect.width_ = 1;
    rect.height_ = 1;
    RSUniRenderUtil::DrawRectForDfx(filterCanvas, rect, color, alpha, extraInfo);
    EXPECT_TRUE(rect.width_ >= 0);
}

/*
 * @tc.name: DealWithNodeGravityTest
 * @tc.desc: Verify function DealWithNodeGravity
 * @tc.type: FUNC
 * @tc.require: issuesI9KRF1
 */
HWTEST_F(RSUniRenderUtilTest, DealWithNodeGravityTest, Function | SmallTest | Level2)
{
    NodeId id = 0;
    RSSurfaceRenderNode node(id);
    ScreenInfo screenInfo;
    node.GetRSSurfaceHandler()->buffer_.buffer = OHOS::SurfaceBuffer::Create();
    node.renderContent_->renderProperties_.frameGravity_ = Gravity::RESIZE;
    RSUniRenderUtil::DealWithNodeGravity(node, screenInfo);
    node.renderContent_->renderProperties_.frameGravity_ = Gravity::TOP_LEFT;
    RSUniRenderUtil::DealWithNodeGravity(node, screenInfo);
    node.renderContent_->renderProperties_.frameGravity_ = Gravity::DEFAULT;
    node.renderContent_->renderProperties_.boundsGeo_->SetHeight(-1.0f);
    RSUniRenderUtil::DealWithNodeGravity(node, screenInfo);
    node.renderContent_->renderProperties_.boundsGeo_->SetWidth(-1.0f);
    RSUniRenderUtil::DealWithNodeGravity(node, screenInfo);
    screenInfo.rotation = ScreenRotation::ROTATION_90;
    RSUniRenderUtil::DealWithNodeGravity(node, screenInfo);
    screenInfo.rotation = ScreenRotation::ROTATION_270;
    RSUniRenderUtil::DealWithNodeGravity(node, screenInfo);
    EXPECT_TRUE(screenInfo.width == 0);
}

/*
 * @tc.name: DealWithNodeGravityTest002
 * @tc.desc: Test DealWithNodeGravity when buffer is nullptr
 * @tc.type: FUNC
 * @tc.require: issueIAJBBO
 */
HWTEST_F(RSUniRenderUtilTest, DealWithNodeGravityTest002, Function | SmallTest | Level2)
{
    NodeId id = 0;
    RSSurfaceRenderNode node(id);
    ScreenInfo screenInfo;
    node.GetRSSurfaceHandler()->buffer_.buffer = nullptr;
    RSUniRenderUtil::DealWithNodeGravity(node, screenInfo);
    EXPECT_TRUE(screenInfo.width == 0);
}

/*
 * @tc.name: DealWithNodeGravityTest003
 * @tc.desc: Test DealWithNodeGravity when screenInfo.rotation is modify
 * @tc.type: FUNC
 * @tc.require: issueIAKA4Y
 */
HWTEST_F(RSUniRenderUtilTest, DealWithNodeGravityTest003, Function | SmallTest | Level2)
{
    NodeId id = 1;
    RSSurfaceRenderNode node(id);
    node.GetRSSurfaceHandler()->buffer_.buffer = OHOS::SurfaceBuffer::Create();
    ScreenInfo screenInfo;
    screenInfo.rotation = ScreenRotation::ROTATION_90;
    RSUniRenderUtil::DealWithNodeGravity(node, screenInfo);
    screenInfo.rotation = ScreenRotation::ROTATION_270;
    RSUniRenderUtil::DealWithNodeGravity(node, screenInfo);
    screenInfo.rotation = ScreenRotation::ROTATION_180;
    RSUniRenderUtil::DealWithNodeGravity(node, screenInfo);
    EXPECT_TRUE(screenInfo.width == 0);
}

/*
 * @tc.name: LayerRotateTest
 * @tc.desc: Verify function LayerRotate
 * @tc.type: FUNC
 * @tc.require: issuesI9KRF1
 */
HWTEST_F(RSUniRenderUtilTest, LayerRotateTest, Function | SmallTest | Level2)
{
    NodeId id = 0;
    RSSurfaceRenderNode node(id);
    ScreenInfo screenInfo;
    screenInfo.rotation = ScreenRotation::ROTATION_90;
    RSUniRenderUtil::LayerRotate(node, screenInfo);

    screenInfo.rotation = ScreenRotation::ROTATION_180;
    RSUniRenderUtil::LayerRotate(node, screenInfo);

    screenInfo.rotation = ScreenRotation::ROTATION_270;
    RSUniRenderUtil::LayerRotate(node, screenInfo);

    screenInfo.rotation = ScreenRotation::ROTATION_0;
    RSUniRenderUtil::LayerRotate(node, screenInfo);
    EXPECT_EQ(screenInfo.width, 0);
}

/*
 * @tc.name: LayerCropTest
 * @tc.desc: Verify function LayerCrop
 * @tc.type: FUNC
 * @tc.require: issuesI9KRF1
 */
HWTEST_F(RSUniRenderUtilTest, LayerCropTest, Function | SmallTest | Level2)
{
    NodeId id = 0;
    RSSurfaceRenderNode node(id);
    ScreenInfo screenInfo;
    RSUniRenderUtil::LayerCrop(node, screenInfo);

    auto dstRect = node.GetDstRect();
    dstRect.left_ = 1;
    RSUniRenderUtil::LayerCrop(node, screenInfo);
    EXPECT_EQ(screenInfo.width, 0);
}

/*
 * @tc.name: GetLayerTransformTest
 * @tc.desc: Verify function GetLayerTransform
 * @tc.type: FUNC
 * @tc.require: issuesI9KRF1
 */
HWTEST_F(RSUniRenderUtilTest, GetLayerTransformTest, Function | SmallTest | Level2)
{
    NodeId id = 0;
    RSSurfaceRenderNode node(id);
    ScreenInfo screenInfo;
    GraphicTransformType type = RSUniRenderUtil::GetLayerTransform(node, screenInfo);

    node.GetRSSurfaceHandler()->consumer_ = IConsumerSurface::Create();
    type = RSUniRenderUtil::GetLayerTransform(node, screenInfo);
    EXPECT_TRUE(type == GraphicTransformType::GRAPHIC_ROTATE_NONE);
}

/*
 * @tc.name: GetLayerTransformTest002
 * @tc.desc: Test GetLayerTransform when consumer and buffer is not nullptr
 * @tc.type: FUNC
 * @tc.require: issueIAJBBO
 */
HWTEST_F(RSUniRenderUtilTest, GetLayerTransformTest002, TestSize.Level2)
{
    NodeId id = 0;
    RSSurfaceRenderNode node(id);
    node.surfaceHandler_ = nullptr;
    ScreenInfo screenInfo;
    GraphicTransformType type = RSUniRenderUtil::GetLayerTransform(node, screenInfo);

    node.surfaceHandler_ = std::make_shared<RSSurfaceHandler>(id);
    ASSERT_NE(node.surfaceHandler_, nullptr);
    node.GetRSSurfaceHandler()->buffer_.buffer = OHOS::SurfaceBuffer::Create();
    node.GetRSSurfaceHandler()->consumer_ = IConsumerSurface::Create();
    type = RSUniRenderUtil::GetLayerTransform(node, screenInfo);
    EXPECT_TRUE(type == GraphicTransformType::GRAPHIC_ROTATE_NONE);
}


/*
 * @tc.name: SrcRectRotateTransformTest
 * @tc.desc: Verify function SrcRectRotateTransform
 * @tc.type: FUNC
 * @tc.require: issuesI9KRF1
 */
HWTEST_F(RSUniRenderUtilTest, SrcRectRotateTransformTest, Function | SmallTest | Level2)
{
    NodeId id = 0;
    RSSurfaceRenderNode node(id);
    RSUniRenderUtil::SrcRectRotateTransform(node, GraphicTransformType::GRAPHIC_ROTATE_NONE);

    node.GetRSSurfaceHandler()->consumer_ = IConsumerSurface::Create();
    RSUniRenderUtil::SrcRectRotateTransform(node, GraphicTransformType::GRAPHIC_ROTATE_NONE);
    EXPECT_FALSE(node.GetRSSurfaceHandler()->GetBuffer());
}

/*
 * @tc.name: SrcRectRotateTransformTest002
 * @tc.desc: Verify function SrcRectRotateTransform
 * @tc.type: FUNC
 * @tc.require: issuesI9KRF1
 */
HWTEST_F(RSUniRenderUtilTest, SrcRectRotateTransformTest002, Function | SmallTest | Level2)
{
    NodeId id = 0;
    RSSurfaceRenderNode node(id);
    node.GetRSSurfaceHandler()->consumer_ = IConsumerSurface::Create();
    node.GetRSSurfaceHandler()->GetConsumer()->SetTransform(GraphicTransformType::GRAPHIC_FLIP_V_ROT270);
    RSUniRenderUtil::SrcRectRotateTransform(node, GraphicTransformType::GRAPHIC_FLIP_V_ROT270);
    node.GetRSSurfaceHandler()->GetConsumer()->SetTransform(GraphicTransformType::GRAPHIC_FLIP_V_ROT180);
    RSUniRenderUtil::SrcRectRotateTransform(node, GraphicTransformType::GRAPHIC_FLIP_V_ROT180);
    node.GetRSSurfaceHandler()->GetConsumer()->SetTransform(GraphicTransformType::GRAPHIC_FLIP_V_ROT90);
    RSUniRenderUtil::SrcRectRotateTransform(node, GraphicTransformType::GRAPHIC_FLIP_V_ROT90);
    EXPECT_FALSE(node.GetRSSurfaceHandler()->GetBuffer());
}

/*
 * @tc.name: HandleHardwareNodeTest
 * @tc.desc: Verify function HandleHardwareNode
 * @tc.type: FUNC
 * @tc.require: issuesI9KRF1
 */
HWTEST_F(RSUniRenderUtilTest, HandleHardwareNodeTest, Function | SmallTest | Level2)
{
    NodeId id = 0;
    auto node = std::make_shared<RSSurfaceRenderNode>(id);
    RSUniRenderUtil::HandleHardwareNode(node);
    node->hasHardwareNode_ = true;
    RSUniRenderUtil::HandleHardwareNode(node);
    node->children_.emplace_back(std::make_shared<RSRenderNode>(id));
    node->nodeType_ = RSSurfaceNodeType::LEASH_WINDOW_NODE;
    RSUniRenderUtil::HandleHardwareNode(node);
    EXPECT_FALSE(node->GetRSSurfaceHandler()->GetBuffer());
}

/*
 * @tc.name: HandleHardwareNodeTest002
 * @tc.desc: Test HandleHardwareNode add child to node
 * @tc.type: FUNC
 * @tc.require: issueIAJOWI
 */
HWTEST_F(RSUniRenderUtilTest, HandleHardwareNodeTest002, Function | SmallTest | Level2)
{
    NodeId id = 1;
    auto node = std::make_shared<RSSurfaceRenderNode>(id);
    ASSERT_NE(node, nullptr);
    node->hasHardwareNode_ = true;
    id = 2;
    auto child = std::make_shared<RSSurfaceRenderNode>(id);
    ASSERT_NE(child, nullptr);
    node->AddChild(child);
    RSUniRenderUtil::HandleHardwareNode(node);
}

/*
 * @tc.name: HandleHardwareNodeTest003
 * @tc.desc: Test HandleHardwareNode add childHardwareEnabledNodes_ to node
 * @tc.type: FUNC
 * @tc.require: issueIAKA4Y
 */
HWTEST_F(RSUniRenderUtilTest, HandleHardwareNodeTest003, Function | SmallTest | Level2)
{
    NodeId id = 1;
    auto node = std::make_shared<RSSurfaceRenderNode>(id);
    ASSERT_NE(node, nullptr);
    node->hasHardwareNode_ = true;
    id = 2;
    auto child = std::make_shared<RSSurfaceRenderNode>(id);
    ASSERT_NE(child, nullptr);
    node->AddChild(child);

    std::shared_ptr<RSSurfaceRenderNode> rsNode = nullptr;
    std::weak_ptr<RSSurfaceRenderNode> rsNodeF = rsNode;
    std::weak_ptr<RSSurfaceRenderNode> rsNodeT = std::make_shared<RSSurfaceRenderNode>(1);
    node->childHardwareEnabledNodes_.emplace_back(rsNodeF);
    node->childHardwareEnabledNodes_.emplace_back(rsNodeT);
    RSUniRenderUtil::HandleHardwareNode(node);
}

/*
 * @tc.name: UpdateRealSrcRectTest
 * @tc.desc: Verify function UpdateRealSrcRect
 * @tc.type: FUNC
 * @tc.require: issuesI9KRF1
 */
HWTEST_F(RSUniRenderUtilTest, UpdateRealSrcRectTest, Function | SmallTest | Level2)
{
    NodeId id = 0;
    RSSurfaceRenderNode node(id);
    RectI absRect;
    node.GetRSSurfaceHandler()->buffer_.buffer = OHOS::SurfaceBuffer::Create();
    node.GetRSSurfaceHandler()->consumer_ = IConsumerSurface::Create();
    RSUniRenderUtil::UpdateRealSrcRect(node, absRect);

    absRect = RectI(1, 1, 1, 1);
    RSUniRenderUtil::UpdateRealSrcRect(node, absRect);
    EXPECT_TRUE(node.GetRSSurfaceHandler()->buffer_.buffer);
}

/*
 * @tc.name: UpdateRealSrcRectTest002
 * @tc.desc: Test UpdateRealSrcRect when consumer is nullptr
 * @tc.type: FUNC
 * @tc.require: issueIAJBBO
 */
HWTEST_F(RSUniRenderUtilTest, UpdateRealSrcRectTest002, Function | SmallTest | Level2)
{
    NodeId id = 0;
    RSSurfaceRenderNode node(id);
    node.stagingRenderParams_ = std::make_unique<RSSurfaceRenderParams>(node.GetId());
    RectI absRect;
    node.GetRSSurfaceHandler()->buffer_.buffer = OHOS::SurfaceBuffer::Create();
    node.GetRSSurfaceHandler()->consumer_ = nullptr;
    RSUniRenderUtil::UpdateRealSrcRect(node, absRect);

    node.GetRSSurfaceHandler()->consumer_ = IConsumerSurface::Create();
    node.GetRSSurfaceHandler()->GetConsumer()->SetTransform(GraphicTransformType::GRAPHIC_FLIP_V_ROT90);
    RSUniRenderUtil::UpdateRealSrcRect(node, absRect);
    node.GetRSSurfaceHandler()->GetConsumer()->SetTransform(GraphicTransformType::GRAPHIC_FLIP_V_ROT270);
    RSUniRenderUtil::UpdateRealSrcRect(node, absRect);

    constexpr uint32_t default_canvas_width = 800;
    constexpr uint32_t default_canvas_height = 600;
    int left = 1;
    int top = 1;
    int right = 1;
    int bottom = 1;
    absRect = RectI(left, top, right, bottom);
    node.GetMutableRenderProperties().SetBoundsWidth(default_canvas_width);
    node.GetMutableRenderProperties().SetBoundsHeight(default_canvas_height);
    node.GetMutableRenderProperties().SetFrameGravity(Gravity::TOP_RIGHT);
    RSUniRenderUtil::UpdateRealSrcRect(node, absRect);
    EXPECT_TRUE(node.GetRSSurfaceHandler()->buffer_.buffer);
}

/*
 * @tc.name: CheckForceHardwareAndUpdateDstRectTest
 * @tc.desc: Verify function CheckForceHardwareAndUpdateDstRect
 * @tc.type: FUNC
 * @tc.require: issuesI9KRF1
 */
HWTEST_F(RSUniRenderUtilTest, CheckForceHardwareAndUpdateDstRectTest, Function | SmallTest | Level2)
{
    NodeId id = 0;
    RSSurfaceRenderNode node(id);
    node.GetRSSurfaceHandler()->buffer_.buffer = OHOS::SurfaceBuffer::Create();
    RSUniRenderUtil::CheckForceHardwareAndUpdateDstRect(node);
    node.isFixRotationByUser_ = true;
    RSUniRenderUtil::CheckForceHardwareAndUpdateDstRect(node);
    EXPECT_TRUE(node.GetOriginalDstRect().IsEmpty());
}

/*
 * @tc.name: CheckForceHardwareAndUpdateDstRectTest002
 * @tc.desc: Test CheckForceHardwareAndUpdateDstRect without nullptr
 * @tc.type: FUNC
 * @tc.require: issueIAJBBO
 */
HWTEST_F(RSUniRenderUtilTest, CheckForceHardwareAndUpdateDstRectTest002, Function | SmallTest | Level2)
{
    NodeId id = 0;
    RSSurfaceRenderNode node(id);
    node.isFixRotationByUser_ = true;
    node.isInFixedRotation_ = true;
    node.GetRSSurfaceHandler()->buffer_.buffer = OHOS::SurfaceBuffer::Create();
    node.GetRSSurfaceHandler()->consumer_ = IConsumerSurface::Create();
    RSUniRenderUtil::CheckForceHardwareAndUpdateDstRect(node);
    EXPECT_TRUE(node.GetOriginalDstRect().IsEmpty());
}

/*
 * @tc.name: SortSubThreadNodesTest
 * @tc.desc: Verify function SortSubThreadNodes
 * @tc.type: FUNC
 * @tc.require: issuesI9KRF1
 */
HWTEST_F(RSUniRenderUtilTest, SortSubThreadNodesTest, TestSize.Level1)
{
    RSUniRenderUtil rsUniRenderUtil;
    std::list<std::shared_ptr<RSSurfaceRenderNode>> subThreadNodes;
    std::shared_ptr<RSSurfaceRenderNode> nodeTest1 = std::make_shared<RSSurfaceRenderNode>(0);
    EXPECT_TRUE(nodeTest1);
    std::shared_ptr<RSSurfaceRenderNode> nodeTest2 = std::make_shared<RSSurfaceRenderNode>(0);
    EXPECT_TRUE(nodeTest2);
    std::shared_ptr<RSSurfaceRenderNode> nodeTest3 = std::make_shared<RSSurfaceRenderNode>(0);
    EXPECT_TRUE(nodeTest3);
    std::shared_ptr<RSSurfaceRenderNode> nodeTest4 = nullptr;

    nodeTest1->SetPriority(NodePriorityType::SUB_FOCUSNODE_PRIORITY);
    nodeTest1->renderContent_->renderProperties_.SetPositionZ(1.0f);
    nodeTest2->SetPriority(NodePriorityType::MAIN_PRIORITY);
    // for test
    nodeTest2->renderContent_->renderProperties_.SetPositionZ(2.0f);
    nodeTest3->SetPriority(NodePriorityType::MAIN_PRIORITY);
    nodeTest3->renderContent_->renderProperties_.SetPositionZ(1.0f);

    subThreadNodes.push_back(nodeTest1);
    subThreadNodes.push_back(nodeTest2);
    subThreadNodes.push_back(nodeTest3);
    // node4 is nullptr
    subThreadNodes.push_back(nodeTest4);

    rsUniRenderUtil.SortSubThreadNodes(subThreadNodes);
    auto it = subThreadNodes.begin();
    EXPECT_EQ((*it)->GetPriority(), NodePriorityType::MAIN_PRIORITY);
    ++it;
    EXPECT_EQ((*it)->GetPriority(), NodePriorityType::MAIN_PRIORITY);
    ++it;
    EXPECT_EQ((*it)->GetPriority(), NodePriorityType::SUB_FOCUSNODE_PRIORITY);
    // for test
    EXPECT_EQ(subThreadNodes.size(), 4);
}

/*
 * @tc.name: CacheSubThreadNodesTest
 * @tc.desc: Verify function CacheSubThreadNodes
 * @tc.type: FUNC
 * @tc.require: issuesI9KRF1
 */
HWTEST_F(RSUniRenderUtilTest, CacheSubThreadNodesTest, TestSize.Level1)
{
    RSUniRenderUtil rsUniRenderUtil;

    std::list<std::shared_ptr<RSSurfaceRenderNode>> subThreadNodes;
    std::list<std::shared_ptr<RSSurfaceRenderNode>> oldSubThreadNodes;

    std::shared_ptr<RSSurfaceRenderNode> nodeTest1 = std::make_shared<RSSurfaceRenderNode>(0);
    EXPECT_TRUE(nodeTest1);
    std::shared_ptr<RSSurfaceRenderNode> nodeTest2 = std::make_shared<RSSurfaceRenderNode>(1);
    EXPECT_TRUE(nodeTest2);
    std::shared_ptr<RSSurfaceRenderNode> nodeTest3 = std::make_shared<RSSurfaceRenderNode>(0);
    nodeTest3->cacheProcessStatus_ = CacheProcessStatus::DOING;
    EXPECT_TRUE(nodeTest3);
    std::shared_ptr<RSSurfaceRenderNode> nodeTest4 = std::make_shared<RSSurfaceRenderNode>(1);
    EXPECT_TRUE(nodeTest4);

    subThreadNodes.push_back(nodeTest1);
    subThreadNodes.push_back(nodeTest2);
    oldSubThreadNodes.push_back(nodeTest3);
    oldSubThreadNodes.push_back(nodeTest4);

    rsUniRenderUtil.CacheSubThreadNodes(oldSubThreadNodes, subThreadNodes);
    // fot test
    EXPECT_EQ(oldSubThreadNodes.size(), 3);
}

/*
 * @tc.name: CacheSubThreadNodesTest002
 * @tc.desc: CacheSubThreadNodes add the same node to oldSubThreadNodes and oldSubThreadNodes
 * @tc.type: FUNC
 * @tc.require: issueIAKA4Y
 */
HWTEST_F(RSUniRenderUtilTest, CacheSubThreadNodesTest002, TestSize.Level1)
{
    RSUniRenderUtil rsUniRenderUtil;
    std::list<std::shared_ptr<RSSurfaceRenderNode>> subThreadNodes;
    std::list<std::shared_ptr<RSSurfaceRenderNode>> oldSubThreadNodes;
    std::shared_ptr<RSSurfaceRenderNode> node1 = std::make_shared<RSSurfaceRenderNode>(1);
    ASSERT_NE(node1, nullptr);
    std::shared_ptr<RSSurfaceRenderNode> node2 = std::make_shared<RSSurfaceRenderNode>(2);
    ASSERT_NE(node2, nullptr);

    subThreadNodes.push_back(node1);
    subThreadNodes.push_back(node2);
    oldSubThreadNodes.push_back(node1);
    oldSubThreadNodes.push_back(node2);
    rsUniRenderUtil.CacheSubThreadNodes(oldSubThreadNodes, subThreadNodes);
    EXPECT_EQ(oldSubThreadNodes.size(), 2);
}

/*
 * @tc.name: LayerScaleDownTest
 * @tc.desc: Verify function LayerScaleDown
 * @tc.type: FUNC
 * @tc.require: issuesI9KRF1
 */
HWTEST_F(RSUniRenderUtilTest, LayerScaleDownTest, TestSize.Level1)
{
    RSUniRenderUtil rsUniRenderUtil;
    auto nodesTest1 = std::make_shared<RSSurfaceRenderNode>(0);
    nodesTest1->GetRSSurfaceHandler()->buffer_.buffer = nullptr;
    rsUniRenderUtil.LayerScaleDown(*nodesTest1);

    auto nodesTest2 = std::make_shared<RSSurfaceRenderNode>(1);
    nodesTest2->GetRSSurfaceHandler()->buffer_.buffer = OHOS::SurfaceBuffer::Create();
    nodesTest2->GetRSSurfaceHandler()->consumer_ = nullptr;
    rsUniRenderUtil.LayerScaleDown(*nodesTest2);
}

/*
 * @tc.name: ProcessCacheImage
 * @tc.desc: ProcessCacheImage test with modify params
 * @tc.type: FUNC
 * @tc.require: issueIAJBBO
 */
HWTEST_F(RSUniRenderUtilTest, ProcessCacheImage, TestSize.Level2)
{
    RSUniRenderUtil rsUniRenderUtil;
    Drawing::Canvas drawingCanvas;
    RSPaintFilterCanvas canvas(&drawingCanvas);
    std::shared_ptr<Drawing::Image> image = std::make_shared<Drawing::Image>();
    ASSERT_NE(image, nullptr);

    rsUniRenderUtil.ProcessCacheImage(canvas, *image);
}

/*
 * @tc.name: ProcessCacheImageRect001
 * @tc.desc: ProcessCacheImageRect test with abnoraml rect params
 * @tc.type: FUNC
 * @tc.require: issueIB2KBH
 */
HWTEST_F(RSUniRenderUtilTest, ProcessCacheImageRect001, TestSize.Level2)
{
    RSUniRenderUtil rsUniRenderUtil;
    Drawing::Canvas drawingCanvas;
    RSPaintFilterCanvas canvas(&drawingCanvas);
    std::shared_ptr<Drawing::Image> image = std::make_shared<Drawing::Image>();
    ASSERT_NE(image, nullptr);

    auto src = Drawing::Rect(-10, -10, -100, -100);  // test value
    auto dst = src;
    rsUniRenderUtil.ProcessCacheImageRect(canvas, *image, src, dst);
}

/*
 * @tc.name: ProcessCacheImageRect002
 * @tc.desc: ProcessCacheImageRect test with noraml rect params
 * @tc.type: FUNC
 * @tc.require: issueIB2KBH
 */
HWTEST_F(RSUniRenderUtilTest, ProcessCacheImageRect002, TestSize.Level2)
{
    RSUniRenderUtil rsUniRenderUtil;
    Drawing::Canvas drawingCanvas;
    RSPaintFilterCanvas canvas(&drawingCanvas);
    std::shared_ptr<Drawing::Image> image = std::make_shared<Drawing::Image>();
    ASSERT_NE(image, nullptr);

    auto src = Drawing::Rect(50, 50, 100, 100);  // test value
    auto dst = src;
    rsUniRenderUtil.ProcessCacheImageRect(canvas, *image, src, dst);
}

/*
 * @tc.name: TraverseAndCollectUIExtensionInfo001
 * @tc.desc: TraverseAndCollectUIExtensionInfo test when node is nullptr
 * @tc.type: FUNC
 * @tc.require: issueIAJBBO
 */
HWTEST_F(RSUniRenderUtilTest, TraverseAndCollectUIExtensionInfo001, TestSize.Level2)
{
    RSUniRenderUtil rsUniRenderUtil;
    std::shared_ptr<RSRenderNode> node = nullptr;
    ASSERT_EQ(node, nullptr);
    Drawing::Matrix parentMatrix = Drawing::Matrix();
    parentMatrix.SetMatrix(1, 0, 0, 0, 1, 0, 0, 0, 1);
    NodeId hostId = 0;
    UIExtensionCallbackData callbackData;

    rsUniRenderUtil.TraverseAndCollectUIExtensionInfo(node, parentMatrix, hostId, callbackData);
}

/*
 * @tc.name: TraverseAndCollectUIExtensionInfo002
 * @tc.desc: TraverseAndCollectUIExtensionInfo test when node is not nullptr
 * @tc.type: FUNC
 * @tc.require: issueIAJBBO
 */
HWTEST_F(RSUniRenderUtilTest, TraverseAndCollectUIExtensionInfo002, TestSize.Level2)
{
    RSUniRenderUtil rsUniRenderUtil;
    std::shared_ptr<RSRenderNode> node = std::make_shared<RSRenderNode>(0);
    ASSERT_NE(node, nullptr);
    node->childrenHasUIExtension_ = true;
    Drawing::Matrix parentMatrix = Drawing::Matrix();
    parentMatrix.SetMatrix(1, 0, 0, 0, 1, 0, 0, 0, 1);
    NodeId hostId = 0;
    UIExtensionCallbackData callbackData;

    rsUniRenderUtil.TraverseAndCollectUIExtensionInfo(node, parentMatrix, hostId, callbackData);
}

/*
 * @tc.name: TraverseAndCollectUIExtensionInfo003
 * @tc.desc: TraverseAndCollectUIExtensionInfo test when nodeType_ != nullptr
 * @tc.type: FUNC
 * @tc.require: issueIAKA4Y
 */
HWTEST_F(RSUniRenderUtilTest, TraverseAndCollectUIExtensionInfo003, TestSize.Level2)
{
    RSUniRenderUtil rsUniRenderUtil;
    std::shared_ptr<RSSurfaceRenderNode> node = std::make_shared<RSSurfaceRenderNode>(1);
    ASSERT_NE(node, nullptr);
    node->SetSurfaceNodeType(RSSurfaceNodeType::STARTING_WINDOW_NODE);
    node->childrenHasUIExtension_ = true;
    Drawing::Matrix parentMatrix = Drawing::Matrix();
    parentMatrix.SetMatrix(1, 0, 0, 0, 1, 0, 0, 0, 1);
    NodeId hostId = 1;
    UIExtensionCallbackData callbackData;
    rsUniRenderUtil.TraverseAndCollectUIExtensionInfo(node, parentMatrix, hostId, callbackData);
}

/*
 * @tc.name: AccumulateMatrixAndAlpha001
 * @tc.desc: AccumulateMatrixAndAlpha test when hwcNode is nullptr
 * @tc.type: FUNC
 * @tc.require: issueIAJBBO
 */
HWTEST_F(RSUniRenderUtilTest, AccumulateMatrixAndAlpha001, TestSize.Level2)
{
    RSUniRenderUtil rsUniRenderUtil;
    std::shared_ptr<RSSurfaceRenderNode> hwcNode = nullptr;
    ASSERT_EQ(hwcNode, nullptr);
    Drawing::Matrix matrix = Drawing::Matrix();
    matrix.SetMatrix(1, 0, 0, 0, 1, 0, 0, 0, 1);
    float alpha = 1.0f;

    rsUniRenderUtil.AccumulateMatrixAndAlpha(hwcNode, matrix, alpha);
}

/*
 * @tc.name: AccumulateMatrixAndAlpha002
 * @tc.desc: AccumulateMatrixAndAlpha test when parent is not nullptr
 * @tc.type: FUNC
 * @tc.require: issueIAJBBO
 */
HWTEST_F(RSUniRenderUtilTest, AccumulateMatrixAndAlpha002, TestSize.Level2)
{
    RSUniRenderUtil rsUniRenderUtil;
    std::shared_ptr<RSSurfaceRenderNode> hwcNode = std::make_shared<RSSurfaceRenderNode>(0);
    ASSERT_NE(hwcNode, nullptr);
    std::shared_ptr<RSSurfaceRenderNode> parent = std::make_shared<RSSurfaceRenderNode>(1);
    ASSERT_NE(parent, nullptr);
    parent->AddChild(hwcNode, 0);

    Drawing::Matrix matrix = Drawing::Matrix();
    matrix.SetMatrix(1, 0, 0, 0, 1, 0, 0, 0, 1);
    float alpha = 1.0f;

    rsUniRenderUtil.AccumulateMatrixAndAlpha(hwcNode, matrix, alpha);
}

/*
 * @tc.name: AccumulateMatrixAndAlpha003
 * @tc.desc: AccumulateMatrixAndAlpha test when alpha != 1.f
 * @tc.type: FUNC
 * @tc.require: issueIAKA4Y
 */
HWTEST_F(RSUniRenderUtilTest, AccumulateMatrixAndAlpha003, TestSize.Level2)
{
    RSUniRenderUtil rsUniRenderUtil;
    std::shared_ptr<RSSurfaceRenderNode> hwcNode = std::make_shared<RSSurfaceRenderNode>(1);
    ASSERT_NE(hwcNode, nullptr);
    std::shared_ptr<RSSurfaceRenderNode> parent = std::make_shared<RSSurfaceRenderNode>(2);
    ASSERT_NE(parent, nullptr);
    parent->AddChild(hwcNode, 0);

    Drawing::Matrix matrix = Drawing::Matrix();
    matrix.SetMatrix(1, 0, 0, 0, 1, 0, 0, 0, 1);
    float alpha = 0.8f;
    rsUniRenderUtil.AccumulateMatrixAndAlpha(hwcNode, matrix, alpha);
}

/*
 * @tc.name: OptimizedFlushAndSubmit001
 * @tc.desc: OptimizedFlushAndSubmit test when gpuContext is nullptr
 * @tc.type: FUNC
 * @tc.require: issueIAJBBO
 */
HWTEST_F(RSUniRenderUtilTest, OptimizedFlushAndSubmit001, TestSize.Level2)
{
    RSUniRenderUtil rsUniRenderUtil;
    auto surface = std::make_shared<Drawing::Surface>();
    ASSERT_NE(surface, nullptr);
    Drawing::GPUContext* gpuContext = nullptr;
    bool optFenceWait = false;

    rsUniRenderUtil.OptimizedFlushAndSubmit(surface, gpuContext, optFenceWait);
}

/*
 * @tc.name: OptimizedFlushAndSubmit002
 * @tc.desc: OptimizedFlushAndSubmit test when surface and gpuContext is multiple
 * @tc.type: FUNC
 * @tc.require: issueIALXTP
 */
HWTEST_F(RSUniRenderUtilTest, OptimizedFlushAndSubmit002, TestSize.Level2)
{
    RSUniRenderUtil rsUniRenderUtil;
    bool optFenceWait = false;
    std::shared_ptr<Drawing::Surface> surface = nullptr;
    rsUniRenderUtil.OptimizedFlushAndSubmit(surface, nullptr, optFenceWait);
    std::shared_ptr<Drawing::GPUContext> gpuContext = std::make_shared<Drawing::GPUContext>();
    ASSERT_NE(gpuContext, nullptr);
    rsUniRenderUtil.OptimizedFlushAndSubmit(surface, gpuContext.get(), optFenceWait);
    surface = std::make_shared<Drawing::Surface>();
    ASSERT_NE(surface, nullptr);
    rsUniRenderUtil.OptimizedFlushAndSubmit(surface, gpuContext.get(), optFenceWait);
}

/*
 * @tc.name: LayerScaleDown001
 * @tc.desc: LayerScaleDown test when buffer is nullptr
 * @tc.type: FUNC
 * @tc.require: issueIAJBBO
 */
HWTEST_F(RSUniRenderUtilTest, LayerScaleDown001, TestSize.Level2)
{
    RSUniRenderUtil rsUniRenderUtil;
    auto rsSurfaceRenderNode = RSTestUtil::CreateSurfaceNode();
    ASSERT_NE(rsSurfaceRenderNode, nullptr);
    RSSurfaceRenderNode& node = static_cast<RSSurfaceRenderNode&>(*(rsSurfaceRenderNode.get()));

    auto srcRect = node.GetSrcRect();
    srcRect.width_ = 100;
    srcRect.height_ = 100;
    node.SetSrcRect(srcRect);
    auto dstRect = node.GetDstRect();
    dstRect.width_ = 200;
    dstRect.height_ = 200;
    node.SetDstRect(dstRect);
    int32_t retWidth = dstRect.width_;
    int32_t retHeight = dstRect.height_;
    rsUniRenderUtil.LayerScaleDown(node);
    ASSERT_EQ(node.GetDstRect().width_, retWidth);
    ASSERT_EQ(node.GetDstRect().height_, retHeight);
}

/*
 * @tc.name: LayerScaleDownt002
 * @tc.desc: LayerScaleDown test when src < dst
 * @tc.type: FUNC
 * @tc.require: issueIAJBBO
 */
HWTEST_F(RSUniRenderUtilTest, LayerScaleDown002, TestSize.Level2)
{
    RSUniRenderUtil rsUniRenderUtil;
    auto rsSurfaceRenderNode = RSTestUtil::CreateSurfaceNodeWithBuffer();
    ASSERT_NE(rsSurfaceRenderNode, nullptr);
    RSSurfaceRenderNode& node = static_cast<RSSurfaceRenderNode&>(*(rsSurfaceRenderNode.get()));
    auto srcRect = node.GetSrcRect();
    srcRect.width_ = 100;
    srcRect.height_ = 200;
    node.SetSrcRect(srcRect);
    auto dstRect = node.GetDstRect();
    dstRect.width_ = 300;
    dstRect.height_ = 400;
    node.SetDstRect(dstRect);
    int32_t retHeight = dstRect.height_ * srcRect.width_ / dstRect.width_;
    rsUniRenderUtil.LayerScaleDown(node);
    ASSERT_EQ(node.GetSrcRect().height_, retHeight);
}

/*
 * @tc.name: LayerScaleDown003
 * @tc.desc: LayerScaleDown test when src > dst
 * @tc.type: FUNC
 * @tc.require: issueIAJBBO
 */
HWTEST_F(RSUniRenderUtilTest, LayerScaleDown003, TestSize.Level2)
{
    RSUniRenderUtil rsUniRenderUtil;
    auto rsSurfaceRenderNode = RSTestUtil::CreateSurfaceNodeWithBuffer();
    ASSERT_NE(rsSurfaceRenderNode, nullptr);
    RSSurfaceRenderNode& node = static_cast<RSSurfaceRenderNode&>(*(rsSurfaceRenderNode.get()));
    auto srcRect = node.GetSrcRect();
    srcRect.width_ = 400;
    srcRect.height_ = 600;
    node.SetSrcRect(srcRect);
    auto dstRect = node.GetDstRect();
    dstRect.width_ = 100;
    dstRect.height_ = 200;
    node.SetDstRect(dstRect);
    int32_t retWidth = srcRect.height_ * dstRect.width_ / dstRect.height_;
    rsUniRenderUtil.LayerScaleDown(node);
    ASSERT_EQ(node.GetSrcRect().width_, retWidth);
}

/*
 * @tc.name: LayerCrop002
 * @tc.desc: LayerCrop test when resDstRect != dstRectI
 * @tc.type: FUNC
 * @tc.require: issueIAJBBO
 */
HWTEST_F(RSUniRenderUtilTest, LayerCrop002, TestSize.Level2)
{
    NodeId id = 0;
    RSSurfaceRenderNode node(id);
    ScreenInfo screenInfo;

    auto dstRect = node.GetDstRect();
    dstRect.left_ = -1;
    RSUniRenderUtil::LayerCrop(node, screenInfo);
    EXPECT_EQ(screenInfo.width, 0);
}

/*
 * @tc.name: LayerCrop003
 * @tc.desc: LayerCrop test when isInFixedRotation_ is true
 * @tc.type: FUNC
 * @tc.require: issueIAJBBO
 */
HWTEST_F(RSUniRenderUtilTest, LayerCrop003, TestSize.Level2)
{
    NodeId id = 0;
    RSSurfaceRenderNode node(id);
    node.isInFixedRotation_ = true;
    ScreenInfo screenInfo;

    auto dstRect = node.GetDstRect();
    dstRect.left_ = -1;
    RSUniRenderUtil::LayerCrop(node, screenInfo);
    EXPECT_EQ(screenInfo.width, 0);
}

/*
 * @tc.name: LayerCrop004
 * @tc.desc: LayerCrop test when isInFixedRotation_ is false
 * @tc.type: FUNC
 * @tc.require: issueIAKA4Y
 */
HWTEST_F(RSUniRenderUtilTest, LayerCrop004, TestSize.Level2)
{
    NodeId id = 1;
    RSSurfaceRenderNode node(id);
    node.isInFixedRotation_ = false;
    ScreenInfo screenInfo;

    auto dstRect = node.GetDstRect();
    dstRect.left_ = -1;
    RSUniRenderUtil::LayerCrop(node, screenInfo);
    EXPECT_EQ(screenInfo.width, 0);
}

/*
 * @tc.name: LayerScaleFit005
 * @tc.desc: LayerScaleFit test when surface is nullptr
 * @tc.type: FUNC
 * @tc.require: issueIAKA4Y
 */
HWTEST_F(RSUniRenderUtilTest, LayerScaleFit005, TestSize.Level2)
{
    RSUniRenderUtil rsUniRenderUtil;
    auto rsSurfaceRenderNode = RSTestUtil::CreateSurfaceNode();
    ASSERT_NE(rsSurfaceRenderNode, nullptr);
    RSSurfaceRenderNode& node = static_cast<RSSurfaceRenderNode&>(*(rsSurfaceRenderNode.get()));
    node.GetRSSurfaceHandler()->consumer_ = nullptr;

    rsUniRenderUtil.LayerScaleFit(node);
}

/*
 * @tc.name: LayerScaleFit004
 * @tc.desc: LayerScaleFit test when buffer is nullptr
 * @tc.type: FUNC
 * @tc.require: issueIAJBBO
 */
HWTEST_F(RSUniRenderUtilTest, LayerScaleFit004, TestSize.Level2)
{
    RSUniRenderUtil rsUniRenderUtil;
    auto rsSurfaceRenderNode = RSTestUtil::CreateSurfaceNode();
    ASSERT_NE(rsSurfaceRenderNode, nullptr);
    RSSurfaceRenderNode& node = static_cast<RSSurfaceRenderNode&>(*(rsSurfaceRenderNode.get()));

    auto srcRect = node.GetSrcRect();
    srcRect.width_ = 100;
    srcRect.height_ = 100;
    node.SetSrcRect(srcRect);
    auto dstRect = node.GetDstRect();
    dstRect.width_ = 200;
    dstRect.height_ = 200;
    node.SetDstRect(dstRect);
    int32_t retWidth = dstRect.width_;
    int32_t retHeight = dstRect.height_;
    rsUniRenderUtil.LayerScaleFit(node);
    ASSERT_EQ(node.GetDstRect().width_, retWidth);
    ASSERT_EQ(node.GetDstRect().height_, retHeight);
}

/*
 * @tc.name: LayerScaleFitTest01
 * @tc.desc: LayerScaleFit test
 * @tc.type: FUNC
 * @tc.require: issueI9SDDH
 */
HWTEST_F(RSUniRenderUtilTest, LayerScaleFitTest01, TestSize.Level2)
{
    RSUniRenderUtil rsUniRenderUtil;
    auto rsSurfaceRenderNode = RSTestUtil::CreateSurfaceNodeWithBuffer();
    ASSERT_NE(rsSurfaceRenderNode, nullptr);
    RSSurfaceRenderNode& node = static_cast<RSSurfaceRenderNode&>(*(rsSurfaceRenderNode.get()));
    auto srcRect = node.GetSrcRect();
    srcRect.width_ = 100;
    srcRect.height_ = 100;
    node.SetSrcRect(srcRect);
    auto dstRect = node.GetDstRect();
    dstRect.width_ = 200;
    dstRect.height_ = 200;
    node.SetDstRect(dstRect);
    int32_t retWidth = dstRect.width_;
    int32_t retHeight = dstRect.height_;
    rsUniRenderUtil.LayerScaleFit(node);
    ASSERT_EQ(node.GetDstRect().width_, retWidth);
    ASSERT_EQ(node.GetDstRect().height_, retHeight);
}

/*
 * @tc.name: LayerScaleFitTest02
 * @tc.desc: LayerScaleFit test
 * @tc.type: FUNC
 * @tc.require: issueI9SDDH
 */
HWTEST_F(RSUniRenderUtilTest, LayerScaleFitTest02, TestSize.Level2)
{
    RSUniRenderUtil rsUniRenderUtil;
    auto rsSurfaceRenderNode = RSTestUtil::CreateSurfaceNodeWithBuffer();
    ASSERT_NE(rsSurfaceRenderNode, nullptr);
    RSSurfaceRenderNode& node = static_cast<RSSurfaceRenderNode&>(*(rsSurfaceRenderNode.get()));
    auto srcRect = node.GetSrcRect();
    srcRect.width_ = 100;
    srcRect.height_ = 200;
    node.SetSrcRect(srcRect);
    auto dstRect = node.GetDstRect();
    dstRect.width_ = 300;
    dstRect.height_ = 400;
    node.SetDstRect(dstRect);
    int32_t retWidth = srcRect.width_ * dstRect.height_ / srcRect.height_;
    int32_t retHeight = dstRect.height_;
    rsUniRenderUtil.LayerScaleFit(node);
    ASSERT_EQ(node.GetDstRect().width_, retWidth);
    ASSERT_EQ(node.GetDstRect().height_, retHeight);
}

/*
 * @tc.name: LayerScaleFitTest03
 * @tc.desc: LayerScaleFit test
 * @tc.type: FUNC
 * @tc.require: issueI9SDDH
 */
HWTEST_F(RSUniRenderUtilTest, LayerScaleFitTest03, TestSize.Level2)
{
    RSUniRenderUtil rsUniRenderUtil;
    auto rsSurfaceRenderNode = RSTestUtil::CreateSurfaceNodeWithBuffer();
    ASSERT_NE(rsSurfaceRenderNode, nullptr);
    RSSurfaceRenderNode& node = static_cast<RSSurfaceRenderNode&>(*(rsSurfaceRenderNode.get()));
    auto srcRect = node.GetSrcRect();
    srcRect.width_ = 400;
    srcRect.height_ = 600;
    node.SetSrcRect(srcRect);
    auto dstRect = node.GetDstRect();
    dstRect.width_ = 100;
    dstRect.height_ = 200;
    node.SetDstRect(dstRect);
    int32_t retWidth = dstRect.width_;
    int32_t retHeight = srcRect.height_ * dstRect.width_ / srcRect.width_;
    rsUniRenderUtil.LayerScaleFit(node);
    ASSERT_EQ(node.GetDstRect().width_, retWidth);
    ASSERT_EQ(node.GetDstRect().height_, retHeight);
}

/*
 * @tc.name: CreateBufferDrawParam001
 * @tc.desc: test CreateBufferDrawParam when surfaceHandler.buffer is nullptr
 * @tc.type: FUNC
 * @tc.require: issueIAJOWI
 */
HWTEST_F(RSUniRenderUtilTest, CreateBufferDrawParam001, TestSize.Level2)
{
    NodeId id = 1;
    RSSurfaceHandler surfaceHandler(id);
    bool forceCPU = true;
    BufferDrawParam params = RSUniRenderUtil::CreateBufferDrawParam(surfaceHandler, forceCPU);
    ASSERT_EQ(params.buffer, nullptr);
}

/*
 * @tc.name: GetMatrixOfBufferToRelRect_003
 * @tc.desc: test GetMatrixOfBufferToRelRect with surfaceNode without consumer
 * @tc.type: FUNC
 * @tc.require: issueIAJBBO
 */
HWTEST_F(RSUniRenderUtilTest, GetMatrixOfBufferToRelRect_003, TestSize.Level2)
{
    auto rsSurfaceRenderNode = RSTestUtil::CreateSurfaceNodeWithBuffer();
    ASSERT_NE(rsSurfaceRenderNode, nullptr);
    RSSurfaceRenderNode& node = static_cast<RSSurfaceRenderNode&>(*(rsSurfaceRenderNode.get()));
    node.GetRSSurfaceHandler()->consumer_ = nullptr;
    auto matrix = RSUniRenderUtil::GetMatrixOfBufferToRelRect(node);
    ASSERT_EQ(matrix, Drawing::Matrix());
}

/*
 * @tc.name: CreateBufferDrawParam002
 * @tc.desc: CreateBufferDrawParam test with RSDisplayRenderNode when buffer is not nullptr
 * @tc.type: FUNC
 * @tc.require: issueIAKDJI
 */
HWTEST_F(RSUniRenderUtilTest, CreateBufferDrawParam002, TestSize.Level2)
{
    RSUniRenderUtil rsUniRenderUtil;
    NodeId id = 1;
    RSDisplayNodeConfig config;
    auto rsDisplayRenderNode = std::make_shared<RSDisplayRenderNode>(id++, config);
    ASSERT_NE(rsDisplayRenderNode, nullptr);
    auto node = std::make_shared<RSRenderNode>(id++);
    auto rsDisplayRenderNodeDrawable = std::make_shared<DrawableV2::RSDisplayRenderNodeDrawable>(node);
    rsDisplayRenderNodeDrawable->surfaceHandler_ = std::make_shared<RSSurfaceHandler>(node->id_);
    rsDisplayRenderNode->renderDrawable_ = rsDisplayRenderNodeDrawable;
    auto surfaceNode = RSTestUtil::CreateSurfaceNodeWithBuffer();
    auto buffer = surfaceNode->surfaceHandler_->GetBuffer();
    ASSERT_NE(buffer, nullptr);
    buffer->SetSurfaceBufferWidth(400);
    buffer->SetSurfaceBufferHeight(400);
    rsDisplayRenderNodeDrawable->surfaceHandler_->buffer_.buffer = buffer;
    auto cpuParam = rsUniRenderUtil.CreateBufferDrawParam(*rsDisplayRenderNode, true);
    auto nocpuParam = rsUniRenderUtil.CreateBufferDrawParam(*rsDisplayRenderNode, false);
    ASSERT_NE(cpuParam.useCPU, nocpuParam.useCPU);
    ASSERT_EQ(cpuParam.buffer, nocpuParam.buffer);
    ASSERT_EQ(cpuParam.acquireFence, nocpuParam.acquireFence);
    ASSERT_EQ(cpuParam.srcRect, nocpuParam.srcRect);
    ASSERT_EQ(cpuParam.dstRect, nocpuParam.dstRect);
}

/*
 * @tc.name: CreateBufferDrawParam003
 * @tc.desc: CreateBufferDrawParam test with RSDisplayRenderNode when drawable is nullptr
 * @tc.type: FUNC
 * @tc.require: issueIAKDJI
 */
HWTEST_F(RSUniRenderUtilTest, CreateBufferDrawParam003, TestSize.Level2)
{
    RSUniRenderUtil rsUniRenderUtil;
    NodeId id = 1;
    RSDisplayNodeConfig config;
    auto rsDisplayRenderNode = std::make_shared<RSDisplayRenderNode>(id++, config);
    auto cpuParam = rsUniRenderUtil.CreateBufferDrawParam(*rsDisplayRenderNode, true);
    auto nocpuParam = rsUniRenderUtil.CreateBufferDrawParam(*rsDisplayRenderNode, false);
    ASSERT_NE(cpuParam.useCPU, nocpuParam.useCPU);
    ASSERT_EQ(cpuParam.buffer, nullptr);
    ASSERT_EQ(nocpuParam.buffer, nullptr);
}

/*
 * @tc.name: CreateBufferDrawParam004
 * @tc.desc: CreateBufferDrawParam test with RSDisplayRenderNode when buffer is nullptr
 * @tc.type: FUNC
 * @tc.require: issueIAKDJI
 */
HWTEST_F(RSUniRenderUtilTest, CreateBufferDrawParam004, TestSize.Level2)
{
    RSUniRenderUtil rsUniRenderUtil;
    NodeId id = 1;
    RSDisplayNodeConfig config;
    auto rsDisplayRenderNode = std::make_shared<RSDisplayRenderNode>(id++, config);
    auto node = std::make_shared<RSRenderNode>(id++);
    auto rsDisplayRenderNodeDrawable = std::make_shared<DrawableV2::RSDisplayRenderNodeDrawable>(node);
    rsDisplayRenderNodeDrawable->surfaceHandler_ = std::make_shared<RSSurfaceHandler>(node->id_);
    rsDisplayRenderNode->renderDrawable_ = rsDisplayRenderNodeDrawable;
    auto cpuParam = rsUniRenderUtil.CreateBufferDrawParam(*rsDisplayRenderNode, true);
    auto nocpuParam = rsUniRenderUtil.CreateBufferDrawParam(*rsDisplayRenderNode, false);
    ASSERT_NE(cpuParam.useCPU, nocpuParam.useCPU);
    ASSERT_EQ(cpuParam.buffer, nullptr);
    ASSERT_EQ(nocpuParam.buffer, nullptr);
}

/*
 * @tc.name: CreateBufferDrawParam005
 * @tc.desc: CreateBufferDrawParam test with RSSurfaceRenderNodeDrawable when param is nullptr
 * @tc.type: FUNC
 * @tc.require: issueIAKDJI
 */
HWTEST_F(RSUniRenderUtilTest, CreateBufferDrawParam005, TestSize.Level2)
{
    RSUniRenderUtil rsUniRenderUtil;
    auto node = RSTestUtil::CreateSurfaceNode();
    auto drawable = std::make_shared<DrawableV2::RSSurfaceRenderNodeDrawable>(node);
    auto cpuParam = rsUniRenderUtil.CreateBufferDrawParam(*drawable, true, 1);
    auto nocpuParam = rsUniRenderUtil.CreateBufferDrawParam(*drawable, false, 1);
    ASSERT_EQ(cpuParam.buffer, nullptr);
    ASSERT_EQ(nocpuParam.buffer, nullptr);
}

/*
 * @tc.name: CreateBufferDrawParam006
 * @tc.desc: CreateBufferDrawParam test with RSSurfaceRenderNodeDrawable when buffer is nullptr
 * @tc.type: FUNC
 * @tc.require: issueIAKDJI
 */
HWTEST_F(RSUniRenderUtilTest, CreateBufferDrawParam006, TestSize.Level2)
{
    RSUniRenderUtil rsUniRenderUtil;
    auto node = RSTestUtil::CreateSurfaceNode();
    auto drawable = std::make_shared<DrawableV2::RSSurfaceRenderNodeDrawable>(node);
    drawable->renderParams_ = std::make_unique<RSSurfaceRenderParams>(node->id_);
    auto cpuParam = rsUniRenderUtil.CreateBufferDrawParam(*drawable, true, 1);
    auto nocpuParam = rsUniRenderUtil.CreateBufferDrawParam(*drawable, false, 1);
    ASSERT_NE(cpuParam.useCPU, nocpuParam.useCPU);
    ASSERT_EQ(cpuParam.useBilinearInterpolation, nocpuParam.useBilinearInterpolation);
    ASSERT_EQ(cpuParam.threadIndex, nocpuParam.threadIndex);
    ASSERT_EQ(cpuParam.buffer, nullptr);
    ASSERT_EQ(nocpuParam.buffer, nullptr);
}

/*
 * @tc.name: CreateBufferDrawParam007
 * @tc.desc: CreateBufferDrawParam test with RSSurfaceRenderNodeDrawable when consumer is nullptr
 * @tc.type: FUNC
 * @tc.require: issueIAKDJI
 */
HWTEST_F(RSUniRenderUtilTest, CreateBufferDrawParam007, TestSize.Level2)
{
    RSUniRenderUtil rsUniRenderUtil;
    auto surfaceNode = RSTestUtil::CreateSurfaceNodeWithBuffer();
    auto node = RSTestUtil::CreateSurfaceNode();
    auto drawable = std::make_shared<DrawableV2::RSSurfaceRenderNodeDrawable>(node);
    auto param = std::make_unique<RSSurfaceRenderParams>(node->id_);
    param->buffer_ = surfaceNode->surfaceHandler_->GetBuffer();
    drawable->renderParams_ = std::move(param);
    auto cpuParam = rsUniRenderUtil.CreateBufferDrawParam(*drawable, true, 1);
    auto nocpuParam = rsUniRenderUtil.CreateBufferDrawParam(*drawable, false, 1);
    ASSERT_NE(cpuParam.useCPU, nocpuParam.useCPU);
    ASSERT_EQ(cpuParam.useBilinearInterpolation, nocpuParam.useBilinearInterpolation);
    ASSERT_EQ(cpuParam.threadIndex, nocpuParam.threadIndex);
    ASSERT_EQ(cpuParam.buffer, nocpuParam.buffer);
    ASSERT_EQ(cpuParam.acquireFence, nocpuParam.acquireFence);
    ASSERT_EQ(cpuParam.srcRect, nocpuParam.srcRect);
}

/*
 * @tc.name: CreateBufferDrawParam008
 * @tc.desc: CreateBufferDrawParam test with RSSurfaceRenderNodeDrawable when consumer is nullptr
 * @tc.type: FUNC
 * @tc.require: issueIAKDJI
 */
HWTEST_F(RSUniRenderUtilTest, CreateBufferDrawParam008, TestSize.Level2)
{
    RSUniRenderUtil rsUniRenderUtil;
    auto surfaceNode = RSTestUtil::CreateSurfaceNodeWithBuffer();
    auto node = RSTestUtil::CreateSurfaceNode();
    auto drawable = std::make_shared<DrawableV2::RSSurfaceRenderNodeDrawable>(node);
    auto param = std::make_unique<RSSurfaceRenderParams>(node->id_);
    param->buffer_ = surfaceNode->surfaceHandler_->GetBuffer();
    drawable->consumerOnDraw_ = surfaceNode->surfaceHandler_->GetConsumer();
    param->scalingMode_ = SCALING_MODE_SCALE_CROP;
    drawable->renderParams_ = std::move(param);
    auto cpuParam = rsUniRenderUtil.CreateBufferDrawParam(*drawable, true, 1);
    auto nocpuParam = rsUniRenderUtil.CreateBufferDrawParam(*drawable, false, 1);
    ASSERT_NE(cpuParam.useCPU, nocpuParam.useCPU);
    ASSERT_EQ(cpuParam.useBilinearInterpolation, nocpuParam.useBilinearInterpolation);
    ASSERT_EQ(cpuParam.threadIndex, nocpuParam.threadIndex);
    ASSERT_EQ(cpuParam.buffer, nocpuParam.buffer);
    ASSERT_EQ(cpuParam.acquireFence, nocpuParam.acquireFence);
    ASSERT_EQ(cpuParam.srcRect, nocpuParam.srcRect);
}

/*
 * @tc.name: CreateBufferDrawParam009
 * @tc.desc: CreateBufferDrawParam test with RSSurfaceRenderNodeDrawable when consumer is nullptr
 * @tc.type: FUNC
 * @tc.require: issueIAKDJI
 */
HWTEST_F(RSUniRenderUtilTest, CreateBufferDrawParam009, TestSize.Level2)
{
    RSUniRenderUtil rsUniRenderUtil;
    auto surfaceNode = RSTestUtil::CreateSurfaceNodeWithBuffer();
    auto node = RSTestUtil::CreateSurfaceNode();
    auto drawable = std::make_shared<DrawableV2::RSSurfaceRenderNodeDrawable>(node);
    auto param = std::make_unique<RSSurfaceRenderParams>(node->id_);
    param->buffer_ = surfaceNode->surfaceHandler_->GetBuffer();
    drawable->consumerOnDraw_ = surfaceNode->surfaceHandler_->GetConsumer();
    param->scalingMode_ = SCALING_MODE_SCALE_FIT;
    drawable->renderParams_ = std::move(param);
    auto cpuParam = rsUniRenderUtil.CreateBufferDrawParam(*drawable, true, 1);
    auto nocpuParam = rsUniRenderUtil.CreateBufferDrawParam(*drawable, false, 1);
    ASSERT_NE(cpuParam.useCPU, nocpuParam.useCPU);
    ASSERT_EQ(cpuParam.useBilinearInterpolation, nocpuParam.useBilinearInterpolation);
    ASSERT_EQ(cpuParam.threadIndex, nocpuParam.threadIndex);
    ASSERT_EQ(cpuParam.buffer, nocpuParam.buffer);
    ASSERT_EQ(cpuParam.acquireFence, nocpuParam.acquireFence);
    ASSERT_EQ(cpuParam.srcRect, nocpuParam.srcRect);
}
/*
 * @tc.name: FlushDmaSurfaceBuffer001
 * @tc.desc: test FlushDmaSurfaceBuffer when pixelMap is nullptr
 * @tc.type: FUNC
 * @tc.require: issueIAL5XA
 */
HWTEST_F(RSUniRenderUtilTest, FlushDmaSurfaceBuffer001, TestSize.Level2)
{
    Media::PixelMap* pixelMap = nullptr;
    ASSERT_EQ(pixelMap, nullptr);
    RSUniRenderUtil::FlushDmaSurfaceBuffer(pixelMap);
}

/*
 * @tc.name: FlushDmaSurfaceBuffer002
 * @tc.desc: test FlushDmaSurfaceBuffer when pixelMap is not nullptr
 * @tc.type: FUNC
 * @tc.require: issueIALXTP
 */
HWTEST_F(RSUniRenderUtilTest, FlushDmaSurfaceBuffer002, TestSize.Level2)
{
    Media::InitializationOptions opts;
    const double width = 100;
    const double height = 100;
    opts.size.width = width;
    opts.size.height = height;
    auto pixelMap = Media::PixelMap::Create(opts);
    ASSERT_NE(pixelMap, nullptr);
    RSUniRenderUtil::FlushDmaSurfaceBuffer(pixelMap.get());
#if defined(ROSEN_OHOS) && defined(RS_ENABLE_VK)
    DmaMem dmaMem;
    Drawing::ImageInfo info = Drawing::ImageInfo{ pixelMap->GetWidth(), pixelMap->GetHeight(),
        Drawing::COLORTYPE_RGBA_8888, Drawing::ALPHATYPE_PREMUL };
    sptr<SurfaceBuffer> surFaceBuffer = dmaMem.DmaMemAlloc(info, pixelMap);
    RSUniRenderUtil::FlushDmaSurfaceBuffer(pixelMap.get());
#endif
}

/*
 * @tc.name: IntersectRect
 * @tc.desc: test GraphicIRect intersect with GraphicIRect
 * @tc.type: FUNC
 * @tc.require: issueIARLU9
 */
HWTEST_F(RSUniRenderUtilTest, IntersectRect, TestSize.Level2)
{
    GraphicIRect srcRect = { 0, 0, 1080, 1920 };
    GraphicIRect emptyRect = { 0, 0, 0, 0 };

    GraphicIRect rect = emptyRect; // no intersect
    GraphicIRect result = RSUniRenderUtil::IntersectRect(srcRect, rect);
    ASSERT_EQ(result, emptyRect);

    rect = { -500, -500, -100, -100 }; // no intersect
    result = RSUniRenderUtil::IntersectRect(srcRect, rect);
    ASSERT_EQ(result, emptyRect);

    rect = { 1100, 0, 100, 100 }; // no intersect
    result = RSUniRenderUtil::IntersectRect(srcRect, rect);
    ASSERT_EQ(result, emptyRect);

    rect = { 200, 200, 800, 800 }; // all intersect
    result = RSUniRenderUtil::IntersectRect(srcRect, rect);
    ASSERT_EQ(result, rect);

    rect = { -100, -100, 3000, 3000 }; // src rect
    result = RSUniRenderUtil::IntersectRect(srcRect, rect);
    ASSERT_EQ(result, srcRect);

    rect = { -100, -100, 1000, 1000 }; // partial intersect
    result = RSUniRenderUtil::IntersectRect(srcRect, rect);
    GraphicIRect expect = { 0, 0, 900, 900 };
    ASSERT_EQ(result, expect);

    rect = { 500, 500, 2000, 2000 }; // partial intersect
    result = RSUniRenderUtil::IntersectRect(srcRect, rect);
    expect = { 500, 500, 580, 1420 };
    ASSERT_EQ(result, expect);
}

/*
 * @tc.name: GetMatrix_001
 * @tc.desc: test GetMatrix with nullptr Node
 * @tc.type: FUNC
 * @tc.require: issueIAVIB4
 */
HWTEST_F(RSUniRenderUtilTest, GetMatrix_001, TestSize.Level2)
{
    std::shared_ptr<RSRenderNode> node = nullptr;
    ASSERT_EQ(node, nullptr);
    ASSERT_EQ(RSUniRenderUtil::GetMatrix(node), std::nullopt);
}

/*
 * @tc.name: GetMatrix_002
 * @tc.desc: test GetMatrix with nullptr boundsGeo_
 * @tc.type: FUNC
 * @tc.require: issueIAVIB4
 */
HWTEST_F(RSUniRenderUtilTest, GetMatrix_002, TestSize.Level2)
{
    NodeId id = 1;
    std::shared_ptr<RSRenderNode> node = std::make_shared<RSRenderNode>(id);
    ASSERT_NE(node, nullptr);
    node->renderContent_->renderProperties_.boundsGeo_ = nullptr;
    ASSERT_EQ(RSUniRenderUtil::GetMatrix(node), std::nullopt);
}

/*
 * @tc.name: GetMatrix_003
 * @tc.desc: test GetMatrix with boundsGeo_
 * @tc.type: FUNC
 * @tc.require: issueIAVIB4
 */
HWTEST_F(RSUniRenderUtilTest, GetMatrix_003, TestSize.Level2)
{
    NodeId id = 1;
    std::shared_ptr<RSRenderNode> node = std::make_shared<RSRenderNode>(id);
    ASSERT_NE(node, nullptr);
    node->renderContent_->renderProperties_.boundsGeo_ = std::make_shared<RSObjAbsGeometry>();
    ASSERT_EQ(RSUniRenderUtil::GetMatrix(node), node->renderContent_->renderProperties_.boundsGeo_->GetMatrix());
}

/*
 * @tc.name: GetMatrix_004
 * @tc.desc: test GetMatrix sandbox hasvalue and parent is nullptr
 * @tc.type: FUNC
 * @tc.require: issueIAVIB4
 */
HWTEST_F(RSUniRenderUtilTest, GetMatrix_004, TestSize.Level2)
{
    NodeId id = 1;
    std::shared_ptr<RSRenderNode> node = std::make_shared<RSRenderNode>(id);
    ASSERT_NE(node, nullptr);
    node->renderContent_->renderProperties_.boundsGeo_ = std::make_shared<RSObjAbsGeometry>();
    node->renderContent_->renderProperties_.sandbox_ = std::make_unique<Sandbox>();
    node->renderContent_->renderProperties_.sandbox_->position_ = std::make_optional<Vector2f>(1.0f, 1.0f);
    ASSERT_EQ(RSUniRenderUtil::GetMatrix(node), std::nullopt);
}

/*
 * @tc.name: GetMatrix_005
 * @tc.desc: test GetMatrix sandbox hasvalue and parent has no geo
 * @tc.type: FUNC
 * @tc.require: issueIAVIB4
 */
HWTEST_F(RSUniRenderUtilTest, GetMatrix_005, TestSize.Level2)
{
    NodeId parentId = 0;
    std::shared_ptr<RSRenderNode> parentNode = std::make_shared<RSRenderNode>(parentId);
    ASSERT_NE(parentNode, nullptr);
    parentNode->renderContent_->renderProperties_.boundsGeo_ = nullptr;
    NodeId id = 1;
    std::shared_ptr<RSRenderNode> node = std::make_shared<RSRenderNode>(id);
    ASSERT_NE(node, nullptr);
    node->renderContent_->renderProperties_.boundsGeo_ = std::make_shared<RSObjAbsGeometry>();
    node->renderContent_->renderProperties_.sandbox_ = std::make_unique<Sandbox>();
    node->renderContent_->renderProperties_.sandbox_->position_ = std::make_optional<Vector2f>(1.0f, 1.0f);
    node->SetParent(parentNode);
    ASSERT_EQ(RSUniRenderUtil::GetMatrix(node), Drawing::Matrix());
}

/*
 * @tc.name: GetMatrix_006
 * @tc.desc: test GetMatrix sandbox hasvalue and parent has geo
 * @tc.type: FUNC
 * @tc.require: issueIAVIB4
 */
HWTEST_F(RSUniRenderUtilTest, GetMatrix_006, TestSize.Level2)
{
    NodeId parentId = 0;
    std::shared_ptr<RSRenderNode> parentNode = std::make_shared<RSRenderNode>(parentId);
    ASSERT_NE(parentNode, nullptr);
    parentNode->renderContent_->renderProperties_.boundsGeo_ = std::make_shared<RSObjAbsGeometry>();
    NodeId id = 1;
    std::shared_ptr<RSRenderNode> node = std::make_shared<RSRenderNode>(id);
    ASSERT_NE(node, nullptr);
    node->renderContent_->renderProperties_.boundsGeo_ = std::make_shared<RSObjAbsGeometry>();
    node->renderContent_->renderProperties_.sandbox_ = std::make_unique<Sandbox>();
    node->renderContent_->renderProperties_.sandbox_->position_ = std::make_optional<Vector2f>(1.0f, 1.0f);
    node->SetParent(parentNode);
    auto invertAbsParentMatrix = Drawing::Matrix();
    parentNode->renderContent_->renderProperties_.boundsGeo_->GetAbsMatrix().Invert(invertAbsParentMatrix);
    auto assertResult = node->renderContent_->renderProperties_.boundsGeo_->GetAbsMatrix();
    assertResult.PostConcat(invertAbsParentMatrix);
    ASSERT_EQ(RSUniRenderUtil::GetMatrix(node), assertResult);
}

/**
 * @tc.name: CheckRenderSkipIfScreenOff001
 * @tc.desc: Test CheckRenderSkipIfScreenOff, no need for extra frame
 * @tc.type: FUNC
 * @tc.require: #I9UNQP
 */
HWTEST_F(RSUniRenderUtilTest, CheckRenderSkipIfScreenOff001, TestSize.Level1)
{
    if (!RSSystemProperties::GetSkipDisplayIfScreenOffEnabled() || RSSystemProperties::IsPcType()) {
        return;
    }
    ScreenId screenId = 1;
    auto screenManager = CreateOrGetScreenManager();
    OHOS::Rosen::impl::RSScreenManager& screenManagerImpl =
        static_cast<OHOS::Rosen::impl::RSScreenManager&>(*screenManager);
    screenManagerImpl.powerOffNeedProcessOneFrame_ = false;

    screenManagerImpl.screenPowerStatus_[screenId] = ScreenPowerStatus::POWER_STATUS_ON;
    EXPECT_FALSE(RSUniRenderUtil::CheckRenderSkipIfScreenOff(false, screenId));
    screenManagerImpl.screenPowerStatus_[screenId] = ScreenPowerStatus::POWER_STATUS_ON_ADVANCED;
    EXPECT_FALSE(RSUniRenderUtil::CheckRenderSkipIfScreenOff(false, screenId));
    screenManagerImpl.screenPowerStatus_[screenId] = ScreenPowerStatus::POWER_STATUS_SUSPEND;
    EXPECT_TRUE(RSUniRenderUtil::CheckRenderSkipIfScreenOff(false, screenId));
    screenManagerImpl.screenPowerStatus_[screenId] = ScreenPowerStatus::POWER_STATUS_OFF;
    EXPECT_TRUE(RSUniRenderUtil::CheckRenderSkipIfScreenOff(false, screenId));
}

/**
 * @tc.name: CheckRenderSkipIfScreenOff002
 * @tc.desc: Test CheckRenderSkipIfScreenOff, need extra frame
 * @tc.type: FUNC
 * @tc.require: #I9UNQP
 */
HWTEST_F(RSUniRenderUtilTest, CheckRenderSkipIfScreenOff002, TestSize.Level1)
{
    if (!RSSystemProperties::GetSkipDisplayIfScreenOffEnabled() || RSSystemProperties::IsPcType()) {
        return;
    }
    ScreenId screenId = 1;
    auto screenManager = CreateOrGetScreenManager();
    OHOS::Rosen::impl::RSScreenManager& screenManagerImpl =
        static_cast<OHOS::Rosen::impl::RSScreenManager&>(*screenManager);

    screenManagerImpl.powerOffNeedProcessOneFrame_ = true;
    screenManagerImpl.screenPowerStatus_[screenId] = ScreenPowerStatus::POWER_STATUS_ON;
    EXPECT_FALSE(RSUniRenderUtil::CheckRenderSkipIfScreenOff(false, screenId));
    screenManagerImpl.powerOffNeedProcessOneFrame_ = true;
    screenManagerImpl.screenPowerStatus_[screenId] = ScreenPowerStatus::POWER_STATUS_ON_ADVANCED;
    EXPECT_FALSE(RSUniRenderUtil::CheckRenderSkipIfScreenOff(false, screenId));
    screenManagerImpl.powerOffNeedProcessOneFrame_ = true;
    screenManagerImpl.screenPowerStatus_[screenId] = ScreenPowerStatus::POWER_STATUS_SUSPEND;
    EXPECT_FALSE(RSUniRenderUtil::CheckRenderSkipIfScreenOff(false, screenId));
    screenManagerImpl.powerOffNeedProcessOneFrame_ = true;
    screenManagerImpl.screenPowerStatus_[screenId] = ScreenPowerStatus::POWER_STATUS_OFF;
    EXPECT_FALSE(RSUniRenderUtil::CheckRenderSkipIfScreenOff(false, screenId));
}
} // namespace OHOS::Rosen
