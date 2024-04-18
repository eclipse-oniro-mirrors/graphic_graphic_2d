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

#include "drawable/rs_surface_render_node_drawable.h"

#include <memory>
#include "common/rs_color.h"
#include "common/rs_common_def.h"
#include "draw/brush.h"
#include "rs_trace.h"

#include "common/rs_obj_abs_geometry.h"
#include "impl_interface/region_impl.h"
#include "memory/rs_tag_tracker.h"
#include "params/rs_display_render_params.h"
#include "pipeline/rs_paint_filter_canvas.h"
#include "pipeline/rs_surface_render_node.h"
#include "pipeline/rs_uni_render_thread.h"
#include "pipeline/rs_uni_render_util.h"

#ifdef RS_PARALLEL
#include "common/rs_color.h"
#include "common/rs_common_def.h"
#include "draw/brush.h"

#include "platform/common/rs_log.h"
#include "utils/rect.h"
#include "utils/region.h"

#include "pipeline/rs_uifirst_manager.h"
#include "pipeline/parallel_render/rs_sub_thread_manager.h"
#include "pipeline/rs_main_thread.h"
#ifdef RS_ENABLE_VK
#include "include/gpu/GrBackendSurface.h"
#include "platform/ohos/backend/native_buffer_utils.h"
#include "platform/ohos/backend/rs_vulkan_context.h"
#endif
#endif

namespace OHOS::Rosen::DrawableV2 {
RSSurfaceRenderNodeDrawable::Registrar RSSurfaceRenderNodeDrawable::instance_;

RSSurfaceRenderNodeDrawable::RSSurfaceRenderNodeDrawable(std::shared_ptr<const RSRenderNode>&& node)
    : RSRenderNodeDrawable(std::move(node)) {}
 
RSSurfaceRenderNodeDrawable::~RSSurfaceRenderNodeDrawable()
{
    ClearCacheSurfaceInThread();
}

RSRenderNodeDrawable::Ptr RSSurfaceRenderNodeDrawable::OnGenerate(std::shared_ptr<const RSRenderNode> node)
{
    RS_TRACE_NAME("RSRenderNodeDrawable::Ptr RSSurfaceRenderNodeDrawable::OnGenerate");
    return new RSSurfaceRenderNodeDrawable(std::move(node));
}

Drawing::Region RSSurfaceRenderNodeDrawable::CalculateVisibleRegion(RSSurfaceRenderParams *surfaceParams,
    std::shared_ptr<RSSurfaceRenderNode> surfaceNode, bool isOffscreen) const
{
    Drawing::Region resultRegion;
    if (!surfaceParams->IsMainWindowType()) {
        return resultRegion;
    }

    // FUTURE: return real region
    if (isOffscreen) {
        resultRegion.SetRect(Drawing::RectI(0, 0,
        DRAWING_MAX_S32_FITS_IN_FLOAT, DRAWING_MAX_S32_FITS_IN_FLOAT));
        return resultRegion;
    }

    // The region is dirty region of this SurfaceNode.
    Occlusion::Region surfaceNodeDirtyRegion(surfaceNode->GetSyncDirtyManager()->GetDirtyRegion());
    // The region is the result of global dirty region AND occlusion region.
    Occlusion::Region globalDirtyRegion = surfaceNode->GetGlobalDirtyRegion();
    // This include dirty region and occlusion region when surfaceNode is mainWindow.
    auto visibleDirtyRegion = globalDirtyRegion.Or(surfaceNodeDirtyRegion);
    if (visibleDirtyRegion.IsEmpty()) {
        RS_LOGD("RSSurfaceRenderNodeDrawable::OnDraw occlusion skip SurfaceName:%s NodeId:%" PRIu64 "",
            surfaceNode->GetName().c_str(), surfaceParams->GetId());
        return resultRegion;
    }

    for (auto& rect : visibleDirtyRegion.GetRegionRects()) {
        Drawing::Region tempRegion;
        tempRegion.SetRect(Drawing::RectI(rect.left_, rect.top_, rect.right_, rect.bottom_));
        resultRegion.Op(tempRegion, Drawing::RegionOp::UNION);
    }
    return resultRegion;
}

bool RSSurfaceRenderNodeDrawable::CheckIfNeedResetRotate(RSPaintFilterCanvas& canvas)
{
    auto matrix = canvas.GetTotalMatrix();
    int angle = RSUniRenderUtil::GetRotationFromMatrix(matrix);
    constexpr int ROTATION_90 = 90;
    return angle != 0 && angle % ROTATION_90 == 0;
}

NodeId RSSurfaceRenderNodeDrawable::FindInstanceChildOfDisplay(std::shared_ptr<RSRenderNode> node)
{
    if (node == nullptr || node->GetParent().lock() == nullptr) {
        return INVALID_NODEID;
    } else if (node->GetParent().lock()->GetType() == RSRenderNodeType::DISPLAY_NODE) {
        return node->GetId();
    } else {
        return FindInstanceChildOfDisplay(node->GetParent().lock());
    }
}

void RSSurfaceRenderNodeDrawable::CacheImgForCapture(RSPaintFilterCanvas& canvas,
    std::shared_ptr<RSDisplayRenderNode> curDisplayNode)
{
    if (!curDisplayNode->GetSecurityDisplay() && canvas.GetSurface() != nullptr) {
        bool resetRotate = CheckIfNeedResetRotate(canvas);
        auto cacheImgForCapture = canvas.GetSurface()->GetImageSnapshot();
        auto mirrorNode = curDisplayNode->GetMirrorSource().lock() ?
            curDisplayNode->GetMirrorSource().lock() : curDisplayNode;
        mirrorNode->SetCacheImgForCapture(cacheImgForCapture);
        mirrorNode->SetResetRotate(resetRotate);
    }
}

void RSSurfaceRenderNodeDrawable::OnDraw(Drawing::Canvas& canvas)
{
    if (!ShouldPaint()) {
        return;
    }

    auto rscanvas = reinterpret_cast<RSPaintFilterCanvas*>(&canvas);
    if (!rscanvas) {
        RS_LOGE("RSSurfaceRenderNodeDrawable::OnDraw, rscanvas us nullptr");
        return;
    }

    auto nodeSp = std::const_pointer_cast<RSRenderNode>(renderNode_);
    auto surfaceNode = std::static_pointer_cast<RSSurfaceRenderNode>(nodeSp);
    auto surfaceParams = static_cast<RSSurfaceRenderParams*>(surfaceNode->GetRenderParams().get());
    if (!surfaceParams) {
        RS_LOGE("RSSurfaceRenderNodeDrawable::OnDraw params is nullptr");
        return;
    }
    auto renderEngine_ = RSUniRenderThread::Instance().GetRenderEngine();
    auto unmappedCache = surfaceParams->GetBufferClearCacheSet();
    if (unmappedCache.size() > 0) {
        // remove imagecahce when its bufferQueue gobackground
        renderEngine_->ClearCacheSet(unmappedCache);
    }
    bool isuifirstNode = rscanvas->GetIsParallelCanvas();
    if (!isuifirstNode && surfaceParams->GetOccludedByFilterCache()) {
        RS_TRACE_NAME_FMT("RSSurfaceRenderNodeDrawable::OnDraw filterCache occlusion skip [%s] Id:%" PRIu64 "",
            surfaceNode->GetName().c_str(), surfaceParams->GetId());
        return;
    }
    Drawing::Region curSurfaceDrawRegion = CalculateVisibleRegion(surfaceParams, surfaceNode, isuifirstNode);
    auto uniParam = RSUniRenderThread::Instance().GetRSRenderThreadParams().get();
    if (!uniParam) {
        RS_LOGE("RSSurfaceRenderNodeDrawable::OnDraw uniParam is nullptr");
        return;
    }
    // when surfacenode named "CapsuleWindow", cache the current canvas as SkImage for screen recording
    auto curDisplayNode = rscanvas->GetCurDisplayNode();
    if (curDisplayNode && surfaceParams->GetName().find("CapsuleWindow") != std::string::npos) {
        CacheImgForCapture(*rscanvas, curDisplayNode);
        NodeId nodeId = FindInstanceChildOfDisplay(surfaceNode->GetParent().lock());
        RSUniRenderThread::Instance().GetRSRenderThreadParams()->SetRootIdOfCaptureWindow(nodeId);
    }
    
    if (!isuifirstNode) {
        MergeDirtyRegionBelowCurSurface(uniParam, surfaceParams, surfaceNode, curSurfaceDrawRegion);
    }

    if (!isuifirstNode && uniParam->IsOpDropped() &&
        surfaceParams->IsMainWindowType() && curSurfaceDrawRegion.IsEmpty()) {
        RS_TRACE_NAME_FMT("RSSurfaceRenderNodeDrawable::OnDraw occlusion skip SurfaceName:%s NodeId:%" PRIu64 "",
            surfaceNode->GetName().c_str(), surfaceParams->GetId());
        return;
    }
    RS_TRACE_NAME("RSSurfaceRenderNodeDrawable::OnDraw:[" + surfaceNode->GetName() + "] " +
        surfaceParams->GetAbsDrawRect().ToString() + "Alpha: " + std::to_string(surfaceNode->GetGlobalAlpha()));

    RS_LOGD("RSSurfaceRenderNodeDrawable::OnDraw node:%{public}" PRIu64 ",child size:%{public}u,"
            "name:%{public}s,OcclusionVisible:%{public}d",
        surfaceParams->GetId(), surfaceNode->GetChildrenCount(), surfaceNode->GetName().c_str(),
        surfaceParams->GetOcclusionVisible());

    if (DealWithUIFirstCache(*surfaceNode, *rscanvas, *surfaceParams, *uniParam)) {
        return;
    }

    Drawing::GPUContext* gpuContext = renderEngine_->GetRenderContext()->GetDrGPUContext();
    surfaceNode->SetDrawingGPUContext(gpuContext); // TO-DO
    RSTagTracker tagTracker(gpuContext, surfaceParams->GetId(), RSTagTracker::TAGTYPE::TAG_DRAW_SURFACENODE);

    surfaceNode->UpdateFilterCacheStatusWithVisible(true);

    RSAutoCanvasRestore acr(rscanvas, RSPaintFilterCanvas::SaveType::kCanvasAndAlpha);

    // Draw base pipeline start
    surfaceParams->ApplyAlphaAndMatrixToCanvas(*rscanvas);

    bool isSelfDrawingSurface = surfaceParams->GetSurfaceNodeType() == RSSurfaceNodeType::SELF_DRAWING_NODE;
    if (isSelfDrawingSurface && !surfaceParams->IsSpherizeValid()) {
        rscanvas->Save();
    }

    if (surfaceParams->IsMainWindowType()) {
        RSRenderNodeDrawable::ClearProcessedNodeCount();
        rscanvas->PushDirtyRegion(curSurfaceDrawRegion);
    }

    auto parentSurfaceMatrix = RSRenderParams::parentSurfaceMatrix_;
    RSRenderParams::parentSurfaceMatrix_ = rscanvas->GetTotalMatrix();

    auto bounds = surfaceParams->GetFrameRect();

    // 1. draw background
    DrawBackground(canvas, bounds);

    if (isSelfDrawingSurface) {
        RSUniRenderUtil::CeilTransXYInCanvasMatrix(*rscanvas);
    }

    // 2. draw self drawing node
    if (surfaceParams->GetBuffer() != nullptr) {
        DealWithSelfDrawingNodeBuffer(*surfaceNode, *rscanvas, *surfaceParams);
    }

    if (isSelfDrawingSurface) {
        rscanvas->Restore();
    }

    // 3. Draw content of this node by the main canvas.
    DrawContent(canvas, bounds);

    // 4. Draw children of this node by the main canvas.
    DrawChildren(canvas, bounds);

    // 5. Draw foreground of this node by the main canvas.
    DrawForeground(canvas, bounds);

    // Draw base pipeline end
    if (surfaceParams->IsMainWindowType()) {
        rscanvas->PopDirtyRegion();
        RS_TRACE_NAME_FMT("RSSurfaceRenderNodeDrawable::OnDraw SurfaceNode: [%s], NodeId: %llu, ProcessedNodes: %d",
            surfaceNode->GetName().c_str(), surfaceNode->GetId(), RSRenderNodeDrawable::GetProcessedNodeCount());
    }

    RSRenderParams::parentSurfaceMatrix_ = parentSurfaceMatrix;
}

void RSSurfaceRenderNodeDrawable::MergeDirtyRegionBelowCurSurface(RSRenderThreadParams* uniParam,
    RSSurfaceRenderParams* surfaceParams,
    std::shared_ptr<RSSurfaceRenderNode>& surfaceNode,
    Drawing::Region& region)
{
    if (surfaceNode->IsMainWindowType() && surfaceParams->GetVisibleRegion().IsEmpty()) {
        return;
    }
    if (surfaceNode->IsMainWindowType() || surfaceNode->IsLeashWindow()) {
        auto& accumulatedDirtyRegion = uniParam->GetAccumulatedDirtyRegion();
        if (surfaceParams->GetIsTransparent()) {
            auto oldDirtyInSurface = Occlusion::Region{
                Occlusion::Rect{ surfaceParams->GetOldDirtyInSurface() } };
            auto dirtyRegion = oldDirtyInSurface.And(accumulatedDirtyRegion);
            if (!dirtyRegion.IsEmpty()) {
                for (auto& rect : dirtyRegion.GetRegionRects()) {
                    Drawing::Region tempRegion;
                    tempRegion.SetRect(Drawing::RectI(
                        rect.left_, rect.top_, rect.right_, rect.bottom_));
                    region.Op(tempRegion, Drawing::RegionOp::UNION);
                }
            }
        }
        // [planing] surfaceDirtyRegion can be optimized by visibleDirtyRegion in some case.
        auto surfaceDirtyRegion = Occlusion::Region {
            Occlusion::Rect{ surfaceNode->GetSyncDirtyManager()->GetDirtyRegion() } };
        accumulatedDirtyRegion.OrSelf(surfaceDirtyRegion);
        // add children window dirty here for uifirst leasf window will not traverse cached children
        if (surfaceParams->GetUifirstNodeEnableParam()) {
            auto childrenDirtyRegion = Occlusion::Region {
                Occlusion::Rect{ surfaceParams->GetUifirstChildrenDirtyRectParam() } };
            accumulatedDirtyRegion.OrSelf(childrenDirtyRegion);
        }
    }
}

void RSSurfaceRenderNodeDrawable::OnCapture(Drawing::Canvas& canvas)
{
    if (!ShouldPaint()) {
        return;
    }

    auto nodeSp = std::const_pointer_cast<RSRenderNode>(renderNode_);
    auto surfaceNode = std::static_pointer_cast<RSSurfaceRenderNode>(nodeSp);
    auto surfaceParams = static_cast<RSSurfaceRenderParams*>(surfaceNode->GetRenderParams().get());

    auto rscanvas = static_cast<RSPaintFilterCanvas*>(&canvas);
    if (!rscanvas) {
        RS_LOGE("RSSurfaceRenderNodeDrawable::OnDraw, rscanvas us nullptr");
        return;
    }

    bool noSpecialLayer = (!surfaceParams->GetIsSecurityLayer() && !surfaceParams->GetIsSkipLayer());
    if (UNLIKELY(RSUniRenderThread::GetCaptureParam().isMirror_) && noSpecialLayer &&
        EnableRecordingOptimization(*surfaceParams)) {
        return;
    }

    RS_TRACE_NAME("RSSurfaceRenderNodeDrawable::OnCapture:[" + surfaceNode->GetName() + "] " +
        surfaceParams->GetAbsDrawRect().ToString() + "Alpha: " + std::to_string(surfaceNode->GetGlobalAlpha()));
    RSAutoCanvasRestore acr(rscanvas, RSPaintFilterCanvas::SaveType::kCanvasAndAlpha);
    if (RSUniRenderThread::GetCaptureParam().isSingleSurface_) {
        CaptureSingleSurfaceNode(*surfaceNode, *rscanvas, *surfaceParams);
    } else {
        CaptureSurfaceInDisplay(*surfaceNode, *rscanvas, *surfaceParams);
    }
}

bool RSSurfaceRenderNodeDrawable::EnableRecordingOptimization(RSRenderParams& params)
{
    auto& threadParams = RSUniRenderThread::Instance().GetRSRenderThreadParams();
    if (threadParams) {
        NodeId nodeId = threadParams->GetRootIdOfCaptureWindow();
        bool hasCaptureImg = threadParams->GetHasCaptureImg();
        if (nodeId == params.GetId()) {
            RS_LOGD("RSSurfaceRenderNodeDrawable::EnableRecordingOptimization: (id:[%{public}" PRIu64 "])",
                params.GetId());
            threadParams->SetStartVisit(true);
        }
        if (hasCaptureImg && !threadParams->GetStartVisit()) {
            RS_LOGD("RSSurfaceRenderNodeDrawable::EnableRecordingOptimization: (id:[%{public}" PRIu64 "]) Skip layer.",
                params.GetId());
            return true;
        }
    }
    return false;
}

void RSSurfaceRenderNodeDrawable::CaptureSingleSurfaceNode(RSSurfaceRenderNode& surfaceNode,
    RSPaintFilterCanvas& canvas, RSSurfaceRenderParams& surfaceParams)
{
    uint32_t saveCount = canvas.GetSaveCount();
    auto nodeType = surfaceParams.GetSurfaceNodeType();
    bool isSelfDrawingSurface = (nodeType == RSSurfaceNodeType::SELF_DRAWING_NODE);
    if (isSelfDrawingSurface && !surfaceParams.IsSpherizeValid()) {
        canvas.Save();
    }

    // First node don't need to cancat matrix for application
    if (RSUniRenderThread::GetCaptureParam().isFirstNode_) {
        // Planning: If node is a sandbox.
        canvas.MultiplyAlpha(surfaceParams.GetAlpha());
        RSUniRenderThread::GetCaptureParam().isFirstNode_ = false;
    } else {
        surfaceParams.ApplyAlphaAndMatrixToCanvas(canvas);
    }
    auto parentSurfaceMatrix = RSRenderParams::parentSurfaceMatrix_;
    RSRenderParams::parentSurfaceMatrix_ = canvas.GetTotalMatrix();

    auto bounds = surfaceParams.GetFrameRect();

    // 1. draw background
    DrawBackground(canvas, bounds);

    if (isSelfDrawingSurface) {
        RSUniRenderUtil::CeilTransXYInCanvasMatrix(canvas);
    }

    if (surfaceParams.GetIsSecurityLayer() || surfaceParams.GetIsSkipLayer()) {
        RS_LOGD("RSSurfaceRenderNodeDrawable::CaptureSingleSurfaceNode: \
            process RSSurfaceRenderNode(id:[%{public}" PRIu64 "]) clear white since it is security layer.",
            surfaceParams.GetId());
        canvas.Clear(Drawing::Color::COLOR_WHITE);
        canvas.RestoreToCount(saveCount);
        return;
    }

    // 2. draw self drawing node
    if (surfaceParams.GetBuffer() != nullptr) {
        DealWithSelfDrawingNodeBuffer(surfaceNode, canvas, surfaceParams);
    }

    if (isSelfDrawingSurface) {
        canvas.Restore();
    }

    auto uniParams = RSUniRenderThread::Instance().GetRSRenderThreadParams().get();
    if (!uniParams) {
        RS_LOGE("RSSurfaceRenderNodeDrawable::CaptureSurfaceInDisplay uniParams is nullptr");
        return;
    }

    if (!(surfaceParams.HasSecurityLayer() || surfaceParams.HasSkipLayer()) &&
        DealWithUIFirstCache(surfaceNode, canvas, surfaceParams, *uniParams)) {
        return;
    }

    // 3. Draw content of this node by the main canvas.
    DrawContent(canvas, bounds);

    // 4. Draw children of this node by the main canvas.
    DrawChildren(canvas, bounds);

    // 5. Draw foreground of this node by the main canvas.
    DrawForeground(canvas, bounds);

    RSRenderParams::parentSurfaceMatrix_ = parentSurfaceMatrix;
}

void RSSurfaceRenderNodeDrawable::CaptureSurfaceInDisplay(RSSurfaceRenderNode& surfaceNode,
    RSPaintFilterCanvas& canvas, RSSurfaceRenderParams& surfaceParams)
{
    if (surfaceParams.GetIsSecurityLayer() || surfaceParams.GetIsSkipLayer()) {
        RS_LOGD("RSSurfaceRenderNodeDrawable::CaptureSurfaceInDisplay: \
            process RSSurfaceRenderNode(id:[%{public}" PRIu64 "]) paused since it is security layer.",
            surfaceParams.GetId());
        return;
    }

    canvas.ConcatMatrix(surfaceParams.GetMatrix());

    auto uniParams = RSUniRenderThread::Instance().GetRSRenderThreadParams().get();
    if (!uniParams) {
        RS_LOGE("RSSurfaceRenderNodeDrawable::CaptureSurfaceInDisplay uniParams is nullptr");
        return;
    }

    if (!(surfaceParams.HasSecurityLayer() || surfaceParams.HasSkipLayer()) &&
        DealWithUIFirstCache(surfaceNode, canvas, surfaceParams, *uniParams)) {
        return;
    }

    auto nodeType = surfaceParams.GetSurfaceNodeType();
    bool isSelfDrawingSurface = (nodeType == RSSurfaceNodeType::SELF_DRAWING_NODE);
    if (isSelfDrawingSurface) {
        canvas.Save();
    }

    surfaceParams.ApplyAlphaAndMatrixToCanvas(canvas);

    auto bounds = surfaceParams.GetFrameRect();

    // 1. draw background
    DrawBackground(canvas, bounds);

    if (isSelfDrawingSurface) {
        RSUniRenderUtil::CeilTransXYInCanvasMatrix(canvas);
    }
    auto parentSurfaceMatrix = RSRenderParams::parentSurfaceMatrix_;
    RSRenderParams::parentSurfaceMatrix_ = canvas.GetTotalMatrix();

    // 2. draw self drawing node
    if (surfaceParams.GetBuffer() != nullptr) {
        DealWithSelfDrawingNodeBuffer(surfaceNode, canvas, surfaceParams);
    }

    if (isSelfDrawingSurface) {
        canvas.Restore();
    }

    // 3. Draw content of this node by the main canvas.
    DrawContent(canvas, bounds);

    // 4. Draw children of this node by the main canvas.
    DrawChildren(canvas, bounds);

    // 5. Draw foreground of this node by the main canvas.
    DrawForeground(canvas, bounds);

    RSRenderParams::parentSurfaceMatrix_ = parentSurfaceMatrix;
}

void RSSurfaceRenderNodeDrawable::DealWithSelfDrawingNodeBuffer(RSSurfaceRenderNode& surfaceNode,
    RSPaintFilterCanvas& canvas, const RSSurfaceRenderParams& surfaceParams)
{
    if (surfaceParams.GetHardwareEnabled() && !RSUniRenderThread::GetCaptureParam().isInCaptureFlag_) {
        if (!surfaceNode.IsHardwareEnabledTopSurface()) {
            RSAutoCanvasRestore arc(&canvas);
            canvas.ClipRect(surfaceParams.GetBounds());
            canvas.Clear(Drawing::Color::COLOR_TRANSPARENT);
        }
        return;
    }

    RSAutoCanvasRestore arc(&canvas);
    // Hwc nodes need to use LayerMatrix(totalMatrix) when doing capturing
    if (RSUniRenderThread::GetCaptureParam().isInCaptureFlag_ &&
        surfaceParams.GetHardwareEnabled()) {
        auto matrix = surfaceParams.GetLayerInfo().matrix;
        matrix.PostScale(RSUniRenderThread::GetCaptureParam().scaleX_, RSUniRenderThread::GetCaptureParam().scaleY_);
        canvas.SetMatrix(matrix);
    }
    
    surfaceNode.SetGlobalAlpha(1.0f); // TO-DO
    pid_t threadId = gettid();
    auto params = RSUniRenderUtil::CreateBufferDrawParam(surfaceNode, false, threadId, true);
    params.targetColorGamut = GraphicColorGamut::GRAPHIC_COLOR_GAMUT_SRGB;
#ifdef USE_VIDEO_PROCESSING_ENGINE
    auto screenManager = CreateOrGetScreenManager();
    auto ancestor = surfaceParams.GetAncestorDisplayNode().lock()->ReinterpretCastTo<RSDisplayRenderNode>();
    if (!ancestor) {
        RS_LOGE("surfaceNode GetAncestorDisplayNode() return nullptr");
        return;
    }
    auto ancestorParam = static_cast<RSDisplayRenderParams*>(ancestor->GetRenderParams().get());
    params.screenBrightnessNits =
        screenManager->GetScreenBrightnessNits(ancestorParam ? ancestorParam->GetScreenId() : 0);
#endif
    auto bgColor = surfaceParams.GetBackgroundColor();
    auto renderEngine = RSUniRenderThread::Instance().GetRenderEngine();
    if ((surfaceParams.GetSelfDrawingNodeType() != SelfDrawingNodeType::VIDEO) &&
        (bgColor != RgbPalette::Transparent())) {
        auto bounds = RSPropertiesPainter::Rect2DrawingRect(
            { 0, 0, surfaceParams.GetBounds().GetWidth(), surfaceParams.GetBounds().GetHeight() });
        Drawing::SaveLayerOps layerOps(&bounds, nullptr);
        canvas.SaveLayer(layerOps);
        canvas.SetAlpha(1.0f);
        Drawing::Brush brush;
        brush.SetColor(Drawing::Color(bgColor.AsArgbInt()));
        canvas.AttachBrush(brush);
        canvas.DrawRoundRect(RSPropertiesPainter::RRect2DrawingRRect(surfaceParams.GetRRect()));
        canvas.DetachBrush();
        renderEngine->DrawSurfaceNodeWithParams(canvas, surfaceNode, params);
        canvas.Restore();
    } else {
        renderEngine->DrawSurfaceNodeWithParams(canvas, surfaceNode, params);
    }
}

bool RSSurfaceRenderNodeDrawable::DealWithUIFirstCache(RSSurfaceRenderNode& surfaceNode,
    RSPaintFilterCanvas& canvas, RSSurfaceRenderParams& surfaceParams, RSRenderThreadParams& uniParams)
{
#ifdef RS_PARALLEL
    if (surfaceParams.GetUifirstNodeEnableParam()) {
        RS_TRACE_NAME_FMT("DrawUIFirstCache [%s] %lx", surfaceNode.GetName().c_str(), surfaceParams.GetId());
        RSUifirstManager::Instance().AddReuseNode(surfaceParams.GetId());
        auto& renderParams = renderNode_->GetRenderParams();
        Drawing::Rect bounds = renderParams ? renderParams->GetBounds() : Drawing::Rect(0, 0, 0, 0);
        RSAutoCanvasRestore acr(&canvas);
        canvas.MultiplyAlpha(surfaceParams.GetAlpha());
        if (!RSUniRenderThread::GetCaptureParam().isSingleSurface_) {
            canvas.ConcatMatrix(surfaceParams.GetMatrix());
        }
        DrawBackground(canvas, bounds);
        bool drawCacheSuccess = true;
        if (!DrawUIFirstCache(canvas)) {
            RS_TRACE_NAME_FMT("DrawUIFirstCache [%s] failed!", surfaceNode.GetName().c_str());
            RS_LOGE("DrawUIFirstCache failed!");
            drawCacheSuccess = false;
        }
        DrawForeground(canvas, bounds);
        if (uniParams.GetUIFirstDebugEnabled()) { // DFX for uifirst
            if (drawCacheSuccess) {
                Drawing::Brush rectBrush;
                // Alpha 128, blue 255
                rectBrush.SetColor(Drawing::Color(128, 0, 0, 255));
                canvas.AttachBrush(rectBrush);
                // Left 300, width 500, height 200
                canvas.DrawRect(Drawing::Rect(300, 0, 500, 200));
                canvas.DetachBrush();
            } else {
                Drawing::Brush rectBrush;
                // Alpha 128, blue 255
                rectBrush.SetColor(Drawing::Color(128, 0, 0, 255));
                canvas.AttachBrush(rectBrush);
                // Left 800, width 1000, height 200
                canvas.DrawRect(Drawing::Rect(800, 0, 1000, 200));
                canvas.DetachBrush();
            }
        }
        return true;
    }
#endif
    return false;
}
} // namespace OHOS::Rosen::DrawableV2
