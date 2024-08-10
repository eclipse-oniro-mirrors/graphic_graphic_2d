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

#include "rs_uni_render_util.h"

#include <cstdint>
#include <memory>
#include <parameter.h>
#include <parameters.h>
#include <string>
#include <unordered_set>

#include "rs_trace.h"
#include "scene_board_judgement.h"

#include "common/rs_optional_trace.h"
#include "drawable/rs_display_render_node_drawable.h"
#include "drawable/rs_surface_render_node_drawable.h"
#include "info_collection/rs_gpu_dirty_region_collection.h"
#include "params/rs_display_render_params.h"
#include "params/rs_surface_render_params.h"
#include "pipeline/parallel_render/rs_sub_thread_manager.h"
#include "pipeline/rs_base_render_util.h"
#include "pipeline/rs_main_thread.h"
#include "pipeline/rs_render_node.h"
#include "pipeline/rs_surface_render_node.h"
#include "platform/common/rs_log.h"
#include "property/rs_properties.h"
#include "render/rs_drawing_filter.h"
#include "render/rs_maskcolor_shader_filter.h"
#include "render/rs_material_filter.h"
#include "render/rs_path.h"

#ifdef RS_ENABLE_VK
#include "include/gpu/GrBackendSurface.h"
#include "platform/ohos/backend/native_buffer_utils.h"
#include "platform/ohos/backend/rs_surface_ohos_vulkan.h"
#include "platform/ohos/backend/rs_vulkan_context.h"
#endif

namespace OHOS {
namespace Rosen {
namespace {
constexpr int32_t FIX_ROTATION_DEGREE_FOR_FOLD_SCREEN = -90;
constexpr const char* CAPTURE_WINDOW_NAME = "CapsuleWindow";
}
void RSUniRenderUtil::MergeDirtyHistory(std::shared_ptr<RSDisplayRenderNode>& node, int32_t bufferAge,
    bool useAlignedDirtyRegion)
{
    auto& curAllSurfaces = node->GetCurAllSurfaces();
    // update all child surfacenode history
    for (auto it = curAllSurfaces.rbegin(); it != curAllSurfaces.rend(); ++it) {
        auto surfaceNode = RSRenderNode::ReinterpretCast<RSSurfaceRenderNode>(*it);
        if (surfaceNode == nullptr || !surfaceNode->IsAppWindow()) {
            continue;
        }
        RS_OPTIONAL_TRACE_NAME_FMT("RSUniRenderUtil::MergeDirtyHistory for surfaceNode %" PRIu64"",
            surfaceNode->GetId());
        auto surfaceDirtyManager = surfaceNode->GetDirtyManager();
        if (UNLIKELY(!surfaceDirtyManager)) {
            continue;
        }
        if (!surfaceDirtyManager->SetBufferAge(bufferAge)) {
            ROSEN_LOGE("RSUniRenderUtil::MergeDirtyHistory with invalid buffer age %{public}d", bufferAge);
        }
        surfaceDirtyManager->IntersectDirtyRect(surfaceNode->GetOldDirtyInSurface());
        surfaceDirtyManager->UpdateDirty(useAlignedDirtyRegion);
    }

    // update display dirtymanager
    node->UpdateDisplayDirtyManager(bufferAge, useAlignedDirtyRegion);
}

void RSUniRenderUtil::MergeDirtyHistoryForDrawable(DrawableV2::RSDisplayRenderNodeDrawable& displayDrawable,
    int32_t bufferAge, RSDisplayRenderParams& params, bool useAlignedDirtyRegion)
{
    auto& curAllSurfaceDrawables = params.GetAllMainAndLeashSurfaceDrawables();
    // update all child surfacenode history
    for (auto it = curAllSurfaceDrawables.rbegin(); it != curAllSurfaceDrawables.rend(); ++it) {
        auto surfaceNodeDrawable = std::static_pointer_cast<DrawableV2::RSSurfaceRenderNodeDrawable>(*it);
        if (surfaceNodeDrawable == nullptr) {
            continue;
        }
        auto surfaceParams = static_cast<RSSurfaceRenderParams*>(surfaceNodeDrawable->GetRenderParams().get());
        auto surfaceDirtyManager = surfaceNodeDrawable->GetSyncDirtyManager();
        if (surfaceParams == nullptr || !surfaceParams->IsAppWindow() || !surfaceDirtyManager) {
            continue;
        }
        RS_OPTIONAL_TRACE_NAME_FMT("RSUniRenderUtil::MergeDirtyHistory for surfaceNode %" PRIu64"",
            surfaceParams->GetId());
        if (!surfaceDirtyManager->SetBufferAge(bufferAge)) {
            ROSEN_LOGW("RSUniRenderUtil::MergeDirtyHistory with invalid buffer age %{public}d", bufferAge);
        }
        surfaceDirtyManager->IntersectDirtyRect(surfaceParams->GetOldDirtyInSurface());
        surfaceDirtyManager->UpdateDirty(useAlignedDirtyRegion);
    }

    // update display dirtymanager
    auto dirtyManager = displayDrawable.GetSyncDirtyManager();
    dirtyManager->SetBufferAge(bufferAge);
    dirtyManager->UpdateDirty(useAlignedDirtyRegion);
}

Occlusion::Region RSUniRenderUtil::MergeVisibleDirtyRegion(
    std::vector<DrawableV2::RSRenderNodeDrawableAdapter::SharedPtr>& allSurfaceNodeDrawables,
    std::vector<NodeId>& hasVisibleDirtyRegionSurfaceVec, bool useAlignedDirtyRegion)
{
    Occlusion::Region allSurfaceVisibleDirtyRegion;
    for (auto it = allSurfaceNodeDrawables.rbegin(); it != allSurfaceNodeDrawables.rend(); ++it) {
        auto surfaceNodeDrawable = std::static_pointer_cast<DrawableV2::RSSurfaceRenderNodeDrawable>(*it);
        if (surfaceNodeDrawable == nullptr) {
            RS_LOGI("MergeVisibleDirtyRegion surfaceNodeDrawable is nullptr");
            continue;
        }
        auto surfaceParams = static_cast<RSSurfaceRenderParams*>(surfaceNodeDrawable->GetRenderParams().get());
        auto surfaceDirtyManager = surfaceNodeDrawable->GetSyncDirtyManager();
        if (!surfaceParams || !surfaceDirtyManager) {
            RS_LOGI("RSUniRenderUtil::MergeVisibleDirtyRegion %{public}s params or dirty manager is nullptr",
                surfaceNodeDrawable->GetName().c_str());
            continue;
        }
        if (!surfaceParams->IsAppWindow() || surfaceParams->GetDstRect().IsEmpty()) {
            continue;
        }
        auto surfaceDirtyRect = surfaceDirtyManager->GetDirtyRegion();
        Occlusion::Rect dirtyRect { surfaceDirtyRect.left_, surfaceDirtyRect.top_, surfaceDirtyRect.GetRight(),
            surfaceDirtyRect.GetBottom() };
        auto visibleRegion = surfaceParams->GetVisibleRegion();
        Occlusion::Region surfaceDirtyRegion { dirtyRect };
        Occlusion::Region surfaceVisibleDirtyRegion = surfaceDirtyRegion.And(visibleRegion);

        surfaceNodeDrawable->SetVisibleDirtyRegion(surfaceVisibleDirtyRegion);
        if (!surfaceVisibleDirtyRegion.IsEmpty()) {
            hasVisibleDirtyRegionSurfaceVec.emplace_back(surfaceParams->GetId());
        }
        if (useAlignedDirtyRegion) {
            Occlusion::Region alignedRegion = AlignedDirtyRegion(surfaceVisibleDirtyRegion);
            surfaceNodeDrawable->SetAlignedVisibleDirtyRegion(alignedRegion);
            allSurfaceVisibleDirtyRegion.OrSelf(alignedRegion);
            GpuDirtyRegionCollection::GetInstance().UpdateActiveDirtyInfoForDFX(surfaceParams->GetId(),
                surfaceNodeDrawable->GetName(), alignedRegion.GetRegionRectIs());
        } else {
            allSurfaceVisibleDirtyRegion = allSurfaceVisibleDirtyRegion.Or(surfaceVisibleDirtyRegion);
            GpuDirtyRegionCollection::GetInstance().UpdateActiveDirtyInfoForDFX(surfaceParams->GetId(),
                surfaceNodeDrawable->GetName(), surfaceVisibleDirtyRegion.GetRegionRectIs());
        }
    }
    return allSurfaceVisibleDirtyRegion;
}

void RSUniRenderUtil::MergeDirtyHistoryInVirtual(DrawableV2::RSDisplayRenderNodeDrawable& displayDrawable,
    int32_t bufferAge, bool renderParallel)
{
    (void)renderParallel;
    auto& params = displayDrawable.GetRenderParams();
    if (!params) {
        RS_LOGE("RSUniRenderUtil::MergeDirtyHistory params is nullptr");
        return;
    }
    auto& curAllSurfaceDrawables = params->GetAllMainAndLeashSurfaceDrawables();
    for (auto it = curAllSurfaceDrawables.rbegin(); it != curAllSurfaceDrawables.rend(); ++it) {
        auto surfaceNodeDrawable = std::static_pointer_cast<DrawableV2::RSSurfaceRenderNodeDrawable>(*it);
        if (surfaceNodeDrawable == nullptr) {
            continue;
        }
        auto surfaceParams = static_cast<RSSurfaceRenderParams*>(surfaceNodeDrawable->GetRenderParams().get());
        if (surfaceParams == nullptr || !surfaceParams->IsAppWindow()) {
            continue;
        }
        RS_OPTIONAL_TRACE_NAME_FMT("RSUniRenderUtil::MergeDirtyHistory for surfaceNode %" PRIu64"",
            surfaceParams->GetId());
        auto surfaceDirtyManager = surfaceNodeDrawable->GetSyncDirtyManager();
        surfaceDirtyManager->MergeDirtyHistoryInVirtual(bufferAge);
    }
    // update display dirtymanager
    auto displayDirtyManager = displayDrawable.GetSyncDirtyManager();
    displayDirtyManager->MergeDirtyHistoryInVirtual(bufferAge);
}

Occlusion::Region RSUniRenderUtil::MergeVisibleDirtyRegionInVirtual(
    std::vector<DrawableV2::RSRenderNodeDrawableAdapter::SharedPtr>& allSurfaceNodeDrawables)
{
    Occlusion::Region allSurfaceVisibleDirtyRegion;
    for (auto it = allSurfaceNodeDrawables.rbegin(); it != allSurfaceNodeDrawables.rend(); ++it) {
        auto surfaceNodeDrawable = std::static_pointer_cast<DrawableV2::RSSurfaceRenderNodeDrawable>(*it);
        if (surfaceNodeDrawable == nullptr) {
            RS_LOGI("MergeVisibleDirtyRegion surfaceNodeDrawable is nullptr");
            continue;
        }
        auto surfaceParams = static_cast<RSSurfaceRenderParams*>(surfaceNodeDrawable->GetRenderParams().get());
        if (!surfaceParams) {
            RS_LOGI("RSUniRenderUtil::MergeVisibleDirtyRegion surface params is nullptr");
            continue;
        }
        if (!surfaceParams->IsAppWindow() || surfaceParams->GetDstRect().IsEmpty() ||
            surfaceParams->GetName().find(CAPTURE_WINDOW_NAME) != std::string::npos ||
            surfaceParams->GetIsSkipLayer()) {
            continue;
        }
        auto surfaceDirtyManager = surfaceNodeDrawable->GetSyncDirtyManager();
        auto surfaceDirtyRect = surfaceDirtyManager->GetDirtyRegionInVirtual();
        Occlusion::Rect dirtyRect { surfaceDirtyRect.left_, surfaceDirtyRect.top_,
            surfaceDirtyRect.GetRight(), surfaceDirtyRect.GetBottom() };
        auto visibleRegion = surfaceParams->GetVisibleRegionInVirtual();
        Occlusion::Region surfaceDirtyRegion { dirtyRect };
        Occlusion::Region surfaceVisibleDirtyRegion = surfaceDirtyRegion.And(visibleRegion);
        allSurfaceVisibleDirtyRegion = allSurfaceVisibleDirtyRegion.Or(surfaceVisibleDirtyRegion);
    }
    return allSurfaceVisibleDirtyRegion;
}

void RSUniRenderUtil::SetAllSurfaceDrawableGlobalDityRegion(
    std::vector<DrawableV2::RSRenderNodeDrawableAdapter::SharedPtr>& allSurfaceDrawables,
    const RectI& globalDirtyRegion)
{
    // Set Surface Global Dirty Region
    for (auto it = allSurfaceDrawables.rbegin(); it != allSurfaceDrawables.rend(); ++it) {
        auto surfaceNodeDrawable = std::static_pointer_cast<DrawableV2::RSSurfaceRenderNodeDrawable>(*it);
        if (surfaceNodeDrawable == nullptr) {
            continue;
        }
        auto surfaceParams = static_cast<RSSurfaceRenderParams*>(surfaceNodeDrawable->GetRenderParams().get());
        if (!surfaceParams) {
            RS_LOGW("RSUniRenderUtil::MergeVisibleDirtyRegion surface params is nullptr");
            continue;
        }
        if (!surfaceParams->IsMainWindowType()) {
            continue;
        }
        // set display dirty region to surfaceNodeDrawable
        surfaceNodeDrawable->SetGlobalDirtyRegion(globalDirtyRegion);
        surfaceNodeDrawable->SetDirtyRegionAlignedEnable(false);
    }
    Occlusion::Region curVisibleDirtyRegion;
    for (auto& it : allSurfaceDrawables) {
        auto surfaceNodeDrawable = std::static_pointer_cast<DrawableV2::RSSurfaceRenderNodeDrawable>(it);
        if (surfaceNodeDrawable == nullptr) {
            continue;
        }
        auto surfaceParams = static_cast<RSSurfaceRenderParams*>(surfaceNodeDrawable->GetRenderParams().get());
        if (!surfaceParams) {
            RS_LOGE("RSUniRenderUtil::MergeVisibleDirtyRegion surface params is nullptr");
            continue;
        }
        if (!surfaceParams->IsMainWindowType()) {
            continue;
        }
        // set display dirty region to surfaceNodeDrawable
        surfaceNodeDrawable->SetDirtyRegionBelowCurrentLayer(curVisibleDirtyRegion);
        auto visibleDirtyRegion = surfaceNodeDrawable->GetVisibleDirtyRegion();
        curVisibleDirtyRegion = curVisibleDirtyRegion.Or(visibleDirtyRegion);
    }
}

std::vector<RectI> RSUniRenderUtil::ScreenIntersectDirtyRects(const Occlusion::Region &region, ScreenInfo& screenInfo)
{
    const std::vector<Occlusion::Rect>& rects = region.GetRegionRects();
    std::vector<RectI> retRects;
    for (const Occlusion::Rect& rect : rects) {
        // origin transformation
#ifdef RS_ENABLE_VK
        if (RSSystemProperties::GetGpuApiType() == GpuApiType::VULKAN ||
            RSSystemProperties::GetGpuApiType() == GpuApiType::DDGR) {
            retRects.emplace_back(RectI(rect.left_, rect.top_,
                rect.right_ - rect.left_, rect.bottom_ - rect.top_));
        } else {
            retRects.emplace_back(RectI(rect.left_, screenInfo.GetRotatedHeight() - rect.bottom_,
                rect.right_ - rect.left_, rect.bottom_ - rect.top_));
        }
#else
        retRects.emplace_back(RectI(rect.left_, screenInfo.GetRotatedHeight() - rect.bottom_,
            rect.right_ - rect.left_, rect.bottom_ - rect.top_));
#endif
    }
    RS_LOGD("ScreenIntersectDirtyRects size %{public}d %{public}s", region.GetSize(), region.GetRegionInfo().c_str());
    return retRects;
}

std::vector<RectI> RSUniRenderUtil::GetFilpDirtyRects(const std::vector<RectI>& srcRects, const ScreenInfo& screenInfo)
{
#ifdef RS_ENABLE_VK
    if (RSSystemProperties::GetGpuApiType() == GpuApiType::VULKAN ||
        RSSystemProperties::GetGpuApiType() == GpuApiType::DDGR) {
        return srcRects;
    }
#endif

    return FilpRects(srcRects, screenInfo);
}

std::vector<RectI> RSUniRenderUtil::FilpRects(const std::vector<RectI>& srcRects, const ScreenInfo& screenInfo)
{
    std::vector<RectI> retRects;
    for (const RectI& rect : srcRects) {
        retRects.emplace_back(RectI(rect.left_, screenInfo.GetRotatedHeight() - rect.top_ - rect.height_,
            rect.width_, rect.height_));
    }
    return retRects;
}

void RSUniRenderUtil::SrcRectScaleFit(BufferDrawParam& params, const sptr<SurfaceBuffer>& buffer,
    const sptr<IConsumerSurface>& surface, RectF& localBounds)
{
    if (buffer == nullptr || surface == nullptr) {
        RS_LOGE("buffer or surface is nullptr");
        return;
    }
    uint32_t srcWidth = static_cast<uint32_t>(params.srcRect.GetWidth());
    uint32_t srcHeight = static_cast<uint32_t>(params.srcRect.GetHeight());
    if (srcHeight == 0 || srcWidth == 0) {
        return;
    }
    uint32_t newWidth;
    uint32_t newHeight;
    // Canvas is able to handle the situation when the window is out of screen, using bounds instead of dst.
    uint32_t boundsWidth = static_cast<uint32_t>(localBounds.GetWidth());
    uint32_t boundsHeight = static_cast<uint32_t>(localBounds.GetHeight());
    if (boundsWidth == 0 || boundsHeight == 0 || srcWidth == 0 || srcHeight == 0) {
        return;
    }
    if (srcWidth * boundsHeight > srcHeight * boundsWidth) {
        newWidth = boundsWidth;
        newHeight = srcHeight * newWidth / srcWidth;
    } else if (srcWidth * boundsHeight < srcHeight * boundsWidth) {
        newHeight = boundsHeight;
        newWidth = newHeight * srcWidth / srcHeight;
    } else {
        newWidth = boundsWidth;
        newHeight = boundsHeight;
    }
    newHeight = newHeight * srcHeight / boundsHeight;
    newWidth = newWidth * srcWidth / boundsWidth;
    if (newWidth < srcWidth) {
        auto halfdw = (srcWidth - newWidth) / 2;
        params.dstRect =
            Drawing::Rect(params.srcRect.GetLeft() + static_cast<int32_t>(halfdw), params.srcRect.GetTop(),
                params.srcRect.GetLeft() + static_cast<int32_t>(halfdw) + static_cast<int32_t>(newWidth),
                params.srcRect.GetTop() + params.srcRect.GetHeight());
    } else if (newHeight < srcHeight) {
        auto halfdh = (srcHeight - newHeight) / 2;
        params.dstRect =
            Drawing::Rect(params.srcRect.GetLeft(), params.srcRect.GetTop() + static_cast<int32_t>(halfdh),
                params.srcRect.GetLeft() + params.srcRect.GetWidth(),
                params.srcRect.GetTop() + static_cast<int32_t>(halfdh) + static_cast<int32_t>(newHeight));
    }
    RS_LOGD("RsDebug RSUniRenderUtil::SrcRectScaleFit name:%{public}s,"
        " dstRect [%{public}f %{public}f %{public}f %{public}f]",
        surface->GetName().c_str(), params.dstRect.GetLeft(), params.dstRect.GetTop(),
        params.dstRect.GetWidth(), params.dstRect.GetHeight());
}

void RSUniRenderUtil::SrcRectScaleDown(BufferDrawParam& params, const sptr<SurfaceBuffer>& buffer,
    const sptr<IConsumerSurface>& surface, RectF& localBounds)
{
    if (buffer == nullptr || surface == nullptr) {
        return;
    }
    uint32_t newWidth = static_cast<uint32_t>(params.srcRect.GetWidth());
    uint32_t newHeight = static_cast<uint32_t>(params.srcRect.GetHeight());
    // Canvas is able to handle the situation when the window is out of screen, using bounds instead of dst.
    uint32_t boundsWidth = static_cast<uint32_t>(localBounds.GetWidth());
    uint32_t boundsHeight = static_cast<uint32_t>(localBounds.GetHeight());

    // If transformType is not a multiple of 180, need to change the correspondence between width & height.
    GraphicTransformType transformType = RSBaseRenderUtil::GetRotateTransform(surface->GetTransform());
    if (transformType == GraphicTransformType::GRAPHIC_ROTATE_270 ||
        transformType == GraphicTransformType::GRAPHIC_ROTATE_90) {
        std::swap(boundsWidth, boundsHeight);
    }

    uint32_t newWidthBoundsHeight = newWidth * boundsHeight;
    uint32_t newHeightBoundsWidth = newHeight * boundsWidth;

    if (newWidthBoundsHeight > newHeightBoundsWidth) {
        newWidth = boundsWidth * newHeight / boundsHeight;
    } else if (newWidthBoundsHeight < newHeightBoundsWidth) {
        newHeight = boundsHeight * newWidth / boundsWidth;
    } else {
        return;
    }

    uint32_t currentWidth = static_cast<uint32_t>(params.srcRect.GetWidth());
    uint32_t currentHeight = static_cast<uint32_t>(params.srcRect.GetHeight());
    if (newWidth < currentWidth) {
        // the crop is too wide
        uint32_t dw = currentWidth - newWidth;
        auto halfdw = dw / 2;
        params.srcRect =
            Drawing::Rect(params.srcRect.GetLeft() + static_cast<int32_t>(halfdw), params.srcRect.GetTop(),
                params.srcRect.GetLeft() + static_cast<int32_t>(halfdw) + static_cast<int32_t>(newWidth),
                params.srcRect.GetTop() + params.srcRect.GetHeight());
    } else {
        // thr crop is too tall
        uint32_t dh = currentHeight - newHeight;
        auto halfdh = dh / 2;
        params.srcRect =
            Drawing::Rect(params.srcRect.GetLeft(), params.srcRect.GetTop() + static_cast<int32_t>(halfdh),
                params.srcRect.GetLeft() + params.srcRect.GetWidth(),
                params.srcRect.GetTop() + static_cast<int32_t>(halfdh) + static_cast<int32_t>(newHeight));
    }
    RS_LOGD("RsDebug RSUniRenderUtil::SrcRectScaleDown name:%{public}s,"
        " srcRect [%{public}f %{public}f %{public}f %{public}f]",
        surface->GetName().c_str(), params.srcRect.GetLeft(), params.srcRect.GetTop(),
        params.srcRect.GetWidth(), params.srcRect.GetHeight());
}

Drawing::Matrix RSUniRenderUtil::GetMatrixOfBufferToRelRect(const RSSurfaceRenderNode& node)
{
    const sptr<SurfaceBuffer> buffer = node.GetRSSurfaceHandler()->GetBuffer();
    if (buffer == nullptr) {
        return Drawing::Matrix();
    }

    auto consumer = node.GetRSSurfaceHandler()->GetConsumer();
    if (consumer == nullptr) {
        return Drawing::Matrix();
    }

    BufferDrawParam params;
    params.buffer = buffer;
    params.srcRect = Drawing::Rect(0, 0, buffer->GetSurfaceBufferWidth(), buffer->GetSurfaceBufferHeight());
    const RSProperties& property = node.GetRenderProperties();
    params.dstRect = Drawing::Rect(0, 0, property.GetBoundsWidth(), property.GetBoundsHeight());
    auto transform = consumer->GetTransform();
    RectF localBounds = { 0.0f, 0.0f, property.GetBoundsWidth(), property.GetBoundsHeight() };
    RSBaseRenderUtil::DealWithSurfaceRotationAndGravity(transform, property.GetFrameGravity(), localBounds, params);
    RSBaseRenderUtil::FlipMatrix(transform, params);
    return params.matrix;
}

BufferDrawParam RSUniRenderUtil::CreateBufferDrawParam(
    const RSSurfaceRenderNode& node, bool forceCPU, uint32_t threadIndex, bool useRenderParams)
{
    BufferDrawParam params;

    auto drawable = node.GetRenderDrawable();
    if (useRenderParams && !drawable) {
        return params;
    }
    auto surfaceDrawable = std::static_pointer_cast<DrawableV2::RSSurfaceRenderNodeDrawable>(drawable);
    auto& nodeParams = surfaceDrawable->GetRenderParams();
    if (useRenderParams && !nodeParams) {
        RS_LOGE("RSUniRenderUtil::CreateBufferDrawParam RenderThread nodeParams is nullptr");
        return params;
    }
    auto surfaceHandler = node.GetRSSurfaceHandler();
    auto surfaceParams = static_cast<RSSurfaceRenderParams*>(nodeParams.get());
    const RSProperties& property = node.GetRenderProperties();

    params.threadIndex = threadIndex;
    params.useBilinearInterpolation = useRenderParams ?
        surfaceParams->NeedBilinearInterpolation() : node.NeedBilinearInterpolation();
    params.useCPU = forceCPU;
    Drawing::Filter filter;
    filter.SetFilterQuality(Drawing::Filter::FilterQuality::LOW);
    params.paint.SetFilter(filter);

    auto boundWidth = useRenderParams ? nodeParams->GetBounds().GetWidth() : property.GetBoundsWidth();
    auto boundHeight = useRenderParams ? nodeParams->GetBounds().GetHeight() : property.GetBoundsHeight();
    params.dstRect = Drawing::Rect(0, 0, boundWidth, boundHeight);

    const sptr<SurfaceBuffer> buffer = useRenderParams ? surfaceParams->GetBuffer() : surfaceHandler->GetBuffer();
    if (buffer == nullptr) {
        return params;
    }
    params.buffer = buffer;
    params.acquireFence = useRenderParams ? nodeParams->GetAcquireFence() : surfaceHandler->GetAcquireFence();
    params.srcRect = Drawing::Rect(0, 0, buffer->GetSurfaceBufferWidth(), buffer->GetSurfaceBufferHeight());

    auto consumer = useRenderParams ? surfaceDrawable->GetConsumerOnDraw() : surfaceHandler->GetConsumer();
    if (consumer == nullptr) {
        return params;
    }
    auto transform = GraphicTransformType::GRAPHIC_ROTATE_NONE;
    if (consumer->GetSurfaceBufferTransformType(buffer, &transform) != GSERROR_OK) {
        RS_LOGE("RSUniRenderUtil::CreateBufferDrawParam GetSurfaceBufferTransformType failed");
    }
    RectF localBounds = { 0.0f, 0.0f, boundWidth, boundHeight };
    auto gravity = useRenderParams ? nodeParams->GetFrameGravity() : property.GetFrameGravity();
    RSBaseRenderUtil::DealWithSurfaceRotationAndGravity(transform, gravity, localBounds, params, surfaceParams);
    RSBaseRenderUtil::FlipMatrix(transform, params);
    ScalingMode scalingMode = surfaceParams->GetPreScalingMode();
    if (consumer->GetScalingMode(buffer->GetSeqNum(), scalingMode) == GSERROR_OK) {
        surfaceParams->SetPreScalingMode(scalingMode);
    }
    if (scalingMode == ScalingMode::SCALING_MODE_SCALE_CROP) {
        SrcRectScaleDown(params, buffer, consumer, localBounds);
    } else if (scalingMode == ScalingMode::SCALING_MODE_SCALE_FIT) {
        SrcRectScaleFit(params, buffer, consumer, localBounds);
    }
    return params;
}

BufferDrawParam RSUniRenderUtil::CreateBufferDrawParam(
    const DrawableV2::RSSurfaceRenderNodeDrawable& surfaceDrawable, bool forceCPU, uint32_t threadIndex)
{
    BufferDrawParam params;
    auto& nodeParams = surfaceDrawable.GetRenderParams();
    if (!nodeParams) {
        RS_LOGE("RSUniRenderUtil::CreateBufferDrawParam RenderThread nodeParams is nullptr");
        return params;
    }
    auto surfaceNodeParams = static_cast<RSSurfaceRenderParams*>(nodeParams.get());
    params.threadIndex = threadIndex;
    params.useBilinearInterpolation = surfaceNodeParams->NeedBilinearInterpolation();
    params.useCPU = forceCPU;
    Drawing::Filter filter;
    filter.SetFilterQuality(Drawing::Filter::FilterQuality::LOW);
    params.paint.SetFilter(filter);

    auto boundWidth = nodeParams->GetBounds().GetWidth();
    auto boundHeight = nodeParams->GetBounds().GetHeight();
    params.dstRect = Drawing::Rect(0, 0, boundWidth, boundHeight);

    const sptr<SurfaceBuffer> buffer = nodeParams->GetBuffer();
    if (buffer == nullptr) {
        return params;
    }
    params.buffer = buffer;
    params.acquireFence = nodeParams->GetAcquireFence();
    params.srcRect = Drawing::Rect(0, 0, buffer->GetSurfaceBufferWidth(), buffer->GetSurfaceBufferHeight());

    auto consumer = surfaceDrawable.GetConsumerOnDraw();
    if (consumer == nullptr) {
        return params;
    }
    auto transform = consumer->GetTransform();
    RectF localBounds = { 0.0f, 0.0f, boundWidth, boundHeight };
    auto gravity = nodeParams->GetFrameGravity();
    RSBaseRenderUtil::DealWithSurfaceRotationAndGravity(transform, gravity, localBounds, params, surfaceNodeParams);
    RSBaseRenderUtil::FlipMatrix(transform, params);
    ScalingMode scalingMode = surfaceNodeParams->GetPreScalingMode();
    if (consumer->GetScalingMode(buffer->GetSeqNum(), scalingMode) == GSERROR_OK) {
        surfaceNodeParams->SetPreScalingMode(scalingMode);
    }
    if (scalingMode == ScalingMode::SCALING_MODE_SCALE_CROP) {
        SrcRectScaleDown(params, buffer, consumer, localBounds);
    } else if (scalingMode == ScalingMode::SCALING_MODE_SCALE_FIT) {
        SrcRectScaleFit(params, buffer, consumer, localBounds);
    }
    return params;
}

BufferDrawParam RSUniRenderUtil::CreateBufferDrawParam(const RSDisplayRenderNode& node, bool forceCPU)
{
    BufferDrawParam params;
    params.useCPU = forceCPU;
    Drawing::Filter filter;
    filter.SetFilterQuality(Drawing::Filter::FilterQuality::LOW);
    params.paint.SetFilter(filter);

    auto drawable = node.GetRenderDrawable();
    if (!drawable) {
        return params;
    }
    auto displayDrawable = std::static_pointer_cast<DrawableV2::RSDisplayRenderNodeDrawable>(drawable);
    auto surfaceHandler = displayDrawable->GetRSSurfaceHandlerOnDraw();
    const sptr<SurfaceBuffer> buffer = surfaceHandler->GetBuffer();
    if (!buffer) {
        RS_LOGE("RSUniRenderUtil::CreateBufferDrawParam buffer is null.");
        return params;
    }
    params.buffer = buffer;
    params.acquireFence = surfaceHandler->GetAcquireFence();
    params.srcRect = Drawing::Rect(0, 0, buffer->GetSurfaceBufferWidth(), buffer->GetSurfaceBufferHeight());
    params.dstRect = Drawing::Rect(0, 0, buffer->GetSurfaceBufferWidth(), buffer->GetSurfaceBufferHeight());
    return params;
}

BufferDrawParam RSUniRenderUtil::CreateBufferDrawParam(const RSSurfaceHandler& surfaceHandler, bool forceCPU)
{
    BufferDrawParam bufferDrawParam;
    bufferDrawParam.useCPU = forceCPU;
    Drawing::Filter filter;
    filter.SetFilterQuality(Drawing::Filter::FilterQuality::LOW);
    bufferDrawParam.paint.SetFilter(filter);

    const sptr<SurfaceBuffer> buffer = surfaceHandler.GetBuffer();
    if (!buffer) {
        RS_LOGE("RSUniRenderUtil::CreateBufferDrawParam buffer is null.");
        return bufferDrawParam;
    }
    bufferDrawParam.buffer = buffer;
    bufferDrawParam.acquireFence = surfaceHandler.GetAcquireFence();
    bufferDrawParam.srcRect = Drawing::Rect(0, 0, buffer->GetSurfaceBufferWidth(), buffer->GetSurfaceBufferHeight());
    bufferDrawParam.dstRect = Drawing::Rect(0, 0, buffer->GetSurfaceBufferWidth(), buffer->GetSurfaceBufferHeight());
    return bufferDrawParam;
}

BufferDrawParam RSUniRenderUtil::CreateLayerBufferDrawParam(const LayerInfoPtr& layer, bool forceCPU)
{
    BufferDrawParam params;
    params.useCPU = forceCPU;
    Drawing::Filter filter;
    filter.SetFilterQuality(Drawing::Filter::FilterQuality::LOW);
    params.paint.SetFilter(filter);
    params.paint.SetAlpha(layer->GetAlpha().gAlpha);
    sptr<SurfaceBuffer> buffer = layer->GetBuffer();
    if (buffer == nullptr) {
        return params;
    }
    params.acquireFence = layer->GetAcquireFence();
    params.buffer = buffer;
    params.srcRect = Drawing::Rect(0, 0, buffer->GetSurfaceBufferWidth(), buffer->GetSurfaceBufferHeight());
    auto boundRect = layer->GetBoundSize();
    params.dstRect = Drawing::Rect(0, 0, boundRect.w, boundRect.h);

    auto layerMatrix = layer->GetMatrix();
    params.matrix = Drawing::Matrix();
    params.matrix.SetMatrix(layerMatrix.scaleX, layerMatrix.skewX, layerMatrix.transX, layerMatrix.skewY,
        layerMatrix.scaleY, layerMatrix.transY, layerMatrix.pers0, layerMatrix.pers1, layerMatrix.pers2);
    int nodeRotation = RSUniRenderUtil::GetRotationFromMatrix(params.matrix); // rotation degree anti-clockwise
    auto layerTransform = layer->GetTransformType();
    // calculate clockwise rotation degree excluded rotation in total matrix
    int realRotation = (nodeRotation +
        RSBaseRenderUtil::RotateEnumToInt(RSBaseRenderUtil::GetRotateTransform(layerTransform))) % 360;
    auto flip = RSBaseRenderUtil::GetFlipTransform(layerTransform);
    // calculate transform in anti-clockwise
    auto transform = RSBaseRenderUtil::RotateEnumToInt(realRotation, flip);

    RectF localBounds = { 0.0f, 0.0f, static_cast<float>(boundRect.w), static_cast<float>(boundRect.h) };
    RSBaseRenderUtil::DealWithSurfaceRotationAndGravity(transform, static_cast<Gravity>(layer->GetGravity()),
        localBounds, params);
    RSBaseRenderUtil::FlipMatrix(transform, params);
    ScalingMode scalingMode = ScalingMode::SCALING_MODE_SCALE_TO_WINDOW;
    const auto& surface = layer->GetSurface();
    if (surface == nullptr) {
        RS_LOGE("buffer or surface is nullptr");
        return params;
    }

    if (surface->GetScalingMode(buffer->GetSeqNum(), scalingMode) != GSERROR_OK) {
        scalingMode = layer->GetScalingMode();
    }

    if (scalingMode == ScalingMode::SCALING_MODE_SCALE_CROP) {
        SrcRectScaleDown(params, buffer, surface, localBounds);
    } else if (scalingMode == ScalingMode::SCALING_MODE_SCALE_FIT) {
        SrcRectScaleFit(params, buffer, surface, localBounds);
    }
    return params;
}

bool RSUniRenderUtil::IsNeedClient(RSSurfaceRenderNode& node, const ComposeInfo& info)
{
    if (RSSystemProperties::IsForceClient()) {
        RS_LOGD("RSUniRenderUtil::IsNeedClient: force client.");
        return true;
    }
    const auto& property = node.GetRenderProperties();
    if (property.GetRotation() != 0 || property.GetRotationX() != 0 || property.GetRotationY() != 0 ||
        property.GetQuaternion() != Quaternion()) {
        RS_LOGD("RSUniRenderUtil::IsNeedClient need client with RSSurfaceRenderNode rotation");
        return true;
    }
    return false;
}

Occlusion::Region RSUniRenderUtil::AlignedDirtyRegion(const Occlusion::Region& dirtyRegion, int32_t alignedBits)
{
    Occlusion::Region alignedRegion;
    if (alignedBits <= 1) {
        return dirtyRegion;
    }
    for (const auto& dirtyRect : dirtyRegion.GetRegionRects()) {
        int32_t left = (dirtyRect.left_ / alignedBits) * alignedBits;
        int32_t top = (dirtyRect.top_ / alignedBits) * alignedBits;
        int32_t width = ((dirtyRect.right_ + alignedBits - 1) / alignedBits) * alignedBits - left;
        int32_t height = ((dirtyRect.bottom_ + alignedBits - 1) / alignedBits) * alignedBits - top;
        Occlusion::Rect rect = { left, top, left + width, top + height };
        Occlusion::Region singleAlignedRegion(rect);
        alignedRegion.OrSelf(singleAlignedRegion);
    }
    return alignedRegion;
}

bool RSUniRenderUtil::HandleSubThreadNode(RSSurfaceRenderNode& node, RSPaintFilterCanvas& canvas)
{
    if (node.IsMainThreadNode()) {
        RS_LOGE("RSUniRenderUtil::HandleSubThreadNode node.IsMainThreadNode()");
        return false;
    } else if (RSMainThread::Instance()->GetDeviceType() == DeviceType::PC &&
        !node.QueryIfAllHwcChildrenForceDisabledByFilter()) {
        return false; // this node should do DSS composition in mainThread although it is assigned to subThread
    }
    if (!node.HasCachedTexture()) {
        RS_TRACE_NAME_FMT("HandleSubThreadNode wait %" PRIu64 "", node.GetId());
#if defined(RS_ENABLE_GL) || defined(RS_ENABLE_VK)
        RSSubThreadManager::Instance()->WaitNodeTask(node.GetId());
        node.UpdateCompletedCacheSurface();
#endif
    }
    RS_OPTIONAL_TRACE_NAME_FMT("RSUniRenderUtil::HandleSubThreadNode %" PRIu64 "", node.GetId());
    node.DrawCacheSurface(canvas, UNI_MAIN_THREAD_INDEX, true);
    return true;
}

bool RSUniRenderUtil::HandleCaptureNode(RSRenderNode& node, RSPaintFilterCanvas& canvas)
{
    auto surfaceNodePtr = node.ReinterpretCastTo<RSSurfaceRenderNode>();
    if (surfaceNodePtr == nullptr ||
        (!surfaceNodePtr->IsAppWindow() && !surfaceNodePtr->IsLeashWindow())) {
        return false;
    }

    auto curNode = surfaceNodePtr;
    if (surfaceNodePtr->IsAppWindow()) {
        auto rsParent = RSBaseRenderNode::ReinterpretCast<RSSurfaceRenderNode>(surfaceNodePtr->GetParent().lock());
        if (rsParent && rsParent->IsLeashWindow()) {
            curNode = rsParent;
        }
    }
    if (!curNode->ShouldPaint()) {
        return false;
    }
    if (curNode->IsOnTheTree()) {
        return HandleSubThreadNode(*curNode, canvas);
    } else {
#if defined(RS_ENABLE_GL) || defined(RS_ENABLE_VK)
        if (curNode->GetCacheSurfaceProcessedStatus() == CacheProcessStatus::DOING) {
            RSSubThreadManager::Instance()->WaitNodeTask(curNode->GetId());
        }
#endif
        return false;
    }
    return false;
}

int RSUniRenderUtil::GetRotationFromMatrix(Drawing::Matrix matrix)
{
    Drawing::Matrix::Buffer value;
    matrix.GetAll(value);

    int rAngle = static_cast<int>(-round(atan2(value[Drawing::Matrix::Index::SKEW_X],
        value[Drawing::Matrix::Index::SCALE_X]) * (180 / PI)));
    // transfer the result to anti-clockwise degrees
    // only rotation with 90°, 180°, 270° are composed through hardware,
    // in which situation the transformation of the layer needs to be set.
    static const std::map<int, int> supportedDegrees = {{90, 270}, {180, 180}, {-90, 90}, {-180, 180}};
    auto iter = supportedDegrees.find(rAngle);
    return iter != supportedDegrees.end() ? iter->second : 0;
}

int RSUniRenderUtil::GetRotationDegreeFromMatrix(Drawing::Matrix matrix)
{
    Drawing::Matrix::Buffer value;
    matrix.GetAll(value);
    return static_cast<int>(-round(atan2(value[Drawing::Matrix::Index::SKEW_X],
        value[Drawing::Matrix::Index::SCALE_X]) * (180 / PI)));
}

bool RSUniRenderUtil::Is3DRotation(Drawing::Matrix matrix)
{
    Drawing::Matrix::Buffer value;
    matrix.GetAll(value);
    // ScaleX and ScaleY must have different sign
    if (!(std::signbit(value[Drawing::Matrix::Index::SCALE_X]) ^
        std::signbit(value[Drawing::Matrix::Index::SCALE_Y]))) {
        return false;
    }

    int rotateX = static_cast<int>(-round(atan2(value[Drawing::Matrix::Index::PERSP_1],
        value[Drawing::Matrix::Index::SCALE_Y]) * (180 / PI)));
    int rotateY = static_cast<int>(-round(atan2(value[Drawing::Matrix::Index::PERSP_0],
        value[Drawing::Matrix::Index::SCALE_X]) * (180 / PI)));
    return (rotateX != 0) || (rotateY != 0);
}


void RSUniRenderUtil::ReleaseColorPickerFilter(std::shared_ptr<RSFilter> RSFilter)
{
    auto drawingFilter = std::static_pointer_cast<RSDrawingFilter>(RSFilter);
    std::shared_ptr<RSShaderFilter> rsShaderFilter =
        drawingFilter->GetShaderFilterWithType(RSShaderFilter::MASK_COLOR);
    if (rsShaderFilter == nullptr) {
        return;
    }
    auto maskColorShaderFilter = std::static_pointer_cast<RSMaskColorShaderFilter>(rsShaderFilter);
    maskColorShaderFilter->ReleaseColorPickerFilter();
}

void RSUniRenderUtil::ReleaseColorPickerResource(std::shared_ptr<RSRenderNode>& node)
{
    if (node == nullptr) {
        return;
    }
    auto& properties = node->GetRenderProperties();
    if (properties.GetColorPickerCacheTaskShadow() != nullptr) {
        properties.ReleaseColorPickerTaskShadow();
    }
    if ((properties.GetFilter() != nullptr &&
        properties.GetFilter()->GetFilterType() == RSFilter::MATERIAL)) {
        ReleaseColorPickerFilter(properties.GetFilter());
    }
    if (properties.GetBackgroundFilter() != nullptr &&
        properties.GetBackgroundFilter()->GetFilterType() == RSFilter::MATERIAL) {
        ReleaseColorPickerFilter(properties.GetBackgroundFilter());
    }
    // Recursive to release color picker resource
    for (auto& child : *node->GetChildren()) {
        if (auto canvasChild = RSBaseRenderNode::ReinterpretCast<RSRenderNode>(child)) {
            if (RSSystemProperties::GetColorPickerPartialEnabled()) {
                ReleaseColorPickerResource(canvasChild);
            }
        }
    }
}

bool RSUniRenderUtil::IsNodeAssignSubThread(std::shared_ptr<RSSurfaceRenderNode> node, bool isDisplayRotation)
{
    auto deviceType = RSMainThread::Instance()->GetDeviceType();
    bool isNeedAssignToSubThread = false;
    if (deviceType != DeviceType::PC && node->IsLeashWindow()) {
        isNeedAssignToSubThread = (node->IsScale() || node->IsScaleInPreFrame()
            || ROSEN_EQ(node->GetGlobalAlpha(), 0.0f) || node->GetForceUIFirst()) && !node->HasFilter();
        RS_TRACE_NAME_FMT("Assign info: name[%s] id[%" PRIu64"]"
            " status:%d filter:%d isScale:%d isScalePreFrame:%d forceUIFirst:%d isNeedAssign:%d",
            node->GetName().c_str(), node->GetId(), node->GetCacheSurfaceProcessedStatus(), node->HasFilter(),
            node->IsScale(), node->IsScaleInPreFrame(), node->GetForceUIFirst(), isNeedAssignToSubThread);
    }
    std::string surfaceName = node->GetName();
    bool needFilterSCB = node->GetSurfaceWindowType() == SurfaceWindowType::SYSTEM_SCB_WINDOW;
    RS_LOGI("RSUniRenderUtil::IsNodeAssignSubThread %s", surfaceName.c_str());

    if (needFilterSCB || node->IsSelfDrawingType()) {
        return false;
    }
    if (node->GetCacheSurfaceProcessedStatus() == CacheProcessStatus::DOING) { // node exceed one vsync
        return true;
    }
    if (deviceType != DeviceType::PC) {
        return isNeedAssignToSubThread;
    } else { // PC or TABLET
        if ((node->IsFocusedNode(RSMainThread::Instance()->GetFocusNodeId()) ||
            node->IsFocusedNode(RSMainThread::Instance()->GetFocusLeashWindowId())) &&
            node->GetHasSharedTransitionNode()) {
            return false;
        }
        return node->QuerySubAssignable(isDisplayRotation);
    }
}

void RSUniRenderUtil::AssignWindowNodes(const std::shared_ptr<RSDisplayRenderNode>& displayNode,
    std::list<std::shared_ptr<RSSurfaceRenderNode>>& mainThreadNodes,
    std::list<std::shared_ptr<RSSurfaceRenderNode>>& subThreadNodes)
{
    if (displayNode == nullptr) {
        ROSEN_LOGE("RSUniRenderUtil::AssignWindowNodes display node is null");
        return;
    }
    bool isRotation = displayNode->IsRotationChanged();
    std::vector<RSBaseRenderNode::SharedPtr> curAllSurfaces;
    if (Rosen::SceneBoardJudgement::IsSceneBoardEnabled()) {
        displayNode->CollectSurface(displayNode, curAllSurfaces, true, true);
    } else {
        curAllSurfaces = *displayNode->GetSortedChildren();
    }
   
    for (auto iter = curAllSurfaces.begin(); iter != curAllSurfaces.end(); iter++) {
        auto node = RSBaseRenderNode::ReinterpretCast<RSSurfaceRenderNode>(*iter);
        if (node == nullptr) {
            ROSEN_LOGE("RSUniRenderUtil::AssignWindowNodes nullptr found in sortedChildren, this should not happen");
            continue;
        }
        // release color picker resource when thread-switching between RS and subthread
        bool lastIsNeedAssignToSubThread = node->GetLastIsNeedAssignToSubThread();
        bool isNodeAssignSubThread = IsNodeAssignSubThread(node, isRotation);
        if (isNodeAssignSubThread != lastIsNeedAssignToSubThread) {
            auto renderNode = RSBaseRenderNode::ReinterpretCast<RSRenderNode>(node);
            if (RSSystemProperties::GetColorPickerPartialEnabled()) {
                ReleaseColorPickerResource(renderNode);
            }
            node->SetLastIsNeedAssignToSubThread(isNodeAssignSubThread);
        }
        if (isNodeAssignSubThread) {
            AssignSubThreadNode(subThreadNodes, node);
        } else {
            AssignMainThreadNode(mainThreadNodes, node);
        }
    }
    SortSubThreadNodes(subThreadNodes);
}

void RSUniRenderUtil::AssignMainThreadNode(std::list<std::shared_ptr<RSSurfaceRenderNode>>& mainThreadNodes,
    const std::shared_ptr<RSSurfaceRenderNode>& node)
{
    if (node == nullptr) {
        ROSEN_LOGW("RSUniRenderUtil::AssignMainThreadNode node is nullptr");
        return;
    }
    mainThreadNodes.emplace_back(node);
    bool changeThread = !node->IsMainThreadNode();
    node->SetIsMainThreadNode(true);
    node->SetNeedSubmitSubThread(false);
    node->SetCacheType(CacheType::NONE);
    HandleHardwareNode(node);
    if (changeThread) {
        RS_LOGD("RSUniRenderUtil::AssignMainThreadNode clear cache surface:[%{public}s, %{public}" PRIu64 "]",
            node->GetName().c_str(), node->GetId());
        ClearCacheSurface(*node, UNI_MAIN_THREAD_INDEX);
        node->SetIsMainThreadNode(true);
        node->SetTextureValidFlag(false);
    }

    if (RSMainThread::Instance()->GetDeviceType() == DeviceType::PC) {
        RS_TRACE_NAME_FMT("AssignMainThread: name: %s, id: %" PRIu64", [HasTransparentSurface: %d, "
            "ChildHasVisibleFilter: %d, HasFilter: %d, QueryIfAllHwcChildrenForceDisabledByFilter: %d]",
            node->GetName().c_str(), node->GetId(), node->GetHasTransparentSurface(),
            node->ChildHasVisibleFilter(), node->HasFilter(),
            node->QueryIfAllHwcChildrenForceDisabledByFilter());
    }
}

void RSUniRenderUtil::AssignSubThreadNode(
    std::list<std::shared_ptr<RSSurfaceRenderNode>>& subThreadNodes, const std::shared_ptr<RSSurfaceRenderNode>& node)
{
    if (node == nullptr) {
        ROSEN_LOGW("RSUniRenderUtil::AssignSubThreadNode node is nullptr");
        return;
    }
    node->SetCacheType(CacheType::CONTENT);
    node->SetIsMainThreadNode(false);
    auto deviceType = RSMainThread::Instance()->GetDeviceType();
    bool dirty = node->GetNeedDrawFocusChange()
        || (!node->IsCurFrameStatic(deviceType) && !node->IsVisibleDirtyEmpty(deviceType));
    // skip complete static window, DO NOT assign it to subthread.
    if (node->GetCacheSurfaceProcessedStatus() == CacheProcessStatus::DONE &&
        node->HasCachedTexture() && node->IsUIFirstSelfDrawCheck() && !dirty) {
        node->SetNeedSubmitSubThread(false);
        RS_OPTIONAL_TRACE_NAME_FMT("subThreadNodes : static skip %s", node->GetName().c_str());
    } else {
        node->SetNeedSubmitSubThread(true);
        node->SetNeedDrawFocusChange(false);
        node->UpdateCacheSurfaceDirtyManager(2); // 2 means buffer age
    }
    node->SetLastFrameChildrenCnt(node->GetChildren()->size());
    subThreadNodes.emplace_back(node);
#if defined(RS_ENABLE_GL) || defined(RS_ENABLE_VK)
    if (node->GetCacheSurfaceProcessedStatus() == CacheProcessStatus::DONE &&
        node->IsCacheSurfaceValid() && node->GetCacheSurfaceNeedUpdated()) {
        node->UpdateCompletedCacheSurface();
        if (node->IsAppWindow() &&
            !RSBaseRenderNode::ReinterpretCast<RSSurfaceRenderNode>(node->GetParent().lock())) {
            node->GetDirtyManager()->MergeDirtyRect(node->GetOldDirty());
        } else {
            for (auto& child : *node->GetSortedChildren()) {
                auto surfaceNode = RSBaseRenderNode::ReinterpretCast<RSSurfaceRenderNode>(child);
                if (surfaceNode && surfaceNode->IsAppWindow()) {
                    surfaceNode->GetDirtyManager()->MergeDirtyRect(surfaceNode->GetOldDirty());
                    break;
                }
            }
        }
        node->SetCacheSurfaceNeedUpdated(false);
    }
#endif
    bool isFocus = node->IsFocusedNode(RSMainThread::Instance()->GetFocusNodeId()) ||
        (node->IsFocusedNode(RSMainThread::Instance()->GetFocusLeashWindowId()));
    if ((deviceType == DeviceType::PC || deviceType == DeviceType::TABLET) && isFocus) {
        node->SetPriority(NodePriorityType::SUB_FOCUSNODE_PRIORITY); // for resolving response latency
        return;
    }
    if (node->HasCachedTexture()) {
        node->SetPriority(NodePriorityType::SUB_LOW_PRIORITY);
    } else {
        node->SetPriority(NodePriorityType::SUB_HIGH_PRIORITY);
    }
}

void RSUniRenderUtil::SortSubThreadNodes(std::list<std::shared_ptr<RSSurfaceRenderNode>>& subThreadNodes)
{
    // sort subThreadNodes by priority and z-order
    subThreadNodes.sort([](const auto& first, const auto& second) -> bool {
        auto node1 = RSBaseRenderNode::ReinterpretCast<RSSurfaceRenderNode>(first);
        auto node2 = RSBaseRenderNode::ReinterpretCast<RSSurfaceRenderNode>(second);
        if (node1 == nullptr || node2 == nullptr) {
            ROSEN_LOGE(
                "RSUniRenderUtil::SortSubThreadNodes sort nullptr found in subThreadNodes, this should not happen");
            return false;
        }
        if (node1->GetPriority() == node2->GetPriority()) {
            return node2->GetRenderProperties().GetPositionZ() < node1->GetRenderProperties().GetPositionZ();
        } else {
            return node1->GetPriority() < node2->GetPriority();
        }
    });
}

void RSUniRenderUtil::CacheSubThreadNodes(std::list<std::shared_ptr<RSSurfaceRenderNode>>& oldSubThreadNodes,
    std::list<std::shared_ptr<RSSurfaceRenderNode>>& subThreadNodes)
{
    std::unordered_set<std::shared_ptr<RSSurfaceRenderNode>> nodes(subThreadNodes.begin(), subThreadNodes.end());
    for (auto node : oldSubThreadNodes) {
        if (nodes.count(node) > 0) {
            continue;
        }
        // The node being processed by sub thread may have been removed.
        if (node->GetCacheSurfaceProcessedStatus() == CacheProcessStatus::DOING) {
            subThreadNodes.emplace_back(node);
        }
    }
    oldSubThreadNodes.clear();
    oldSubThreadNodes = subThreadNodes;
}

void RSUniRenderUtil::HandleHardwareNode(const std::shared_ptr<RSSurfaceRenderNode>& node)
{
    if (!node->HasHardwareNode()) {
        return;
    }
    auto appWindow = node;
    if (node->IsLeashWindow()) {
        for (auto& child : *node->GetSortedChildren()) {
            auto surfaceNodePtr = RSBaseRenderNode::ReinterpretCast<RSSurfaceRenderNode>(child);
            if (surfaceNodePtr && surfaceNodePtr->IsAppWindow()) {
                appWindow = surfaceNodePtr;
                break;
            }
        }
    }
    auto hardwareEnabledNodes = appWindow->GetChildHardwareEnabledNodes();
    for (auto& hardwareEnabledNode : hardwareEnabledNodes) {
        auto hardwareEnabledNodePtr = hardwareEnabledNode.lock();
        if (hardwareEnabledNodePtr) {
            hardwareEnabledNodePtr->SetHardwareDisabledByCache(false);
        }
    }
}

void RSUniRenderUtil::ClearSurfaceIfNeed(const RSRenderNodeMap& map,
    const std::shared_ptr<RSDisplayRenderNode>& displayNode,
    std::set<std::shared_ptr<RSBaseRenderNode>>& oldChildren,
    DeviceType deviceType)
{
    if (displayNode == nullptr) {
        return;
    }
    std::vector<RSBaseRenderNode::SharedPtr> curAllSurfaces;
    if (Rosen::SceneBoardJudgement::IsSceneBoardEnabled()) {
        curAllSurfaces = displayNode->GetCurAllSurfaces(true);
    } else {
        curAllSurfaces = *displayNode->GetSortedChildren();
    }
    std::set<std::shared_ptr<RSBaseRenderNode>> tmpSet(curAllSurfaces.begin(), curAllSurfaces.end());
    for (auto& child : oldChildren) {
        auto surface = RSBaseRenderNode::ReinterpretCast<RSSurfaceRenderNode>(child);
        if (!surface) {
            continue;
        }
        if (tmpSet.count(surface) == 0) {
            if (surface->GetCacheSurfaceProcessedStatus() == CacheProcessStatus::DOING) {
                tmpSet.emplace(surface);
                continue;
            }
            if (map.GetRenderNode(surface->GetId()) != nullptr) {
                RS_LOGD("RSUniRenderUtil::ClearSurfaceIfNeed clear cache surface:[%{public}s, %{public}" PRIu64 "]",
                    surface->GetName().c_str(), surface->GetId());
                if (deviceType == DeviceType::PHONE) {
                    ClearCacheSurface(*surface, UNI_MAIN_THREAD_INDEX);
                    surface->SetIsMainThreadNode(true);
                    surface->SetTextureValidFlag(false);
                } else {
                    if (RSMainThread::Instance()->IsPCThreeFingerScenesListScene()) {
                        ClearCacheSurface(*surface, UNI_MAIN_THREAD_INDEX, false);
                    } else {
                        ClearCacheSurface(*surface, UNI_MAIN_THREAD_INDEX);
                    }
                }
            }
        }
    }
    oldChildren.swap(tmpSet);
}

void RSUniRenderUtil::ClearCacheSurface(RSRenderNode& node, uint32_t threadIndex, bool isClearCompletedCacheSurface)
{
    RS_LOGD("ClearCacheSurface node: [%{public}" PRIu64 "]", node.GetId());
    uint32_t cacheSurfaceThreadIndex = node.GetCacheSurfaceThreadIndex();
    uint32_t completedSurfaceThreadIndex = node.GetCompletedSurfaceThreadIndex();
    if (cacheSurfaceThreadIndex == threadIndex && completedSurfaceThreadIndex == threadIndex) {
        node.ClearCacheSurface(isClearCompletedCacheSurface);
        return;
    }
    std::shared_ptr<Drawing::Surface> completedCacheSurface = isClearCompletedCacheSurface ?
        node.GetCompletedCacheSurface(threadIndex, false, true) : nullptr;
    ClearNodeCacheSurface(node.GetCacheSurface(threadIndex, false, true),
        std::move(completedCacheSurface), cacheSurfaceThreadIndex, completedSurfaceThreadIndex);
    node.ClearCacheSurface(isClearCompletedCacheSurface);
}

void RSUniRenderUtil::ClearNodeCacheSurface(std::shared_ptr<Drawing::Surface>&& cacheSurface,
    std::shared_ptr<Drawing::Surface>&& cacheCompletedSurface,
    uint32_t cacheSurfaceThreadIndex, uint32_t completedSurfaceThreadIndex)
{
    PostReleaseSurfaceTask(std::move(cacheSurface), cacheSurfaceThreadIndex);
    PostReleaseSurfaceTask(std::move(cacheCompletedSurface), completedSurfaceThreadIndex);
}

void RSUniRenderUtil::PostReleaseSurfaceTask(std::shared_ptr<Drawing::Surface>&& surface, uint32_t threadIndex)
{
    if (surface == nullptr) {
        return;
    }

    if (threadIndex == UNI_MAIN_THREAD_INDEX || threadIndex == UNI_RENDER_THREAD_INDEX) {
        if (RSUniRenderJudgement::IsUniRender()) {
            auto instance = &(RSUniRenderThread::Instance());
            instance->AddToReleaseQueue(std::move(surface));
            instance->PostTask([instance] () {
                instance->ReleaseSurface();
            });
        } else {
            auto instance = RSMainThread::Instance();
            instance->AddToReleaseQueue(std::move(surface));
            instance->PostTask([instance] () {
                instance->ReleaseSurface();
            });
        }
    } else {
#if defined(RS_ENABLE_GL) || defined(RS_ENABLE_VK)
        auto instance = RSSubThreadManager::Instance();
        instance->AddToReleaseQueue(std::move(surface), threadIndex);
        instance->ReleaseSurface(threadIndex);
#endif
    }
}

void RSUniRenderUtil::DrawRectForDfx(RSPaintFilterCanvas& canvas, const RectI& rect, Drawing::Color color,
    float alpha, const std::string& extraInfo)
{
    if (rect.width_ <= 0 || rect.height_ <= 0) {
        RS_LOGD("DrawRectForDfx rect is invalid.");
        return;
    }
    RS_LOGD("DrawRectForDfx current rect = %{public}s", rect.ToString().c_str());
    auto dstRect = Drawing::Rect(rect.left_, rect.top_,
        rect.left_ + rect.width_, rect.top_ + rect.height_);

    std::string position = rect.ToString() + extraInfo;

    const int defaultTextOffsetX = 6; // text position is 6 pixelSize right side of the Rect
    const int defaultTextOffsetY = 30; // text position has 30 pixelSize under the Rect
    Drawing::Brush rectBrush;
    std::shared_ptr<Drawing::Typeface> typeFace = nullptr;

    // font size: 24
    std::shared_ptr<Drawing::TextBlob> textBlob =
        Drawing::TextBlob::MakeFromString(position.c_str(), Drawing::Font(typeFace, 24.0f, 1.0f, 0.0f));

    rectBrush.SetColor(color);
    rectBrush.SetAntiAlias(true);
    rectBrush.SetAlphaF(alpha);
    canvas.AttachBrush(rectBrush);
    canvas.DrawRect(dstRect);
    canvas.DetachBrush();
    canvas.AttachBrush(Drawing::Brush());
    canvas.DrawTextBlob(textBlob.get(), rect.left_ + defaultTextOffsetX, rect.top_ + defaultTextOffsetY);
    canvas.DetachBrush();
}

#ifdef RS_ENABLE_VK
uint32_t RSUniRenderUtil::FindMemoryType(uint32_t typeFilter, VkMemoryPropertyFlags properties)
{
    if (OHOS::Rosen::RSSystemProperties::GetGpuApiType() != OHOS::Rosen::GpuApiType::VULKAN &&
        OHOS::Rosen::RSSystemProperties::GetGpuApiType() != OHOS::Rosen::GpuApiType::DDGR) {
        return UINT32_MAX;
    }
    auto& vkContext = OHOS::Rosen::RsVulkanContext::GetSingleton().GetRsVulkanInterface();
    VkPhysicalDevice physicalDevice = vkContext.GetPhysicalDevice();

    VkPhysicalDeviceMemoryProperties memProperties;
    vkContext.vkGetPhysicalDeviceMemoryProperties(physicalDevice, &memProperties);

    for (uint32_t i = 0; i < memProperties.memoryTypeCount; i++) {
        if ((typeFilter & (1 << i)) && (memProperties.memoryTypes[i].propertyFlags & properties) == properties) {
            return i;
        }
    }

    return UINT32_MAX;
}

void RSUniRenderUtil::SetVkImageInfo(std::shared_ptr<OHOS::Rosen::Drawing::VKTextureInfo> vkImageInfo,
    const VkImageCreateInfo& imageInfo)
{
    vkImageInfo->imageTiling = imageInfo.tiling;
    vkImageInfo->imageLayout = imageInfo.initialLayout;
    vkImageInfo->format = imageInfo.format;
    vkImageInfo->imageUsageFlags = imageInfo.usage;
    vkImageInfo->levelCount = imageInfo.mipLevels;
    vkImageInfo->currentQueueFamily = VK_QUEUE_FAMILY_EXTERNAL;
    vkImageInfo->ycbcrConversionInfo = {};
    vkImageInfo->sharingMode = imageInfo.sharingMode;
}

Drawing::BackendTexture RSUniRenderUtil::MakeBackendTexture(uint32_t width, uint32_t height, VkFormat format)
{
    VkImageTiling tiling = VK_IMAGE_TILING_OPTIMAL;
    VkImageUsageFlags usage = VK_IMAGE_USAGE_TRANSFER_SRC_BIT | VK_IMAGE_USAGE_TRANSFER_DST_BIT |
        VK_IMAGE_USAGE_SAMPLED_BIT | VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT;
    VkImageCreateInfo imageInfo {
        .sType = VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO,
        .pNext = nullptr,
        .flags = 0,
        .imageType = VK_IMAGE_TYPE_2D,
        .format = format,
        .extent = {width, height, 1},
        .mipLevels = 1,
        .arrayLayers = 1,
        .samples = VK_SAMPLE_COUNT_1_BIT,
        .tiling = tiling,
        .usage = usage,
        .sharingMode = VK_SHARING_MODE_EXCLUSIVE,
        .initialLayout = VK_IMAGE_LAYOUT_UNDEFINED
    };

    auto& vkContext = OHOS::Rosen::RsVulkanContext::GetSingleton().GetRsVulkanInterface();
    VkDevice device = vkContext.GetDevice();
    VkImage image = VK_NULL_HANDLE;
    VkDeviceMemory memory = VK_NULL_HANDLE;

    if (width * height > VKIMAGE_LIMIT_SIZE) {
        ROSEN_LOGE(
            "RSUniRenderUtil::MakeBackendTexture failed, image is too large, width:%{public}u, height::%{public}u",
            width, height);
        return {};
    }

    if (vkContext.vkCreateImage(device, &imageInfo, nullptr, &image) != VK_SUCCESS) {
        return {};
    }

    VkMemoryRequirements memRequirements;
    vkContext.vkGetImageMemoryRequirements(device, image, &memRequirements);

    VkMemoryAllocateInfo allocInfo{};
    allocInfo.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
    allocInfo.allocationSize = memRequirements.size;
    allocInfo.memoryTypeIndex = FindMemoryType(memRequirements.memoryTypeBits, VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT);
    if (allocInfo.memoryTypeIndex == UINT32_MAX) {
        return {};
    }

    if (vkContext.vkAllocateMemory(device, &allocInfo, nullptr, &memory) != VK_SUCCESS) {
        return {};
    }

    vkContext.vkBindImageMemory(device, image, memory, 0);

    OHOS::Rosen::Drawing::BackendTexture backendTexture(true);
    OHOS::Rosen::Drawing::TextureInfo textureInfo;
    textureInfo.SetWidth(width);
    textureInfo.SetHeight(height);

    std::shared_ptr<OHOS::Rosen::Drawing::VKTextureInfo> vkImageInfo =
        std::make_shared<OHOS::Rosen::Drawing::VKTextureInfo>();
    vkImageInfo->vkImage = image;
    vkImageInfo->vkAlloc.memory = memory;
    vkImageInfo->vkAlloc.size = memRequirements.size;

    SetVkImageInfo(vkImageInfo, imageInfo);
    textureInfo.SetVKTextureInfo(vkImageInfo);
    backendTexture.SetTextureInfo(textureInfo);
    return backendTexture;
}
#endif

RectI RSUniRenderUtil::SrcRectRotateTransform(RSSurfaceRenderNode& node)
{
    auto consumer = node.GetRSSurfaceHandler()->GetConsumer();
    if (!consumer) {
        return node.GetSrcRect();
    }
    RectI srcRect = node.GetSrcRect();
    int left = srcRect.GetLeft();
    int top = srcRect.GetTop();
    int width = srcRect.GetWidth();
    int height = srcRect.GetHeight();
    GraphicTransformType transformType =
        RSBaseRenderUtil::GetRotateTransform(consumer->GetTransform());
    int boundsWidth = static_cast<int>(node.GetRenderProperties().GetBoundsWidth());
    int boundsHeight = static_cast<int>(node.GetRenderProperties().GetBoundsHeight());
    // Left > 0 means move xComponent to the left outside of the screen
    // Top > 0 means move xComponent to the top outside of the screen
    // The left and top should recalculate when transformType is not GRAPHIC_ROTATE_NONEq
    // The width and height should exchange when transformType is GRAPHIC_ROTATE_270 and GRAPHIC_ROTATE_90
    switch (transformType) {
        case GraphicTransformType::GRAPHIC_ROTATE_270: {
            left = std::max(top, 0);
            top = std::max(boundsWidth - width - srcRect.GetLeft(), 0);
            srcRect = RectI {left, top, height, width};
            break;
        }
        case GraphicTransformType::GRAPHIC_ROTATE_180: {
            left = std::max(boundsWidth - width - left, 0);
            top = std::max(boundsHeight - height - top, 0);
            srcRect = RectI {left, top, width, height};
            break;
        }
        case GraphicTransformType::GRAPHIC_ROTATE_90: {
            left = std::max(boundsHeight - height - top, 0);
            top = std::max(srcRect.GetLeft(), 0);
            srcRect = RectI {left, top, height, width};
            break;
        }
        default: {
            break;
        }
    }
    return srcRect;
}
 
void RSUniRenderUtil::UpdateRealSrcRect(RSSurfaceRenderNode& node, const RectI& absRect)
{
    auto surfaceHandler = node.GetRSSurfaceHandler();
    auto consumer = surfaceHandler->GetConsumer();
    if (!consumer) {
        return;
    }
    auto srcRect = SrcRectRotateTransform(node);
    const auto& property = node.GetRenderProperties();
    const auto bufferWidth = surfaceHandler->GetBuffer()->GetSurfaceBufferWidth();
    const auto bufferHeight = surfaceHandler->GetBuffer()->GetSurfaceBufferHeight();
    auto boundsWidth = property.GetBoundsWidth();
    auto boundsHeight = property.GetBoundsHeight();
    GraphicTransformType transformType = RSBaseRenderUtil::GetRotateTransform(consumer->GetTransform());
    if (transformType == GraphicTransformType::GRAPHIC_ROTATE_270 ||
        transformType == GraphicTransformType::GRAPHIC_ROTATE_90) {
        std::swap(boundsWidth, boundsHeight);
    }
    if ((bufferWidth != boundsWidth || bufferHeight != boundsHeight) &&
        node.GetRenderProperties().GetFrameGravity() != Gravity::TOP_LEFT) {
        float xScale = (ROSEN_EQ(boundsWidth, 0.0f) ? 1.0f : bufferWidth / boundsWidth);
        float yScale = (ROSEN_EQ(boundsHeight, 0.0f) ? 1.0f : bufferHeight / boundsHeight);
        const auto nodeParams = static_cast<RSSurfaceRenderParams*>(node.GetStagingRenderParams().get());
        // If the scaling mode is SCALING_MODE_SCALE_TO_WINDOW, the scale should use smaller one.
        ScalingMode scalingMode = nodeParams->GetPreScalingMode();
        if (consumer->GetScalingMode(surfaceHandler->GetBuffer()->GetSeqNum(), scalingMode) == GSERROR_OK) {
            nodeParams->SetPreScalingMode(scalingMode);
        }
        if (scalingMode == ScalingMode::SCALING_MODE_SCALE_CROP) {
            float scale = std::min(xScale, yScale);
            srcRect.left_ = srcRect.left_ * scale;
            srcRect.top_ = srcRect.top_ * scale;
            if (ROSEN_EQ(scale, 0.f)) {
                node.SetSrcRect(srcRect);
                return;
            }
            srcRect.width_ = (bufferWidth / scale - (boundsWidth - srcRect.width_)) * scale;
            srcRect.height_ = (bufferHeight / scale - (boundsHeight - srcRect.height_)) * scale;
        } else {
            if (absRect == node.GetDstRect()) {
                // If the SurfaceRenderNode is completely in the DisplayRenderNode,
                // we do not need to crop the buffer.
                srcRect.width_ = bufferWidth;
                srcRect.height_ = bufferHeight;
            } else {
                srcRect.left_ = srcRect.left_ * xScale;
                srcRect.top_ = srcRect.top_ * yScale;
                srcRect.width_ = std::min(static_cast<int32_t>(std::ceil(srcRect.width_ * xScale)), bufferWidth);
                srcRect.height_ = std::min(static_cast<int32_t>(std::ceil(srcRect.height_ * yScale)), bufferHeight);
            }
        }
    }
    RectI bufferRect(0, 0, bufferWidth, bufferHeight);
    RectI newSrcRect = srcRect.IntersectRect(bufferRect);
    node.SetSrcRect(newSrcRect);
}
 
void RSUniRenderUtil::DealWithNodeGravity(RSSurfaceRenderNode& node, const ScreenInfo& screenInfo)
{
    if (!node.GetRSSurfaceHandler()->GetBuffer()) {
        return;
    }
    const auto& property = node.GetRenderProperties();
    const float frameWidth = node.GetRSSurfaceHandler()->GetBuffer()->GetSurfaceBufferWidth();
    const float frameHeight = node.GetRSSurfaceHandler()->GetBuffer()->GetSurfaceBufferHeight();
    const float boundsWidth = property.GetBoundsWidth();
    const float boundsHeight = property.GetBoundsHeight();
    const Gravity frameGravity = property.GetFrameGravity();

    CheckForceHardwareAndUpdateDstRect(node);
    // we do not need to do additional works for Gravity::RESIZE and if frameSize == boundsSize.
    if (frameGravity == Gravity::RESIZE || frameGravity == Gravity::TOP_LEFT ||
        (frameWidth == boundsWidth && frameHeight == boundsHeight)) {
        return;
    }
 
    // get current node's translate matrix and calculate gravity matrix.
    auto translateMatrix = Drawing::Matrix();
    translateMatrix.Translate(node.GetTotalMatrix().Get(Drawing::Matrix::Index::TRANS_X),
        std::ceil(node.GetTotalMatrix().Get(Drawing::Matrix::Index::TRANS_Y)));
    Drawing::Matrix gravityMatrix;
    (void)RSPropertiesPainter::GetGravityMatrix(frameGravity,
        RectF {0.0f, 0.0f, boundsWidth, boundsHeight}, frameWidth, frameHeight, gravityMatrix);
    // create a canvas to calculate new dstRect and new srcRect
    int32_t screenWidth = screenInfo.phyWidth;
    int32_t screenHeight = screenInfo.phyHeight;
    const auto screenRotation = screenInfo.rotation;
    if (screenRotation == ScreenRotation::ROTATION_90 || screenRotation == ScreenRotation::ROTATION_270) {
        std::swap(screenWidth, screenHeight);
    }
 
    auto canvas = std::make_unique<Drawing::Canvas>(screenWidth, screenHeight);
    canvas->ConcatMatrix(translateMatrix);
    canvas->ConcatMatrix(gravityMatrix);
    Drawing::Rect clipRect;
    gravityMatrix.MapRect(clipRect, Drawing::Rect(0, 0, frameWidth, frameHeight));
    canvas->ClipRect(Drawing::Rect(0, 0, clipRect.GetWidth(), clipRect.GetHeight()), Drawing::ClipOp::INTERSECT);
    Drawing::RectI newDstRect = canvas->GetDeviceClipBounds();
    auto dstRect = node.GetDstRect();
    // we make the newDstRect as the intersection of new and old dstRect,
    // to deal with the situation that frameSize > boundsSize.
    newDstRect.Intersect(Drawing::RectI(
        dstRect.left_, dstRect.top_, dstRect.width_ + dstRect.left_, dstRect.height_ + dstRect.top_));
    auto localRect = canvas->GetLocalClipBounds();
    int left = std::clamp<int>(localRect.GetLeft(), 0, frameWidth);
    int top = std::clamp<int>(localRect.GetTop(), 0, frameHeight);
    int width = std::clamp<int>(localRect.GetWidth(), 0, frameWidth - left);
    int height = std::clamp<int>(localRect.GetHeight(), 0, frameHeight - top);
 
    node.SetDstRect({newDstRect.GetLeft(), newDstRect.GetTop(), newDstRect.GetWidth(), newDstRect.GetHeight()});
    node.SetSrcRect({left, top, width, height});
}

void RSUniRenderUtil::CheckForceHardwareAndUpdateDstRect(RSSurfaceRenderNode& node)
{
    auto surfaceHandler = node.GetRSSurfaceHandler();
    if (!surfaceHandler->GetConsumer() || !node.GetForceHardware() || !surfaceHandler->GetBuffer()) {
        return;
    }
    RectI srcRect = { 0, 0,
        surfaceHandler->GetBuffer()->GetSurfaceBufferWidth(), surfaceHandler->GetBuffer()->GetSurfaceBufferHeight() };
    node.SetSrcRect(srcRect);
    auto dstRect = node.GetDstRect();
    auto originalDstRect = node.GetOriginalDstRect();
    dstRect.left_ += (dstRect.width_ - originalDstRect.width_) / 2;
    dstRect.top_ += (dstRect.height_ - originalDstRect.height_) / 2;
    dstRect.width_ = originalDstRect.width_;
    dstRect.height_ = originalDstRect.height_;
    node.SetDstRect(dstRect);
}
 
void RSUniRenderUtil::LayerRotate(RSSurfaceRenderNode& node, const ScreenInfo& screenInfo)
{
    const auto screenWidth = static_cast<int32_t>(screenInfo.width);
    const auto screenHeight = static_cast<int32_t>(screenInfo.height);
    const auto screenRotation = screenInfo.rotation;
    const auto rect = node.GetDstRect();
    switch (screenRotation) {
        case ScreenRotation::ROTATION_90: {
            node.SetDstRect({rect.top_, screenHeight - rect.left_ - rect.width_, rect.height_, rect.width_});
            break;
        }
        case ScreenRotation::ROTATION_180: {
            node.SetDstRect({screenWidth - rect.left_ - rect.width_, screenHeight - rect.top_ - rect.height_,
                rect.width_, rect.height_});
            break;
        }
        case ScreenRotation::ROTATION_270: {
            node.SetDstRect({screenWidth - rect.top_ - rect.height_, rect.left_, rect.height_, rect.width_});
            break;
        }
        default:  {
            break;
        }
    }
}
 
GraphicTransformType RSUniRenderUtil::GetLayerTransform(RSSurfaceRenderNode& node, const ScreenInfo& screenInfo)
{
    auto surfaceHandler = node.GetRSSurfaceHandler();
    if (!surfaceHandler) {
        return GraphicTransformType::GRAPHIC_ROTATE_NONE;
    }
    auto consumer = surfaceHandler->GetConsumer();
    static int32_t rotationDegree = (system::GetParameter("const.build.product", "") == "ALT") ||
        (system::GetParameter("const.build.product", "") == "ICL") ?
        FIX_ROTATION_DEGREE_FOR_FOLD_SCREEN : 0;
    int surfaceNodeRotation = node.GetForceHardwareByUser() ? -1 * rotationDegree :
        RSUniRenderUtil::GetRotationFromMatrix(node.GetTotalMatrix());
    auto transformType = GraphicTransformType::GRAPHIC_ROTATE_NONE;
    auto buffer = node.GetRSSurfaceHandler()->GetBuffer();
    if (consumer != nullptr && buffer != nullptr) {
        if (consumer->GetSurfaceBufferTransformType(buffer, &transformType) != GSERROR_OK) {
            RS_LOGE("RSUniRenderUtil::GetLayerTransform GetSurfaceBufferTransformType failed");
        }
    }
    int consumerTransform = RSBaseRenderUtil::RotateEnumToInt(RSBaseRenderUtil::GetRotateTransform(transformType));
    GraphicTransformType consumerFlip = RSBaseRenderUtil::GetFlipTransform(transformType);
    int totalRotation = (RSBaseRenderUtil::RotateEnumToInt(screenInfo.rotation) +
        surfaceNodeRotation + consumerTransform) % 360;
    GraphicTransformType rotateEnum = RSBaseRenderUtil::RotateEnumToInt(totalRotation, consumerFlip);
    return rotateEnum;
}
 
void RSUniRenderUtil::LayerCrop(RSSurfaceRenderNode& node, const ScreenInfo& screenInfo)
{
    auto dstRect = node.GetDstRect();
    auto srcRect = node.GetSrcRect();
    auto originSrcRect = srcRect;
 
    RectI dstRectI(dstRect.left_, dstRect.top_, dstRect.width_, dstRect.height_);
    int32_t screenWidth = static_cast<int32_t>(screenInfo.phyWidth);
    int32_t screenHeight = static_cast<int32_t>(screenInfo.phyHeight);
    RectI screenRectI(0, 0, screenWidth, screenHeight);
    RectI resDstRect = dstRectI.IntersectRect(screenRectI);
    if (resDstRect == dstRectI) {
        return;
    }
    if (node.GetForceHardware()) {
        node.SetDstRect(resDstRect);
        return;
    }
    dstRect = {resDstRect.left_, resDstRect.top_, resDstRect.width_, resDstRect.height_};
    srcRect.left_ = resDstRect.IsEmpty() ? 0 : std::ceil((resDstRect.left_ - dstRectI.left_) *
        originSrcRect.width_ / dstRectI.width_);
    srcRect.top_ = resDstRect.IsEmpty() ? 0 : std::ceil((resDstRect.top_ - dstRectI.top_) *
        originSrcRect.height_ / dstRectI.height_);
    srcRect.width_ = dstRectI.IsEmpty() ? 0 : originSrcRect.width_ * resDstRect.width_ / dstRectI.width_;
    srcRect.height_ = dstRectI.IsEmpty() ? 0 : originSrcRect.height_ * resDstRect.height_ / dstRectI.height_;
    node.SetDstRect(dstRect);
    node.SetSrcRect(srcRect);
}
 
void RSUniRenderUtil::LayerScaleDown(RSSurfaceRenderNode& node)
{
    const auto& buffer = node.GetRSSurfaceHandler()->GetBuffer();
    const auto& surface = node.GetRSSurfaceHandler()->GetConsumer();
    if (buffer == nullptr || surface == nullptr) {
        return;
    }
    constexpr uint32_t FLAT_ANGLE = 180;
    auto dstRect = node.GetDstRect();
    auto srcRect = node.GetSrcRect();

    uint32_t newWidth = static_cast<uint32_t>(srcRect.width_);
    uint32_t newHeight = static_cast<uint32_t>(srcRect.height_);
    uint32_t dstWidth = static_cast<uint32_t>(dstRect.width_);
    uint32_t dstHeight = static_cast<uint32_t>(dstRect.height_);

    // If surfaceRotation is not a multiple of 180, need to change the correspondence between width & height.
    // ScreenRotation has been processed in SetLayerSize, and do not change the width & height correspondence.
    int surfaceRotation = RSUniRenderUtil::GetRotationFromMatrix(node.GetTotalMatrix()) +
        RSBaseRenderUtil::RotateEnumToInt(RSBaseRenderUtil::GetRotateTransform(surface->GetTransform()));
    if (surfaceRotation % FLAT_ANGLE != 0) {
        std::swap(dstWidth, dstHeight);
    }

    uint32_t newWidthDstHeight = newWidth * dstHeight;
    uint32_t newHeightDstWidth = newHeight * dstWidth;

    if (newWidthDstHeight > newHeightDstWidth) {
        // too wide
        newWidth = dstWidth * newHeight / dstHeight;
    } else if (newWidthDstHeight < newHeightDstWidth) {
        // too tall
        newHeight = dstHeight * newWidth / dstWidth;
    } else {
        return;
    }

    uint32_t currentWidth = static_cast<uint32_t>(srcRect.width_);
    uint32_t currentHeight = static_cast<uint32_t>(srcRect.height_);

    if (newWidth < currentWidth) {
        // the crop is too wide
        uint32_t dw = currentWidth - newWidth;
        auto halfdw = dw / 2;
        srcRect.left_ += static_cast<int32_t>(halfdw);
        srcRect.width_ = static_cast<int32_t>(newWidth);
    } else {
        // thr crop is too tall
        uint32_t dh = currentHeight - newHeight;
        auto halfdh = dh / 2;
        srcRect.top_ += static_cast<int32_t>(halfdh);
        srcRect.height_ = static_cast<int32_t>(newHeight);
    }
    node.SetSrcRect(srcRect);
}

void RSUniRenderUtil::LayerScaleFit(RSSurfaceRenderNode& node)
{
    const auto& buffer = node.GetRSSurfaceHandler()->GetBuffer();
    const auto& surface = node.GetRSSurfaceHandler()->GetConsumer();
    if (buffer == nullptr || surface == nullptr) {
        return;
    }
    constexpr uint32_t FLAT_ANGLE = 180;
    auto dstRect = node.GetDstRect();
    auto srcRect = node.GetSrcRect();

    // If surfaceRotation is not a multiple of 180, need to change the correspondence between width & height.
    // ScreenRotation has been processed in SetLayerSize, and do not change the width & height correspondence.
    int surfaceRotation = RSUniRenderUtil::GetRotationFromMatrix(node.GetTotalMatrix()) +
        RSBaseRenderUtil::RotateEnumToInt(RSBaseRenderUtil::GetRotateTransform(surface->GetTransform()));
    if (surfaceRotation % FLAT_ANGLE != 0) {
        std::swap(srcRect.width_, srcRect.height_);
    }

    uint32_t newWidth = static_cast<uint32_t>(srcRect.width_);
    uint32_t newHeight = static_cast<uint32_t>(srcRect.height_);
    uint32_t dstWidth = static_cast<uint32_t>(dstRect.width_);
    uint32_t dstHeight = static_cast<uint32_t>(dstRect.height_);
    
    uint32_t newWidthDstHeight = newWidth * dstHeight;
    uint32_t newHeightDstWidth = newHeight * dstWidth;

    if (newWidthDstHeight > newHeightDstWidth) {
        newHeight = newHeight * dstWidth / newWidth;
        newWidth = dstWidth;
    } else if (newWidthDstHeight < newHeightDstWidth) {
        newWidth = newWidth * dstHeight / newHeight;
        newHeight = dstHeight;
    } else {
        newHeight = dstHeight;
        newWidth = dstWidth;
    }

    if (newWidth < dstWidth) {
        uint32_t dw = dstWidth - newWidth;
        auto halfdw = dw / 2;
        dstRect.left_ += static_cast<int32_t>(halfdw);
    } else if (newHeight < dstHeight) {
        uint32_t dh = dstHeight - newHeight;
        auto halfdh = dh / 2;
        dstRect.top_ += static_cast<int32_t>(halfdh);
    }
    dstRect.height_ = static_cast<int32_t>(newHeight);
    dstRect.width_ = static_cast<int32_t>(newWidth);
    node.SetDstRect(dstRect);

    RS_LOGD("RsDebug RSUniRenderUtil::LayerScaleFit layer has been scalefit dst[%{public}d %{public}d"
        " %{public}d %{public}d] src[%{public}d %{public}d %{public}d %{public}d]",
        dstRect.left_, dstRect.top_, dstRect.width_, dstRect.height_, srcRect.left_,
        srcRect.top_, srcRect.width_, srcRect.height_);
}

void RSUniRenderUtil::OptimizedFlushAndSubmit(std::shared_ptr<Drawing::Surface>& surface,
    Drawing::GPUContext* const grContext, bool optFenceWait)
{
    if (!surface || !grContext) {
        RS_LOGE("RSUniRenderUtil::OptimizedFlushAndSubmit cacheSurface or grContext are nullptr");
        return;
    }
    RS_TRACE_NAME_FMT("Render surface flush and submit");
#ifdef RS_ENABLE_VK
    if ((RSSystemProperties::GetGpuApiType() == GpuApiType::VULKAN ||
        RSSystemProperties::GetGpuApiType() == GpuApiType::DDGR) && optFenceWait) {
        auto& vkContext = RsVulkanContext::GetSingleton().GetRsVulkanInterface();

        VkExportSemaphoreCreateInfo exportSemaphoreCreateInfo;
        exportSemaphoreCreateInfo.sType = VK_STRUCTURE_TYPE_EXPORT_SEMAPHORE_CREATE_INFO;
        exportSemaphoreCreateInfo.pNext = nullptr;
        exportSemaphoreCreateInfo.handleTypes = VK_EXTERNAL_SEMAPHORE_HANDLE_TYPE_SYNC_FD_BIT;

        VkSemaphoreCreateInfo semaphoreInfo;
        semaphoreInfo.sType = VK_STRUCTURE_TYPE_SEMAPHORE_CREATE_INFO;
        semaphoreInfo.pNext = &exportSemaphoreCreateInfo;
        semaphoreInfo.flags = 0;
        VkSemaphore semaphore;
        vkContext.vkCreateSemaphore(vkContext.GetDevice(), &semaphoreInfo, nullptr, &semaphore);
        GrBackendSemaphore backendSemaphore;
        backendSemaphore.initVulkan(semaphore);

        DestroySemaphoreInfo* destroyInfo =
            new DestroySemaphoreInfo(vkContext.vkDestroySemaphore, vkContext.GetDevice(), semaphore);

        Drawing::FlushInfo drawingFlushInfo;
        drawingFlushInfo.backendSurfaceAccess = true;
        drawingFlushInfo.numSemaphores = 1;
        drawingFlushInfo.backendSemaphore = static_cast<void*>(&backendSemaphore);
        drawingFlushInfo.finishedProc = [](void *context) {
            DestroySemaphoreInfo::DestroySemaphore(context);
        };
        drawingFlushInfo.finishedContext = destroyInfo;
        surface->Flush(&drawingFlushInfo);
        grContext->Submit();
        DestroySemaphoreInfo::DestroySemaphore(destroyInfo);
    } else {
        surface->FlushAndSubmit(true);
    }
#else
    surface->FlushAndSubmit(true);
#endif
}

void RSUniRenderUtil::AccumulateMatrixAndAlpha(std::shared_ptr<RSSurfaceRenderNode>& hwcNode,
    Drawing::Matrix& matrix, float& alpha)
{
    if (hwcNode == nullptr) {
        return;
    }
    const auto& property = hwcNode->GetRenderProperties();
    alpha = property.GetAlpha();
    matrix = property.GetBoundsGeometry()->GetMatrix();
    auto parent = hwcNode->GetParent().lock();
    while (parent && parent->GetType() != RSRenderNodeType::DISPLAY_NODE) {
        const auto& curProperty = parent->GetRenderProperties();
        alpha *= curProperty.GetAlpha();
        matrix.PostConcat(curProperty.GetBoundsGeometry()->GetMatrix());
        if (ROSEN_EQ(alpha, 1.f)) {
            parent->DisableDrawingCacheByHwcNode();
        }
        parent = parent->GetParent().lock();
    }
    if (!parent) {
        return;
    }
    const auto& parentProperty = parent->GetRenderProperties();
    alpha *= parentProperty.GetAlpha();
    matrix.PostConcat(parentProperty.GetBoundsGeometry()->GetMatrix());
}

SecRectInfo RSUniRenderUtil::GenerateSecRectInfoFromNode(RSRenderNode& node, RectI rect)
{
    SecRectInfo uiExtensionRectInfo;
    uiExtensionRectInfo.relativeCoords = rect;
    uiExtensionRectInfo.scale = node.GetRenderProperties().GetScale();
    return uiExtensionRectInfo;
}

SecSurfaceInfo RSUniRenderUtil::GenerateSecSurfaceInfoFromNode(
    NodeId uiExtensionId, NodeId hostId, SecRectInfo uiExtensionRectInfo)
{
    SecSurfaceInfo secSurfaceInfo;
    secSurfaceInfo.uiExtensionRectInfo = uiExtensionRectInfo;
    secSurfaceInfo.uiExtensionPid = ExtractPid(uiExtensionId);
    secSurfaceInfo.hostPid = ExtractPid(hostId);
    secSurfaceInfo.uiExtensionNodeId = uiExtensionId;
    secSurfaceInfo.hostNodeId = hostId;
    return secSurfaceInfo;
}

void RSUniRenderUtil::UIExtensionFindAndTraverseAncestor(
    const RSRenderNodeMap& nodeMap, UIExtensionCallbackData& callbackData)
{
    const auto& secUIExtensionNodes = RSSurfaceRenderNode::GetSecUIExtensionNodes();
    for (auto it = secUIExtensionNodes.begin(); it != secUIExtensionNodes.end(); ++it) {
        currentUIExtensionIndex_ = -1;
        // only traverse host node one time, even if it has multiple uiextension children.
        if (callbackData.find(it->second) != callbackData.end()) {
            continue;
        }
        auto hostNode = RSBaseRenderNode::ReinterpretCast<RSSurfaceRenderNode>(nodeMap.GetRenderNode(it->second));
        if (!hostNode || !hostNode->GetSortedChildren()) {
            RS_LOGE("RSUniRenderUtil::UIExtensionFindAndTraverseAncestor failed to get host node or its children.");
            return;
        }
        for (const auto& child : *hostNode->GetSortedChildren()) {
            TraverseAndCollectUIExtensionInfo(child, Drawing::Matrix(), hostNode->GetId(), callbackData);
        }
    }
}

void RSUniRenderUtil::TraverseAndCollectUIExtensionInfo(std::shared_ptr<RSRenderNode> node,
    Drawing::Matrix parentMatrix, NodeId hostId, UIExtensionCallbackData& callbackData)
{
    if (!node) {
        return;
    }
    // update position relative to host app window node.
    std::optional<Drawing::Point> offset;
    auto parent = node->GetParent().lock();
    if (parent && !(node->IsInstanceOf<RSSurfaceRenderNode>())) {
        const auto& parentRenderProperties = parent->GetRenderProperties();
        offset = Drawing::Point { parentRenderProperties.GetFrameOffsetX(), parentRenderProperties.GetFrameOffsetY() };
    }
    const auto& nodeRenderProperties = node->GetRenderProperties();
    RSObjAbsGeometry boundsGeo = nodeRenderProperties.GetBoundsGeometry() == nullptr ?
        RSObjAbsGeometry() : *(nodeRenderProperties.GetBoundsGeometry());
    boundsGeo.UpdateMatrix(&parentMatrix, offset);
    auto rect = boundsGeo.MapAbsRect(node->GetSelfDrawRect().JoinRect(node->GetChildrenRect().ConvertTo<float>()));
    // if node is UIExtension type, update its own info, and skip its children.
    if (auto surfaceNode = RSBaseRenderNode::ReinterpretCast<RSSurfaceRenderNode>(node)) {
        if (surfaceNode->IsUIExtension()) {
            currentUIExtensionIndex_++;
            // if host node is not recorded in callbackData, insert it.
            auto [iter, inserted] = callbackData.insert(std::pair(hostId, std::vector<SecSurfaceInfo>{}));
            if (iter != callbackData.end()) {
                iter->second.push_back(GenerateSecSurfaceInfoFromNode(
                    surfaceNode->GetId(), hostId, GenerateSecRectInfoFromNode(*surfaceNode, rect)));
            }
            if (surfaceNode->ChildrenHasUIExtension()) {
                RS_LOGW("RSUniRenderUtil::TraverseAndCollectUIExtensionInfo UIExtension node [%{public}" PRIu64 "]"
                    " has children UIExtension, not surpported!", surfaceNode->GetId());
            }
            return;
        }
    }
    // if the node is traversed after a UIExtension, collect it and skip its children (except it has UIExtension child.)
    auto iter = callbackData.find(hostId);
    if (iter != callbackData.end() && currentUIExtensionIndex_ != -1 &&
        currentUIExtensionIndex_ < static_cast<int>((iter->second).size())) {
        (iter->second)[currentUIExtensionIndex_].upperNodes.push_back(GenerateSecRectInfoFromNode(*node, rect));
        if (!node->ChildrenHasUIExtension()) {
            return;
        }
    }
    // continue to traverse.
    for (const auto& child : *node->GetSortedChildren()) {
        TraverseAndCollectUIExtensionInfo(child, boundsGeo.GetAbsMatrix(), hostId, callbackData);
    }
}

void RSUniRenderUtil::ProcessCacheImage(RSPaintFilterCanvas& canvas, Drawing::Image& cacheImageProcessed)
{
    Drawing::Brush brush;
    brush.SetAntiAlias(true);
    canvas.AttachBrush(brush);
    // Be cautious when changing FilterMode and MipmapMode that may affect clarity
    auto sampling = Drawing::SamplingOptions(Drawing::FilterMode::LINEAR, Drawing::MipmapMode::NEAREST);
    canvas.DrawImage(cacheImageProcessed, 0, 0, sampling);
    canvas.DetachBrush();
}
} // namespace Rosen
} // namespace OHOS
