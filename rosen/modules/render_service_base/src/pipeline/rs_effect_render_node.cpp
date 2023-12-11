/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "pipeline/rs_effect_render_node.h"

#include "memory/rs_memory_track.h"

#include "common/rs_obj_abs_geometry.h"
#include "property/rs_properties_painter.h"
#include "visitor/rs_node_visitor.h"
#include "platform/common/rs_log.h"

namespace OHOS {
namespace Rosen {
RSEffectRenderNode::RSEffectRenderNode(NodeId id, const std::weak_ptr<RSContext>& context) : RSRenderNode(id, context)
{
    MemoryInfo info = {sizeof(*this), ExtractPid(id), id, MEMORY_TYPE::MEM_RENDER_NODE};
    MemoryTrack::Instance().AddNodeRecord(id, info);
}

RSEffectRenderNode::~RSEffectRenderNode()
{
    MemoryTrack::Instance().RemoveNodeRecord(GetId());
}

void RSEffectRenderNode::Prepare(const std::shared_ptr<RSNodeVisitor>& visitor)
{
    if (!visitor) {
        return;
    }
    visitor->PrepareEffectRenderNode(*this);
}

void RSEffectRenderNode::Process(const std::shared_ptr<RSNodeVisitor>& visitor)
{
    if (!visitor) {
        return;
    }
    RSRenderNode::RenderTraceDebug();
    visitor->ProcessEffectRenderNode(*this);
}

void RSEffectRenderNode::ProcessRenderBeforeChildren(RSPaintFilterCanvas& canvas)
{
    RSRenderNode::ProcessTransitionBeforeChildren(canvas);
    auto& properties = GetRenderProperties();
    // Disable effect region if either of the following conditions is met:
    // 1. Effect region is null or empty (except when bg Image is set)
    // 2. Background filter is null
    // 3. Canvas is offscreen
    if ((!effectRegion_.has_value() && properties.GetBgImage() == nullptr) ||
        properties.GetBackgroundFilter() == nullptr ||
        canvas.GetCacheType() == RSPaintFilterCanvas::CacheType::OFFSCREEN) {
        canvas.SetEffectData(nullptr);
        return;
    }
#ifndef USE_ROSEN_DRAWING
    auto surface = canvas.GetSurface();
    if (!surface) {
        return;
    }
    auto absRect = GetRenderProperties().GetBoundsGeometry()->GetAbsRect();
    auto boundsRect = GetRenderProperties().GetBoundsRect();

    if (properties.GetBgImage() == nullptr) {
        // EffectRenderNode w/o background image
        RSPropertiesPainter::DrawBackgroundEffect(properties, canvas, effectRegion_.value());
    } else if (auto& filterCacheManager = properties.GetFilterCacheManager(false);
        filterCacheManager != nullptr && filterCacheManager->IsCacheValid()) {
        // EffectRenderNode w/ background image, cache is valid
        RSPropertiesPainter::DrawBackgroundEffect(properties, canvas,
            SkIRect::MakeXYWH(
                boundsRect.GetLeft(), boundsRect.GetTop(), boundsRect.GetWidth(), boundsRect.GetHeight()));
    } else {
        // EffectRenderNode w/ background image, cache is invalid
        auto offscreenSurface = surface->makeSurface(absRect.GetWidth(), absRect.GetHeight());
        auto offscreenCanvas = std::make_shared<RSPaintFilterCanvas>(offscreenSurface.get());
        auto matrix = canvas.getTotalMatrix();
        matrix.setTranslateX(0);
        matrix.setTranslateY(0);
        offscreenCanvas->setMatrix(matrix);
        // draw background onto offscreen canvas
        RSPropertiesPainter::DrawBackground(properties, *offscreenCanvas);
        // generate effect data
        RSPropertiesPainter::DrawBackgroundEffect(
            properties, *offscreenCanvas, SkIRect::MakeWH(boundsRect.GetWidth(), boundsRect.GetHeight()));
        // extract effect data from offscreen canvas and set to canvas
        canvas.SetEffectData(offscreenCanvas->GetEffectData());
    }
#else
    // PLANNING: add drawing implementation
#endif
}

RectI RSEffectRenderNode::GetFilterRect() const
{
    if (GetRenderProperties().GetBgImage()) {
        return RSRenderNode::GetFilterRect();
    }
    if (!effectRegion_.has_value()) {
        ROSEN_LOGE("RSEffectRenderNode::GetFilterRect: effectRegion has no value");
        return {};
    }
#ifndef USE_ROSEN_DRAWING
    auto& matrix = GetRenderProperties().GetBoundsGeometry()->GetAbsMatrix();
    // re-map local rect to absolute rect
    auto bounds = matrix.mapRect(SkRect::Make(*effectRegion_)).roundOut();
    return { bounds.x(), bounds.y(), bounds.width(), bounds.height() };
#else
    // PLANNING: add drawing implementation
    return {};
#endif
}


#ifndef USE_ROSEN_DRAWING
std::optional<SkPath> RSEffectRenderNode::InitializeEffectRegion() const
{
    // Only need to collect effect region if the background image is null
    return (GetRenderProperties().GetBgImage()) ? std::nullopt : std::make_optional<SkPath>();
}
#else
std::optional<Drawing::Path> RSEffectRenderNode::InitializeEffectRegion() const
{
    return (GetRenderProperties().GetBgImage()) ? std::nullopt : std::make_optional<Drawing::Path>();
}
#endif

#ifndef USE_ROSEN_DRAWING
void RSEffectRenderNode::SetEffectRegion(const std::optional<SkPath>& region)
#else
void RSEffectRenderNode::SetEffectRegion(const std::optional<Drawing::Path>& region)
#endif
{
    if (!region.has_value() || GetRenderProperties().GetBgImage()) {
        effectRegion_.reset();
        ROSEN_LOGD("RSEffectRenderNode::SetEffectRegion: no need to collect effect region.");
        return;
    }
#ifndef USE_ROSEN_DRAWING
    const auto& geoPtr = GetRenderProperties().GetBoundsGeometry();
    const auto& matrix = geoPtr->GetAbsMatrix();
    const auto& absRect = geoPtr->GetAbsRect();
    // intersect effect region with node bounds
    auto rect = region->getBounds();
    if (!rect.intersect(
        SkRect::MakeLTRB(absRect.GetLeft(), absRect.GetTop(), absRect.GetRight(), absRect.GetBottom()))) {
        effectRegion_.reset();
        ROSEN_LOGD("RSEffectRenderNode::SetEffectRegion: no valid effect region.");
        return;
    }

    // Map absolute rect to local matrix
    SkMatrix revertMatrix;
    if (!matrix.invert(&revertMatrix)) {
        effectRegion_.reset();
        ROSEN_LOGD("RSEffectRenderNode::SetEffectRegion: get invert matrix failed.");
        return;
    }
    auto prevEffectRegion = std::move(effectRegion_);
    effectRegion_ = revertMatrix.mapRect(rect).roundOut();

    // Update cache state if filter region has changed
    auto& manager = GetRenderProperties().GetFilterCacheManager(false);
    if (!manager || !manager->IsCacheValid()) {
        ROSEN_LOGD("RSEffectRenderNode::SetEffectRegion: CacheManager is null or invalid");
        return;
    }
    if (prevEffectRegion.has_value() && !prevEffectRegion->contains(*effectRegion_)) {
        manager->UpdateCacheStateWithFilterRegion();
    }
#else
    // PLANNING: add drawing implementation
#endif
}

void RSEffectRenderNode::UpdateFilterCacheManagerWithCacheRegion(
    RSDirtyRegionManager& dirtyManager, const std::optional<RectI>& clipRect) const
{
    // No need to invalidate cache if background image is not null
    if (GetRenderProperties().GetBgImage()) {
        return;
    }
    RSRenderNode::UpdateFilterCacheManagerWithCacheRegion(dirtyManager, clipRect);
}

void RSEffectRenderNode::UpdateFilterCacheWithDirty(RSDirtyRegionManager& dirtyManager, bool isForeground) const
{
    // No need to invalidate cache if background image is not null
    if (GetRenderProperties().GetBgImage()) {
        return;
    }
    RSRenderNode::UpdateFilterCacheWithDirty(dirtyManager, isForeground);
}
} // namespace Rosen
} // namespace OHOS
