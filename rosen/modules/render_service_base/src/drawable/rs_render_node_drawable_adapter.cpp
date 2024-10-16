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

#include "drawable/rs_render_node_drawable_adapter.h"

#include "skia_adapter/skia_canvas.h"
#include "src/core/SkCanvasPriv.h"

#include "common/rs_optional_trace.h"
#include "drawable/rs_misc_drawable.h"
#include "drawable/rs_render_node_shadow_drawable.h"
#include "params/rs_canvas_drawing_render_params.h"
#include "params/rs_display_render_params.h"
#include "params/rs_effect_render_params.h"
#include "params/rs_surface_render_params.h"
#include "pipeline/rs_context.h"
#include "pipeline/rs_render_node.h"
#include "pipeline/rs_render_node_gc.h"
#include "platform/common/rs_log.h"

namespace OHOS::Rosen::DrawableV2 {
std::map<RSRenderNodeType, RSRenderNodeDrawableAdapter::Generator> RSRenderNodeDrawableAdapter::GeneratorMap;
std::map<NodeId, RSRenderNodeDrawableAdapter::WeakPtr> RSRenderNodeDrawableAdapter::RenderNodeDrawableCache_;
RSRenderNodeDrawableAdapter::DrawableVec RSRenderNodeDrawableAdapter::toClearDrawableVec_;
RSRenderNodeDrawableAdapter::CmdListVec RSRenderNodeDrawableAdapter::toClearCmdListVec_;
#ifdef ROSEN_OHOS
thread_local RSRenderNodeDrawableAdapter* RSRenderNodeDrawableAdapter::curDrawingCacheRoot_ = nullptr;
#else
RSRenderNodeDrawableAdapter* RSRenderNodeDrawableAdapter::curDrawingCacheRoot_ = nullptr;
#endif

RSRenderNodeDrawableAdapter::RSRenderNodeDrawableAdapter(std::shared_ptr<const RSRenderNode>&& node)
    : nodeType_(node ? node->GetType() : RSRenderNodeType::UNKNOW), renderNode_(std::move(node)) {}

RSRenderNodeDrawableAdapter::~RSRenderNodeDrawableAdapter() = default;

RSRenderNodeDrawableAdapter::SharedPtr RSRenderNodeDrawableAdapter::GetDrawableById(NodeId id)
{
    std::lock_guard<std::mutex> lock(cacheMapMutex_);
    if (const auto cacheIt = RenderNodeDrawableCache_.find(id); cacheIt != RenderNodeDrawableCache_.end()) {
        if (const auto ptr = cacheIt->second.lock()) {
            return ptr;
        }
    }
    return nullptr;
}

RSRenderNodeDrawableAdapter::SharedPtr RSRenderNodeDrawableAdapter::OnGenerate(
    const std::shared_ptr<const RSRenderNode>& node)
{
    if (node == nullptr) {
        return nullptr;
    }
    if (node->renderDrawable_ != nullptr) {
        return node->renderDrawable_;
    }
    static const auto Destructor = [](RSRenderNodeDrawableAdapter* ptr) {
        RemoveDrawableFromCache(ptr->nodeId_); // Remove from cache before deleting
        RSRenderNodeGC::DrawableDestructor(ptr);
    };
    auto id = node->GetId();
    // Try to get a cached drawable if it exists.
    {
        std::lock_guard<std::mutex> lock(cacheMapMutex_);
        if (const auto cacheIt = RenderNodeDrawableCache_.find(id); cacheIt != RenderNodeDrawableCache_.end()) {
            if (const auto ptr = cacheIt->second.lock()) {
                ROSEN_LOGE("RSRenderNodeDrawableAdapter::OnGenerate, node id in Cache is %{public}" PRIu64, id);
                return ptr;
            } else {
                RenderNodeDrawableCache_.erase(cacheIt);
            }
        }
    }
    // If we don't have a cached drawable, try to generate a new one and cache it.
    const auto it = GeneratorMap.find(node->GetType());
    if (it == GeneratorMap.end()) {
        ROSEN_LOGE("RSRenderNodeDrawableAdapter::OnGenerate, node type %d is not supported", node->GetType());
        return nullptr;
    }
    auto ptr = it->second(node);
    auto sharedPtr = std::shared_ptr<RSRenderNodeDrawableAdapter>(ptr, Destructor);
    node->renderDrawable_ = sharedPtr;
    sharedPtr->nodeId_ = id;
    InitRenderParams(node, sharedPtr);

    {
        std::lock_guard<std::mutex> lock(cacheMapMutex_);
        RenderNodeDrawableCache_.emplace(id, sharedPtr);
    }
    return sharedPtr;
}

void RSRenderNodeDrawableAdapter::InitRenderParams(const std::shared_ptr<const RSRenderNode>& node,
                                            std::shared_ptr<RSRenderNodeDrawableAdapter>& sharedPtr)
{
    switch (node->GetType()) {
        case RSRenderNodeType::SURFACE_NODE:
            sharedPtr->renderParams_ = std::make_unique<RSSurfaceRenderParams>(sharedPtr->nodeId_);
            sharedPtr->uifirstRenderParams_ = std::make_unique<RSSurfaceRenderParams>(sharedPtr->nodeId_);
            break;
        case RSRenderNodeType::DISPLAY_NODE:
            sharedPtr->renderParams_ = std::make_unique<RSDisplayRenderParams>(sharedPtr->nodeId_);
            sharedPtr->uifirstRenderParams_ = std::make_unique<RSDisplayRenderParams>(sharedPtr->nodeId_);
            break;
        case RSRenderNodeType::EFFECT_NODE:
            sharedPtr->renderParams_ = std::make_unique<RSEffectRenderParams>(sharedPtr->nodeId_);
            sharedPtr->uifirstRenderParams_ = std::make_unique<RSEffectRenderParams>(sharedPtr->nodeId_);
            break;
        case RSRenderNodeType::CANVAS_DRAWING_NODE:
            sharedPtr->renderParams_ = std::make_unique<RSCanvasDrawingRenderParams>(sharedPtr->nodeId_);
            sharedPtr->uifirstRenderParams_ = std::make_unique<RSCanvasDrawingRenderParams>(sharedPtr->nodeId_);
            break;
        default:
            sharedPtr->renderParams_ = std::make_unique<RSRenderParams>(sharedPtr->nodeId_);
            sharedPtr->uifirstRenderParams_ = std::make_unique<RSRenderParams>(sharedPtr->nodeId_);
            break;
    }
}

RSRenderNodeDrawableAdapter::SharedPtr RSRenderNodeDrawableAdapter::OnGenerateShadowDrawable(
    const std::shared_ptr<const RSRenderNode>& node, const std::shared_ptr<RSRenderNodeDrawableAdapter>& drawable)
{
    static std::map<NodeId, RSRenderNodeDrawableAdapter::WeakPtr> shadowDrawableCache;
    static std::mutex shadowCacheMapMutex;
    static const auto Destructor = [](RSRenderNodeDrawableAdapter* ptr) {
        {
            std::lock_guard<std::mutex> lock(shadowCacheMapMutex);
            shadowDrawableCache.erase(ptr->nodeId_); // Remove from cache before deleting
        }
        RSRenderNodeGC::DrawableDestructor(ptr);
    };

    if (node == nullptr) {
        return nullptr;
    }
    auto id = node->GetId();
    // Try to get a cached drawable if it exists.
    {
        std::lock_guard<std::mutex> lock(shadowCacheMapMutex);
        if (const auto cacheIt = shadowDrawableCache.find(id); cacheIt != shadowDrawableCache.end()) {
            if (const auto ptr = cacheIt->second.lock()) {
                return ptr;
            } else {
                shadowDrawableCache.erase(cacheIt);
            }
        }
    }

    auto ptr = new RSRenderNodeShadowDrawable(node, drawable);
    auto sharedPtr = std::shared_ptr<RSRenderNodeDrawableAdapter>(ptr, Destructor);
    {
        std::lock_guard<std::mutex> lock(shadowCacheMapMutex);
        shadowDrawableCache.emplace(id, sharedPtr);
    }
    return sharedPtr;
}

void RSRenderNodeDrawableAdapter::DrawRangeImpl(
    Drawing::Canvas& canvas, const Drawing::Rect& rect, int8_t start, int8_t end) const
{
    if (drawCmdList_.empty() || start < 0 || end < 0 || start > end) {
        return;
    }

    if (end > static_cast<int8_t>(drawCmdList_.size())) {
        ROSEN_LOGE("RSRenderNodeDrawableAdapter::DrawRangeImpl, end is invalid");
        return;
    }

    if (UNLIKELY(skipType_ != SkipType::NONE)) {
        auto skipIndex_ = GetSkipIndex();
        if (start <= skipIndex_ && end > skipIndex_) {
            // skip index is in the range
            for (auto i = start; i < skipIndex_; i++) {
                drawCmdList_[i](&canvas, &rect);
            }
            for (auto i = skipIndex_ + 1; i < end; i++) {
                drawCmdList_[i](&canvas, &rect);
            }
            return;
        }
        // skip index is not in the range, fall back to normal drawing
    }

    for (auto i = start; i < end; i++) {
        drawCmdList_[i](&canvas, &rect);
    }
}

void RSRenderNodeDrawableAdapter::DrawImpl(Drawing::Canvas& canvas, const Drawing::Rect& rect, int8_t index) const
{
    if (drawCmdList_.empty() || index < 0 || index >= static_cast<int8_t>(drawCmdList_.size())) {
        return;
    }

    if (UNLIKELY(skipType_ != SkipType::NONE)) {
        auto skipIndex_ = GetSkipIndex();
        if (index == skipIndex_) {
            return;
        }
    }

    drawCmdList_[index](&canvas, &rect);
}

void RSRenderNodeDrawableAdapter::DrawBackground(Drawing::Canvas& canvas, const Drawing::Rect& rect) const
{
    DrawRangeImpl(canvas, rect, 0, drawCmdIndex_.backgroundEndIndex_);
}

void RSRenderNodeDrawableAdapter::DrawContent(Drawing::Canvas& canvas, const Drawing::Rect& rect) const
{
    if (drawCmdList_.empty()) {
        return;
    }

    auto index = drawCmdIndex_.contentIndex_;
    if (index == -1) {
        return;
    }
    drawCmdList_[index](&canvas, &rect);
}

void RSRenderNodeDrawableAdapter::DrawChildren(Drawing::Canvas& canvas, const Drawing::Rect& rect) const
{
    if (drawCmdList_.empty()) {
        return;
    }

    auto index = drawCmdIndex_.childrenIndex_;
    if (index == -1) {
        return;
    }
    drawCmdList_[index](&canvas, &rect);
}

void RSRenderNodeDrawableAdapter::DrawUifirstContentChildren(Drawing::Canvas& canvas, const Drawing::Rect& rect) const
{
    if (uifirstDrawCmdList_.empty()) {
        return;
    }

    const auto& drawCmdList = uifirstDrawCmdList_;
    auto contentIdx = uifirstDrawCmdIndex_.contentIndex_;
    auto childrenIdx = uifirstDrawCmdIndex_.childrenIndex_;
    if (contentIdx != -1) {
        drawCmdList[contentIdx](&canvas, &rect);
    }
    if (childrenIdx != -1) {
        drawCmdList[childrenIdx](&canvas, &rect);
    }
}

void RSRenderNodeDrawableAdapter::DrawForeground(Drawing::Canvas& canvas, const Drawing::Rect& rect) const
{
    DrawRangeImpl(canvas, rect, drawCmdIndex_.foregroundBeginIndex_, drawCmdIndex_.endIndex_);
}

void RSRenderNodeDrawableAdapter::DrawAll(Drawing::Canvas& canvas, const Drawing::Rect& rect) const
{
    DrawRangeImpl(canvas, rect, 0, drawCmdIndex_.endIndex_);
}

// can only run in sync mode
void RSRenderNodeDrawableAdapter::DumpDrawableTree(int32_t depth, std::string& out, const RSContext& context) const
{
    for (int32_t i = 0; i < depth; ++i) {
        out += "  ";
    }
    auto renderNode = (depth == 0 && nodeId_ == INVALID_NODEID) ? context.GetGlobalRootRenderNode()
                                                        : context.GetNodeMap().GetRenderNode<RSRenderNode>(nodeId_);
    if (renderNode == nullptr) {
        out += "[" + std::to_string(nodeId_) + ": nullptr]\n";
        return;
    }
    RSRenderNode::DumpNodeType(nodeType_, out);
    out += "[" + std::to_string(nodeId_) +  "]";
    renderNode->DumpSubClassNode(out);
    out += ", DrawableVec:[" + DumpDrawableVec(renderNode) + "]";
    if (renderParams_ == nullptr) {
        out += ", StagingParams null";
    } else {
        out += ", " + renderParams_->ToString();
    }

    if (skipType_ != SkipType::NONE) {
        out += ", SkipType:" + std::to_string(static_cast<int>(skipType_));
        out += ", SkipIndex:" + std::to_string(GetSkipIndex());
    }

    out += "\n";

    auto childrenDrawable = std::static_pointer_cast<RSChildrenDrawable>(
        renderNode->drawableVec_[static_cast<int32_t>(RSDrawableSlot::CHILDREN)]);
    if (childrenDrawable) {
        for (const auto& renderNodeDrawable : childrenDrawable->childrenDrawableVec_) {
            renderNodeDrawable->DumpDrawableTree(depth + 1, out, context);
        }
    }
}

// can only run in sync mode
std::string RSRenderNodeDrawableAdapter::DumpDrawableVec(const std::shared_ptr<RSRenderNode>& renderNode) const
{
    if (renderNode == nullptr) {
        return "";
    }
    const auto& drawableVec = renderNode->drawableVec_;
    std::string str;
    for (uint8_t i = 0; i < drawableVec.size(); ++i) {
        if (drawableVec[i]) {
            str += std::to_string(i) + ", ";
        }
    }
    // str has more than 2 chars
    if (str.length() > 2) {
        str.pop_back();
        str.pop_back();
    }

    return str;
}

bool RSRenderNodeDrawableAdapter::QuickReject(Drawing::Canvas& canvas, const RectF& localDrawRect)
{
    auto paintFilterCanvas = static_cast<RSPaintFilterCanvas*>(&canvas);
    if (paintFilterCanvas->IsDirtyRegionStackEmpty() || paintFilterCanvas->GetIsParallelCanvas()) {
        return false;
    }

    Drawing::Rect dst;
    canvas.GetTotalMatrix().MapRect(
        dst, { localDrawRect.GetLeft(), localDrawRect.GetTop(), localDrawRect.GetRight(), localDrawRect.GetBottom() });
    auto originalCanvas = paintFilterCanvas->GetOriginalCanvas();
    if (originalCanvas && !paintFilterCanvas->GetOffscreenDataList().empty()) {
        originalCanvas->GetTotalMatrix().MapRect(dst, dst);
    }
    auto deviceClipRegion = paintFilterCanvas->GetCurDirtyRegion();
    Drawing::Region dstRegion;
    if (!dstRegion.SetRect(dst.RoundOut()) && !dst.IsEmpty()) {
        RS_LOGW("invalid dstDrawRect: %{public}s, RoundOut: %{public}s",
            dst.ToString().c_str(), dst.RoundOut().ToString().c_str());
        RS_OPTIONAL_TRACE_NAME_FMT("invalid dstDrawRect: %s, RoundOut: %s",
            dst.ToString().c_str(), dst.RoundOut().ToString().c_str());
        return false;
    }
    return !(deviceClipRegion.IsIntersects(dstRegion));
}

void RSRenderNodeDrawableAdapter::DrawBackgroundWithoutFilterAndEffect(
    Drawing::Canvas& canvas, const RSRenderParams& params)
{
    if (uifirstDrawCmdList_.empty()) {
        return;
    }

    auto backgroundIndex = drawCmdIndex_.backgroundEndIndex_;
    auto bounds = params.GetBounds();
    auto curCanvas = static_cast<RSPaintFilterCanvas*>(&canvas);
    for (auto index = 0; index < backgroundIndex; ++index) {
        if (index == drawCmdIndex_.shadowIndex_) {
            if (!params.GetShadowRect().IsEmpty()) {
                auto shadowRect = params.GetShadowRect();
                RS_OPTIONAL_TRACE_NAME_FMT("ClipHoleForBlur shadowRect:[%.2f, %.2f, %.2f, %.2f]", shadowRect.GetLeft(),
                    shadowRect.GetTop(), shadowRect.GetWidth(), shadowRect.GetHeight());
                Drawing::AutoCanvasRestore arc(*curCanvas, true);
                auto coreCanvas = curCanvas->GetCanvasData();
                auto skiaCanvas = static_cast<Drawing::SkiaCanvas*>(coreCanvas.get());
                SkCanvasPriv::ResetClip(skiaCanvas->ExportSkCanvas());
                curCanvas->ClipRect(shadowRect);
                curCanvas->Clear(Drawing::Color::COLOR_TRANSPARENT);
                if (curDrawingCacheRoot_ != nullptr) {
                    curDrawingCacheRoot_->filterRects_.emplace_back(curCanvas->GetDeviceClipBounds());
                }
            } else {
                drawCmdList_[index](&canvas, &bounds);
            }
            continue;
        }
        if (index != drawCmdIndex_.useEffectIndex_ || index != drawCmdIndex_.backgroundFilterIndex_) {
            RS_OPTIONAL_TRACE_NAME_FMT(
                "ClipHoleForBlur filterRect:[%.2f, %.2f]", bounds.GetWidth(), bounds.GetHeight());
            Drawing::AutoCanvasRestore arc(*curCanvas, true);
            curCanvas->ClipRect(bounds, Drawing::ClipOp::INTERSECT, false);
            curCanvas->Clear(Drawing::Color::COLOR_TRANSPARENT);
            if (curDrawingCacheRoot_ != nullptr) {
                curDrawingCacheRoot_->filterRects_.emplace_back(curCanvas->GetDeviceClipBounds());
            }
        } else {
            drawCmdList_[index](&canvas, &bounds);
        }
    }
}

void RSRenderNodeDrawableAdapter::CheckShadowRectAndDrawBackground(
    Drawing::Canvas& canvas, const RSRenderParams& params)
{
    // The shadow without shadowRect has drawn in Nodegroup's cache, so we can't draw it again
    if (!params.GetShadowRect().IsEmpty()) {
        DrawBackground(canvas, params.GetBounds());
    } else {
        DrawRangeImpl(
            canvas, params.GetBounds(), drawCmdIndex_.foregroundFilterBeginIndex_, drawCmdIndex_.backgroundEndIndex_);
    }
    if (curDrawingCacheRoot_) {
        curDrawingCacheRoot_->ReduceFilterRectSize(GetCountOfClipHoleForCache(params));
    }
}

void RSRenderNodeDrawableAdapter::DrawBeforeCacheWithForegroundFilter(Drawing::Canvas& canvas,
    const Drawing::Rect& rect) const
{
    DrawRangeImpl(canvas, rect, 0, static_cast<int8_t>(drawCmdIndex_.foregroundFilterBeginIndex_));
}

void RSRenderNodeDrawableAdapter::DrawCacheWithForegroundFilter(Drawing::Canvas& canvas,
    const Drawing::Rect& rect) const
{
    DrawRangeImpl(canvas, rect, drawCmdIndex_.foregroundFilterBeginIndex_,
        drawCmdIndex_.foregroundFilterEndIndex_);
}

void RSRenderNodeDrawableAdapter::DrawAfterCacheWithForegroundFilter(Drawing::Canvas& canvas,
    const Drawing::Rect& rect) const
{
    DrawRangeImpl(canvas, rect, drawCmdIndex_.foregroundFilterEndIndex_,
        drawCmdIndex_.endIndex_);
}

void RSRenderNodeDrawableAdapter::DrawCacheWithProperty(Drawing::Canvas& canvas, const Drawing::Rect& rect) const
{
    DrawRangeImpl(canvas, rect, drawCmdIndex_.renderGroupBeginIndex_,
        drawCmdIndex_.renderGroupEndIndex_);
}

void RSRenderNodeDrawableAdapter::DrawBeforeCacheWithProperty(Drawing::Canvas& canvas, const Drawing::Rect& rect) const
{
    DrawRangeImpl(canvas, rect, 0, static_cast<int8_t>(drawCmdIndex_.renderGroupBeginIndex_));
}

void RSRenderNodeDrawableAdapter::DrawAfterCacheWithProperty(Drawing::Canvas& canvas, const Drawing::Rect& rect) const
{
    DrawRangeImpl(canvas, rect, drawCmdIndex_.renderGroupEndIndex_,
        drawCmdIndex_.endIndex_);
}

bool RSRenderNodeDrawableAdapter::HasFilterOrEffect() const
{
    return drawCmdIndex_.shadowIndex_ != -1 || drawCmdIndex_.backgroundFilterIndex_ != -1 ||
           drawCmdIndex_.useEffectIndex_ != -1;
}

void RSRenderNodeDrawableAdapter::ClearResource()
{
    RS_TRACE_NAME_FMT("ClearResource count drawable %d, cmdList %d",
        toClearDrawableVec_.size(), toClearCmdListVec_.size());
    toClearDrawableVec_.clear();
    toClearCmdListVec_.clear();
}

void RSRenderNodeDrawableAdapter::AddToClearDrawables(DrawableVec &vec)
{
    for (auto &drawable: vec) {
        toClearDrawableVec_.push_back(drawable);
    }
    vec.clear();
}

void RSRenderNodeDrawableAdapter::AddToClearCmdList(CmdListVec &vec)
{
    for (auto &cmdList: vec) {
        toClearCmdListVec_.push_back(cmdList);
    }
    vec.clear();
}

int RSRenderNodeDrawableAdapter::GetCountOfClipHoleForCache(const RSRenderParams& params) const
{
    int count = drawCmdIndex_.shadowIndex_ != -1 && !params.GetShadowRect().IsEmpty() ? 1 : 0;
    count += drawCmdIndex_.shadowIndex_ != -1 ? 1 : 0;
    count += drawCmdIndex_.useEffectIndex_ != -1 ? 1 : 0;
    return count;
}

int8_t RSRenderNodeDrawableAdapter::GetSkipIndex() const
{
    switch (skipType_) {
        case SkipType::SKIP_BACKGROUND_COLOR:
            return drawCmdIndex_.backgroundColorIndex_;
        case SkipType::SKIP_SHADOW:
            return drawCmdIndex_.shadowIndex_;
        case SkipType::NONE:
        default:
            return -1;
    }
}

void RSRenderNodeDrawableAdapter::RemoveDrawableFromCache(const NodeId nodeId)
{
    std::lock_guard<std::mutex> lock(cacheMapMutex_);
    RenderNodeDrawableCache_.erase(nodeId);
}

void RSRenderNodeDrawableAdapter::RegisterClearSurfaceFunc(ClearSurfaceTask task)
{
    clearSurfaceTask_ = task;
}

void RSRenderNodeDrawableAdapter::ResetClearSurfaceFunc()
{
    clearSurfaceTask_ = nullptr;
}

void RSRenderNodeDrawableAdapter::TryClearSurfaceOnSync()
{
    if (!clearSurfaceTask_) {
        return;
    }
    clearSurfaceTask_();
}

void RSRenderNodeDrawableAdapter::SetSkipCacheLayer(bool hasSkipCacheLayer)
{
    hasSkipCacheLayer_ = hasSkipCacheLayer;
}

void RSRenderNodeDrawableAdapter::ApplyForegroundColorIfNeed(Drawing::Canvas& canvas, const Drawing::Rect& rect) const
{
    if (drawCmdIndex_.envForeGroundColorIndex_ != -1) {
        drawCmdList_[drawCmdIndex_.envForeGroundColorIndex_](&canvas, &rect);
    }
}

bool RSRenderNodeDrawableAdapter::IsFilterCacheValidForOcclusion() const
{
    if (!RSSystemProperties::GetBlurEnabled() || !RSSystemProperties::GetFilterCacheEnabled() ||
        !RSUniRenderJudgement::IsUniRender()) {
        ROSEN_LOGD("blur is disabled or filter cache is disabled.");
        return false;
    }

    bool val = false;
    if (backgroundFilterDrawable_) {
        val = val || backgroundFilterDrawable_->IsFilterCacheValidForOcclusion();
    }
    if (compositingFilterDrawable_) {
        val = val || compositingFilterDrawable_->IsFilterCacheValidForOcclusion();
    }
    return val;
}

const RectI RSRenderNodeDrawableAdapter::GetFilterCachedRegion() const
{
    RectI rect{0, 0, 0, 0};
    if (!RSSystemProperties::GetBlurEnabled()) {
        ROSEN_LOGD("blur is disabled");
        return rect;
    }

    if (compositingFilterDrawable_) {
        return compositingFilterDrawable_->GetFilterCachedRegion();
    } else if (backgroundFilterDrawable_) {
        return backgroundFilterDrawable_->GetFilterCachedRegion();
    } else {
        return rect;
    }
}

} // namespace OHOS::Rosen::DrawableV2
