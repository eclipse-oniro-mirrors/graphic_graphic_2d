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

#include "drawable/rs_render_node_drawable.h"

#include "common/rs_common_def.h"
#include "common/rs_optional_trace.h"
#include "pipeline/rs_paint_filter_canvas.h"
#include "pipeline/rs_task_dispatcher.h"
#include "pipeline/rs_uni_render_thread.h"
#include "pipeline/rs_uni_render_util.h"
#include "platform/common/rs_log.h"
#include "rs_trace.h"

namespace OHOS::Rosen::DrawableV2 {
#ifdef RS_ENABLE_VK
#include "include/gpu/GrBackendSurface.h"

#include "platform/ohos/backend/native_buffer_utils.h"
#include "platform/ohos/backend/rs_vulkan_context.h"
#endif
RSRenderNodeDrawable::Registrar RSRenderNodeDrawable::instance_;
thread_local bool RSRenderNodeDrawable::drawBlurForCache_ = false;
thread_local bool RSRenderNodeDrawable::isOpDropped_ = true;

namespace {
constexpr int32_t DRAWING_CACHE_MAX_UPDATE_TIME = 3;
constexpr float CACHE_FILL_ALPHA = 0.2f;
constexpr float CACHE_UPDATE_FILL_ALPHA = 0.8f;
}
RSRenderNodeDrawable::RSRenderNodeDrawable(std::shared_ptr<const RSRenderNode>&& node)
    : RSRenderNodeDrawableAdapter(std::move(node))
{
    auto task = [this] { this->RSRenderNodeDrawable::ClearCachedSurface(); };
    RegisterClearSurfaceFunc(task);
}

RSRenderNodeDrawable::~RSRenderNodeDrawable()
{
    ClearCachedSurface();
    ResetClearSurfaceFunc();
}

RSRenderNodeDrawable::Ptr RSRenderNodeDrawable::OnGenerate(std::shared_ptr<const RSRenderNode> node)
{
    return new RSRenderNodeDrawable(std::move(node));
}

void RSRenderNodeDrawable::Draw(Drawing::Canvas& canvas)
{
    if (UNLIKELY(RSUniRenderThread::IsInCaptureProcess())) {
        OnCapture(canvas);
    } else {
        OnDraw(canvas);
    }
}

/*
 * This function will be called recursively many times, and the logic should be as concise as possible.
 */
void RSRenderNodeDrawable::OnDraw(Drawing::Canvas& canvas)
{
    RSRenderNodeDrawable::TotalProcessedNodeCountInc();
    Drawing::Rect bounds = GetRenderParams() ? GetRenderParams()->GetFrameRect() : Drawing::Rect(0, 0, 0, 0);

    DrawAll(canvas, bounds);
}

/*
 * This function will be called recursively many times, and the logic should be as concise as possible.
 */
void RSRenderNodeDrawable::OnCapture(Drawing::Canvas& canvas)
{
    RSRenderNodeDrawable::OnDraw(canvas);
}

void RSRenderNodeDrawable::GenerateCacheIfNeed(Drawing::Canvas& canvas, RSRenderParams& params)
{
    // check if drawing cache enabled
    if (params.GetDrawingCacheType() != RSDrawingCacheType::DISABLED_CACHE) {
        RS_OPTIONAL_TRACE_NAME_FMT("RSCanvasRenderNodeDrawable::OnDraw id:%llu cacheType:%d cacheChanged:%d"
                                   " size:[%.2f, %.2f] ChildHasVisibleFilter:%d ChildHasVisibleEffect:%d"
                                   " shadowRect:[%.2f, %.2f, %.2f, %.2f] HasFilterOrEffect:%d",
            params.GetId(), params.GetDrawingCacheType(), params.GetDrawingCacheChanged(), params.GetCacheSize().x_,
            params.GetCacheSize().y_, params.ChildHasVisibleFilter(), params.ChildHasVisibleEffect(),
            params.GetShadowRect().GetLeft(), params.GetShadowRect().GetTop(), params.GetShadowRect().GetWidth(),
            params.GetShadowRect().GetHeight(), HasFilterOrEffect());
    }

    if (params.GetRSFreezeFlag()) {
        RS_OPTIONAL_TRACE_NAME_FMT("RSCanvasRenderNodeDrawable::GenerateCacheIfNeed id:%llu"
                                   " GetRSFreezeFlag:%d hasFilter:%d",
            params.GetId(), params.GetRSFreezeFlag(), params.ChildHasVisibleFilter());
    }

    // check drawing cache type (disabled: clear cache)
    if ((params.GetDrawingCacheType() == RSDrawingCacheType::DISABLED_CACHE && !OpincGetCachedMark()) &&
        !params.GetRSFreezeFlag()) {
        ClearCachedSurface();
        {
            std::lock_guard<std::mutex> lock(drawingCacheMapMutex_);
            drawingCacheUpdateTimeMap_.erase(nodeId_);
        }
        return;
    }

    {
        std::scoped_lock<std::recursive_mutex> cacheLock(cacheMutex_);
        if (cachedSurface_ == nullptr) {
            // Remove node id in update time map to avoid update time exceeds DRAWING_CACHE_MAX_UPDATE_TIME
            // (If cache disabled for node not on the tree, we clear cache in OnSync func, but we can't clear node
            // id in drawingCacheUpdateTimeMap_ [drawable will not be visited in RT].
            // If this node is marked node group by arkui again, we should first clear update time here, otherwise
            // update time will accumulate.)
            std::lock_guard<std::mutex> mapLock(drawingCacheMapMutex_);
            drawingCacheUpdateTimeMap_.erase(nodeId_);
        }
    }
    // generate(first time)/update cache(cache changed) [TARGET -> DISABLED if >= MAX UPDATE TIME]
    int32_t updateTimes = 0;
    bool needUpdateCache = CheckIfNeedUpdateCache(params, updateTimes);
    if (needUpdateCache && params.GetDrawingCacheType() == RSDrawingCacheType::TARGETED_CACHE &&
        updateTimes >= DRAWING_CACHE_MAX_UPDATE_TIME) {
        RS_TRACE_NAME_FMT("DisableCache by update time > 3, id:%llu", params.GetId());
        params.SetDrawingCacheType(RSDrawingCacheType::DISABLED_CACHE);
        ClearCachedSurface();
    }
    // reset drawing cache changed false for render param if drawable is visited this frame
    // if this drawble is skipped due to occlusion skip of app surface node, this flag should be kept for next frame
    params.SetDrawingCacheChanged(false, true);
    bool hasFilter = params.ChildHasVisibleFilter() || params.ChildHasVisibleEffect();
    if ((params.GetDrawingCacheType() == RSDrawingCacheType::DISABLED_CACHE || (!needUpdateCache && !hasFilter))
        && !OpincGetCachedMark() && !params.GetRSFreezeFlag()) {
        return;
    }

    if (needUpdateCache) {
        filterRects_.clear();
    }
    bool isForegroundFilterCache = params.GetForegroundFilterCache() != nullptr;
    // in case of no filter
    if (needUpdateCache && (!hasFilter || isForegroundFilterCache || params.GetRSFreezeFlag())) {
        RS_TRACE_NAME_FMT("UpdateCacheSurface id:%llu, isForegroundFilter:%d", nodeId_, isForegroundFilterCache);
        UpdateCacheSurface(canvas, params);
        return;
    }

    // in case of with filter
    auto curCanvas = static_cast<RSPaintFilterCanvas*>(&canvas);
    if (needUpdateCache) {
        // 1. update cache without filer/shadow/effect & clip hole
        auto canvasType = curCanvas->GetCacheType();
        // set canvas type as OFFSCREEN to not draw filter/shadow/filter
        curCanvas->SetCacheType(RSPaintFilterCanvas::CacheType::OFFSCREEN);
        RS_TRACE_NAME_FMT("UpdateCacheSurface with filter id:%llu", nodeId_);
        RSRenderNodeDrawableAdapter* root = curDrawingCacheRoot_;
        curDrawingCacheRoot_ = this;
        UpdateCacheSurface(canvas, params);
        curCanvas->SetCacheType(canvasType);
        curDrawingCacheRoot_ = root;
    }
}

void RSRenderNodeDrawable::TraverseSubTreeAndDrawFilterWithClip(Drawing::Canvas& canvas, const RSRenderParams& params)
{
    if (filterRects_.empty()) {
        return;
    }
    DrawBackground(canvas, params.GetBounds());
    Drawing::Region filterRegion;
    for (auto& rect : filterRects_) {
        Drawing::Region region;
        region.SetRect(rect);
        filterRegion.Op(region, Drawing::RegionOp::UNION);
    }
    Drawing::Path filetrPath;
    filterRegion.GetBoundaryPath(&filetrPath);
    canvas.ClipPath(filetrPath);
    DrawContent(canvas, params.GetFrameRect());
    DrawChildren(canvas, params.GetBounds());
    DrawForeground(canvas, params.GetBounds());
}

void RSRenderNodeDrawable::CheckCacheTypeAndDraw(Drawing::Canvas& canvas, const RSRenderParams& params)
{
    bool hasFilter = params.ChildHasVisibleFilter() || params.ChildHasVisibleEffect();
    if (hasFilter && params.GetDrawingCacheType() != RSDrawingCacheType::DISABLED_CACHE &&
        params.GetForegroundFilterCache() == nullptr) {
        // traverse children to draw filter/shadow/effect
        Drawing::AutoCanvasRestore arc(canvas, true);
        bool isOpDropped = isOpDropped_;
        isOpDropped_ = false;
        drawBlurForCache_ = true; // may use in uifirst subthread
        auto drawableCacheType = GetCacheType();
        SetCacheType(DrawableCacheType::NONE);
        RS_TRACE_NAME_FMT("DrawBlurForCache id:%llu", nodeId_);
        TraverseSubTreeAndDrawFilterWithClip(canvas, params);
        SetCacheType(drawableCacheType);
        isOpDropped_ = isOpDropped;
        drawBlurForCache_ = false;
    }

    auto curCanvas = static_cast<RSPaintFilterCanvas*>(&canvas);
    if (drawBlurForCache_ && !params.ChildHasVisibleFilter() && !params.ChildHasVisibleEffect() &&
        !HasFilterOrEffect()) {
        RS_OPTIONAL_TRACE_NAME_FMT("CheckCacheTypeAndDraw id:%llu child without filter, skip", nodeId_);
        return;
    }

    // RSPaintFilterCanvas::CacheType::OFFSCREEN case
    if (curCanvas->GetCacheType() == RSPaintFilterCanvas::CacheType::OFFSCREEN) {
        if (HasFilterOrEffect() && params.GetForegroundFilterCache() == nullptr) {
            // clip hole for filter/shadow
            DrawBackgroundWithoutFilterAndEffect(canvas, params);
            DrawContent(canvas, params.GetFrameRect());
            DrawChildren(canvas, params.GetBounds());
            DrawForeground(canvas, params.GetBounds());
            return;
        }
    }

    switch (GetCacheType()) {
        case DrawableCacheType::NONE: {
            RSRenderNodeDrawable::OnDraw(canvas);
            break;
        }
        case DrawableCacheType::CONTENT: {
            RS_OPTIONAL_TRACE_NAME_FMT("DrawCachedImage id:%llu", nodeId_);
            if (LIKELY(!params.GetDrawingCacheIncludeProperty())) {
                DrawBackground(canvas, params.GetBounds());
                DrawCachedImage(*curCanvas, params.GetCacheSize());
                DrawForeground(canvas, params.GetBounds());
            } else if (params.GetForegroundFilterCache() != nullptr) {
                DrawBeforeCacheWithForegroundFilter(canvas, params.GetBounds());
                DrawCachedImage(*curCanvas, params.GetCacheSize(), params.GetForegroundFilterCache());
                DrawAfterCacheWithForegroundFilter(canvas, params.GetBounds());
            } else {
                DrawBeforeCacheWithProperty(canvas, params.GetBounds());
                DrawCachedImage(*curCanvas, params.GetCacheSize());
                DrawAfterCacheWithProperty(canvas, params.GetBounds());
            }
            UpdateCacheInfoForDfx(canvas, params.GetBounds(), params.GetId());
            break;
        }
        default:
            break;
    }
}

void RSRenderNodeDrawable::UpdateCacheInfoForDfx(Drawing::Canvas& canvas, const Drawing::Rect& rect, NodeId id)
{
    if (!isDrawingCacheDfxEnabled_) {
        return;
    }
    Drawing::Rect dst;
    canvas.GetTotalMatrix().MapRect(dst, rect);
    RectI dfxRect(static_cast<int>(dst.GetLeft()), static_cast<int>(dst.GetTop()), static_cast<int>(dst.GetWidth()),
        static_cast<int>(dst.GetHeight()));
    int32_t updateTimes = 0;
    {
        std::lock_guard<std::mutex> lock(drawingCacheMapMutex_);
        if (drawingCacheUpdateTimeMap_.count(nodeId_) > 0) {
            updateTimes = drawingCacheUpdateTimeMap_.at(nodeId_);
        }
    }
    {
        std::lock_guard<std::mutex> lock(drawingCacheInfoMutex_);
        drawingCacheInfos_[id] = std::make_pair(dfxRect, updateTimes);
    }
}

void RSRenderNodeDrawable::DrawDfxForCacheInfo(RSPaintFilterCanvas& canvas)
{
    if (isDrawingCacheEnabled_ && isDrawingCacheDfxEnabled_) {
        std::lock_guard<std::mutex> lock(drawingCacheInfoMutex_);
        for (const auto& [id, cacheInfo] : drawingCacheInfos_) {
            std::string extraInfo = ", updateTimes:" + std::to_string(cacheInfo.second);
            bool cacheUpdated = cacheUpdatedNodeMap_.count(id) > 0;
            auto color = cacheUpdated ? Drawing::Color::COLOR_RED : Drawing::Color::COLOR_BLUE;
            float alpha = cacheUpdated ? CACHE_UPDATE_FILL_ALPHA : CACHE_FILL_ALPHA;
            RSUniRenderUtil::DrawRectForDfx(canvas, cacheInfo.first, color, alpha, extraInfo);
        }
    }

    if (autoCacheDrawingEnable_ && !isDrawingCacheDfxEnabled_) {
        for (const auto& info : autoCacheRenderNodeInfos_) {
            RSUniRenderUtil::DrawRectForDfx(
                canvas, info.first, Drawing::Color::COLOR_BLUE, 0.2f, info.second); // alpha 0.2 by default
        }
    }
}

void RSRenderNodeDrawable::DumpDrawableTree(std::string& out) const
{
    std::function<void()> dumpDrawableTreeSyncTask = [&out, this]() -> void {
        if (skipType_ != DrawableV2::SkipType::NONE) {
            out += ", SkipType:" + std::to_string(static_cast<int>(skipType_));
            out += ", SkipIndex:" + std::to_string(GetSkipIndex());
        }
        out += "\n";
        auto& params = GetRenderParams();
        if (params) {
            out += ", params" + params->ToString();
        }
    };
    RSUniRenderThread::Instance().PostSyncTask(dumpDrawableTreeSyncTask);
}

void RSRenderNodeDrawable::SetCacheType(DrawableCacheType cacheType)
{
    cacheType_ = cacheType;
}

DrawableCacheType RSRenderNodeDrawable::GetCacheType() const
{
    return cacheType_;
}

std::shared_ptr<Drawing::Surface> RSRenderNodeDrawable::GetCachedSurface(pid_t threadId) const
{
    std::scoped_lock<std::recursive_mutex> lock(cacheMutex_);
    return threadId == cacheThreadId_ ? cachedSurface_ : nullptr;
}

void RSRenderNodeDrawable::InitCachedSurface(Drawing::GPUContext* gpuContext, const Vector2f& cacheSize, pid_t threadId)
{
#if (defined(RS_ENABLE_GL) || defined(RS_ENABLE_VK)) && (defined RS_ENABLE_EGLIMAGE)
    if (gpuContext == nullptr) {
        return;
    }
    ClearCachedSurface();
    cacheThreadId_ = threadId;
    int32_t width = 0;
    int32_t height = 0;
    if (IsComputeDrawAreaSucc()) {
        auto& unionRect = GetOpListUnionArea();
        width = static_cast<int32_t>(unionRect.GetWidth());
        height = static_cast<int32_t>(unionRect.GetHeight());
    } else {
        width = static_cast<int32_t>(cacheSize.x_);
        height = static_cast<int32_t>(cacheSize.y_);
    }

#ifdef RS_ENABLE_GL
    if (OHOS::Rosen::RSSystemProperties::GetGpuApiType() != OHOS::Rosen::GpuApiType::VULKAN &&
        OHOS::Rosen::RSSystemProperties::GetGpuApiType() != OHOS::Rosen::GpuApiType::DDGR) {
        Drawing::ImageInfo info = Drawing::ImageInfo::MakeN32Premul(width, height);
        std::scoped_lock<std::recursive_mutex> lock(cacheMutex_);
        cachedSurface_ = Drawing::Surface::MakeRenderTarget(gpuContext, true, info);
    }
#endif
#ifdef RS_ENABLE_VK
    if (OHOS::Rosen::RSSystemProperties::GetGpuApiType() == OHOS::Rosen::GpuApiType::VULKAN ||
        OHOS::Rosen::RSSystemProperties::GetGpuApiType() == OHOS::Rosen::GpuApiType::DDGR) {
        std::scoped_lock<std::recursive_mutex> lock(cacheMutex_);
        cachedBackendTexture_ = RSUniRenderUtil::MakeBackendTexture(width, height);
        auto vkTextureInfo = cachedBackendTexture_.GetTextureInfo().GetVKTextureInfo();
        if (!cachedBackendTexture_.IsValid() || !vkTextureInfo) {
            return;
        }
        vulkanCleanupHelper_ = new NativeBufferUtils::VulkanCleanupHelper(
            RsVulkanContext::GetSingleton(), vkTextureInfo->vkImage, vkTextureInfo->vkAlloc.memory);
        cachedSurface_ = Drawing::Surface::MakeFromBackendTexture(gpuContext, cachedBackendTexture_.GetTextureInfo(),
            Drawing::TextureOrigin::BOTTOM_LEFT, 1, Drawing::ColorType::COLORTYPE_RGBA_8888, nullptr,
            NativeBufferUtils::DeleteVkImage, vulkanCleanupHelper_);
    }
#endif
#else
    cachedSurface_ =
        Drawing::Surface::MakeRasterN32Premul(static_cast<int32_t>(cacheSize.x_), static_cast<int32_t>(cacheSize.y_));
#endif
}

bool RSRenderNodeDrawable::NeedInitCachedSurface(const Vector2f& newSize)
{
    auto width = static_cast<int32_t>(newSize.x_);
    auto height = static_cast<int32_t>(newSize.y_);
    if (IsComputeDrawAreaSucc()) {
        auto& unionRect = GetOpListUnionArea();
        width = static_cast<int32_t>(unionRect.GetWidth());
        height = static_cast<int32_t>(unionRect.GetHeight());
    }
    std::scoped_lock<std::recursive_mutex> lock(cacheMutex_);
    if (cachedSurface_ == nullptr) {
        return true;
    }
    auto cacheCanvas = cachedSurface_->GetCanvas();
    if (cacheCanvas == nullptr) {
        return true;
    }
    return cacheCanvas->GetWidth() != width || cacheCanvas->GetHeight() != height;
}

#if defined(RS_ENABLE_GL) || defined(RS_ENABLE_VK)
struct SharedTextureContext {
    SharedTextureContext(std::shared_ptr<Drawing::Image> sharedImage)
        : sharedImage_(std::move(sharedImage)) {}

private:
    std::shared_ptr<Drawing::Image> sharedImage_;
};

static void DeleteSharedTextureContext(void* context)
{
    SharedTextureContext* cleanupHelper = static_cast<SharedTextureContext*>(context);
    if (cleanupHelper != nullptr) {
        delete cleanupHelper;
    }
}
#endif

std::shared_ptr<Drawing::Image> RSRenderNodeDrawable::GetCachedImage(RSPaintFilterCanvas& canvas)
{
    std::scoped_lock<std::recursive_mutex> lock(cacheMutex_);
    if (!cachedSurface_ || !cachedImage_) {
        RS_LOGE("RSRenderNodeDrawable::GetCachedImage invalid cachedSurface_");
        return nullptr;
    }

    // do not use threadId to judge image grcontext change
    if (cachedImage_->IsValid(canvas.GetGPUContext().get())) {
        return cachedImage_;
    }
#ifdef RS_ENABLE_GL
    if (OHOS::Rosen::RSSystemProperties::GetGpuApiType() != OHOS::Rosen::GpuApiType::VULKAN &&
        OHOS::Rosen::RSSystemProperties::GetGpuApiType() != OHOS::Rosen::GpuApiType::DDGR) {
        Drawing::TextureOrigin origin = Drawing::TextureOrigin::BOTTOM_LEFT;
        Drawing::BitmapFormat info = Drawing::BitmapFormat{cachedImage_->GetColorType(), cachedImage_->GetAlphaType()};
        SharedTextureContext* sharedContext = new SharedTextureContext(cachedImage_); // will move image
        cachedImage_ = std::make_shared<Drawing::Image>();
        bool ret = cachedImage_->BuildFromTexture(*canvas.GetGPUContext(), cachedBackendTexture_.GetTextureInfo(),
            origin, info, nullptr, DeleteSharedTextureContext, sharedContext);
        if (!ret) {
            RS_LOGE("RSRenderNodeDrawable::GetCachedImage image BuildFromTexture failed");
            return nullptr;
        }
    }
#endif

#ifdef RS_ENABLE_VK
    if (OHOS::Rosen::RSSystemProperties::GetGpuApiType() == OHOS::Rosen::GpuApiType::VULKAN ||
        OHOS::Rosen::RSSystemProperties::GetGpuApiType() == OHOS::Rosen::GpuApiType::DDGR) {
        if (vulkanCleanupHelper_ == nullptr) {
            return nullptr;
        }
        Drawing::TextureOrigin origin = Drawing::TextureOrigin::BOTTOM_LEFT;
        Drawing::BitmapFormat info = Drawing::BitmapFormat{cachedImage_->GetColorType(), cachedImage_->GetAlphaType()};
        cachedImage_ = std::make_shared<Drawing::Image>();
        bool ret = cachedImage_->BuildFromTexture(*canvas.GetGPUContext(), cachedBackendTexture_.GetTextureInfo(),
            origin, info, nullptr, NativeBufferUtils::DeleteVkImage, vulkanCleanupHelper_->Ref());
        if (!ret) {
            RS_LOGE("RSRenderNodeDrawable::GetCachedImage image BuildFromTexture failed");
            return nullptr;
        }
    }
#endif
    return cachedImage_;
}

void RSRenderNodeDrawable::DrawCachedImage(RSPaintFilterCanvas& canvas, const Vector2f& boundSize,
    const std::shared_ptr<RSFilter>& rsFilter)
{
    auto cacheImage = GetCachedImage(canvas);
    if (cacheImage == nullptr) {
        RS_LOGE("RSRenderNodeDrawable::DrawCachedImage image null");
        return;
    }
    if (RSSystemProperties::GetRecordingEnabled()) {
        if (cacheImage->IsTextureBacked()) {
            RS_LOGI("RSRenderNodeDrawable::DrawCachedImage convert cacheImage from texture to raster image");
            cacheImage = cacheImage->MakeRasterImage();
        }
    }
    if (cacheImage == nullptr || cacheImage->GetWidth() == 0 || cacheImage->GetHeight() == 0) {
        RS_LOGE("RSRenderNodeDrawable::DrawCachedImage invalid cacheimage");
        return;
    }
    float scaleX = boundSize.x_ / static_cast<float>(cacheImage->GetWidth());
    float scaleY = boundSize.y_ / static_cast<float>(cacheImage->GetHeight());
    if (IsComputeDrawAreaSucc()) {
        auto& unionRect = GetOpListUnionArea();
        scaleX = unionRect.GetWidth() / static_cast<float>(cacheImage->GetWidth());
        scaleY = unionRect.GetHeight() / static_cast<float>(cacheImage->GetHeight());
    }

    Drawing::AutoCanvasRestore arc(canvas, true);
    canvas.Scale(scaleX, scaleY);
    Drawing::Brush brush;
    canvas.AttachBrush(brush);
    auto samplingOptions = Drawing::SamplingOptions(Drawing::FilterMode::LINEAR, Drawing::MipmapMode::NONE);
    if (IsComputeDrawAreaSucc() && DrawAutoCache(canvas, *cacheImage,
        samplingOptions, Drawing::SrcRectConstraint::STRICT_SRC_RECT_CONSTRAINT)) {
        canvas.DetachBrush();
        DrawAutoCacheDfx(canvas, autoCacheRenderNodeInfos_);
        return;
    }
    if (rsFilter != nullptr) {
        RS_OPTIONAL_TRACE_NAME_FMT("RSRenderNodeDrawable::DrawCachedImage image width: %d, height: %d, %s",
            cacheImage->GetWidth(), cacheImage->GetHeight(), rsFilter->GetDescription().c_str());
        auto foregroundFilter = std::static_pointer_cast<RSDrawingFilterOriginal>(rsFilter);
        foregroundFilter->DrawImageRect(canvas, cacheImage, Drawing::Rect(0, 0, cacheImage->GetWidth(),
        cacheImage->GetHeight()), Drawing::Rect(0, 0, cacheImage->GetWidth(), cacheImage->GetHeight()));
     } else {
         canvas.DrawImage(*cacheImage, 0.0, 0.0, samplingOptions);
     }
    canvas.DetachBrush();
}

void RSRenderNodeDrawable::ClearCachedSurface()
{
    SetCacheType(DrawableCacheType::NONE);
    std::scoped_lock<std::recursive_mutex> lock(cacheMutex_);
    if (cachedSurface_ == nullptr) {
        return;
    }

    auto clearTask = [surface = cachedSurface_]() mutable { surface = nullptr; };
    cachedSurface_ = nullptr;
    cachedImage_ = nullptr;
    RSTaskDispatcher::GetInstance().PostTask(cacheThreadId_.load(), clearTask);

#ifdef RS_ENABLE_VK
    if (OHOS::Rosen::RSSystemProperties::GetGpuApiType() == OHOS::Rosen::GpuApiType::VULKAN ||
        OHOS::Rosen::RSSystemProperties::GetGpuApiType() == OHOS::Rosen::GpuApiType::DDGR) {
        vulkanCleanupHelper_ = nullptr;
    }
#endif
}

bool RSRenderNodeDrawable::CheckIfNeedUpdateCache(RSRenderParams& params, int32_t& updateTimes)
{
    {
        std::lock_guard<std::mutex> lock(drawingCacheMapMutex_);
        if (drawingCacheUpdateTimeMap_.count(nodeId_) > 0) {
            updateTimes = drawingCacheUpdateTimeMap_.at(nodeId_);
        }
    }

    RS_OPTIONAL_TRACE_NAME_FMT("CheckUpdateCache id:%llu updateTimes:%d type:%d cacheChanged:%d size:[%.2f, %.2f]",
        nodeId_, updateTimes, params.GetDrawingCacheType(), params.GetDrawingCacheChanged(),
        params.GetCacheSize().x_, params.GetCacheSize().y_);

    // node freeze
    if (params.GetRSFreezeFlag()) {
        return updateTimes == 0;
    }

    if ((params.GetDrawingCacheType() == RSDrawingCacheType::TARGETED_CACHE && params.NeedFilter() &&
        params.GetDrawingCacheIncludeProperty()) || ROSEN_LE(params.GetCacheSize().x_, 0.f) ||
        ROSEN_LE(params.GetCacheSize().y_, 0.f)) {
        params.SetDrawingCacheType(RSDrawingCacheType::DISABLED_CACHE);
        ClearCachedSurface();
        return false;
    }

    if (NeedInitCachedSurface(params.GetCacheSize())) {
        ClearCachedSurface();
        return true;
    }

    if (updateTimes == 0 || params.GetDrawingCacheChanged()) {
        return true;
    }
    return false;
}

void RSRenderNodeDrawable::UpdateCacheSurface(Drawing::Canvas& canvas, const RSRenderParams& params)
{
    auto curCanvas = static_cast<RSPaintFilterCanvas*>(&canvas);
    pid_t threadId = gettid();
    auto cacheSurface = GetCachedSurface(threadId);
    if (cacheSurface == nullptr) {
        RS_TRACE_NAME_FMT("InitCachedSurface size:[%.2f, %.2f]", params.GetCacheSize().x_, params.GetCacheSize().y_);
        InitCachedSurface(curCanvas->GetGPUContext().get(), params.GetCacheSize(), threadId);
        cacheSurface = GetCachedSurface(threadId);
        if (cacheSurface == nullptr) {
            return;
        }
    }

    auto cacheCanvas = std::make_shared<RSPaintFilterCanvas>(cacheSurface.get());
    if (!cacheCanvas) {
        return;
    }

    // copy current canvas properties into cacheCanvas
    const auto& renderEngine = RSUniRenderThread::Instance().GetRenderEngine();
    if (renderEngine) {
        cacheCanvas->SetHighContrast(renderEngine->IsHighContrastEnabled());
    }
    cacheCanvas->CopyConfigurationToOffscreenCanvas(*curCanvas);
    // Using filter cache in multi-thread environment may cause GPU memory leak or invalid textures
    // [PLANNNING] disable it in sub-thread.

    // When drawing CacheSurface, all child node should be drawn.
    // So set isOpDropped_ = false here.
    bool isOpDropped = isOpDropped_;
    isOpDropped_ = false;
    Drawing::AutoCanvasRestore arc(*cacheCanvas, true);
    cacheCanvas->Clear(Drawing::Color::COLOR_TRANSPARENT);

    OpincCanvasUnionTranslate(*cacheCanvas);
    if (params.GetRSFreezeFlag()) {
        cacheCanvas->SetDisableFilterCache(true);
    }
    // draw content + children
    auto bounds = params.GetBounds();
    if (LIKELY(!params.GetDrawingCacheIncludeProperty())) {
        DrawContent(*cacheCanvas, params.GetFrameRect());
        DrawChildren(*cacheCanvas, bounds);
    } else if (params.GetForegroundFilterCache() != nullptr) {
        DrawCacheWithForegroundFilter(*cacheCanvas, bounds);
    } else {
        DrawCacheWithProperty(*cacheCanvas, bounds);
    }
    ResumeOpincCanvasTranslate(*cacheCanvas);

    isOpDropped_ = isOpDropped;

    // get image & backend
    cachedImage_ = cacheSurface->GetImageSnapshot();
    if (cachedImage_) {
        SetCacheType(DrawableCacheType::CONTENT);
    }
#if RS_ENABLE_GL
    // vk backend has been created when surface init.
    if (OHOS::Rosen::RSSystemProperties::GetGpuApiType() != OHOS::Rosen::GpuApiType::VULKAN &&
        OHOS::Rosen::RSSystemProperties::GetGpuApiType() != OHOS::Rosen::GpuApiType::DDGR) {
        cachedBackendTexture_ = cacheSurface->GetBackendTexture();
    }
#endif
    // update cache updateTimes
    {
        std::lock_guard<std::mutex> lock(drawingCacheMapMutex_);
        drawingCacheUpdateTimeMap_[nodeId_]++;
    }
    {
        std::lock_guard<std::mutex> lock(drawingCacheInfoMutex_);
        cacheUpdatedNodeMap_.emplace(params.GetId(), true);
    }
}

int RSRenderNodeDrawable::GetTotalProcessedNodeCount()
{
    return totalProcessedNodeCount_;
}

void RSRenderNodeDrawable::TotalProcessedNodeCountInc()
{
    ++totalProcessedNodeCount_;
}

void RSRenderNodeDrawable::ClearTotalProcessedNodeCount()
{
    totalProcessedNodeCount_ = 0;
}

int RSRenderNodeDrawable::GetProcessedNodeCount()
{
    return processedNodeCount_;
}

void RSRenderNodeDrawable::ProcessedNodeCountInc()
{
    ++processedNodeCount_;
}

void RSRenderNodeDrawable::ClearProcessedNodeCount()
{
    processedNodeCount_ = 0;
}
} // namespace OHOS::Rosen::DrawableV2
