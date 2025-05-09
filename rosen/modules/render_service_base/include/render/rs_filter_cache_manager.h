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

#ifndef RENDER_SERVICE_BASE_PROPERTY_RS_FILTER_CACHE_MANAGER_H
#define RENDER_SERVICE_BASE_PROPERTY_RS_FILTER_CACHE_MANAGER_H

#include <atomic>
#if defined(NEW_SKIA) && (defined(RS_ENABLE_GL) || defined(RS_ENABLE_VK))
#include <condition_variable>

#include "event_handler.h"
#include "draw/canvas.h"
#include "draw/surface.h"
#include "utils/rect.h"

#include "common/rs_macros.h"
#include "common/rs_rect.h"
#include "pipeline/rs_dirty_region_manager.h"
#include "pipeline/rs_paint_filter_canvas.h"
#include "platform/common/rs_system_properties.h"
#include "render/rs_filter.h"

namespace OHOS {
namespace Rosen {
class RSDrawingFilter;
// Note: we don't care about if the filter will be applied to background or foreground, the caller should take care of
// this. This means if both background and foreground need to apply filter, the caller should create two
// RSFilterCacheManager, pass the correct dirty region, and call the DrawFilter() in correct order.
// Warn: Using filter cache in multi-thread environment may cause GPU memory leak or invalid textures.
class RSB_EXPORT RSFilterCacheManager final {
public:
    RSFilterCacheManager() = default;
    ~RSFilterCacheManager() = default;
    RSFilterCacheManager(const RSFilterCacheManager&) = delete;
    RSFilterCacheManager(const RSFilterCacheManager&&) = delete;
    RSFilterCacheManager& operator=(const RSFilterCacheManager&) = delete;
    RSFilterCacheManager& operator=(const RSFilterCacheManager&&) = delete;

    // Call these functions during the prepare phase to validate the cache state with the filter, if filter region is
    // intersected with cached region, and if cached region is intersected with dirty region.
    void UpdateCacheStateWithFilterHash(const std::shared_ptr<RSFilter>& filter);
    void UpdateCacheStateWithFilterRegion(); // call when filter region out of cached region.
    bool UpdateCacheStateWithDirtyRegion(
        const RSDirtyRegionManager& dirtyManager); // call when dirty region intersects with cached region.
    void UpdateCacheStateWithDirtyRegion();
    const RectI& GetCachedImageRegion() const;
    FilterCacheType GetCachedType() const;

    // Call this function during the process phase to apply the filter. Depending on the cache state, it may either
    // regenerate the cache or reuse the existing cache.
    // Note: If srcRect or dstRect is empty, we'll use the DeviceClipRect as the corresponding rect.
    void DrawFilter(RSPaintFilterCanvas& canvas, const std::shared_ptr<RSDrawingFilter>& filter,
        bool manuallyHandleFilterCache = false, bool shouldClearFilteredCache = true,
        const std::optional<Drawing::RectI>& srcRect = std::nullopt,
        const std::optional<Drawing::RectI>& dstRect = std::nullopt);

    // This function is similar to DrawFilter(), but instead of drawing anything on the canvas, it simply returns the
    // cache data. This is used with effect component in RSPropertiesPainter::DrawBackgroundEffect.
    const std::shared_ptr<RSPaintFilterCanvas::CachedEffectData> GeneratedCachedEffectData(RSPaintFilterCanvas& canvas,
        const std::shared_ptr<RSDrawingFilter>& filter, const std::optional<Drawing::RectI>& srcRect = std::nullopt,
        const std::optional<Drawing::RectI>& dstRect = std::nullopt);

    uint8_t CalcDirectionBias(const Drawing::Matrix& mat);
    enum CacheType : uint8_t {
        CACHE_TYPE_NONE              = 0,
        CACHE_TYPE_SNAPSHOT          = 1,
        CACHE_TYPE_FILTERED_SNAPSHOT = 2,
        CACHE_TYPE_BOTH              = CACHE_TYPE_SNAPSHOT | CACHE_TYPE_FILTERED_SNAPSHOT,
    };

    // Call this function to manually invalidate the cache. The next time DrawFilter() is called, it will regenerate the
    // cache.
    void ReleaseCacheOffTree();
    void StopFilterPartialRender();
    void InvalidateFilterCache(FilterCacheType clearType = FilterCacheType::BOTH);

    // To reduce memory usage, clear one of the cached images.
    void CompactFilterCache();

    inline bool IsCacheValid() const
    {
        return cachedSnapshot_ != nullptr || cachedFilteredSnapshot_ != nullptr;
    }

    static bool GetFilterInvalid();
    static void SetFilterInvalid(bool invalidFilter);

    bool IsForceUseFilterCache() const;
    void MarkFilterForceUseCache(bool forceUseCache = true);
    bool IsForceClearFilterCache() const;
    void MarkFilterForceClearCache();
    void RecordFilterInfos(const std::shared_ptr<RSFilter>& rsFilter);
    void MarkFilterRegionChanged();
    void MarkFilterRegionInteractWithDirty();
    void MarkForceClearCacheWithLastFrame();
    void MarkFilterRegionIsLargeArea();
    bool IsAIBarCacheValid();
    void MarkEffectNode();
    void MarkNeedClearFilterCache(NodeId nodeId);
    bool NeedPendingPurge() const;
    bool IsSkippingFrame() const;
    void MarkRotationChanged();
    bool IsFilterCacheValidForOcclusion();
    void MarkNodeIsOccluded(bool isOccluded);
    bool IsFilterCacheValid() const;
    void SwapDataAndInitStagingFlags(std::unique_ptr<RSFilterCacheManager>& cacheManager);
    bool WouldDrawLargeAreaBlur();
    bool WouldDrawLargeAreaBlurPrecisely();
    void MarkInForegroundFilterAndCheckNeedForceClearCache(bool inForegroundFilter);
    RSFilter::FilterType GetFilterType() const {
        return filterType_;
    }

private:
    void TakeSnapshot(RSPaintFilterCanvas& canvas, const std::shared_ptr<RSDrawingFilter>& filter,
        const Drawing::RectI& srcRect);
    void GenerateFilteredSnapshot(
        RSPaintFilterCanvas& canvas, const std::shared_ptr<RSDrawingFilter>& filter, const Drawing::RectI& dstRect);
    bool DrawFilterWithoutSnapshot(RSPaintFilterCanvas& canvas, const std::shared_ptr<RSDrawingFilter>& filter,
        const Drawing::RectI& src, const Drawing::RectI& dst, bool shouldClearFilteredCache);
    void DrawCachedFilteredSnapshot(RSPaintFilterCanvas& canvas, const Drawing::RectI& dstRect,
        const std::shared_ptr<RSDrawingFilter>& filter) const;
    bool CanDiscardCanvas(RSPaintFilterCanvas& canvas, const Drawing::RectI& dstRect) const;
    // Validate the input srcRect and dstRect, and return the validated rects.
    std::tuple<Drawing::RectI, Drawing::RectI> ValidateParams(RSPaintFilterCanvas& canvas,
        const std::optional<Drawing::RectI>& srcRect, const std::optional<Drawing::RectI>& dstRect);
    inline static void ClipVisibleRect(RSPaintFilterCanvas& canvas);
    // Check if the cache is valid in current GrContext, since FilterCache will never be used in multi-thread
    // environment, we don't need to attempt to reattach SkImages.
    void CheckCachedImages(RSPaintFilterCanvas& canvas);

    const char* GetCacheState() const;

    void UpdateFlags(FilterCacheType type, bool cacheValid);
    void ClearFilterCache();

    // We keep both the snapshot and filtered snapshot in the cache, and clear unneeded one in next frame.
    // Note: rect in cachedSnapshot_ and cachedFilteredSnapshot_ is in device coordinate.
    std::shared_ptr<RSPaintFilterCanvas::CachedEffectData> cachedSnapshot_ = nullptr;
    std::shared_ptr<RSPaintFilterCanvas::CachedEffectData> cachedFilteredSnapshot_ = nullptr;

    // Hash of previous filter, used to determine if we need to invalidate cachedFilteredSnapshot_.
    uint32_t cachedFilterHash_ = 0;

    // Region of the cached image, used to determine if we need to invalidate the cache.
    RectI snapshotRegion_; // Note: in device coordinate.

    // This flag is used to notify unirender_thread need to clear gpu memory.
    static inline std::atomic_bool filterInvalid_ = false;

    // flags for clearing filter cache
    // All stagingXXX variables should be read & written by render_service thread
    bool stagingForceUseCache_ = false;
    bool stagingForceClearCache_ = false;
    uint32_t stagingCachedFilterHash_ = 0;
    bool stagingFilterHashChanged_ = false;
    bool stagingFilterRegionChanged_ = false;
    bool stagingFilterInteractWithDirty_ = false;
    bool stagingRotationChanged_ = false;
    bool stagingForceClearCacheForLastFrame_ = false;
    bool stagingIsAIBarInteractWithHWC_ = false;
    bool stagingIsEffectNode_ = false;
    bool stagingInForegroundFilter_ = false;

    // clear one of snapshot cache and filtered cache after drawing
    // All renderXXX variables should be read & written by render_thread or OnSync() function
    bool renderClearFilteredCacheAfterDrawing_ = false;
    bool renderFilterHashChanged_ = false;
    bool renderForceClearCacheForLastFrame_ = false;
    bool renderIsEffectNode_ = false;
    bool renderIsSkipFrame_ = false;

    // the type cache needed clear before drawing
    FilterCacheType stagingClearType_ = FilterCacheType::NONE;
    FilterCacheType renderClearType_ = FilterCacheType::NONE;
    FilterCacheType lastCacheType_ = FilterCacheType::NONE;
    bool stagingIsOccluded_ = false;

    // force cache with cacheUpdateInterval_
    bool stagingIsLargeArea_ = false;
    bool canSkipFrame_ = false;
    bool stagingIsSkipFrame_  = false;
    RSFilter::FilterType filterType_ = RSFilter::NONE;

    // Cache age, used to determine if we can delay the cache update.
    int cacheUpdateInterval_ = 0;
    bool isFilterCacheValid_ = false; // catch status in current frame
    // Whether we need to purge the cache after this frame.
    bool pendingPurge_ = false;

    // last stagingInForegroundFilter_ value
    bool lastInForegroundFilter_ = false;

public:
    static bool isCCMFilterCacheEnable_;
    static bool isCCMEffectMergeEnable_;
};
} // namespace Rosen
} // namespace OHOS
#endif

#endif // RENDER_SERVICE_BASE_PROPERTY_RS_FILTER_CACHE_MANAGER_H
