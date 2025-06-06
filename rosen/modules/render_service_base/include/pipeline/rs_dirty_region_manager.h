/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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
#ifndef RENDER_SERVICE_CLIENT_CORE_PIPELINE_RS_DIRTY_REGION_MANAGER_H
#define RENDER_SERVICE_CLIENT_CORE_PIPELINE_RS_DIRTY_REGION_MANAGER_H

#include <map>
#include <vector>

#include "common/rs_macros.h"
#include "common/rs_rect.h"
#include "dirty_region/rs_filter_dirty_collector.h"
#include "platform/common/rs_system_properties.h"

namespace OHOS {
namespace Rosen {
// classify dfx debug options
enum DebugRegionType {
    CURRENT_SUB = 0,
    CURRENT_WHOLE,
    MULTI_HISTORY,
    EGL_DAMAGE,
    TYPE_MAX
};

// classify types that cause region dirty
enum DirtyRegionType {
    UPDATE_DIRTY_REGION = 0,
    OVERLAY_RECT,
    FILTER_RECT,
    SHADOW_RECT,
    PREPARE_CLIP_RECT,
    REMOVE_CHILD_RECT,
    RENDER_PROPERTIES_RECT,
    CANVAS_NODE_SKIP_RECT,
    OUTLINE_RECT,
    SUBTREE_SKIP_RECT,
    SUBTREE_SKIP_OUT_OF_PARENT_RECT,
    TYPE_AMOUNT
};

class RSB_EXPORT RSDirtyRegionManager final {
    friend class RSFilterCacheManager;
public:
    static constexpr int32_t ALIGNED_BITS = 32;
    RSDirtyRegionManager();
    RSDirtyRegionManager(bool isDisplayDirtyManager);
    ~RSDirtyRegionManager() = default;
    // update/expand current frame dirtyregion
    void MergeDirtyRect(const RectI& rect, bool isDebugRect = false);
    // update/expand current frame dirtyregion if intersect
    bool MergeDirtyRectIfIntersect(const RectI& rect);
    // update/expand dirtyregion after merge history
    void MergeDirtyRectAfterMergeHistory(const RectI& rect);
    // clip dirtyregion in current frame
    void IntersectDirtyRect(const RectI& rect);
    // Clip currentframe dirtyRegion intersected with surfaceRect
    void ClipDirtyRectWithinSurface();
    // clear allinfo except dirtyregion history
    void Clear();
    // record hwc region for virtual screen
    void MergeHwcDirtyRect(const RectI& rect);

    // update current frame's visited dirtyregion
    void UpdateVisitedDirtyRects(const std::vector<RectI>& rects);
    RectI GetIntersectedVisitedDirtyRect(const RectI& absRect) const;
    void UpdateCacheableFilterRect(const RectI& rect);
    bool IfCacheableFilterRectFullyCover(const RectI& targetRect);
    bool IsCacheableFilterRectEmpty() const
    {
        return cacheableFilterRects_.empty();
    }

    void InvalidateFilterCacheRect()
    {
        isFilterCacheRectValid_ = false;
    }

    bool IsFilterCacheRectValid()
    {
        return isFilterCacheRectValid_;
    }

    // return current frame dirtyregion, can be changed in prepare and process (displaynode) stage
    const RectI& GetCurrentFrameDirtyRegion();
    // return merged historical region
    const RectI& GetDirtyRegion() const;
    // return mapAbs dirtyRegion
    const RectI& GetCurrentFrameMpsAbsDirtyRect() const;

    std::vector<RectI> GetCurrentFrameAdvancedDirtyRegion() const
    {
        return currentFrameAdvancedDirtyRegion_;
    }

    std::vector<RectI> GetAdvancedDirtyRegion() const
    {
        return advancedDirtyRegion_;
    }

    std::vector<RectI> GetDirtyRegionForQuickReject() const
    {
        return dirtyRegionForQuickReject_;
    }

    void SetDirtyRegionForQuickReject(std::vector<RectI> region)
    {
        dirtyRegionForQuickReject_ = region;
    }

    void SetCurrentFrameDirtyRect(const RectI& dirtyRect);
    /*  return merged historical region upside down in left-bottom origin coordinate
        reason: when use OpenGL SetDamageRegion, coordinate system conversion exists.
    */
    RectI GetDirtyRegionFlipWithinSurface() const;
    std::vector<RectI> GetAdvancedDirtyRegionFlipWithinSurface() const;
    // return current frame's region from dirtyregion history
    const RectI& GetLatestDirtyRegion() const;
    // return merged historical region upside down in left-bottom origin coordinate
    RectI GetRectFlipWithinSurface(const RectI& rect) const;
    // get aligned rect as times of alignedBits
    static RectI GetPixelAlignedRect(const RectI& rect, int32_t alignedBits = ALIGNED_BITS);
    // return true if current frame dirtyregion is not empty
    bool IsCurrentFrameDirty() const;
    // return true if dirtyregion after merge history is not empty
    bool IsDirty() const;
    // push currentframe dirtyregion into history, and merge history according to bufferage
    void UpdateDirty(bool enableAligned = false);
    // align current frame dirtyregion before merge history
    void UpdateDirtyByAligned(int32_t alignedBits = ALIGNED_BITS);
    bool SetBufferAge(const int age);

    // uifirst dirty
    const RectI GetUiLatestHistoryDirtyRegions(const int historyIndex = 4) const; // 4 means default history index

    void SetActiveSurfaceRect(const RectI& rect)
    {
        auto dstRect = surfaceRect_.IntersectRect(rect);
        lastActiveSurfaceRect_ = activeSurfaceRect_;
        activeSurfaceRect_ = dstRect;
    }

    bool IsActiveSurfaceRectChanged() const
    {
        return lastActiveSurfaceRect_ != activeSurfaceRect_;
    }

    const RectI& GetLastActiveSurfaceRect() const
    {
        return lastActiveSurfaceRect_;
    }

    const RectI& GetActiveSurfaceRect() const
    {
        return activeSurfaceRect_;
    }

    bool SetSurfaceRect(const RectI& rect)
    {
        if (rect.IsEmpty()) {
            return false;
        }
        lastSurfaceRect_ = surfaceRect_;
        surfaceRect_ = rect;
        return true;
    }

    bool IsSurfaceRectChanged() const
    {
        return lastSurfaceRect_ != surfaceRect_;
    }

    bool SetSurfaceSize(const int32_t width, const int32_t height)
    {
        return SetSurfaceRect(RectI(0, 0, width, height));
    }

    RectI GetSurfaceRect() const
    {
        return surfaceRect_;
    }
    void MergeSurfaceRect();
    // Reset current frame dirtyregion to surfacerect to realize full refreshing
    void ResetDirtyAsSurfaceSize();

    void UpdateDebugRegionTypeEnable(DirtyRegionDebugType dirtyDebugType);

    inline bool IsDebugRegionTypeEnable(DebugRegionType var) const
    {
        if (var < DebugRegionType::TYPE_MAX) {
            return debugRegionEnabled_[var];
        }
        return false;
    }
    // OnSync must be Executed after UpdateDirty API
    void OnSync(std::shared_ptr<RSDirtyRegionManager> targetManager);

    // added for dirty region dfx
    void UpdateDirtyRegionInfoForDfx(NodeId id, RSRenderNodeType nodeType = RSRenderNodeType::CANVAS_NODE,
        DirtyRegionType dirtyType = DirtyRegionType::UPDATE_DIRTY_REGION, const RectI& rect = RectI());
    void GetDirtyRegionInfo(std::map<NodeId, RectI>& target,
        RSRenderNodeType nodeType = RSRenderNodeType::CANVAS_NODE,
        DirtyRegionType dirtyType = DirtyRegionType::UPDATE_DIRTY_REGION) const;

    void MarkAsTargetForDfx()
    {
        isDfxTarget_ = true;
    }

    bool IsTargetForDfx() {
        return isDfxTarget_;
    }

    bool HasOffset();
    void SetOffset(int offsetX, int offsetY);
    RectI GetOffsetedDirtyRegion() const;

    const std::vector<RectI>& GetMergedDirtyRegions() const
    {
        return mergedDirtyRegions_;
    }

    void MergeDirtyHistoryInVirtual(unsigned int age)
    {
        mergedDirtyInVirtualScreen_ = MergeHistory(age, currentFrameDirtyRegion_);
    }

    RectI GetDirtyRegionInVirtual() const
    {
        return mergedDirtyInVirtualScreen_;
    }

    RectI GetHwcDirtyRegion() const
    {
        return hwcDirtyRegion_;
    }

    const RectI& GetUifirstFrameDirtyRegion();
    void SetUifirstFrameDirtyRect(const RectI& dirtyRect);

    void SetMaxNumOfDirtyRects(int maxNumOfDirtyRects)
    {
        maxNumOfDirtyRects_ = maxNumOfDirtyRects;
    }

    void SetAdvancedDirtyRegionType(AdvancedDirtyRegionType advancedDirtyRegionType)
    {
        advancedDirtyRegionType_ = advancedDirtyRegionType;
    }

    RSFilterDirtyCollector& GetFilterCollector()
    {
        return filterCollector_;
    }

    void SetPartialRenderEnabled(bool isPartialRenderEnabled)
    {
        isEnabledChanged_ = (isPartialRenderEnabled_ != isPartialRenderEnabled);
        isPartialRenderEnabled_ = isPartialRenderEnabled;
    }
    
    bool GetEnabledChanged() const
    {
        return isEnabledChanged_;
    }

private:
    void UpdateMaxNumOfDirtyRectByState();
    void UpdateCurrentFrameAdvancedDirtyRegion(RectI rect);
    void MergeAdvancedDirtyHistory(unsigned int age);
    std::vector<RectI> GetAdvancedDirtyHistory(unsigned int i) const;
    RectI MergeHistory(unsigned int age, RectI rect) const;
    void PushHistory(RectI rect);
    // get his rect according to index offset
    RectI GetHistory(unsigned int i) const;
    void AlignHistory();

    bool isDfxTarget_ = false;
    bool isDirtyRegionAlignedEnable_ = false;
    bool isFilterCacheRectValid_ = true;
    bool isDisplayDirtyManager_ = false;
    bool isPartialRenderEnabled_ = false;
    bool isEnabledChanged_ = false;
    bool hasOffset_ = false;
    std::atomic<bool> isSync_ = false;
    int historyHead_ = -1;
    unsigned int historySize_ = 0;
    const unsigned HISTORY_QUEUE_MAX_SIZE = 10;
    int maxNumOfDirtyRects_ = 1;
    AdvancedDirtyRegionType advancedDirtyRegionType_ = AdvancedDirtyRegionType::DISABLED;
    // may add new set function for bufferAge
    unsigned int bufferAge_ = 0;
    // Used for coordinate switch, i.e. dirtyRegion = dirtyRegion + offset.
    // For example when dirtymanager is used in cachesurface when surfacenode's
    // shadow and surfacenode are cached in a surface, dirty region's coordinate should start
    // from shadow's left-top rather than that of displaynode.
    // Normally, this value should be set to:
    //      offsetX_ =  - surfacePos.x + shadowWidth
    //      offsetY_ =  - surfacePos.y + shadowHeight
    int offsetX_ = 0;
    int offsetY_ = 0;
    RectI lastActiveSurfaceRect_;   // active rect of the canvas surface in the last frame
    RectI activeSurfaceRect_;       // active rect of the canvas surface
    RectI lastSurfaceRect_;         // rect of the canvas surface in the last frame
    RectI surfaceRect_;             // rect of the canvas surface
    RectI dirtyRegion_;             // dirtyregion after merge history
    RectI currentFrameDirtyRegion_; // dirtyRegion in current frame
    RectI uifirstFrameDirtyRegion_; // dirtyRegion in current frame
    RectI hwcDirtyRegion_;          // hwc dirty region used in virtual screen
    RectI debugRect_;               // dirtyRegion for showing currentFreshRate debug
    RectI mergedDirtyInVirtualScreen_;
    std::vector<RectI> visitedDirtyRegions_ = {};  // visited app's dirtyRegion
    std::vector<RectI> cacheableFilterRects_ = {};  // node's region if filter cachable
    std::vector<RectI> mergedDirtyRegions_ = {};

    std::vector<RectI> advancedDirtyRegion_ = {};
    std::vector<RectI> currentFrameAdvancedDirtyRegion_ = {};
    std::vector<RectI> dirtyRegionForQuickReject_ = {};
    std::vector<std::vector<RectI>> advancedDirtyHistory_ = {};

    // added for dfx
    std::vector<std::map<NodeId, RectI>> dirtyCanvasNodeInfo_;
    std::vector<std::map<NodeId, RectI>> dirtySurfaceNodeInfo_;
    std::vector<bool> debugRegionEnabled_;
    std::vector<RectI> dirtyHistory_;

    RSFilterDirtyCollector filterCollector_;
};
} // namespace Rosen
} // namespace OHOS

#endif // RENDER_SERVICE_CLIENT_CORE_PIPELINE_RS_DIRTY_REGION_MANAGER_H
