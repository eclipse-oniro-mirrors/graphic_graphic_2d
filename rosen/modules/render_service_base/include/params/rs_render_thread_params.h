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

#ifndef RENDER_SERVICE_BASE_PARAMS_RS_RENDER_THREAD_PARAMS_H
#define RENDER_SERVICE_BASE_PARAMS_RS_RENDER_THREAD_PARAMS_H

#include <memory>
#include <vector>
#include "common/rs_occlusion_region.h"
#include "pipeline/rs_surface_render_node.h"
#include "platform/ohos/rs_jank_stats.h"
#include "property/rs_properties.h"

namespace OHOS::Rosen {
struct CaptureParam {
    bool isSnapshot_ = false;
    bool isSingleSurface_ = false;
    bool isMirror_ = false;
    NodeId rootIdInWhiteList_ = INVALID_NODEID;
    float scaleX_ = 0.0f;
    float scaleY_ = 0.0f;
    bool isFirstNode_ = false;
    bool isSystemCalling_ = false;
    CaptureParam() {}
    CaptureParam(bool isSnapshot, bool isSingleSurface, bool isMirror,
        float scaleX, float scaleY, bool isFirstNode = false, bool isSystemCalling = false)
        : isSnapshot_(isSnapshot),
        isSingleSurface_(isSingleSurface),
        isMirror_(isMirror),
        scaleX_(scaleX),
        scaleY_(scaleY),
        isFirstNode_(isFirstNode),
        isSystemCalling_(isSystemCalling) {}
};
struct HardCursorInfo {
    NodeId id = INVALID_NODEID;
    DrawableV2::RSRenderNodeDrawableAdapter::SharedPtr drawablePtr = nullptr;
};
class RSB_EXPORT RSRenderThreadParams {
public:
    RSRenderThreadParams() = default;
    virtual ~RSRenderThreadParams() = default;

    bool IsPartialRenderEnabled() const
    {
        return isPartialRenderEnabled_;
    }

    bool IsRegionDebugEnabled() const
    {
        return isRegionDebugEnabled_;
    }

    bool IsAllSurfaceVisibleDebugEnabled() const
    {
        return isAllSurfaceVisibleDebugEnabled_;
    }

    bool IsVirtualDirtyEnabled() const
    {
        return isVirtualDirtyEnabled_;
    }

    bool IsExpandScreenDirtyEnabled() const
    {
        return isExpandScreenDirtyEnabled_;
    }

    bool IsVirtualDirtyDfxEnabled() const
    {
        return isVirtualDirtyDfxEnabled_;
    }

    bool IsOpDropped() const
    {
        return isOpDropped_;
    }

    void SetOpDropped(bool opDropped)
    {
        isOpDropped_ = opDropped;
    }

    bool GetUIFirstDebugEnabled() const
    {
        return isUIFirstDebugEnable_;
    }

    void SetUIFirstCurrentFrameCanSkipFirstWait(bool canSkip)
    {
        isUIFirstCurrentFrameCanSkipFirstWait_ = canSkip;
    }

    bool GetUIFirstCurrentFrameCanSkipFirstWait() const
    {
        return isUIFirstCurrentFrameCanSkipFirstWait_;
    }

    void SetTimestamp(uint64_t timestamp)
    {
        timestamp_ = timestamp;
    }

    uint64_t GetCurrentTimestamp() const
    {
        return timestamp_;
    }

    void SetActualTimestamp(int64_t timestamp)
    {
        actualTimestamp_ = timestamp;
    }

    int64_t GetActualTimestamp() const
    {
        return actualTimestamp_;
    }

    void SetVsyncId(uint64_t vsyncId)
    {
        vsyncId_ = vsyncId;
    }

    uint64_t GetVsyncId() const
    {
        return vsyncId_;
    }

    void SetForceRefreshFlag(bool isForceRefresh)
    {
        isForceRefresh_ = isForceRefresh;
    }

    bool GetForceRefreshFlag() const
    {
        return isForceRefresh_;
    }

    const std::vector<DrawableV2::RSRenderNodeDrawableAdapter::SharedPtr>& GetSelfDrawables() const
    {
        return selfDrawables_;
    }

    const std::vector<DrawableV2::RSRenderNodeDrawableAdapter::SharedPtr>& GetHardwareEnabledTypeDrawables() const
    {
        return hardwareEnabledTypeDrawables_;
    }

    const HardCursorInfo& GetHardCursorDrawables() const
    {
        return hardCursorDrawables_;
    }
    
    void SetPendingScreenRefreshRate(uint32_t rate)
    {
        pendingScreenRefreshRate_ = rate;
    }

    uint32_t GetPendingScreenRefreshRate() const
    {
        return pendingScreenRefreshRate_;
    }

    void SetPendingConstraintRelativeTime(uint64_t relativeTime)
    {
        pendingConstraintRelativeTime_ = relativeTime;
    }

    uint64_t GetPendingConstraintRelativeTime() const
    {
        return pendingConstraintRelativeTime_;
    }

    Occlusion::Region& GetAccumulatedDirtyRegion()
    {
        return accumulatedDirtyRegion_;
    }

    bool Reset()
    {
        accumulatedDirtyRegion_.Reset();
        return true;
    }

    bool GetWatermarkFlag() const
    {
        return watermarkFlag_;
    }

    std::shared_ptr<Media::PixelMap> GetWatermark(const std::string& name) const;

    std::shared_ptr<Drawing::Image> GetWatermarkImg() const
    {
        return watermarkImg_;
    }

    void SetWatermark(bool watermarkFlag, const std::shared_ptr<Drawing::Image>& watermarkImg)
    {
        watermarkFlag_ = watermarkFlag;
        watermarkImg_ = watermarkImg;
    }

    void SetWatermarks(std::unordered_map<std::string, std::shared_ptr<Media::PixelMap>>& watermarks);

    void SetOcclusionEnabled(bool isOcclusionEnabled)
    {
        isOcclusionEnabled_ = isOcclusionEnabled;
    }

    bool IsOcclusionEnabled() const
    {
        return isOcclusionEnabled_;
    }

    void SetCurtainScreenUsingStatus(bool isCurtainScreenOn)
    {
        isCurtainScreenOn_ = isCurtainScreenOn;
    }

    bool IsCurtainScreenOn() const
    {
        return isCurtainScreenOn_;
    }
    
    void SetForceCommitLayer(bool forceCommit)
    {
        isForceCommitLayer_ = forceCommit;
    }

    bool GetForceCommitLayer() const
    {
        return isForceCommitLayer_;
    }

    void SetCacheEnabledForRotation(bool flag)
    {
        cacheEnabledForRotation_ = flag;
    }

    bool GetCacheEnabledForRotation() const
    {
        return cacheEnabledForRotation_;
    }

    void SetScreenSwitchStatus(bool flag)
    {
        isScreenSwitching_ = flag;
    }

    bool GetScreenSwitchStatus() const
    {
        return isScreenSwitching_;
    }

    void SetRequestNextVsyncFlag(bool flag)
    {
        needRequestNextVsyncAnimate_ = flag;
    }

    bool GetRequestNextVsyncFlag() const
    {
        return needRequestNextVsyncAnimate_;
    }

    void SetOnVsyncStartTime(int64_t time)
    {
        onVsyncStartTime_ = time;
    }

    int64_t GetOnVsyncStartTime() const
    {
        return onVsyncStartTime_;
    }

    void SetOnVsyncStartTimeSteady(int64_t timeSteady)
    {
        onVsyncStartTimeSteady_ = timeSteady;
    }

    int64_t GetOnVsyncStartTimeSteady() const
    {
        return onVsyncStartTimeSteady_;
    }

    void SetOnVsyncStartTimeSteadyFloat(float timeSteadyFloat)
    {
        onVsyncStartTimeSteadyFloat_ = timeSteadyFloat;
    }

    float GetOnVsyncStartTimeSteadyFloat() const
    {
        return onVsyncStartTimeSteadyFloat_;
    }

    void SetIsUniRenderAndOnVsync(bool isUniRenderAndOnVsync)
    {
        isUniRenderAndOnVsync_ = isUniRenderAndOnVsync;
    }

    bool IsUniRenderAndOnVsync() const
    {
        return isUniRenderAndOnVsync_;
    }

    void SetContext(std::shared_ptr<RSContext> context)
    {
        context_ = context;
    }

    const std::shared_ptr<RSContext> GetContext() const
    {
        return context_.lock();
    }

    void SetClipRegion(const Drawing::Region& clipRegion)
    {
        clipRegion_.Clone(clipRegion);
    }

    const Drawing::Region& GetClipRegion() const
    {
        return clipRegion_;
    }

    void SetForceMirrorScreenDirty(bool flag)
    {
        isMirrorScreenDirty_ = flag;
    }

    bool GetForceMirrorScreenDirty() const
    {
        return isMirrorScreenDirty_;
    }

    void SetImplicitAnimationEnd(bool isImplicitAnimationEnd)
    {
        isImplicitAnimationEnd_ = isImplicitAnimationEnd;
    }

    bool GetImplicitAnimationEnd() const
    {
        return isImplicitAnimationEnd_;
    }

    void SetDiscardJankFrames(bool discardJankFrames)
    {
        discardJankFrames_ = discardJankFrames;
    }

    bool GetDiscardJankFrames() const
    {
        return discardJankFrames_;
    }

    bool HasMirrorDisplay() const
    {
        return hasMirrorDisplay_;
    }

    void SetSecExemption(bool isSecurityExemption)
    {
        isSecurityExemption_ = isSecurityExemption;
    }

    bool GetSecExemption() const
    {
        return isSecurityExemption_;
    }

    bool IsOverDrawEnabled() const
    {
        return isOverDrawEnabled_;
    }

    bool IsDrawingCacheDfxEnabled() const
    {
        return isDrawingCacheDfxEnabled_;
    }

private:
    // Used by hardware thred
    uint64_t timestamp_ = 0;
    int64_t actualTimestamp_ = 0;
    uint64_t vsyncId_ = 0;
    bool isForceRefresh_ = false;
    uint32_t pendingScreenRefreshRate_ = 0;
    uint64_t pendingConstraintRelativeTime_ = 0;
    // RSDirtyRectsDfx dfx
    std::vector<std::string> dfxTargetSurfaceNames_;
    bool isRegionDebugEnabled_ = false;
    bool isPartialRenderEnabled_ = false;
    bool isDirtyRegionDfxEnabled_ = false;
    bool isTargetDirtyRegionDfxEnabled_ = false;
    bool isDisplayDirtyDfxEnabled_ = false;
    bool isOpaqueRegionDfxEnabled_ = false;
    bool isVisibleRegionDfxEnabled_ = false;
    bool isAllSurfaceVisibleDebugEnabled_ = false;
    bool isOpDropped_ = false;
    bool isOcclusionEnabled_ = false;
    bool isUIFirstDebugEnable_ = false;
    bool isUIFirstCurrentFrameCanSkipFirstWait_ = false;
    bool isVirtualDirtyDfxEnabled_ = false;
    bool isVirtualDirtyEnabled_ = false;
    bool isExpandScreenDirtyEnabled_ = false;
    bool isMirrorScreenDirty_ = false;
    bool cacheEnabledForRotation_ = false;
    bool isScreenSwitching_ = false;
    DirtyRegionDebugType dirtyRegionDebugType_ = DirtyRegionDebugType::DISABLED;
    std::vector<DrawableV2::RSRenderNodeDrawableAdapter::SharedPtr> selfDrawables_;
    std::vector<DrawableV2::RSRenderNodeDrawableAdapter::SharedPtr> hardwareEnabledTypeDrawables_;
    HardCursorInfo hardCursorDrawables_;
    bool isForceCommitLayer_ = false;
    bool hasMirrorDisplay_ = false;
    // accumulatedDirtyRegion to decide whether to skip tranasparent nodes.
    Occlusion::Region accumulatedDirtyRegion_;
    bool watermarkFlag_ = false;
    std::shared_ptr<Drawing::Image> watermarkImg_ = nullptr;
    std::unordered_map<std::string, std::shared_ptr<Media::PixelMap>> surfaceNodeWatermarks_;

    bool needRequestNextVsyncAnimate_ = false;
    bool isOverDrawEnabled_ = false;
    bool isDrawingCacheDfxEnabled_ = false;

    int64_t onVsyncStartTime_ = TIMESTAMP_INITIAL;
    int64_t onVsyncStartTimeSteady_ = TIMESTAMP_INITIAL;
    float onVsyncStartTimeSteadyFloat_ = TIMESTAMP_INITIAL_FLOAT;
    bool isUniRenderAndOnVsync_ = false;
    std::weak_ptr<RSContext> context_;
    bool isCurtainScreenOn_ = false;

    Drawing::Region clipRegion_;
    bool isImplicitAnimationEnd_ = false;
    bool discardJankFrames_ = false;

    bool isSecurityExemption_ = false;

    friend class RSMainThread;
    friend class RSUniRenderVisitor;
    friend class RSDirtyRectsDfx;
};

class RSRenderThreadParamsManager {
public:
    RSRenderThreadParamsManager() = default;
    ~RSRenderThreadParamsManager() = default;

    static RSRenderThreadParamsManager& Instance()
    {
        static RSRenderThreadParamsManager instance;
        return instance;
    }

    inline void SetRSRenderThreadParams(std::unique_ptr<RSRenderThreadParams>&& renderThreadParams)
    {
        renderThreadParams_ = std::move(renderThreadParams);
    }
    inline const std::unique_ptr<RSRenderThreadParams>& GetRSRenderThreadParams() const
    {
        return renderThreadParams_;
    }

private:
    static inline thread_local std::unique_ptr<RSRenderThreadParams> renderThreadParams_ = nullptr;
};
} // namespace OHOS::Rosen
#endif // RENDER_SERVICE_BASE_PARAMS_RS_RENDER_THREAD_PARAMS_H
