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
#include "pipeline/rs_screen_render_node.h"
#include "pipeline/rs_surface_render_node.h"
#include "platform/ohos/rs_jank_stats.h"
#include "property/rs_properties.h"
#include "screen_manager/rs_screen_info.h"

namespace OHOS::Rosen {
class RSProcessor;
class RSSLRScaleFunction;
struct CaptureParam {
    bool isSnapshot_ = false;
    bool isSingleSurface_ = false;
    bool isMirror_ = false;
    uint64_t virtualScreenId_ = INVALID_SCREEN_ID;
    NodeId rootIdInWhiteList_ = INVALID_NODEID;
    bool isFirstNode_ = false;
    bool isSystemCalling_ = false;
    bool isSelfCapture_ = false;
    bool isNeedBlur_ = false;
    bool isSoloNodeUiCapture_ = false;
    NodeId endNodeId_ = INVALID_NODEID;
    bool captureFinished_ = false;
    bool needCaptureSpecialLayer_ = false;
    CaptureParam() {}
    CaptureParam(bool isSnapshot, bool isSingleSurface, bool isMirror, bool isFirstNode = false,
        bool isSystemCalling = false, bool isSelfCapture = false, bool isNeedBlur = false,
        bool isSoloNodeUiCapture = false, NodeId endNodeId = INVALID_NODEID, bool captureFinished = false,
        bool needCaptureSpecialLayer = false)
        : isSnapshot_(isSnapshot), isSingleSurface_(isSingleSurface), isMirror_(isMirror), isFirstNode_(isFirstNode),
        isSystemCalling_(isSystemCalling), isSelfCapture_(isSelfCapture), isNeedBlur_(isNeedBlur),
        isSoloNodeUiCapture_(isSoloNodeUiCapture), endNodeId_(endNodeId), captureFinished_(captureFinished),
        needCaptureSpecialLayer_(needCaptureSpecialLayer) {}
};
struct HardCursorInfo {
    NodeId id = INVALID_NODEID;
    DrawableV2::RSRenderNodeDrawableAdapter::SharedPtr drawablePtr = nullptr;
};

enum ForceCommitReason {
    NO_FORCE = 0,
    FORCED_BY_UNI_RENDER_FLAG = 1,
    FORCED_BY_HWC_UPDATE = 1 << 1,
    FORCED_BY_POINTER_WINDOW = 1 << 2,
};

class RSB_EXPORT RSRenderThreadParams {
public:
    using DrawablesVec = std::vector<std::tuple<NodeId, NodeId,
        DrawableV2::RSRenderNodeDrawableAdapter::SharedPtr>>;

    RSRenderThreadParams() = default;
    virtual ~RSRenderThreadParams() = default;

    void SetSecurityDisplay(bool isSecurityDisplay);
    bool IsSecurityDisplay() const;

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

    void SetVirtualDirtyEnabled(bool isVirtualDirtyEnabled)
    {
        isVirtualDirtyEnabled_ = isVirtualDirtyEnabled;
    }

    bool IsVirtualDirtyEnabled() const
    {
        return isVirtualDirtyEnabled_;
    }

    void SetVirtualExpandScreenDirtyEnabled(bool isVirtualExpandScreenDirtyEnabled)
    {
        isVirtualExpandScreenDirtyEnabled_ = isVirtualExpandScreenDirtyEnabled;
    }

    bool IsVirtualExpandScreenDirtyEnabled() const
    {
        return isVirtualExpandScreenDirtyEnabled_;
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

    bool IsDirtyAlignEnabled() const
    {
        return isDirtyAlignEnabled_;
    }

    bool IsStencilPixelOcclusionCullingEnabled() const
    {
        return isStencilPixelOcclusionCullingEnabled_;
    }

    bool HasDisplayHdrOn() const
    {
        return hasDisplayHdrOn_;
    }

    bool IsMirrorScreen() const
    {
        return isMirrorScreen_;
    }

    void SetIsMirrorScreen(bool isMirrorScreen)
    {
        isMirrorScreen_ = isMirrorScreen;
    }

    bool IsFirstVisitCrossNodeDisplay() const
    {
        return isFirstVisitCrossNodeDisplay_;
    }

    void SetIsFirstVisitCrossNodeDisplay(bool isFirstVisitCrossNodeDisplay)
    {
        isFirstVisitCrossNodeDisplay_ = isFirstVisitCrossNodeDisplay;
    }

    CrossNodeOffScreenRenderDebugType GetCrossNodeOffScreenStatus() const
    {
        return isCrossNodeOffscreenOn_;
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

    void SetFastComposeTimeStampDiff(uint64_t fastComposeTimeStampDiff)
    {
        fastComposeTimeStampDiff_ = fastComposeTimeStampDiff;
    }

    uint64_t GetFastComposeTimeStampDiff() const
    {
        return fastComposeTimeStampDiff_;
    }

    const std::vector<DrawableV2::RSRenderNodeDrawableAdapter::SharedPtr>& GetSelfDrawables() const
    {
        return selfDrawables_;
    }

    const DrawablesVec& GetHardwareEnabledTypeDrawables() const
    {
        return hardwareEnabledTypeDrawables_;
    }

    const auto& GetHardCursorDrawables() const
    {
        return hardCursorDrawableVec_;
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

    std::shared_ptr<Drawing::Image> GetWatermark(const std::string& name) const;

    std::shared_ptr<Drawing::Image> GetWatermarkImg() const
    {
        return watermarkImg_;
    }

    void SetWatermark(bool watermarkFlag, const std::shared_ptr<Drawing::Image>& watermarkImg)
    {
        watermarkFlag_ = watermarkFlag;
        watermarkImg_ = watermarkImg;
    }

    void SetWatermarks(std::unordered_map<std::string, std::pair<std::shared_ptr<Drawing::Image>, pid_t>>& watermarks);

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

    void SetForceCommitLayer(uint32_t forceCommitReason)
    {
        forceCommitReason_ = forceCommitReason;
    }

    uint32_t GetForceCommitReason() const
    {
        return forceCommitReason_;
    }

    void SetCacheEnabledForRotation(bool flag)
    {
        cacheEnabledForRotation_ = flag;
    }

    bool GetCacheEnabledForRotation() const
    {
        return cacheEnabledForRotation_;
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

    const ScreenInfo& GetScreenInfo() const
    {
        return screenInfo_;
    }

    void SetScreenInfo(const ScreenInfo& info)
    {
        screenInfo_ = info;
    }

#ifdef RS_ENABLE_OVERLAY_DISPLAY
    bool GetOverlayDisplayEnable() const
    {
        return overlayDisplayEnable_;
    }
#endif

    CompositeType GetCompositeType() const
    {
        return compositeType_;
    }

    void SetCompositeType(CompositeType type)
    {
        compositeType_ = type;
    }
    NodeId GetCurrentVisitDisplayDrawableId() const
    {
        return currentVisitDisplayDrawableId_;
    }
    void SetCurrentVisitDisplayDrawableId(NodeId displayId)
    {
        currentVisitDisplayDrawableId_ = displayId;
    }

    bool HasPhysicMirror() const
    {
        return isMirrorScreen_ && compositeType_ == CompositeType::UNI_RENDER_COMPOSITE;
    }

    AdvancedDirtyRegionType GetAdvancedDirtyType() const
    {
        return advancedDirtyType_;
    }

    void SetRSProcessor(const std::shared_ptr<RSProcessor>& processor)
    {
        processor_ = processor;
    }

    std::shared_ptr<RSProcessor> GetRSProcessor() const
    {
        return processor_;
    }

    void SetVirtualDirtyRefresh(bool virtualdirtyRefresh)
    {
        virtualDirtyRefresh_ = virtualdirtyRefresh;
    }

    bool GetVirtualDirtyRefresh() const
    {
        return virtualDirtyRefresh_;
    }

    void SetSLRScaleManager(std::shared_ptr<RSSLRScaleFunction> slrManager)
    {
        slrManager_ = slrManager;
    }

    std::shared_ptr<RSSLRScaleFunction> GetSLRScaleManager() const
    {
        return slrManager_;
    }

private:
    bool virtualDirtyRefresh_ = false;
    // Used by hardware thred
    uint64_t timestamp_ = 0;
    int64_t actualTimestamp_ = 0;
    uint64_t vsyncId_ = 0;
    bool isForceRefresh_ = false;
    uint32_t pendingScreenRefreshRate_ = 0;
    uint64_t pendingConstraintRelativeTime_ = 0;
    uint64_t fastComposeTimeStampDiff_ = 0;
    // RSDirtyRectsDfx dfx
    std::vector<std::string> dfxTargetSurfaceNames_;
    bool hasDisplayHdrOn_ = false;
    bool isMirrorScreen_ = false;
    bool isFirstVisitCrossNodeDisplay_ = false;
    bool isRegionDebugEnabled_ = false;
    bool isPartialRenderEnabled_ = false;
    bool isDirtyRegionDfxEnabled_ = false;
    bool isTargetDirtyRegionDfxEnabled_ = false;
    bool isDisplayDirtyDfxEnabled_ = false;
    bool isOpaqueRegionDfxEnabled_ = false;
    bool isVisibleRegionDfxEnabled_ = false;
    bool isMergedDirtyRegionDfxEnabled_ = false;
    bool isAllSurfaceVisibleDebugEnabled_ = false;
    bool isOpDropped_ = false;
    bool isDirtyAlignEnabled_ = false;
    bool isStencilPixelOcclusionCullingEnabled_ = false;
    bool isOcclusionEnabled_ = false;
    CrossNodeOffScreenRenderDebugType isCrossNodeOffscreenOn_ = CrossNodeOffScreenRenderDebugType::ENABLE;
    bool isUIFirstDebugEnable_ = false;
    bool isUIFirstCurrentFrameCanSkipFirstWait_ = false;
    bool isVirtualDirtyDfxEnabled_ = false;
    bool isVirtualDirtyEnabled_ = false;
    bool isVirtualExpandScreenDirtyEnabled_ = false;
    bool isMirrorScreenDirty_ = false;
    bool cacheEnabledForRotation_ = false;
    NodeId currentVisitDisplayDrawableId_ = INVALID_NODEID;
    AdvancedDirtyRegionType advancedDirtyType_ = AdvancedDirtyRegionType::DISABLED;
    DirtyRegionDebugType dirtyRegionDebugType_ = DirtyRegionDebugType::DISABLED;
    std::vector<DrawableV2::RSRenderNodeDrawableAdapter::SharedPtr> selfDrawables_;
    DrawablesVec hardwareEnabledTypeDrawables_;
    std::vector<std::tuple<NodeId, NodeId, DrawableV2::RSRenderNodeDrawableAdapter::SharedPtr>> hardCursorDrawableVec_;
    uint32_t forceCommitReason_ = 0;
    bool hasMirrorDisplay_ = false;
    // accumulatedDirtyRegion to decide whether to skip tranasparent nodes.
    Occlusion::Region accumulatedDirtyRegion_;
    bool watermarkFlag_ = false;
    std::shared_ptr<Drawing::Image> watermarkImg_ = nullptr;
    std::unordered_map<std::string, std::pair<std::shared_ptr<Drawing::Image>, pid_t>> surfaceWatermarks_;
    std::shared_ptr<RSSLRScaleFunction> slrManager_ = nullptr;

    bool isOverDrawEnabled_ = false;
    bool isDrawingCacheDfxEnabled_ = false;

    int64_t onVsyncStartTime_ = TIMESTAMP_INITIAL;
    int64_t onVsyncStartTimeSteady_ = TIMESTAMP_INITIAL;
    float onVsyncStartTimeSteadyFloat_ = TIMESTAMP_INITIAL_FLOAT;
    bool isUniRenderAndOnVsync_ = false;
    std::weak_ptr<RSContext> context_;
    bool isCurtainScreenOn_ = false;
    CompositeType compositeType_ = CompositeType::HARDWARE_COMPOSITE;

#ifdef RS_ENABLE_OVERLAY_DISPLAY
    bool overlayDisplayEnable_{false};
#endif

    Drawing::Region clipRegion_;
    bool isImplicitAnimationEnd_ = false;
    bool discardJankFrames_ = false;

    bool isSecurityExemption_ = false;
    // use to mark security display
    bool isSecurityDisplay_ = false;
    ScreenInfo screenInfo_ = {};
    std::shared_ptr<RSProcessor> processor_ = nullptr;

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
