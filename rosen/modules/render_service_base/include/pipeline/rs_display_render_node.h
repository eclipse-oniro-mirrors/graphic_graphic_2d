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
#ifndef RENDER_SERVICE_CLIENT_CORE_PIPELINE_RS_DISPLAY_RENDER_NODE_H
#define RENDER_SERVICE_CLIENT_CORE_PIPELINE_RS_DISPLAY_RENDER_NODE_H

#include <memory>
#include <mutex>

#ifndef ROSEN_CROSS_PLATFORM
#include <ibuffer_consumer_listener.h>
#include <iconsumer_surface.h>
#include <surface.h>
#include "sync_fence.h"
#endif

#include "common/rs_macros.h"
#include "memory/rs_memory_track.h"
#include "pipeline/rs_render_node.h"
#include "pipeline/rs_surface_handler.h"
#include "rs_surface_render_node.h"
#include <screen_manager/screen_types.h>
#include "screen_manager/rs_screen_info.h"
#ifdef NEW_RENDER_CONTEXT
#include "rs_render_surface.h"
#else
#include "platform/drawing/rs_surface.h"
#endif

namespace OHOS {
namespace Rosen {
class RSB_EXPORT RSDisplayRenderNode : public RSRenderNode, public RSSurfaceHandler {
public:
    enum CompositeType {
        UNI_RENDER_COMPOSITE = 0,
        UNI_RENDER_MIRROR_COMPOSITE,
        UNI_RENDER_EXPAND_COMPOSITE,
        HARDWARE_COMPOSITE,
        SOFTWARE_COMPOSITE
    };
    using WeakPtr = std::weak_ptr<RSDisplayRenderNode>;
    using SharedPtr = std::shared_ptr<RSDisplayRenderNode>;
    static inline constexpr RSRenderNodeType Type = RSRenderNodeType::DISPLAY_NODE;

    ~RSDisplayRenderNode() override;
    void SetIsOnTheTree(bool flag, NodeId instanceRootNodeId = INVALID_NODEID,
        NodeId firstLevelNodeId = INVALID_NODEID, NodeId cacheNodeId = INVALID_NODEID,
        NodeId uifirstRootNodeId = INVALID_NODEID) override;

    void SetScreenId(uint64_t screenId)
    {
        screenId_ = screenId;
    }

    uint64_t GetScreenId() const
    {
        return screenId_;
    }

    void SetRogSize(uint32_t rogWidth, uint32_t rogHeight)
    {
        rogWidth_ = rogWidth;
        rogHeight_ = rogHeight;
    }

    uint32_t GetRogWidth() const
    {
        return rogWidth_;
    }

    void SetRenderWindowsName(std::vector<std::string>& windowsName)
    {
        windowsName_ = windowsName;
    }

    std::vector<std::string>& GetRenderWindowName()
    {
        return windowsName_;
    }

    uint32_t GetRogHeight() const
    {
        return rogHeight_;
    }

    void SetDisplayOffset(int32_t offsetX, int32_t offsetY)
    {
        offsetX_ = offsetX;
        offsetY_ = offsetY;
    }

    int32_t GetDisplayOffsetX() const
    {
        return offsetX_;
    }

    int32_t GetDisplayOffsetY() const
    {
        return offsetY_;
    }

    bool GetFingerprint() const
    {
        return hasFingerprint_;
    }

    void SetFingerprint(bool hasFingerprint)
    {
        hasFingerprint_ = hasFingerprint;
    }

    void SetScreenRotation(const ScreenRotation& screenRotation)
    {
        screenRotation_ = screenRotation;
    }

    ScreenRotation GetScreenRotation()
    {
        return screenRotation_;
    }

    void CollectSurface(
        const std::shared_ptr<RSBaseRenderNode>& node, std::vector<RSBaseRenderNode::SharedPtr>& vec,
        bool isUniRender, bool onlyFirstLevel) override;
    void QuickPrepare(const std::shared_ptr<RSNodeVisitor>& visitor) override;
    void Prepare(const std::shared_ptr<RSNodeVisitor>& visitor) override;
    void Process(const std::shared_ptr<RSNodeVisitor>& visitor) override;

    RSRenderNodeType GetType() const override
    {
        return RSRenderNodeType::DISPLAY_NODE;
    }

    bool IsMirrorDisplay() const;

    void SetCompositeType(CompositeType type);
    CompositeType GetCompositeType() const;
    void SetForceSoftComposite(bool flag);
    bool IsForceSoftComposite() const;
    void SetMirrorSource(SharedPtr node);
    void ResetMirrorSource();
    void SetIsMirrorDisplay(bool isMirror);
    void SetSecurityDisplay(bool isSecurityDisplay);
    bool GetSecurityDisplay() const;
    bool SkipFrame(uint32_t skipFrameInterval) override;
    void SetBootAnimation(bool isBootAnimation) override;
    bool GetBootAnimation() const override;
    WeakPtr GetMirrorSource() const
    {
        return mirrorSource_;
    }

    bool HasDisappearingTransition(bool) const override
    {
        return false;
    }
#ifdef NEW_RENDER_CONTEXT
    std::shared_ptr<RSRenderSurface> GetRSSurface() const
    {
        return surface_;
    }
    void SetVirtualSurface(std::shared_ptr<RSRenderSurface>& virtualSurface, uint64_t pSurfaceUniqueId)
    {
        virtualSurface_ = virtualSurface;
        virtualSurfaceUniqueId_ = pSurfaceUniqueId;
    }
    std::shared_ptr<RSRenderSurface> GetVirtualSurface(uint64_t pSurfaceUniqueId)
    {
        return virtualSurfaceUniqueId_ != pSurfaceUniqueId ? nullptr : virtualSurface_;
    }
#else
    std::shared_ptr<RSSurface> GetRSSurface() const
    {
        return surface_;
    }
    void SetVirtualSurface(std::shared_ptr<RSSurface>& virtualSurface, uint64_t pSurfaceUniqueId)
    {
        virtualSurface_ = virtualSurface;
        virtualSurfaceUniqueId_ = pSurfaceUniqueId;
    }
    std::shared_ptr<RSSurface> GetVirtualSurface(uint64_t pSurfaceUniqueId)
    {
        return virtualSurfaceUniqueId_ != pSurfaceUniqueId ? nullptr : virtualSurface_;
    }
#endif
    // Use in vulkan parallel rendering
    void SetIsParallelDisplayNode(bool isParallelDisplayNode)
    {
        isParallelDisplayNode_ = isParallelDisplayNode;
    }

    bool IsParallelDisplayNode() const
    {
        return isParallelDisplayNode_;
    }

#ifndef ROSEN_CROSS_PLATFORM
    bool CreateSurface(sptr<IBufferConsumerListener> listener);
    sptr<IBufferConsumerListener> GetConsumerListener() const
    {
        return consumerListener_;
    }
#endif

    bool IsSurfaceCreated() const
    {
        return surfaceCreated_;
    }

    ScreenRotation GetRotation() const;

    std::shared_ptr<RSDirtyRegionManager> GetDirtyManager() const
    {
        return dirtyManager_;
    }
    std::shared_ptr<RSDirtyRegionManager> GetSyncDirtyManager() const
    {
        return syncDirtyManager_;
    }
    void UpdateDisplayDirtyManager(int32_t bufferage, bool useAlignedDirtyRegion = false, bool renderParallel = false);
    void ClearCurrentSurfacePos();
    void UpdateSurfaceNodePos(NodeId id, RectI rect)
    {
// add: #if defined(RS_ENABLE_PARALLEL_RENDER) && (defined (RS_ENABLE_GL) || defined (RS_ENABLE_VK))
// add:     std::unique_lock<std::mutex> lock(mtx_);
// add: #endif
        currentFrameSurfacePos_[id] = rect;
    }

    RectI GetLastFrameSurfacePos(NodeId id)
    {
        if (lastFrameSurfacePos_.count(id) == 0) {
            return {};
        }
        return lastFrameSurfacePos_[id];
    }

    RectI GetCurrentFrameSurfacePos(NodeId id)
    {
        if (currentFrameSurfacePos_.count(id) == 0) {
            return {};
        }
        return currentFrameSurfacePos_[id];
    }

    const std::vector<RectI> GetSurfaceChangedRects() const
    {
        std::vector<RectI> rects;
        for (const auto& lastFrameSurfacePo : lastFrameSurfacePos_) {
            if (currentFrameSurfacePos_.find(lastFrameSurfacePo.first) == currentFrameSurfacePos_.end()) {
                rects.emplace_back(lastFrameSurfacePo.second);
            }
        }
        for (const auto& currentFrameSurfacePo : currentFrameSurfacePos_) {
            if (lastFrameSurfacePos_.find(currentFrameSurfacePo.first) == lastFrameSurfacePos_.end()) {
                rects.emplace_back(currentFrameSurfacePo.second);
            }
        }
        return rects;
    }

    std::vector<RSBaseRenderNode::SharedPtr>& GetCurAllSurfaces()
    {
        return curAllSurfaces_;
    }
    std::vector<RSBaseRenderNode::SharedPtr>& GetCurAllSurfaces(bool onlyFirstLevel)
    {
        return onlyFirstLevel ? curAllFirstLevelSurfaces_ : curAllSurfaces_;
    }

    void UpdateRenderParams() override;
    void UpdatePartialRenderParams();
    void UpdateScreenRenderParams(ScreenInfo& screenInfo, std::map<ScreenId, bool>& displayHasSecSurface,
        std::map<ScreenId, bool>& displayHasSkipSurface, std::map<ScreenId, bool>& displayHasProtectedSurface,
        std::map<ScreenId, bool>& hasCaptureWindow);
    void UpdateOffscreenRenderParams(bool needOffscreen);
    void RecordMainAndLeashSurfaces(RSBaseRenderNode::SharedPtr surface);
    std::vector<RSBaseRenderNode::SharedPtr>& GetAllMainAndLeashSurfaces() { return curMainAndLeashSurfaceNodes_;}

    void UpdateRotation();
    bool IsRotationChanged() const;
    bool IsLastRotationChanged() const {
        return lastRotationChanged_;
    }
    bool IsFirstTimeToProcessor() const {
        return isFirstTimeToProcessor_;
    }

    void SetOriginScreenRotation(const ScreenRotation& rotate) {
        originScreenRotation_ = rotate;
        isFirstTimeToProcessor_ = false;
    }
    ScreenRotation GetOriginScreenRotation() const {
        return originScreenRotation_;
    }

    void SetInitMatrix(const Drawing::Matrix& matrix) {
        initMatrix_ = matrix;
        isFirstTimeToProcessor_ = false;
    }

    const Drawing::Matrix& GetInitMatrix() const {
        return initMatrix_;
    }

    std::shared_ptr<Drawing::Image> GetCacheImgForCapture() {
        return cacheImgForCapture_;
    }
    void SetCacheImgForCapture(std::shared_ptr<Drawing::Image> cacheImgForCapture) {
        cacheImgForCapture_ = cacheImgForCapture;
    }
    std::shared_ptr<Drawing::Image> GetOffScreenCacheImgForCapture() {
        return offScreenCacheImgForCapture_;
    }
    void SetOffScreenCacheImgForCapture(std::shared_ptr<Drawing::Image> offScreenCacheImgForCapture) {
        offScreenCacheImgForCapture_ = offScreenCacheImgForCapture;
    }
    NodeId GetRootIdOfCaptureWindow() {
        return rootIdOfCaptureWindow_;
    }
    void SetRootIdOfCaptureWindow(NodeId rootIdOfCaptureWindow) {
        rootIdOfCaptureWindow_ = rootIdOfCaptureWindow;
    }
    bool GetResetRotate() const {
        return resetRotate_;
    }
    void SetResetRotate(bool resetRotate) {
        resetRotate_ = resetRotate;
    }

    void SetMainAndLeashSurfaceDirty(bool isDirty);

    void SetHDRPresent(bool hdrPresent);

    std::map<NodeId, std::shared_ptr<RSSurfaceRenderNode>>& GetDirtySurfaceNodeMap()
    {
        return dirtySurfaceNodeMap_;
    }

    void ClearSurfaceSrcRect()
    {
        surfaceSrcRects_.clear();
    }

    void ClearSurfaceDstRect()
    {
        surfaceDstRects_.clear();
    }

    void ClearSurfaceTotalMatrix()
    {
        surfaceTotalMatrix_.clear();
    }

    void SetSurfaceSrcRect(NodeId id, RectI rect)
    {
        surfaceSrcRects_[id] = rect;
    }

    void SetSurfaceDstRect(NodeId id, RectI rect)
    {
        surfaceDstRects_[id] = rect;
    }

    void SetSurfaceTotalMatrix(NodeId id, const Drawing::Matrix& totalMatrix)
    {
        surfaceTotalMatrix_[id] = totalMatrix;
    }

    RectI GetSurfaceSrcRect(NodeId id) const
    {
        auto iter = surfaceSrcRects_.find(id);
        if (iter == surfaceSrcRects_.cend()) {
            return RectI();
        }

        return iter->second;
    }

    RectI GetSurfaceDstRect(NodeId id) const
    {
        auto iter = surfaceDstRects_.find(id);
        if (iter == surfaceDstRects_.cend()) {
            return {};
        }

        return iter->second;
    }

    Drawing::Matrix GetSurfaceTotalMatrix(NodeId id) const
    {
        auto iter = surfaceTotalMatrix_.find(id);
        if (iter == surfaceTotalMatrix_.cend()) {
            return {};
        }

        return iter->second;
    }

    // Use in MultiLayersPerf
    int GetSurfaceCountForMultiLayersPerf() const
    {
        return surfaceCountForMultiLayersPerf_;
    }

    const std::vector<NodeId>& GetLastSurfaceIds() const {
        return lastSurfaceIds_;
    }

    void SetLastSurfaceIds(std::vector<NodeId> lastSurfaceIds) {
        lastSurfaceIds_ = std::move(lastSurfaceIds);
    }

    const std::vector<RectI>& GetDirtyRects() const
    {
        return dirtyRects_;
    }

    void SetDirtyRects(const std::vector<RectI>& rects)
    {
        dirtyRects_ = rects;
    }

    void SetScbNodePid(const std::vector<int32_t>& oldScbPids, int32_t currentScbPid)
    {
        oldScbPids_ = oldScbPids;
        currentScbPid_ = currentScbPid;
        isNeedWaitNewScbPid_ = true;
    }

    std::vector<int32_t> GetOldScbPids() const
    {
        return oldScbPids_;
    }

    int32_t GetCurrentScbPid() const
    {
        return currentScbPid_;
    }

    ChildrenListSharedPtr GetSortedChildren() const override;

protected:
    void OnSync() override;
private:
    explicit RSDisplayRenderNode(
        NodeId id, const RSDisplayNodeConfig& config, const std::weak_ptr<RSContext>& context = {});
    void InitRenderParams() override;
    void HandleCurMainAndLeashSurfaceNodes();
    // vector of sufacenodes will records dirtyregions by itself
    std::vector<RSBaseRenderNode::SharedPtr> curMainAndLeashSurfaceNodes_;
    CompositeType compositeType_ { HARDWARE_COMPOSITE };
    ScreenRotation screenRotation_ = ScreenRotation::ROTATION_0;
    ScreenRotation originScreenRotation_ = ScreenRotation::ROTATION_0;
    uint64_t screenId_;
    int32_t offsetX_;
    int32_t offsetY_;
    uint32_t rogWidth_;
    uint32_t rogHeight_;
    bool forceSoftComposite_ { false };
    bool isMirroredDisplay_ = false;
    bool isSecurityDisplay_ = false;
    WeakPtr mirrorSource_;
    float lastRotation_ = 0.f;
    bool lastRotationChanged_ = false;
    Drawing::Matrix initMatrix_;
    bool isFirstTimeToProcessor_ = true;
#ifdef NEW_RENDER_CONTEXT
    std::shared_ptr<RSRenderSurface> surface_;
    std::shared_ptr<RSRenderSurface> virtualSurface_;
#else
    std::shared_ptr<RSSurface> surface_;
    std::shared_ptr<RSSurface> virtualSurface_;
#endif
    uint64_t virtualSurfaceUniqueId_ = 0;
    bool surfaceCreated_ { false };
    bool hasFingerprint_ = false;
#ifndef ROSEN_CROSS_PLATFORM
    sptr<IBufferConsumerListener> consumerListener_;
#endif
    uint64_t frameCount_ = 0;

    std::map<NodeId, RectI> lastFrameSurfacePos_;
    std::map<NodeId, RectI> currentFrameSurfacePos_;
    std::shared_ptr<RSDirtyRegionManager> dirtyManager_ = nullptr;
    std::vector<std::string> windowsName_;
    std::shared_ptr<RSDirtyRegionManager> syncDirtyManager_ = nullptr;

    std::vector<RSBaseRenderNode::SharedPtr> curAllSurfaces_;
    std::vector<RSBaseRenderNode::SharedPtr> curAllFirstLevelSurfaces_;
    std::mutex mtx_;

    // Use in screen recording optimization
    std::shared_ptr<Drawing::Image> cacheImgForCapture_ = nullptr;
    std::shared_ptr<Drawing::Image> offScreenCacheImgForCapture_ = nullptr;
    NodeId rootIdOfCaptureWindow_ = INVALID_NODEID;
    bool resetRotate_ = false;

    // Use in vulkan parallel rendering
    bool isParallelDisplayNode_ = false;

    // Use in MultiLayersPerf
    int surfaceCountForMultiLayersPerf_ = 0;

    std::map<NodeId, std::shared_ptr<RSSurfaceRenderNode>> dirtySurfaceNodeMap_;

	// support multiscreen
    std::map<NodeId, RectI> surfaceSrcRects_;
    std::map<NodeId, RectI> surfaceDstRects_;
    std::map<NodeId, Drawing::Matrix> surfaceTotalMatrix_;

    std::vector<NodeId> lastSurfaceIds_;
    std::vector<RectI> dirtyRects_;

    std::vector<int32_t> oldScbPids_ {};
    int32_t currentScbPid_ = -1;
    mutable bool isNeedWaitNewScbPid_ = false;
    mutable std::shared_ptr<std::vector<std::shared_ptr<RSRenderNode>>> currentChildrenList_ =
        std::make_shared<std::vector<std::shared_ptr<RSRenderNode>>>();

    friend class DisplayNodeCommandHelper;
};
} // namespace Rosen
} // namespace OHOS

#endif // RENDER_SERVICE_CLIENT_CORE_PIPELINE_RS_DISPLAY_RENDER_NODE_H
