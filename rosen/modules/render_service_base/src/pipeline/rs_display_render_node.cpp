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

#include "pipeline/rs_display_render_node.h"

#include "common/rs_obj_abs_geometry.h"
#include "common/rs_optional_trace.h"
#include "common/rs_special_layer_manager.h"
#include "params/rs_display_render_params.h"
#include "pipeline/rs_render_node.h"
#include "pipeline/rs_surface_render_node.h"
#include "platform/common/rs_log.h"
#include "screen_manager/screen_types.h"
#include "visitor/rs_node_visitor.h"
#include "transaction/rs_render_service_client.h"
namespace OHOS {
namespace Rosen {
constexpr int64_t MAX_JITTER_NS = 2000000; // 2ms

RSDisplayRenderNode::RSDisplayRenderNode(
    NodeId id, const RSDisplayNodeConfig& config, const std::weak_ptr<RSContext>& context)
    : RSRenderNode(id, context), isMirroredDisplay_(config.isMirrored), offsetX_(0), offsetY_(0),
      screenId_(config.screenId), dirtyManager_(std::make_shared<RSDirtyRegionManager>(true))
{
    RS_LOGI("RSScreen RSDisplayRenderNode ctor id:%{public}" PRIu64 ", config[screenid:%{public}" PRIu64
        ", isMirrored%{public}d, mirrorNodeId:%{public}" PRIu64 ", isSync:%{public}d",
        id, screenId_, config.isMirror, config.mirrorNodeId, config.isSync);
    MemoryInfo info = {sizeof(*this), ExtractPid(id), id, MEMORY_TYPE::MEM_RENDER_NODE};
    MemoryTrack::Instance().AddNodeRecord(id, info);
    MemorySnapshot::Instance().AddCpuMemory(ExtractPid(id), sizeof(*this));
}

RSDisplayRenderNode::~RSDisplayRenderNode()
{
    RS_LOGI("RSScreen RSDisplayRenderNode dtor id:%{public}" PRIu64 ", screenId:%{public}" PRIu64, GetId(), screenId_);
    MemoryTrack::Instance().RemoveNodeRecord(GetId());
    MemorySnapshot::Instance().RemoveCpuMemory(ExtractPid(GetId()), sizeof(*this));
}

void RSDisplayRenderNode::CollectSurface(
    const std::shared_ptr<RSBaseRenderNode>& node, std::vector<RSBaseRenderNode::SharedPtr>& vec, bool isUniRender,
    bool onlyFirstLevel)
{
    for (auto& child : *node->GetSortedChildren()) {
        child->CollectSurface(child, vec, isUniRender, onlyFirstLevel);
    }
}

void RSDisplayRenderNode::QuickPrepare(const std::shared_ptr<RSNodeVisitor>& visitor)
{
    if (!visitor) {
        return;
    }
    ApplyModifiers();
    visitor->QuickPrepareDisplayRenderNode(*this);
}

void RSDisplayRenderNode::Prepare(const std::shared_ptr<RSNodeVisitor>& visitor)
{
    if (!visitor) {
        return;
    }
    ApplyModifiers();
    visitor->PrepareDisplayRenderNode(*this);
}

void RSDisplayRenderNode::Process(const std::shared_ptr<RSNodeVisitor>& visitor)
{
    if (!visitor) {
        return;
    }
    RSRenderNode::RenderTraceDebug();
    visitor->ProcessDisplayRenderNode(*this);
}

void RSDisplayRenderNode::SetIsOnTheTree(bool flag, NodeId instanceRootNodeId, NodeId firstLevelNodeId,
    NodeId cacheNodeId, NodeId uifirstRootNodeId, NodeId displayNodeId)
{
    // if node is marked as cacheRoot, update subtree status when update surface
    // in case prepare stage upper cacheRoot cannot specify dirty subnode
    RSRenderNode::SetIsOnTheTree(flag, GetId(), firstLevelNodeId, cacheNodeId, uifirstRootNodeId, GetId());
}

void RSDisplayRenderNode::SetScreenId(uint64_t screenId)
{
	if (releaseScreenDmaBufferTask_ && screenId_ != screenId) {
		releaseScreenDmaBufferTask_(screenId_);
	}
	RS_TRACE_NAME_FMT("RSScreenManager %s:displayNode[%" PRIu64 "] change screen [%" PRIu64 "] "
		"to [%" PRIu64 "].", __func__, GetId(), screenId_, screenId);
	RS_LOGW("RSScreenManager %{public}s:displayNode[%{public}" PRIu64 "] change screen [%{public}" PRIu64 "] "
		"to [%{public}" PRIu64 "].", __func__, GetId(), screenId_, screenId);
	screenId_ = screenId;
}

RSDisplayRenderNode::CompositeType RSDisplayRenderNode::GetCompositeType() const
{
    return compositeType_;
}

void RSDisplayRenderNode::SetCompositeType(RSDisplayRenderNode::CompositeType type)
{
    compositeType_ = type;
}

void RSDisplayRenderNode::SetForceSoftComposite(bool flag)
{
    forceSoftComposite_ = flag;
}

bool RSDisplayRenderNode::IsForceSoftComposite() const
{
    return forceSoftComposite_;
}

void RSDisplayRenderNode::SetMirrorSource(SharedPtr node)
{
    if (!isMirroredDisplay_ || node == nullptr) {
        return;
    }
    mirrorSource_ = node;
}

void RSDisplayRenderNode::ResetMirrorSource()
{
    mirrorSource_.reset();
}

bool RSDisplayRenderNode::IsMirrorDisplay() const
{
    return isMirroredDisplay_;
}

void RSDisplayRenderNode::SetSecurityDisplay(bool isSecurityDisplay)
{
    isSecurityDisplay_ = isSecurityDisplay;
}

bool RSDisplayRenderNode::GetSecurityDisplay() const
{
    return isSecurityDisplay_;
}

void RSDisplayRenderNode::SetIsMirrorDisplay(bool isMirror)
{
    isMirroredDisplay_ = isMirror;
    RS_LOGD("RSDisplayRenderNode::SetIsMirrorDisplay, node id:[%{public}" PRIu64 "], isMirrorDisplay: [%{public}s]",
        GetId(), IsMirrorDisplay() ? "true" : "false");
}

void RSDisplayRenderNode::SetBootAnimation(bool isBootAnimation)
{
    ROSEN_LOGD("SetBootAnimation:: id:[%{public}" PRIu64 ", isBootAnimation:%{public}d",
        GetId(), isBootAnimation);
    isBootAnimation_ = isBootAnimation;

    auto parent = GetParent().lock();
    if (parent == nullptr) {
        return;
    }
    if (isBootAnimation) {
        parent->SetContainBootAnimation(true);
    }
}

bool RSDisplayRenderNode::GetBootAnimation() const
{
    return isBootAnimation_;
}

void RSDisplayRenderNode::InitRenderParams()
{
#ifdef RS_ENABLE_GPU
    stagingRenderParams_ = std::make_unique<RSDisplayRenderParams>(GetId());
    DrawableV2::RSRenderNodeDrawableAdapter::OnGenerate(shared_from_this());
    if (renderDrawable_ == nullptr) {
        RS_LOGE("RSDisplayRenderNode::InitRenderParams failed");
        return;
    }
#endif
}

ReleaseDmaBufferTask RSDisplayRenderNode::releaseScreenDmaBufferTask_;
void RSDisplayRenderNode::SetReleaseTask(ReleaseDmaBufferTask callback)
{
    if (!releaseScreenDmaBufferTask_ && callback) {
        releaseScreenDmaBufferTask_ = callback;
    } else {
        RS_LOGE("RreleaseScreenDmaBufferTask_ register failed!");
    }
}

void RSDisplayRenderNode::OnSync()
{
#ifdef RS_ENABLE_GPU
    RS_OPTIONAL_TRACE_NAME_FMT("RSDisplayRenderNode::OnSync global dirty[%s]",
        dirtyManager_->GetCurrentFrameDirtyRegion().ToString().c_str());
    auto displayParams = static_cast<RSDisplayRenderParams*>(stagingRenderParams_.get());
    if (displayParams == nullptr) {
        RS_LOGE("RSDisplayRenderNode::OnSync displayParams is null");
        return;
    }
    if (!renderDrawable_) {
        return;
    }
    auto syncDirtyManager = renderDrawable_->GetSyncDirtyManager();
    dirtyManager_->OnSync(syncDirtyManager);
    displayParams->SetZoomed(curZoomState_);
    displayParams->SetNeedSync(true);
    RSRenderNode::OnSync();
#endif
}

void RSDisplayRenderNode::HandleCurMainAndLeashSurfaceNodes()
{
    surfaceCountForMultiLayersPerf_ = 0;
    for (const auto& surface : curMainAndLeashSurfaceNodes_) {
        auto surfaceNode = RSBaseRenderNode::ReinterpretCast<RSSurfaceRenderNode>(surface);
        if (!surfaceNode || surfaceNode->IsLeashWindow() || !surfaceNode->IsOnTheTree()) {
            continue;
        }
        surfaceCountForMultiLayersPerf_++;
    }
    curMainAndLeashSurfaceNodes_.clear();
}

void RSDisplayRenderNode::RecordMainAndLeashSurfaces(RSBaseRenderNode::SharedPtr surface)
{
    curMainAndLeashSurfaceNodes_.push_back(surface);
}

void RSDisplayRenderNode::RecordTopSurfaceOpaqueRects(Occlusion::Rect rect)
{
    topSurfaceOpaqueRects_.push_back(rect);
}

void RSDisplayRenderNode::UpdateRenderParams()
{
#ifdef RS_ENABLE_GPU
    auto displayParams = static_cast<RSDisplayRenderParams*>(stagingRenderParams_.get());
    if (displayParams == nullptr) {
        RS_LOGE("RSDisplayRenderNode::UpdateRenderParams displayParams is null");
        return;
    }
    displayParams->offsetX_ = GetDisplayOffsetX();
    displayParams->offsetY_ = GetDisplayOffsetY();
    displayParams->nodeRotation_ = GetRotation();
    auto mirroredNode = GetMirrorSource().lock();
    if (mirroredNode == nullptr) {
        displayParams->mirrorSourceId_ = INVALID_NODEID;
        displayParams->mirrorSourceDrawable_.reset();
        RS_LOGW("RSDisplayRenderNode::UpdateRenderParams mirroredNode is null");
    } else {
        displayParams->mirrorSourceDrawable_ = mirroredNode->GetRenderDrawable();
        displayParams->mirrorSourceId_ = mirroredNode->GetId();
    }
    displayParams->isSecurityExemption_ = isSecurityExemption_;
    displayParams->mirrorSource_ = GetMirrorSource();
    displayParams->hasSecLayerInVisibleRect_ = hasSecLayerInVisibleRect_;
    displayParams->hasSecLayerInVisibleRectChanged_ = hasSecLayerInVisibleRectChanged_;
    RSRenderNode::UpdateRenderParams();
#endif
}

void RSDisplayRenderNode::UpdateScreenRenderParams(ScreenRenderParams& screenRenderParams)
{
#ifdef RS_ENABLE_GPU
    auto displayParams = static_cast<RSDisplayRenderParams*>(stagingRenderParams_.get());
    if (displayParams == nullptr) {
        RS_LOGE("RSDisplayRenderNode::UpdateScreenRenderParams displayParams is null");
        return;
    }
    displayParams->screenId_ = GetScreenId();
    displayParams->screenRotation_ = GetScreenRotation();
    displayParams->compositeType_ = GetCompositeType();
    displayParams->hasChildCrossNode_ = HasChildCrossNode();
    displayParams->isMirrorScreen_ = IsMirrorScreen();
    displayParams->isFirstVisitCrossNodeDisplay_ = IsFirstVisitCrossNodeDisplay();
    displayParams->isSecurityDisplay_ = GetSecurityDisplay();
    displayParams->screenInfo_ = std::move(screenRenderParams.screenInfo);
    displayParams->specialLayerManager_ = specialLayerManager_;
    displayParams->displaySpecailSurfaceChanged_ = std::move(screenRenderParams.displaySpecailSurfaceChanged);
    displayParams->hasCaptureWindow_ = std::move(screenRenderParams.hasCaptureWindow);
#endif
}

void RSDisplayRenderNode::UpdateOffscreenRenderParams(bool needOffscreen)
{
#ifdef RS_ENABLE_GPU
    auto displayParams = static_cast<RSDisplayRenderParams*>(stagingRenderParams_.get());
    if (displayParams == nullptr) {
        RS_LOGE("RSDisplayRenderNode::UpdateOffscreenRenderParams displayParams is null");
        return;
    }
    displayParams->SetNeedOffscreen(needOffscreen);
#endif
}

void RSDisplayRenderNode::UpdatePartialRenderParams()
{
#ifdef RS_ENABLE_GPU
    auto displayParams = static_cast<RSDisplayRenderParams*>(stagingRenderParams_.get());
    if (displayParams == nullptr) {
        RS_LOGE("RSDisplayRenderNode::UpdatePartialRenderParams displayParams is null");
        return;
    }
    displayParams->SetAllMainAndLeashSurfaces(curMainAndLeashSurfaceNodes_);
#endif
}

bool RSDisplayRenderNode::SkipFrame(uint32_t refreshRate, uint32_t skipFrameInterval)
{
    if (refreshRate == 0 || skipFrameInterval <= 1) {
        return false;
    }
    int64_t currentTime = std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    // when refreshRate % skipFrameInterval != 0 means the skipFrameInterval is the virtual screen refresh rate
    if (refreshRate % skipFrameInterval != 0) {
        int64_t minFrameInterval = 1000000000LL / skipFrameInterval;
        if (minFrameInterval == 0) {
            return false;
        }
        // lastRefreshTime_ is next frame expected refresh time for virtual display
        if (lastRefreshTime_ <= 0) {
            lastRefreshTime_ = currentTime + minFrameInterval;
            return false;
        }
        if (currentTime < (lastRefreshTime_ - MAX_JITTER_NS)) {
            return true;
        }
        int64_t intervalNums = (currentTime - lastRefreshTime_ + MAX_JITTER_NS) / minFrameInterval;
        lastRefreshTime_ += (intervalNums + 1) * minFrameInterval;
        return false;
    }
    // the skipFrameInterval is equal to 60 divide the virtual screen refresh rate
    int64_t refreshInterval = currentTime - lastRefreshTime_;
    // 1000000000ns == 1s, 110/100 allows 10% over.
    bool needSkip = refreshInterval < (1000000000LL / refreshRate) * (skipFrameInterval - 1) * 110 / 100;
    if (!needSkip) {
        lastRefreshTime_ = currentTime;
    }
    return needSkip;
}

void RSDisplayRenderNode::SetDisplayGlobalZOrder(float zOrder)
{
#ifdef RS_ENABLE_GPU
    auto displayParams = static_cast<RSDisplayRenderParams*>(stagingRenderParams_.get());
    if (displayParams == nullptr) {
        RS_LOGE("RSDisplayRenderNode::SetDisplayGlobalZOrder displayParams is null");
        return;
    }
    displayParams->SetGlobalZOrder(zOrder);
#endif
}


ScreenRotation RSDisplayRenderNode::GetRotation() const
{
    auto& boundsGeoPtr = (GetRenderProperties().GetBoundsGeometry());
    if (boundsGeoPtr == nullptr) {
        return ScreenRotation::ROTATION_0;
    }
    // -90.0f: convert rotation degree to 4 enum values
    return static_cast<ScreenRotation>(static_cast<int32_t>(std::roundf(boundsGeoPtr->GetRotation() / -90.0f)) % 4);
}

bool RSDisplayRenderNode::IsRotationChanged() const
{
    auto& boundsGeoPtr = (GetRenderProperties().GetBoundsGeometry());
    if (boundsGeoPtr == nullptr) {
        return false;
    }
    // boundsGeoPtr->IsNeedClientCompose() return false if rotation degree is times of 90
    // which means rotation is end.
    bool isRotationEnd = !boundsGeoPtr->IsNeedClientCompose();
    return !(ROSEN_EQ(boundsGeoPtr->GetRotation(), lastRotation_) && isRotationEnd);
}

bool RSDisplayRenderNode::IsRotationFinished() const
{
    auto& boundsGeoPtr = (GetRenderProperties().GetBoundsGeometry());
    if (boundsGeoPtr == nullptr) {
        return false;
    }
    // boundsGeoPtr->IsNeedClientCompose() return false if rotation degree is times of 90
    // which means rotation is end.
    bool isRotationEnd = !boundsGeoPtr->IsNeedClientCompose();
    return !ROSEN_EQ(boundsGeoPtr->GetRotation(), lastRotation_) && isRotationEnd;
}

void RSDisplayRenderNode::UpdateRotation()
{
#ifdef RS_ENABLE_GPU
    auto displayParams = static_cast<RSDisplayRenderParams*>(stagingRenderParams_.get());
    if (displayParams == nullptr) {
        RS_LOGE("%{public}s displayParams is nullptr", __func__);
        return;
    }
    AddToPendingSyncList();

    auto& boundsGeoPtr = (GetRenderProperties().GetBoundsGeometry());
    if (boundsGeoPtr == nullptr) {
        return;
    }
    displayParams->SetRotationFinished(IsRotationFinished());
    lastRotationChanged_ = IsRotationChanged();
    lastRotation_ = boundsGeoPtr->GetRotation();
    preRotationStatus_ = curRotationStatus_;
    curRotationStatus_ = IsRotationChanged();
    displayParams->SetRotationChanged(curRotationStatus_);
#endif
}

void RSDisplayRenderNode::UpdateDisplayDirtyManager(int32_t bufferage, bool useAlignedDirtyRegion)
{
    dirtyManager_->SetBufferAge(bufferage);
    dirtyManager_->UpdateDirty(useAlignedDirtyRegion);
}

void RSDisplayRenderNode::ClearCurrentSurfacePos()
{
    lastFrameSurfacePos_ = std::move(currentFrameSurfacePos_);
    lastFrameSurfacesByDescZOrder_ = std::move(currentFrameSurfacesByDescZOrder_);
}

void RSDisplayRenderNode::SetMainAndLeashSurfaceDirty(bool isDirty)
{
#ifdef RS_ENABLE_GPU
    auto displayParams = static_cast<RSDisplayRenderParams*>(stagingRenderParams_.get());
    if (displayParams == nullptr) {
        RS_LOGE("%{public}s displayParams is nullptr", __func__);
        return;
    }
    displayParams->SetMainAndLeashSurfaceDirty(isDirty);
    if (stagingRenderParams_->NeedSync()) {
        AddToPendingSyncList();
    }
#endif
}

void RSDisplayRenderNode::SetFingerprint(bool hasFingerprint)
{
#ifdef RS_ENABLE_GPU
    if (hasFingerprint_ == hasFingerprint) {
        return;
    }
    auto displayParams = static_cast<RSDisplayRenderParams*>(stagingRenderParams_.get());
    if (displayParams == nullptr) {
        RS_LOGE("%{public}s displayParams is nullptr", __func__);
        return;
    }
    displayParams->SetFingerprint(hasFingerprint);
    if (stagingRenderParams_->NeedSync()) {
        AddToPendingSyncList();
    }
    hasFingerprint_ = hasFingerprint;
#endif
}

void RSDisplayRenderNode::SetHDRPresent(bool hdrPresent)
{
#ifdef RS_ENABLE_GPU
    auto displayParams = static_cast<RSDisplayRenderParams*>(stagingRenderParams_.get());
    if (displayParams == nullptr) {
        RS_LOGE("%{public}s displayParams is nullptr", __func__);
        return;
    }
    displayParams->SetHDRPresent(hdrPresent);
    if (stagingRenderParams_->NeedSync()) {
        AddToPendingSyncList();
    }
#endif
}

void RSDisplayRenderNode::SetBrightnessRatio(float brightnessRatio)
{
#ifdef RS_ENABLE_GPU
    auto displayParams = static_cast<RSDisplayRenderParams*>(stagingRenderParams_.get());
    if (displayParams == nullptr) {
        RS_LOGE("%{public}s displayParams is nullptr", __func__);
        return;
    }
    displayParams->SetBrightnessRatio(brightnessRatio);
    if (stagingRenderParams_->NeedSync()) {
        AddToPendingSyncList();
    }
#endif
}

void RSDisplayRenderNode::SetPixelFormat(const GraphicPixelFormat& pixelFormat)
{
#ifdef RS_ENABLE_GPU
    if (pixelFormat_ == pixelFormat) {
        return;
    }
    auto displayParams = static_cast<RSDisplayRenderParams*>(stagingRenderParams_.get());
    if (!displayParams) {
        RS_LOGE("%{public}s displayParams is nullptr", __func__);
        return;
    }
    displayParams->SetNewPixelFormat(pixelFormat);
    if (stagingRenderParams_->NeedSync()) {
        AddToPendingSyncList();
    }
    pixelFormat_ = pixelFormat;
#endif
}

GraphicPixelFormat RSDisplayRenderNode::GetPixelFormat() const
{
    return pixelFormat_;
}

void RSDisplayRenderNode::SetColorSpace(const GraphicColorGamut& colorSpace)
{
#ifdef RS_ENABLE_GPU
    if (colorSpace_ == colorSpace) {
        return;
    }
    auto displayParams = static_cast<RSDisplayRenderParams*>(stagingRenderParams_.get());
    if (displayParams == nullptr) {
        RS_LOGE("%{public}s displayParams is nullptr", __func__);
        return;
    }
    displayParams->SetNewColorSpace(colorSpace);
    if (stagingRenderParams_->NeedSync()) {
        AddToPendingSyncList();
    }
    colorSpace_ = colorSpace;
#endif
}

GraphicColorGamut RSDisplayRenderNode::GetColorSpace() const
{
    return colorSpace_;
}

RSRenderNode::ChildrenListSharedPtr RSDisplayRenderNode::GetSortedChildren() const
{
    int32_t currentScbPid = GetCurrentScbPid();
    ChildrenListSharedPtr fullChildrenList = RSRenderNode::GetSortedChildren();
    if (currentScbPid < 0) {
        return fullChildrenList;
    }
    if (isNeedWaitNewScbPid_) {
        for (auto it = (*fullChildrenList).rbegin(); it != (*fullChildrenList).rend(); ++it) {
            auto& child = *it;
            auto childPid = ExtractPid(child->GetId());
            if (childPid == currentScbPid) {
                RS_LOGI("child scb pid equals current scb pid");
                isNeedWaitNewScbPid_ = false;
                break;
            }
        }
    }
    if (isNeedWaitNewScbPid_ && lastScbPid_ < 0) {
        return fullChildrenList;
    }
    std::vector<int32_t> oldScbPids = GetOldScbPids();
    currentChildrenList_->clear();
    for (auto& child : *fullChildrenList) {
        if (child == nullptr) {
            continue;
        }
        auto childPid = ExtractPid(child->GetId());
        auto pidIter = std::find(oldScbPids.begin(), oldScbPids.end(), childPid);
        // only when isNeedWaitNewScbPid_ is ture, put lastScb's child to currentChildrenList_
        if (pidIter != oldScbPids.end() && (!isNeedWaitNewScbPid_ || childPid != lastScbPid_)) {
            child->SetIsOntheTreeOnlyFlag(false);
            continue;
        } else if (childPid == currentScbPid) {
            child->SetIsOntheTreeOnlyFlag(true);
        }
        currentChildrenList_->emplace_back(child);
    }
    isFullChildrenListValid_ = false;
    return std::atomic_load_explicit(&currentChildrenList_, std::memory_order_acquire);
}

Occlusion::Region RSDisplayRenderNode::GetDisappearedSurfaceRegionBelowCurrent(NodeId currentSurface) const
{
    Occlusion::Region result;
    auto it = std::find_if(lastFrameSurfacesByDescZOrder_.begin(), lastFrameSurfacesByDescZOrder_.end(),
        [currentSurface](const std::pair<NodeId, RectI>& surface) { return surface.first == currentSurface; });
    if (it == lastFrameSurfacesByDescZOrder_.end()) {
        return result;
    }

    for (++it; it != lastFrameSurfacesByDescZOrder_.end(); ++it) {
        if (currentFrameSurfacePos_.count(it->first) != 0) {
            break;
        }
        Occlusion::Region disappearedSurface{ Occlusion::Rect{ it->second } };
        result.OrSelf(disappearedSurface);
    }
    return result;
}

bool RSDisplayRenderNode::IsZoomStateChange() const
{
    return preZoomState_ != curZoomState_;
}


void RSDisplayRenderNode::SetScreenStatusNotifyTask(ScreenStatusNotifyTask task)
{
    screenStatusNotifyTask_ = task;
}

void RSDisplayRenderNode::NotifyScreenNotSwitching()
{
    if (screenStatusNotifyTask_) {
        screenStatusNotifyTask_(false);
        ROSEN_LOGI("RSDisplayRenderNode::NotifyScreenNotSwitching SetScreenSwitchStatus true");
        RS_TRACE_NAME_FMT("NotifyScreenNotSwitching");
    }
}

void RSDisplayRenderNode::SetWindowContainer(std::shared_ptr<RSBaseRenderNode> container)
{
    if (auto oldContainer = std::exchange(windowContainer_, container)) {
        if (container) {
            RS_LOGD("RSDisplayRenderNode::SetWindowContainer oldContainer: %{public}" PRIu64
                ", newContainer: %{public}" PRIu64, oldContainer->GetId(), container->GetId());
        } else {
            RS_LOGD("RSDisplayRenderNode::SetWindowContainer oldContainer: %{public}" PRIu64,
                oldContainer->GetId());
        }
    }
}

std::shared_ptr<RSBaseRenderNode> RSDisplayRenderNode::GetWindowContainer() const
{
    return windowContainer_;
}
} // namespace Rosen
} // namespace OHOS
