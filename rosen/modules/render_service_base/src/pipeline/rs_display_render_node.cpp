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
#include "params/rs_display_render_params.h"
#include "pipeline/rs_render_node.h"
#include "pipeline/rs_surface_render_node.h"
#include "platform/common/rs_log.h"
#include "screen_manager/screen_types.h"
#include "visitor/rs_node_visitor.h"
#include "transaction/rs_render_service_client.h"
namespace OHOS {
namespace Rosen {
RSDisplayRenderNode::RSDisplayRenderNode(
    NodeId id, const RSDisplayNodeConfig& config, const std::weak_ptr<RSContext>& context)
    : RSRenderNode(id, context), screenId_(config.screenId), offsetX_(0), offsetY_(0),
      isMirroredDisplay_(config.isMirrored), dirtyManager_(std::make_shared<RSDirtyRegionManager>(true))
{
    RS_LOGI("RSDisplayRenderNode ctor id:%{public}" PRIu64 "", id);
    MemoryInfo info = {sizeof(*this), ExtractPid(id), id, MEMORY_TYPE::MEM_RENDER_NODE};
    MemoryTrack::Instance().AddNodeRecord(id, info);
}

RSDisplayRenderNode::~RSDisplayRenderNode()
{
    RS_LOGI("RSDisplayRenderNode dtor id:%{public}" PRIu64 "", GetId());
    MemoryTrack::Instance().RemoveNodeRecord(GetId());
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
    NodeId cacheNodeId, NodeId uifirstRootNodeId)
{
    // if node is marked as cacheRoot, update subtree status when update surface
    // in case prepare stage upper cacheRoot cannot specify dirty subnode
    RSRenderNode::SetIsOnTheTree(flag, GetId(), firstLevelNodeId, cacheNodeId, uifirstRootNodeId);
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
    stagingRenderParams_ = std::make_unique<RSDisplayRenderParams>(GetId());
    DrawableV2::RSRenderNodeDrawableAdapter::OnGenerate(shared_from_this());
    if (renderDrawable_ == nullptr) {
        RS_LOGE("RSDisplayRenderNode::InitRenderParams failed");
        return;
    }
}

void RSDisplayRenderNode::OnSync()
{
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
    displayParams->SetNeedSync(true);
    RSRenderNode::OnSync();
    HandleCurMainAndLeashSurfaceNodes();
}

void RSDisplayRenderNode::HandleCurMainAndLeashSurfaceNodes()
{
    surfaceCountForMultiLayersPerf_ = 0;
    for (const auto& surface : curMainAndLeashSurfaceNodes_) {
        auto surfaceNode = RSBaseRenderNode::ReinterpretCast<RSSurfaceRenderNode>(surface);
        if (!surfaceNode || surfaceNode->IsLeashWindow()) {
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

void RSDisplayRenderNode::UpdateRenderParams()
{
    auto displayParams = static_cast<RSDisplayRenderParams*>(stagingRenderParams_.get());
    if (displayParams == nullptr) {
        RS_LOGE("RSDisplayRenderNode::UpdateRenderParams displayParams is null");
        return;
    }
    auto mirroredNode = GetMirrorSource().lock();
    if (mirroredNode == nullptr) {
        displayParams->mirrorSourceId_ = INVALID_NODEID;
        RS_LOGW("RSDisplayRenderNode::UpdateRenderParams mirroredNode is null");
    } else {
        displayParams->mirrorSourceDrawable_ = mirroredNode->GetRenderDrawable();
        displayParams->mirrorSourceId_ = mirroredNode->GetId();
    }
    displayParams->offsetX_ = GetDisplayOffsetX();
    displayParams->offsetY_ = GetDisplayOffsetY();
    displayParams->nodeRotation_ = GetRotation();
    displayParams->mirrorSource_ = GetMirrorSource();
    RSRenderNode::UpdateRenderParams();
}

void RSDisplayRenderNode::UpdateScreenRenderParams(ScreenRenderParams& screenRenderParams)
{
    auto displayParams = static_cast<RSDisplayRenderParams*>(stagingRenderParams_.get());
    if (displayParams == nullptr) {
        RS_LOGE("RSDisplayRenderNode::UpdateScreenRenderParams displayParams is null");
        return;
    }
    displayParams->screenId_ = GetScreenId();
    displayParams->screenRotation_ = GetScreenRotation();
    displayParams->compositeType_ = GetCompositeType();
    displayParams->isSecurityDisplay_ = GetSecurityDisplay();
    displayParams->screenInfo_ = std::move(screenRenderParams.screenInfo);
    displayParams->displayHasSecSurface_ = std::move(screenRenderParams.displayHasSecSurface);
    displayParams->displayHasSkipSurface_ = std::move(screenRenderParams.displayHasSkipSurface);
    displayParams->displayHasProtectedSurface_ = std::move(screenRenderParams.displayHasProtectedSurface);
    displayParams->displaySpecailSurfaceChanged_ = std::move(screenRenderParams.displaySpecailSurfaceChanged);
    displayParams->hasCaptureWindow_ = std::move(screenRenderParams.hasCaptureWindow);
}

void RSDisplayRenderNode::UpdateOffscreenRenderParams(bool needOffscreen)
{
    auto displayParams = static_cast<RSDisplayRenderParams*>(stagingRenderParams_.get());
    if (displayParams == nullptr) {
        RS_LOGE("RSDisplayRenderNode::UpdateOffscreenRenderParams displayParams is null");
        return;
    }
    displayParams->SetNeedOffscreen(needOffscreen);
}

void RSDisplayRenderNode::UpdatePartialRenderParams()
{
    auto displayParams = static_cast<RSDisplayRenderParams*>(stagingRenderParams_.get());
    if (displayParams == nullptr) {
        RS_LOGE("RSDisplayRenderNode::UpdatePartialRenderParams displayParams is null");
        return;
    }
    displayParams->SetAllMainAndLeashSurfaces(curMainAndLeashSurfaceNodes_);
}

bool RSDisplayRenderNode::SkipFrame(uint32_t refreshRate, uint32_t skipFrameInterval)
{
    if (refreshRate == 0 || skipFrameInterval <= 1) {
        return false;
    }
    int64_t currentTime = std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
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
    auto displayParams = static_cast<RSDisplayRenderParams*>(stagingRenderParams_.get());
    if (displayParams == nullptr) {
        RS_LOGE("RSDisplayRenderNode::SetDisplayGlobalZOrder displayParams is null");
        return;
    }
    displayParams->SetGlobalZOrder(zOrder);
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

void RSDisplayRenderNode::UpdateRotation()
{
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
    lastRotationChanged_ = IsRotationChanged();
    lastRotation_ = boundsGeoPtr->GetRotation();
    preRotationStatus_ = curRotationStatus_;
    curRotationStatus_ = IsRotationChanged();
    displayParams->SetRotationChanged(curRotationStatus_);
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
    auto displayParams = static_cast<RSDisplayRenderParams*>(stagingRenderParams_.get());
    if (displayParams == nullptr) {
        RS_LOGE("%{public}s displayParams is nullptr", __func__);
        return;
    }
    displayParams->SetMainAndLeashSurfaceDirty(isDirty);
    if (stagingRenderParams_->NeedSync()) {
        AddToPendingSyncList();
    }
}

void RSDisplayRenderNode::SetHDRPresent(bool hdrPresent)
{
    auto displayParams = static_cast<RSDisplayRenderParams*>(stagingRenderParams_.get());
    if (displayParams == nullptr) {
        RS_LOGE("%{public}s displayParams is nullptr", __func__);
        return;
    }
    displayParams->SetHDRPresent(hdrPresent);
    if (stagingRenderParams_->NeedSync()) {
        AddToPendingSyncList();
    }
}

void RSDisplayRenderNode::SetBrightnessRatio(float brightnessRatio)
{
    auto displayParams = static_cast<RSDisplayRenderParams*>(stagingRenderParams_.get());
    displayParams->SetBrightnessRatio(brightnessRatio);
    if (stagingRenderParams_->NeedSync()) {
        AddToPendingSyncList();
    }
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
    if (isNeedWaitNewScbPid_) {
        return fullChildrenList;
    }
    std::vector<int32_t> oldScbPids = GetOldScbPids();
    currentChildrenList_->clear();
    for (auto& child : *fullChildrenList) {
        auto childPid = ExtractPid(child->GetId());
        auto pidIter = std::find(oldScbPids.begin(), oldScbPids.end(), childPid);
        if (pidIter != oldScbPids.end()) {
            continue;
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
} // namespace Rosen
} // namespace OHOS
