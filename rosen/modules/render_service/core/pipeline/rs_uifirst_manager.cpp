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


#include "pipeline/rs_uifirst_manager.h"

#include "luminance/rs_luminance_control.h"
#include "rs_trace.h"

#include "common/rs_optional_trace.h"
#include "drawable/rs_surface_render_node_drawable.h"
#include "params/rs_display_render_params.h"
#include "pipeline/parallel_render/rs_sub_thread_manager.h"
#include "pipeline/rs_canvas_render_node.h"
#include "pipeline/rs_uni_render_util.h"
#include "pipeline/rs_main_thread.h"
#include "platform/common/rs_log.h"

// use in mainthread, post subthread, not affect renderthread
namespace OHOS {
namespace Rosen {
namespace {
    static constexpr int EVENT_START_TIMEOUT = 500;
    static constexpr int EVENT_STOP_TIMEOUT = 150;
    static constexpr int EVENT_DISABLE_UIFIRST_GAP = 100;
    constexpr std::string_view ARKTSCARDNODE_NAME = "ArkTSCardNode";
    constexpr std::string_view EVENT_DISABLE_UIFIRST = "APP_LIST_FLING";
    static inline int64_t GetCurSysTime()
    {
        auto curTime = std::chrono::system_clock::now().time_since_epoch();
        return std::chrono::duration_cast<std::chrono::milliseconds>(curTime).count();
    }
};

RSUifirstManager& RSUifirstManager::Instance()
{
    static RSUifirstManager instance; // store in mainthread instance ?
    return instance;
}

RSUifirstManager::RSUifirstManager() :
#if defined(RS_ENABLE_VK)
    useDmaBuffer_(RSSystemParameters::GetUIFirstDmaBufferEnabled() &&
        RSSystemProperties::IsPhoneType() && RSSystemProperties::GetGpuApiType() == GpuApiType::VULKAN)
#else
    useDmaBuffer_(false)
#endif
{}

std::shared_ptr<DrawableV2::RSSurfaceRenderNodeDrawable> RSUifirstManager::GetSurfaceDrawableByID(NodeId id)
{
    if (const auto cacheIt = subthreadProcessingNode_.find(id); cacheIt != subthreadProcessingNode_.end()) {
        if (const auto ptr = cacheIt->second) {
            return std::static_pointer_cast<DrawableV2::RSSurfaceRenderNodeDrawable>(ptr);
        }
    }
    // unlikely
    auto ptr = DrawableV2::RSRenderNodeDrawableAdapter::GetDrawableById(id);
    if (ptr) {
        return std::static_pointer_cast<DrawableV2::RSSurfaceRenderNodeDrawable>(ptr);
    }
    return nullptr;
}

void RSUifirstManager::SetUifirstNodeEnableParam(RSSurfaceRenderNode& node, MultiThreadCacheType type)
{
    node.SetUifirstNodeEnableParam(type); // update drawable param
    if (node.IsLeashWindow() && type != MultiThreadCacheType::ARKTS_CARD) {
        for (auto& child : *(node.GetChildren())) {
            if (!child) {
                continue;
            }
            auto surfaceChild = child->ReinterpretCastTo<RSSurfaceRenderNode>();
            if (!surfaceChild) {
                continue;
            }
            if (surfaceChild->IsMainWindowType()) {
                surfaceChild->SetIsParentUifirstNodeEnableParam(type == MultiThreadCacheType::LEASH_WINDOW ||
                    type == MultiThreadCacheType::NONFOCUS_WINDOW);
                continue;
            }
        }
    }
}

// unref in sub when cache done
void RSUifirstManager::AddProcessDoneNode(NodeId id)
{
    // mutex
    if (id == INVALID_NODEID) {
        return;
    }
    RS_OPTIONAL_TRACE_NAME_FMT("sub done %lld", id);
    std::lock_guard<std::mutex> lock(childernDrawableMutex_);
    subthreadProcessDoneNode_.push_back(id);
}

void RSUifirstManager::ResetUifirstNode(std::shared_ptr<RSSurfaceRenderNode>& nodePtr)
{
    if (!nodePtr) {
        return;
    }
    nodePtr->SetUifirstUseStarting(false);
    SetUifirstNodeEnableParam(*nodePtr, MultiThreadCacheType::NONE);
    RSMainThread::Instance()->GetContext().AddPendingSyncNode(nodePtr);
    auto drawable = GetSurfaceDrawableByID(nodePtr->GetId());
    if (drawable) {
        drawable->ResetUifirst();
    }
    nodePtr->SetIsNodeToBeCaptured(false);
}

void RSUifirstManager::MergeOldDirty(RSSurfaceRenderNode& node)
{
    auto params = static_cast<RSSurfaceRenderParams*>(node.GetStagingRenderParams().get());
    if (!params->GetPreSurfaceCacheContentStatic()) {
        return;
    }
    if (node.IsAppWindow() && !RSBaseRenderNode::ReinterpretCast<RSSurfaceRenderNode>(node.GetParent().lock())) {
        node.GetDirtyManager()->MergeDirtyRect(node.GetOldDirty());
        return;
    }
    for (auto& child : *node.GetSortedChildren()) {
        auto surfaceNode = RSBaseRenderNode::ReinterpretCast<RSSurfaceRenderNode>(child);
        if (surfaceNode && surfaceNode->IsAppWindow()) {
            surfaceNode->GetDirtyManager()->MergeDirtyRect(surfaceNode->GetOldDirty());
            break;
        }
    }
}

void RSUifirstManager::RenderGroupUpdate(std::shared_ptr<DrawableV2::RSSurfaceRenderNodeDrawable> drawable)
{
    auto nodeSp = mainThread_->GetContext().GetNodeMap().GetRenderNode(drawable->GetId());
    if (nodeSp == nullptr) {
        return;
    }
    auto surfaceNode = std::static_pointer_cast<const RSSurfaceRenderNode>(nodeSp);
    if (surfaceNode == nullptr) {
        return;
    }
    // mark all parent rendergroup need update; planning: mark autoCache need update
    auto node = surfaceNode->GetParent().lock();
    if (node == nullptr) {
        return;
    }

    do {
        if (node->GetType() == RSRenderNodeType::DISPLAY_NODE) {
            break;
        }
        if (node->IsSuggestedDrawInGroup()) {
            RS_OPTIONAL_TRACE_NAME_FMT("cache_changed by uifirst card %lld", node->GetId());
            node->SetDrawingCacheChanged(true);
            node->AddToPendingSyncList();
        }
        node = node->GetParent().lock();
    } while (node);
}

void RSUifirstManager::ProcessForceUpdateNode()
{
    if (!mainThread_) {
        return;
    }
    std::vector<std::shared_ptr<RSRenderNode>> toDirtyNodes;
    for (auto id : pendingForceUpdateNode_) {
        auto node = mainThread_->GetContext().GetNodeMap().GetRenderNode(id);
        if (!node) {
            continue;
        }
        toDirtyNodes.push_back(node);
        if (!node->IsDirty() && !node->IsSubTreeDirty()) {
            markForceUpdateByUifirst_.push_back(node);
            node->SetForceUpdateByUifirst(true);
        }
        if (node->GetLastFrameUifirstFlag() == MultiThreadCacheType::ARKTS_CARD) {
            continue;
        }
        for (auto& child : *node->GetChildren()) {
            if (!child) {
                continue;
            }
            auto surfaceNode = child->ReinterpretCastTo<RSSurfaceRenderNode>();
            if (!surfaceNode || !surfaceNode->IsMainWindowType()) {
                continue;
            }
            toDirtyNodes.push_back(child);
            if (!child->IsDirty() && !child->IsSubTreeDirty()) {
                markForceUpdateByUifirst_.push_back(child);
                child->SetForceUpdateByUifirst(true);
            }
        }
    }
    for (auto& node : toDirtyNodes) {
        ROSEN_LOGD("Node id %{public}" PRIu64 " set dirty, force update", node->GetId());
        node->SetDirty(true);
    }
    pendingForceUpdateNode_.clear();
}

void RSUifirstManager::NotifyUIStartingWindow(NodeId id, bool hasCachedTexture)
{
    auto node = RSBaseRenderNode::ReinterpretCast<RSSurfaceRenderNode>(
        mainThread_->GetContext().GetNodeMap().GetRenderNode(id));
    if (node != nullptr && !hasCachedTexture && node->IsLeashWindow()) {
        std::shared_ptr<RSSurfaceRenderNode> startingWindow = nullptr;
        bool uifirstFirstFrameComplete = false;
        for (auto& child : *node->GetChildren()) {
            if (!child) {
                continue;
            }
            auto canvasChild = child->ReinterpretCastTo<RSCanvasRenderNode>();
            if (canvasChild && canvasChild->GetStartingWindowFlag()) {
                uifirstFirstFrameComplete = true;
                continue;
            }
            auto surfaceChild = child->ReinterpretCastTo<RSSurfaceRenderNode>();
            if (surfaceChild && surfaceChild->IsMainWindowType()) {
                startingWindow = surfaceChild;
                continue;
            }
        }
        if (uifirstFirstFrameComplete && startingWindow) {
            uifirstFirstFrameComplete = false;
            startingWindow->SetIsNotifyUIBufferAvailable(false);
            uifirstFirstFrameComplete = true;
            RS_TRACE_NAME_FMT("NotifyUIBufferAvailable by uifirst %lld", startingWindow->GetId());
            RS_LOGD("uifirst NotifyUIBufferAvailable by uifirst");
        }
    }
}

void RSUifirstManager::ProcessDoneNodeInner()
{
    std::vector<NodeId> tmp;
    {
        std::lock_guard<std::mutex> lock(childernDrawableMutex_);
        if (subthreadProcessDoneNode_.size() == 0) {
            return;
        }
        std::swap(tmp, subthreadProcessDoneNode_);
        subthreadProcessDoneNode_.clear();
    }
    RS_TRACE_NAME_FMT("ProcessDoneNode num%d", tmp.size());
    for (auto& id : tmp) {
        RS_OPTIONAL_TRACE_NAME_FMT("Done %lld", id);
        auto drawable = GetSurfaceDrawableByID(id);
        if (drawable && drawable->GetCacheSurfaceNeedUpdated() &&
            drawable->GetCacheSurface(UNI_MAIN_THREAD_INDEX, false)) {
            NotifyUIStartingWindow(id, drawable->HasCachedTexture());
            drawable->UpdateCompletedCacheSurface();
            RenderGroupUpdate(drawable);
            SetHasDoneNodeFlag(true);
            pendingForceUpdateNode_.push_back(id);
        }
        subthreadProcessingNode_.erase(id);
    }
}
void RSUifirstManager::ProcessDoneNode()
{
    SetHasDoneNodeFlag(false);
    ProcessDoneNodeInner();

    // reset node when node is not doing
    for (auto it = capturedNodes_.begin(); it != capturedNodes_.end();) {
        if (subthreadProcessingNode_.find(*it) == subthreadProcessingNode_.end()) {
            // reset uifirst
            auto node = RSBaseRenderNode::ReinterpretCast<RSSurfaceRenderNode>(
                mainThread_->GetContext().GetNodeMap().GetRenderNode(*it));
            if (node == nullptr) {
                it = capturedNodes_.erase(it);
                continue;
            }
            
            ResetUifirstNode(node);
            it = capturedNodes_.erase(it);
        } else {
            it++;
        }
    }
    for (auto it = pendingResetNodes_.begin(); it != pendingResetNodes_.end();) {
        if (subthreadProcessingNode_.find(it->first) == subthreadProcessingNode_.end()) {
            ResetUifirstNode(it->second);
            it = pendingResetNodes_.erase(it);
        } else {
            it++;
        }
    }

    for (auto it = subthreadProcessingNode_.begin(); it != subthreadProcessingNode_.end();) {
        auto id = it->first;
        auto drawable = GetSurfaceDrawableByID(id);
        if (!drawable) {
            ++it;
            continue;
        }
        if (drawable->HasCachedTexture() && drawable->GetCacheSurfaceProcessedStatus() == CacheProcessStatus::WAITING) {
            it = subthreadProcessingNode_.erase(it);
            continue;
        }
        pendingPostNodes_.erase(it->first); // dele doing node in pendingpostlist
        pendingPostCardNodes_.erase(it->first);
        ++it;
    }
}

void RSUifirstManager::SyncHDRDisplayParam(std::shared_ptr<DrawableV2::RSSurfaceRenderNodeDrawable> drawable)
{
    auto surfaceParams = static_cast<RSSurfaceRenderParams*>(drawable->GetRenderParams().get());
    if (!surfaceParams || !surfaceParams->GetAncestorDisplayNode().lock()) {
        return;
    }
    auto ancestor = surfaceParams->GetAncestorDisplayNode().lock()->ReinterpretCastTo<RSDisplayRenderNode>();
    if (!ancestor) {
        return;
    }
    auto displayParams = static_cast<RSDisplayRenderParams*>(ancestor->GetRenderParams().get());
    if (!displayParams) {
        return;
    }
    bool isHdrOn = displayParams->GetHDRPresent();
    ScreenId id = displayParams->GetScreenId();
    drawable->SetHDRPresent(isHdrOn);
    if (isHdrOn) {
        // 0 means defalut brightnessRatio
        drawable->SetBrightnessRatio(RSLuminanceControl::Get().GetHdrBrightnessRatio(id, 0));
        drawable->SetScreenId(id);
        drawable->SetTargetColorGamut(displayParams->GetNewColorSpace());
    }
    RS_LOGD("UIFirstHDR SyncDisplayParam:%{public}d, ratio:%{public}f", drawable->GetHDRPresent(),
        drawable->GetBrightnessRatio());
}

bool RSUifirstManager::CheckVisibleDirtyRegionIsEmpty(std::shared_ptr<RSSurfaceRenderNode> node)
{
    if (RSMainThread::Instance()->GetDeviceType() != DeviceType::PC) {
        return false;
    }
    for (auto& child : *node->GetSortedChildren()) {
        if (std::shared_ptr<RSSurfaceRenderNode> surfaceNode =
                RSBaseRenderNode::ReinterpretCast<RSSurfaceRenderNode>(child)) {
            auto visibleRegion = surfaceNode->GetVisibleRegion();
            if (visibleRegion.IsEmpty()) {
                surfaceNode->SetUIFirstIsPurge(false);
                return true;
            }
            auto drawable = surfaceNode->GetRenderDrawable();
            if (!drawable) {
                continue;
            }
            auto surfaceDrawable = std::static_pointer_cast<DrawableV2::RSSurfaceRenderNodeDrawable>(drawable);
            auto surfaceDirtyRect = surfaceDrawable->GetSyncDirtyManager()->GetCurrentFrameDirtyRegion();
            Occlusion::Rect dirtyRect { surfaceDirtyRect.left_, surfaceDirtyRect.top_,
                surfaceDirtyRect.GetRight(), surfaceDirtyRect.GetBottom() };
            Occlusion::Region surfaceDirtyRegion { dirtyRect };
            Occlusion::Region surfaceVisibleDirtyRegion = surfaceDirtyRegion.And(visibleRegion);
            if (surfaceVisibleDirtyRegion.IsEmpty()) {
                surfaceNode->SetUIFirstIsPurge(false);
                return true;
            }
            if (!surfaceNode->GetUIFirstIsPurge()) {
                surfaceNode->SetUIFirstIsPurge(true);
                return false;
            }
        }
    }
    return false;
}

void RSUifirstManager::DoPurgePendingPostNodes(std::unordered_map<NodeId,
    std::shared_ptr<RSSurfaceRenderNode>>& pendingNode)
{
    auto deviceType = RSMainThread::Instance()->GetDeviceType();
    for (auto it = pendingNode.begin(); it != pendingNode.end();) {
        auto id = it->first;
        auto drawable = GetSurfaceDrawableByID(id);
        if (!drawable) {
            ++it;
            continue;
        }
        SyncHDRDisplayParam(drawable);
        // Skipping drawing is not allowed when there is an HDR display.
        if (drawable->GetHDRPresent()) {
            ++it;
            continue;
        }
        auto surfaceParams = static_cast<RSSurfaceRenderParams*>(drawable->GetRenderParams().get());
        auto node = it->second;
        if (!surfaceParams || !node) {
            ++it;
            continue;
        }
        bool staticContent = node->GetLastFrameUifirstFlag() == MultiThreadCacheType::ARKTS_CARD ?
            node->GetForceUpdateByUifirst() : drawable->IsCurFrameStatic(deviceType);
        if (drawable->HasCachedTexture() && (staticContent || CheckVisibleDirtyRegionIsEmpty(node)) &&
            (subthreadProcessingNode_.find(id) == subthreadProcessingNode_.end()) &&
            !drawable->IsSubThreadSkip()) {
            RS_OPTIONAL_TRACE_NAME_FMT("Purge node name %s", surfaceParams->GetName().c_str());
            it = pendingNode.erase(it);
        } else {
            ++it;
        }
    }
}

void RSUifirstManager::PurgePendingPostNodes()
{
    RS_OPTIONAL_TRACE_NAME_FMT("PurgePendingPostNodes");
    DoPurgePendingPostNodes(pendingPostNodes_);
    DoPurgePendingPostNodes(pendingPostCardNodes_);
    for (auto& node : markForceUpdateByUifirst_) {
        node->SetForceUpdateByUifirst(false);
    }
    markForceUpdateByUifirst_.clear();
}

void RSUifirstManager::PostSubTask(NodeId id)
{
    RS_TRACE_NAME("post UpdateCacheSurface");

    if (subthreadProcessingNode_.find(id) != subthreadProcessingNode_.end()) { // drawable is doing, do not send
        RS_TRACE_NAME_FMT("node %lld is doning", id);
        RS_LOGE("RSUifirstManager ERROR: post task twice");
        return;
    }

    // 1.find in cache list(done to dele) 2.find in global list
    auto drawable = DrawableV2::RSRenderNodeDrawableAdapter::GetDrawableById(id);
    if (drawable) {
        // ref drawable
        subthreadProcessingNode_[id] = drawable;
        // post task
        RS_OPTIONAL_TRACE_NAME_FMT("Post_SubTask_s %lld", id);
        RSSubThreadManager::Instance()->ScheduleRenderNodeDrawable(
            std::static_pointer_cast<DrawableV2::RSSurfaceRenderNodeDrawable>(drawable));
    }
}

void RSUifirstManager::TryReleaseTextureForIdleThread()
{
    if (noUifirstNodeFrameCount_.load() <= CLEAR_RES_THRESHOLD) {
        return;
    }
    RSSubThreadManager::Instance()->TryReleaseTextureForIdleThread();
}

void RSUifirstManager::PostReleaseCacheSurfaceSubTasks()
{
    for (auto cardNode : collectedCardNodes_) {
        PostReleaseCacheSurfaceSubTask(cardNode);
    }
}

void RSUifirstManager::PostReleaseCacheSurfaceSubTask(NodeId id)
{
    RS_OPTIONAL_TRACE_NAME_FMT("post ReleaseCacheSurface %d", id);

    if (subthreadProcessingNode_.find(id) != subthreadProcessingNode_.end()) { // drawable is doing, do not send
        RS_TRACE_NAME_FMT("node %lx is doning", id);
        RS_LOGE("RSUifirstManager ERROR: try to clean running node");
        return;
    }

    // 1.find in cache list(done to dele) 2.find in global list
    auto drawable = DrawableV2::RSRenderNodeDrawableAdapter::GetDrawableById(id);
    if (drawable) {
        // post task
        RS_OPTIONAL_TRACE_NAME_FMT("Post_SubTask_s %lx", id);
        RSSubThreadManager::Instance()->ScheduleReleaseCacheSurfaceOnly(
            std::static_pointer_cast<DrawableV2::RSSurfaceRenderNodeDrawable>(drawable));
    }
}

void RSUifirstManager::UpdateSkipSyncNode()
{
    processingNodeSkipSync_.clear();
    processingNodePartialSync_.clear();
    processingCardNodeSkipSync_.clear();
    RS_OPTIONAL_TRACE_NAME_FMT("UpdateSkipSyncNode doning%d", subthreadProcessingNode_.size());
    if (subthreadProcessingNode_.size() == 0) {
        return;
    }
    if (!mainThread_) {
        return;
    }
    for (auto it = subthreadProcessingNode_.begin(); it != subthreadProcessingNode_.end(); it++) {
        RS_OPTIONAL_TRACE_NAME_FMT("doning%lld", it->first);
        auto node = mainThread_->GetContext().GetNodeMap().GetRenderNode(it->first);
        if (!node) {
            continue;
        }
        auto surfaceNode = node->ReinterpretCastTo<RSSurfaceRenderNode>();
        if (!surfaceNode) {
            continue;
        }
        // ArkTSCard
        if (NodeIsInCardWhiteList(*node)) {
            if (surfaceNode->GetLastFrameUifirstFlag() == MultiThreadCacheType::ARKTS_CARD) {
                processingCardNodeSkipSync_.insert(it->first);
                continue;
            }
        }

        // leash window
        processingNodePartialSync_.insert(it->first); // partial sync
        std::vector<std::pair<NodeId, std::weak_ptr<RSSurfaceRenderNode>>> allSubSurfaceNodes;
        surfaceNode->GetAllSubSurfaceNodes(allSubSurfaceNodes);
        for (auto& [id, subSurfaceNode] : allSubSurfaceNodes) {
            processingNodeSkipSync_.insert(id); // skip sync
        }
    }
}

void RSUifirstManager::ProcessSubDoneNode()
{
    RS_OPTIONAL_TRACE_NAME_FMT("ProcessSubDoneNode");
    ConvertPendingNodeToDrawable();
    ProcessDoneNode(); // release finish drawable
    UpdateSkipSyncNode();
    RestoreSkipSyncNode();
    ResetCurrentFrameDeletedCardNodes();
}

void RSUifirstManager::ConvertPendingNodeToDrawable()
{
    {
        std::lock_guard<std::mutex> lock(useDmaBufferMutex_);
        if (!useDmaBuffer_) {
            return;
        }
    }
    pendingPostDrawables_.clear();
    for (const auto& iter : pendingPostNodes_) {
        if (iter.second && GetUseDmaBuffer(iter.second->GetName())) {
            if (auto drawableNode = DrawableV2::RSRenderNodeDrawableAdapter::OnGenerate(iter.second)) {
                pendingPostDrawables_.emplace_back(
                    std::static_pointer_cast<DrawableV2::RSSurfaceRenderNodeDrawable>(drawableNode));
            }
        }
    }
}

bool RSUifirstManager::CollectSkipSyncNode(const std::shared_ptr<RSRenderNode> &node)
{
    if (!node) {
        return false;
    }
    if (pendingPostNodes_.find(node->GetId()) != pendingPostNodes_.end() ||
        pendingPostCardNodes_.find(node->GetId()) != pendingPostCardNodes_.end()) {
        node->SetUifirstSyncFlag(true);
    }

    if (NodeIsInCardWhiteList(*node) && processingCardNodeSkipSync_.count(node->GetUifirstRootNodeId())) {
        pendingSyncForSkipBefore_[node->GetUifirstRootNodeId()].push_back(node);
        if (node->GetUifirstRootNodeId() == node->GetId()) {
            RS_OPTIONAL_TRACE_NAME_FMT("set partial_sync card %lld root%lld",
                node->GetId(), node->GetUifirstRootNodeId());
            node->SetUifirstSkipPartialSync(true);
            return false;
        } else {
            RS_OPTIONAL_TRACE_NAME_FMT("CollectSkipSyncNode card root %lld, node %lld",
                node->GetUifirstRootNodeId(), node->GetId());
            return true;
        }
    }
    if (processingNodePartialSync_.count(node->GetInstanceRootNodeId()) > 0) {
        pendingSyncForSkipBefore_[node->GetInstanceRootNodeId()].push_back(node);
        if (node->GetInstanceRootNodeId() == node->GetId()) {
            RS_OPTIONAL_TRACE_NAME_FMT("set partial_sync %lld root%lld", node->GetId(), node->GetInstanceRootNodeId());
            node->SetUifirstSkipPartialSync(true);
            return false;
        } else {
            RS_OPTIONAL_TRACE_NAME_FMT("CollectSkipSyncNode root %lld, node %lld",
                node->GetInstanceRootNodeId(), node->GetId());
            return true;
        }
    } else if (processingNodeSkipSync_.count(node->GetInstanceRootNodeId()) > 0) {
        RS_OPTIONAL_TRACE_NAME_FMT("CollectSkipSyncNode root %lld, node %lld",
            node->GetInstanceRootNodeId(), node->GetId());
        pendingSyncForSkipBefore_[node->GetInstanceRootNodeId()].push_back(node);
        return true;
    } else {
        return false;
    }
}

void RSUifirstManager::RestoreSkipSyncNode()
{
    std::vector<NodeId> todele;
    for (auto& it : pendingSyncForSkipBefore_) {
        if (processingNodeSkipSync_.count(it.first) == 0 && processingNodePartialSync_.count(it.first) == 0 &&
            processingCardNodeSkipSync_.count(it.first) == 0) {
            todele.push_back(it.first);
            RS_OPTIONAL_TRACE_NAME_FMT("RestoreSkipSyncNode %lld num%d", it.first, it.second.size());
            for (auto& node : it.second) {
                node->SetUifirstSkipPartialSync(false);
                node->AddToPendingSyncList();
            }
        }
    }
    for (auto id : todele) {
        pendingSyncForSkipBefore_.erase(id);
    }
}

void RSUifirstManager::ClearSubthreadRes()
{
    RS_OPTIONAL_TRACE_NAME_FMT("ClearSubthreadRes");
    if (subthreadProcessingNode_.size() == 0 &&
        pendingSyncForSkipBefore_.size() == 0) {
        noUifirstNodeFrameCount_.fetch_add(1);
        if (noUifirstNodeFrameCount_.load() == CLEAR_RES_THRESHOLD) {
            RSSubThreadManager::Instance()->ResetSubThreadGrContext();
            PostReleaseCacheSurfaceSubTasks();
        }
    } else {
        noUifirstNodeFrameCount_.store(0);
    }
    reuseNodes_.clear();
}

void RSUifirstManager::ForceClearSubthreadRes()
{
    noUifirstNodeFrameCount_.store(0);
    RSSubThreadManager::Instance()->ReleaseTexture();
}

void RSUifirstManager::SetNodePriorty(std::list<NodeId>& result,
    std::unordered_map<NodeId, std::shared_ptr<RSSurfaceRenderNode>>& pendingNode)
{
    bool isFocusNodeFound = false;
    for (auto& item : pendingNode) {
        auto const& [id, value] = item;
        auto drawable = GetSurfaceDrawableByID(id);
        if (!drawable) {
            continue;
        }
        if (!isFocusNodeFound) {
            bool isFocus = ((id == RSMainThread::Instance()->GetFocusNodeId()) ||
                (id == RSMainThread::Instance()->GetFocusLeashWindowId()));
            if (isFocus) {
                // for resolving response latency
                drawable->SetRenderCachePriority(NodePriorityType::SUB_FOCUSNODE_PRIORITY);
                isFocusNodeFound = true;
            }
        }
        if (drawable->HasCachedTexture()) {
            drawable->SetRenderCachePriority(NodePriorityType::SUB_LOW_PRIORITY);
        } else {
            drawable->SetRenderCachePriority(NodePriorityType::SUB_HIGH_PRIORITY);
        }
        if (drawable->GetCacheSurfaceProcessedStatus() == CacheProcessStatus::WAITING) {
            drawable->SetRenderCachePriority(NodePriorityType::SUB_HIGH_PRIORITY);
        }
        sortedSubThreadNodeIds_.emplace_back(id);
    }
}

void RSUifirstManager::SortSubThreadNodesPriority()
{
    sortedSubThreadNodeIds_.clear();
    SetNodePriorty(sortedSubThreadNodeIds_, pendingPostNodes_);
    SetNodePriorty(sortedSubThreadNodeIds_, pendingPostCardNodes_);

    sortedSubThreadNodeIds_.sort([this](const auto& first, const auto& second) -> bool {
        auto drawable1 = GetSurfaceDrawableByID(first);
        auto drawable2 = GetSurfaceDrawableByID(second);
        if (drawable1 == nullptr || drawable2 == nullptr) {
            ROSEN_LOGE("RSUifirstManager::SortSubThreadNodesPriority sort nullptr found in pendingPostNodes_, "
                "this should not happen");
            return false;
        }
        auto surfaceParams1 = static_cast<RSSurfaceRenderParams*>(drawable1->GetRenderParams().get());
        if (!surfaceParams1) {
            RS_LOGE("RSSurfaceRenderNodeDrawable::sortsubthread params1 is nullptr");
            return false;
        }
        auto surfaceParams2 = static_cast<RSSurfaceRenderParams*>(drawable2->GetRenderParams().get());
        if (!surfaceParams2) {
            RS_LOGE("RSSurfaceRenderNodeDrawable::sortsubthread params2 is nullptr");
            return false;
        }
        if (drawable1->GetRenderCachePriority() == drawable2->GetRenderCachePriority()) {
            return surfaceParams2->GetPositionZ() < surfaceParams1->GetPositionZ();
        } else {
            return drawable1->GetRenderCachePriority() < drawable2->GetRenderCachePriority();
        }
    });
}

// post in drawframe sync time
void RSUifirstManager::PostUifistSubTasks()
{
    PurgePendingPostNodes();
    SortSubThreadNodesPriority();
    if (sortedSubThreadNodeIds_.size() > 0) {
        for (auto& id : sortedSubThreadNodeIds_) {
            PostSubTask(id);
        }
        pendingPostNodes_.clear();
        pendingPostCardNodes_.clear();
        sortedSubThreadNodeIds_.clear();
    } else {
        ClearSubthreadRes();
    }
}

bool RSUifirstManager::IsInLeashWindowTree(RSSurfaceRenderNode& node, NodeId instanceRootId)
{
    if (node.GetInstanceRootNodeId() == instanceRootId) {
        return true;
    }
    if (!node.IsLeashWindow()) {
        return false;
    }
    for (auto& child : *(node.GetChildren())) {
        if (!child) {
            continue;
        }
        auto surfaceChild = child->ReinterpretCastTo<RSSurfaceRenderNode>();
        if (!surfaceChild) {
            continue;
        }
        if (surfaceChild->GetInstanceRootNodeId() == instanceRootId) {
            return true;
        }
    }
    return false;
}

static inline bool LeashWindowContainMainWindow(RSSurfaceRenderNode& node)
{
    if (node.IsLeashWindow() && node.HasSubSurfaceNodes()) {
        return true;
    }
    return false;
}

void RSUifirstManager::AddPendingPostNode(NodeId id, std::shared_ptr<RSSurfaceRenderNode>& node,
    MultiThreadCacheType currentFrameCacheType)
{
    if (id == INVALID_NODEID) {
        return;
    }

    // process for uifirst node
    UpdateChildrenDirtyRect(*node);
    node->SetHwcChildrenDisabledStateByUifirst();
    node->SetLeashWindowVisibleRegionEmptyParam();
    node->AddToPendingSyncList();

    if (currentFrameCacheType == MultiThreadCacheType::LEASH_WINDOW ||
        currentFrameCacheType == MultiThreadCacheType::NONFOCUS_WINDOW) {
        if (isRecentTaskScene_.load() && !node->IsNodeToBeCaptured() &&
            currentFrameCacheType == MultiThreadCacheType::LEASH_WINDOW) {
            node->SetIsNodeToBeCaptured(true);
        }
        // delete card node in leashwindow tree
        for (auto it = pendingPostCardNodes_.begin(); it != pendingPostCardNodes_.end();) {
            auto surfaceNode = it->second;
            if (surfaceNode && IsInLeashWindowTree(*node, surfaceNode->GetInstanceRootNodeId())) {
                DisableUifirstNode(*surfaceNode);
                it = pendingPostCardNodes_.erase(it);
            } else {
                it++;
            }
        }
        pendingPostNodes_[id] = node;
    } else if (currentFrameCacheType == MultiThreadCacheType::ARKTS_CARD) {
        pendingPostCardNodes_[id] = node;
    }

    if (pendingResetNodes_.count(id)) {
        pendingResetNodes_.erase(id); // enable uifirst when waiting for reset
    }
}

NodeId RSUifirstManager::LeashWindowContainMainWindowAndStarting(RSSurfaceRenderNode& node)
{
    if (!node.IsLeashWindow()) {
        return INVALID_NODEID;
    }
    int mainwindowNum = 0;
    int canvasNodeNum = 0;
    bool support = true;
    std::shared_ptr<RSRenderNode> startingWindow = nullptr;
    for (auto& child : *(node.GetSortedChildren())) {
        if (!child) {
            continue;
        }
        RS_TRACE_NAME_FMT("nID:%lld , nType:%d, support:%d, canvasNodeNum:%d, mainwindowNum:%d",
            child->GetId(), static_cast<int>(child->GetType()), support, canvasNodeNum, mainwindowNum);
        auto canvasChild = child->ReinterpretCastTo<RSCanvasRenderNode>();
        if (canvasChild && canvasChild->GetChildrenCount() == 0 && mainwindowNum > 0) {
            canvasNodeNum++;
            startingWindow = canvasChild;
            continue;
        }
        auto surfaceChild = child->ReinterpretCastTo<RSSurfaceRenderNode>();
        if (surfaceChild && surfaceChild->IsMainWindowType() && canvasNodeNum == 0) {
            mainwindowNum++;
            continue;
        }
        support = false;
    }
    RS_TRACE_NAME_FMT("uifirst_node support:%d, canvasNodeNum:%d, mainwindowNum:%d, startingWindow:%d",
        support, canvasNodeNum, mainwindowNum, startingWindow != nullptr);
    if (support && canvasNodeNum == 1 && mainwindowNum > 0 && startingWindow) { // starting window & appwindow
        startingWindow->SetStartingWindowFlag(true);
        return startingWindow->GetId();
    } else {
        return INVALID_NODEID;
    }
}

void RSUifirstManager::AddPendingResetNode(NodeId id, std::shared_ptr<RSSurfaceRenderNode>& node)
{
    if (id == INVALID_NODEID) {
        return;
    }
    pendingResetNodes_[id] = node;
}

CacheProcessStatus RSUifirstManager::GetNodeStatus(NodeId id)
{
    auto drawable = GetSurfaceDrawableByID(id);
    if (drawable) {
        return drawable->GetCacheSurfaceProcessedStatus();
    }
    return CacheProcessStatus::UNKNOWN;
}

void RSUifirstManager::UpdateCompletedSurface(NodeId id)
{
    auto drawable = GetSurfaceDrawableByID(id);
    if (drawable) {
        drawable->UpdateCompletedCacheSurface();
    }
}

// add&clear in render
void RSUifirstManager::AddReuseNode(NodeId id)
{
    if (id == INVALID_NODEID) {
        return;
    }
    reuseNodes_.insert(id);
}

void RSUifirstManager::OnProcessEventResponse(DataBaseRs& info)
{
    RS_OPTIONAL_TRACE_NAME_FMT("uifirst uniqueId:%lld, appPid:%lld, sceneId:%s",
        info.uniqueId, info.appPid, info.sceneId.c_str());
    EventInfo eventInfo = {GetCurSysTime(), 0, info.uniqueId, info.appPid, info.sceneId, {}};
    std::lock_guard<std::mutex> lock(globalFrameEventMutex_);
    for (auto it = globalFrameEvent_.begin(); it != globalFrameEvent_.end(); it++) {
        it->disableNodes.clear();
    }
    globalFrameEvent_.push_back(std::move(eventInfo));
    currentFrameCanSkipFirstWait_ = EventsCanSkipFirstWait(globalFrameEvent_);
}

void RSUifirstManager::OnProcessEventComplete(DataBaseRs& info)
{
    int64_t curSysTime = GetCurSysTime();
    std::lock_guard<std::mutex> lock(globalFrameEventMutex_);
    for (auto it = globalFrameEvent_.begin(); it != globalFrameEvent_.end(); it++) {
        if (it->uniqueId == info.uniqueId && it->sceneId == info.sceneId) {
            // delay delete for animation continue
            it->stopTime = curSysTime;
            break;
        }
    }
}

void RSUifirstManager::EventDisableLeashWindowCache(NodeId id, EventInfo& info)
{
    std::lock_guard<std::mutex> lock(globalFrameEventMutex_);
    for (auto it = globalFrameEvent_.begin(); it != globalFrameEvent_.end(); it++) {
        if (it->uniqueId == info.uniqueId && it->sceneId == info.sceneId) {
            it->disableNodes.insert(id);
            break;
        }
    }
}

void RSUifirstManager::PrepareCurrentFrameEvent()
{
    int64_t curSysTime = GetCurSysTime();
    currentFrameEvent_.clear();
    if (!mainThread_ || entryViewNodeId_ == INVALID_NODEID || negativeScreenNodeId_ == INVALID_NODEID) {
        mainThread_ = RSMainThread::Instance();
        if (mainThread_) {
            entryViewNodeId_ = mainThread_->GetContext().GetNodeMap().GetEntryViewNodeId();
            negativeScreenNodeId_ = mainThread_->GetContext().GetNodeMap().GetNegativeScreenNodeId();
            scbPid_ = ExtractPid(entryViewNodeId_);
        }
    }
    {
        std::lock_guard<std::mutex> lock(globalFrameEventMutex_);
        for (auto it = globalFrameEvent_.begin(); it != globalFrameEvent_.end();) {
            if (it->stopTime != 0 &&
                ((curSysTime > it->stopTime) && (curSysTime - it->stopTime) > EVENT_STOP_TIMEOUT)) {
                it = globalFrameEvent_.erase(it);
                continue;
            }

            if ((curSysTime > it->startTime) && (curSysTime - it->startTime) > EVENT_START_TIMEOUT) {
                it = globalFrameEvent_.erase(it);
                continue;
            }
            it++;
        }
        if (globalFrameEvent_.empty()) {
            currentFrameCanSkipFirstWait_ = false;
            return;
        }
        // copy global to current, judge leashwindow stop
        currentFrameEvent_.assign(globalFrameEvent_.begin(), globalFrameEvent_.end());
    }
    currentFrameCanSkipFirstWait_ = EventsCanSkipFirstWait(currentFrameEvent_);
}

void RSUifirstManager::OnProcessAnimateScene(SystemAnimatedScenes systemAnimatedScene)
{
    RS_TRACE_NAME_FMT("RSUifirstManager::OnProcessAnimateScene systemAnimatedScene:%d", systemAnimatedScene);
    if ((systemAnimatedScene == SystemAnimatedScenes::ENTER_RECENTS) && !isRecentTaskScene_.load()) {
        isRecentTaskScene_ = true;
    } else if ((systemAnimatedScene == SystemAnimatedScenes::EXIT_RECENTS) && isRecentTaskScene_.load()) {
        isRecentTaskScene_ = false;
    }
}

bool RSUifirstManager::NodeIsInCardWhiteList(RSRenderNode& node)
{
    if ((entryViewNodeId_ != INVALID_NODEID) && (negativeScreenNodeId_ != INVALID_NODEID)) {
        auto instanceRootId = node.GetInstanceRootNodeId();
        if (instanceRootId == entryViewNodeId_ || instanceRootId == negativeScreenNodeId_) {
            return true;
        }
    }
    return false;
}

bool RSUifirstManager::IsCardSkipFirstWaitScene(std::string& scene, int32_t appPid)
{
    if (appPid != scbPid_) {
        return false;
    }
    for (auto& item : cardCanSkipFirstWaitScene_) {
        if ((scene.find(item) != std::string::npos)) {
            return true;
        }
    }
    return false;
}

bool RSUifirstManager::EventsCanSkipFirstWait(std::vector<EventInfo>& events)
{
    if (events.empty()) {
        return false;
    }
    if (isCurrentFrameHasCardNodeReCreate_) {
        RS_OPTIONAL_TRACE_NAME("uifirst current frame can't skip wait");
        return false;
    }
    for (auto& item : events) {
        if (IsCardSkipFirstWaitScene(item.sceneId, item.appPid)) {
            return true;
        }
    }
    return false;
}

bool RSUifirstManager::IsScreenshotAnimation()
{
    for (auto& it : currentFrameEvent_) {
        if (std::find(screenshotAnimation_.begin(), screenshotAnimation_.end(), it.sceneId) !=
            screenshotAnimation_.end()) {
            return true;
        }
    }
    return false;
}

bool RSUifirstManager::CheckIfAppWindowHasAnimation(RSSurfaceRenderNode& node)
{
    if (currentFrameEvent_.empty()) {
        return false;
    }

    std::set<int32_t> appPids;
    if (node.IsAppWindow()) {
        appPids.insert(ExtractPid(node.GetId()));
    } else if (node.IsLeashWindow()) {
        for (auto& child : *(node.GetChildren())) {
            if (!child) {
                continue;
            }
            auto surfaceChild = child->ReinterpretCastTo<RSSurfaceRenderNode>();
            if (!surfaceChild) {
                continue;
            }
            if (surfaceChild->IsAppWindow()) {
                appPids.insert(ExtractPid(surfaceChild->GetId()));
            }
        }
    }

    if (appPids.empty()) {
        return false;
    }
    for (auto& item : currentFrameEvent_) {
        if (item.disableNodes.count(node.GetId())) {
            return true;
        }
        if (appPids.count(item.appPid) && (node.GetUifirstStartTime() > 0) &&
            (node.GetUifirstStartTime() < (item.startTime - EVENT_DISABLE_UIFIRST_GAP)) &&
            (item.sceneId.find(EVENT_DISABLE_UIFIRST) != std::string::npos)) {
            EventDisableLeashWindowCache(node.GetId(), item);
            return true; // app has animation, stop leashwindow uifirst
        }
    }
    return false;
}

bool RSUifirstManager::IsArkTsCardCache(RSSurfaceRenderNode& node, bool animation) // maybe canvas node ?
{
    auto baseNode = node.GetAncestorDisplayNode().lock();
    if (!baseNode) {
        RS_LOGE("surfaceNode GetAncestorDisplayNode().lock() return nullptr");
        return false;
    }
    auto curDisplayNode = baseNode->ReinterpretCastTo<RSDisplayRenderNode>();
    if (curDisplayNode == nullptr) {
        RS_LOGE("surfaceNode GetAncestorDisplayNode().lock() return nullptr");
        return false;
    }
    if (RSLuminanceControl::Get().IsHdrOn(curDisplayNode->GetScreenId())) {
        return false;
    }
    bool flag = ((RSMainThread::Instance()->GetDeviceType() == DeviceType::PHONE) &&
        (node.GetSurfaceNodeType() == RSSurfaceNodeType::ABILITY_COMPONENT_NODE) &&
        RSUifirstManager::Instance().NodeIsInCardWhiteList(node) &&
        (node.ShouldPaint()) && (node.GetName().find(ARKTSCARDNODE_NAME) != std::string::npos));
    if (flag) { // Planning: mark by arkui or app
        return true;
    }
    return false;
}

// animation first, may reuse last image cache
bool RSUifirstManager::IsLeashWindowCache(RSSurfaceRenderNode& node, bool animation)
{
    if (RSUifirstManager::Instance().GetUseDmaBuffer(node.GetName())) {
        return true;
    }
    bool isNeedAssignToSubThread = false;
    if ((RSMainThread::Instance()->GetDeviceType() == DeviceType::PC) ||
        (node.GetFirstLevelNodeId() != node.GetId()) ||
        (RSUifirstManager::Instance().NodeIsInCardWhiteList(node)) ||
        (RSUifirstManager::Instance().CheckIfAppWindowHasAnimation(node))) {
        return false;
    }
    if (node.IsLeashWindow()) {
        if (RSUifirstManager::Instance().IsRecentTaskScene()) {
            isNeedAssignToSubThread = node.IsScale() && LeashWindowContainMainWindow(node);
        } else {
            isNeedAssignToSubThread = animation || node.IsNodeToBeCaptured();
        }
        // 1: Planning: support multi appwindows
        isNeedAssignToSubThread = (isNeedAssignToSubThread || ROSEN_EQ(node.GetGlobalAlpha(), 0.0f) ||
                node.GetForceUIFirst()) && !node.HasFilter() && !RSUifirstManager::Instance().rotationChanged_;
    }

    std::string surfaceName = node.GetName();
    bool needFilterSCB = node.GetSurfaceWindowType() == SurfaceWindowType::SYSTEM_SCB_WINDOW;
    if (needFilterSCB || node.IsSelfDrawingType()) {
        RS_TRACE_NAME_FMT("IsLeashWindowCache: needFilterSCB [%d]", needFilterSCB);
        return false;
    }
    RS_TRACE_NAME_FMT("IsLeashWindowCache: toSubThread[%d] IsScale[%d]"
        " filter:[%d] rotate[%d] captured[%d]",
        isNeedAssignToSubThread, node.IsScale(),
        node.HasFilter(), RSUifirstManager::Instance().rotationChanged_, node.IsNodeToBeCaptured());
    return isNeedAssignToSubThread;
}

// NonFocusWindow, may reuse last image cache
bool RSUifirstManager::IsNonFocusWindowCache(RSSurfaceRenderNode& node, bool animation)
{
    bool isDisplayRotation = RSUifirstManager::Instance().rotationChanged_;
    if ((RSMainThread::Instance()->GetDeviceType() != DeviceType::PC) ||
        (node.GetFirstLevelNodeId() != node.GetId()) ||
        (RSUifirstManager::Instance().NodeIsInCardWhiteList(node))) {
        return false;
    }

    std::string surfaceName = node.GetName();
    bool needFilterSCB = node.GetSurfaceWindowType() == SurfaceWindowType::SYSTEM_SCB_WINDOW;
    if (!node.GetForceUIFirst() && (needFilterSCB || node.IsSelfDrawingType())) {
        return false;
    }
    if ((node.IsFocusedNode(RSMainThread::Instance()->GetFocusNodeId()) ||
        node.IsFocusedNode(RSMainThread::Instance()->GetFocusLeashWindowId())) &&
        node.GetHasSharedTransitionNode()) {
        return false;
    }
    return node.QuerySubAssignable(isDisplayRotation);
}

void RSUifirstManager::UpdateUifirstNodes(RSSurfaceRenderNode& node, bool ancestorNodeHasAnimation)
{
    RS_TRACE_NAME_FMT("UpdateUifirstNodes: Id[%llu] name[%s] FLId[%llu] Ani[%d] Support[%d] isUiFirstOn[%d]",
        node.GetId(), node.GetName().c_str(), node.GetFirstLevelNodeId(),
        ancestorNodeHasAnimation, node.GetUifirstSupportFlag(), isUiFirstOn_);
    if (!isUiFirstOn_ || !node.GetUifirstSupportFlag()) {
        UifirstStateChange(node, MultiThreadCacheType::NONE);
        if (!node.isUifirstNode_) {
            node.isUifirstDelay_++;
            if (node.isUifirstDelay_ > EVENT_STOP_TIMEOUT) {
                node.isUifirstNode_ = true;
            }
        }
        return;
    }
    if (RSUifirstManager::IsLeashWindowCache(node, ancestorNodeHasAnimation)) {
        UifirstStateChange(node, MultiThreadCacheType::LEASH_WINDOW);
        return;
    }
    if (RSUifirstManager::IsNonFocusWindowCache(node, ancestorNodeHasAnimation)) {
        UifirstStateChange(node, MultiThreadCacheType::NONFOCUS_WINDOW);
        return;
    }
    if (RSUifirstManager::IsArkTsCardCache(node, ancestorNodeHasAnimation)) {
        UifirstStateChange(node, MultiThreadCacheType::ARKTS_CARD);
        return;
    }
    UifirstStateChange(node, MultiThreadCacheType::NONE);
}

void RSUifirstManager::UpdateUIFirstNodeUseDma(RSSurfaceRenderNode& node, const std::vector<RectI>& rects)
{
    if (!GetUseDmaBuffer(node.GetName())) {
        return;
    }
    bool intersect = false;
    for (auto& rect : rects) {
        if (rect.Intersect(node.GetDstRect())) {
            intersect = true;
            break;
        }
    }
    node.SetHardwareForcedDisabledState(intersect);

    Drawing::Matrix totalMatrix;
    float alpha = 1.f;
    auto surfaceNode = node.ReinterpretCastTo<RSSurfaceRenderNode>();
    RSUniRenderUtil::AccumulateMatrixAndAlpha(surfaceNode, totalMatrix, alpha);
    node.SetTotalMatrix(totalMatrix);
}

void RSUifirstManager::UifirstStateChange(RSSurfaceRenderNode& node, MultiThreadCacheType currentFrameCacheType)
{
    auto lastFrameCacheType = node.GetLastFrameUifirstFlag();
    if ((lastFrameCacheType != MultiThreadCacheType::NONE) && (lastFrameCacheType != currentFrameCacheType)) {
        // not support cache type switch, just disable multithread cache
        currentFrameCacheType = MultiThreadCacheType::NONE;
    }
    if (lastFrameCacheType == MultiThreadCacheType::NONE) { // likely branch: last is disable
        if (currentFrameCacheType != MultiThreadCacheType::NONE) { // switch: disable -> enable
            auto surfaceNode = RSBaseRenderNode::ReinterpretCast<RSSurfaceRenderNode>(node.shared_from_this());
            RS_OPTIONAL_TRACE_NAME_FMT("UIFirst_switch disable -> enable %lld", node.GetId());
            SetUifirstNodeEnableParam(node, currentFrameCacheType);
            if (currentFrameCacheType == MultiThreadCacheType::ARKTS_CARD) { // now only update ArkTSCardNode
                node.UpdateTreeUifirstRootNodeId(node.GetId());
            }
            if (currentFrameCacheType == MultiThreadCacheType::LEASH_WINDOW) {
                node.SetUifirstUseStarting(LeashWindowContainMainWindowAndStarting(*surfaceNode));
            }
            auto func = &RSUifirstManager::ProcessTreeStateChange;
            node.RegisterTreeStateChangeCallback(func);
            node.SetUifirstStartTime(GetCurSysTime());
            AddPendingPostNode(node.GetId(), surfaceNode, currentFrameCacheType); // clear pending reset status
            AddCardNodes(node.GetId(), currentFrameCacheType);
        } else { // keep disable
            RS_OPTIONAL_TRACE_NAME_FMT("UIFirst_keep disable  %lld", node.GetId());
        }
    } else { // last is enable
        auto surfaceNode = RSBaseRenderNode::ReinterpretCast<RSSurfaceRenderNode>(node.shared_from_this());
        if (currentFrameCacheType != MultiThreadCacheType::NONE) { // keep enable
            RS_OPTIONAL_TRACE_NAME_FMT("UIFirst_keep enable  %lld", node.GetId());
            MergeOldDirty(node);
            AddPendingPostNode(node.GetId(), surfaceNode, currentFrameCacheType);
        } else { // switch: enable -> disable
            RS_OPTIONAL_TRACE_NAME_FMT("UIFirst_switch enable -> disable %lld", node.GetId());
            node.SetUifirstStartTime(-1); // -1: default start time
            AddPendingResetNode(node.GetId(), surfaceNode); // set false onsync when task done
            RemoveCardNodes(node.GetId());
        }
    }
    node.SetLastFrameUifirstFlag(currentFrameCacheType);
}

// appwindow will not be traversed in process when cache leashwindow
void RSUifirstManager::UpdateChildrenDirtyRect(RSSurfaceRenderNode& node)
{
    RectI rect(0, 0, 0, 0);
    if (node.IsLeashWindow()) {
        for (auto& child : *(node.GetChildren())) {
            if (!child) {
                continue;
            }
            auto surfaceChild = child->ReinterpretCastTo<RSSurfaceRenderNode>();
            if (!surfaceChild) {
                continue;
            }
            if (surfaceChild->IsMainWindowType()) {
                rect = rect.JoinRect(surfaceChild->GetOldDirtyInSurface());
                continue;
            }
        }
    }
    node.SetUifirstChildrenDirtyRectParam(rect);
}

void RSUifirstManager::CreateUIFirstLayer(std::shared_ptr<RSProcessor>& processor)
{
    {
        std::lock_guard<std::mutex> lock(useDmaBufferMutex_);
        if (!useDmaBuffer_) {
            return;
        }
    }
    for (auto& drawable : pendingPostDrawables_) {
        if (!drawable) {
            continue;
        }
        auto& param = drawable->GetRenderParams();
        if (!param) {
            continue;
        }
        auto params = static_cast<RSSurfaceRenderParams*>(param.get());
        if (params && params->GetHardwareEnabled()) {
            processor->CreateUIFirstLayer(*drawable, *params);
        }
    }
}

void RSUifirstManager::UpdateUIFirstLayerInfo(const ScreenInfo& screenInfo, float zOrder)
{
    {
        std::lock_guard<std::mutex> lock(useDmaBufferMutex_);
        if (!useDmaBuffer_) {
            return;
        }
    }
    for (const auto& iter : pendingPostNodes_) {
        auto& node = iter.second;
        if (node && GetUseDmaBuffer(node->GetName())) {
            node->GetRSSurfaceHandler()->SetGlobalZOrder(node->IsHardwareForcedDisabled() ? -1.f : zOrder++);
            auto transform = RSUniRenderUtil::GetLayerTransform(*node, screenInfo);
            node->UpdateHwcNodeLayerInfo(transform);
            node->SetIsLastFrameHwcEnabled(!node->IsHardwareForcedDisabled());
        }
    }
}

void RSUifirstManager::ProcessTreeStateChange(RSSurfaceRenderNode& node)
{
    RSUifirstManager::Instance().CheckCurrentFrameHasCardNodeReCreate(node);
    // Planning: do not clear complete image for card
    if (node.IsOnTheTree() || node.IsNodeToBeCaptured()) {
        return;
    }
    RSUifirstManager::Instance().DisableUifirstNode(node);
    RSUifirstManager::Instance().ForceClearSubthreadRes();
    RSUifirstManager::Instance().RemoveCardNodes(node.GetId());
}

void RSUifirstManager::DisableUifirstNode(RSSurfaceRenderNode& node)
{
    RS_TRACE_NAME_FMT("DisableUifirstNode");
    UifirstStateChange(node, MultiThreadCacheType::NONE);
}

void RSUifirstManager::AddCapturedNodes(NodeId id)
{
    capturedNodes_.push_back(id);
}

void RSUifirstManager::SetUseDmaBuffer(bool val)
{
    std::lock_guard<std::mutex> lock(useDmaBufferMutex_);
#if defined(RS_ENABLE_VK)
    useDmaBuffer_ = val && RSSystemParameters::GetUIFirstDmaBufferEnabled() &&
        RSSystemProperties::IsPhoneType() && RSSystemProperties::GetGpuApiType() == GpuApiType::VULKAN;
#else
    useDmaBuffer_ = false;
#endif
}

bool RSUifirstManager::GetUseDmaBuffer(const std::string& name)
{
    std::lock_guard<std::mutex> lock(useDmaBufferMutex_);
    return useDmaBuffer_ && name.find("ScreenShotWindow") != std::string::npos;
}

void RSUifirstManager::ResetCurrentFrameDeletedCardNodes()
{
    currentFrameDeletedCardNodes_.clear();
    isCurrentFrameHasCardNodeReCreate_ = false;
}

void RSUifirstManager::CheckCurrentFrameHasCardNodeReCreate(const RSSurfaceRenderNode& node)
{
    if (node.GetSurfaceNodeType() != RSSurfaceNodeType::ABILITY_COMPONENT_NODE ||
        node.GetName().find(ARKTSCARDNODE_NAME) == std::string::npos) {
        return;
    }
    if (!node.IsOnTheTree()) {
        currentFrameDeletedCardNodes_.emplace_back(node.GetId());
    } else if (std::find(currentFrameDeletedCardNodes_.begin(), currentFrameDeletedCardNodes_.end(),
        node.GetId()) != currentFrameDeletedCardNodes_.end()) {
        isCurrentFrameHasCardNodeReCreate_ = true;
    }
}

} // namespace Rosen
} // namespace OHOS
