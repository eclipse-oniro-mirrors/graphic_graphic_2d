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

#include "rs_sub_thread_cache.h"
#include "rs_trace.h"

#include "common/rs_common_hook.h"
#include "common/rs_optional_trace.h"
#include "display_engine/rs_luminance_control.h"
#include "drawable/rs_surface_render_node_drawable.h"
#include "feature/uifirst/rs_sub_thread_manager.h"
#include "feature/uifirst/rs_uifirst_frame_rate_control.h"
#include "feature/uifirst/rs_uifirst_manager.h"
#include "feature_cfg/graphic_feature_param_manager.h"
#ifdef RS_ENABLE_OVERLAY_DISPLAY
#include "feature/overlay_display/rs_overlay_display_manager.h"
#endif
#include "memory/rs_memory_manager.h"
#include "params/rs_screen_render_params.h"
#include "pipeline/render_thread/rs_uni_render_util.h"
#include "pipeline/rs_canvas_render_node.h"
#include "pipeline/rs_root_render_node.h"
#include "pipeline/main_thread/rs_main_thread.h"
#include "platform/common/rs_log.h"

#undef LOG_TAG
#define LOG_TAG "RSUifirstManager"

// use in mainthread, post subthread, not affect renderthread
namespace OHOS {
namespace Rosen {
namespace {
    constexpr int EVENT_START_TIMEOUT = 500;
    constexpr int EVENT_STOP_TIMEOUT = 150;
    constexpr int EVENT_DISABLE_UIFIRST_GAP = 100;
    constexpr int CLEAR_CACHE_DELAY = 400;
    constexpr size_t MAX_CLEAR_CACHE_NODE_COUNT = 500; // 500 is the maximum number of nodes can be added to the list.
    const std::string CLEAR_CACHE_TASK_PREFIX = "uifirst_clear_cache_";
    constexpr std::string_view ARKTSCARDNODE_NAME = "ArkTSCardNode";
    constexpr std::string_view EVENT_DISABLE_UIFIRST = "APP_LIST_FLING";
    constexpr int UIFIRST_TASKSKIP_PRIO_THRESHOLD = 3;
    constexpr int UIFIRST_POSTTASK_HIGHPRIO_MAX = 6;
    constexpr int SUBTHREAD_CONTROL_FRAMERATE_NODE_LIMIT = 10;
    constexpr int CACHED_SURFACE_IS_TRANSPARENT = 0;
    inline int64_t GetCurSysTime()
    {
        auto curTime = std::chrono::system_clock::now().time_since_epoch();
        return std::chrono::duration_cast<std::chrono::milliseconds>(curTime).count();
    }
    constexpr float CACHE_SIZE_SPIKE_THRESHOLD = 0.1f;
};

RSUifirstManager& RSUifirstManager::Instance()
{
    static RSUifirstManager instance; // store in mainthread instance ?
    return instance;
}

std::shared_ptr<DrawableV2::RSSurfaceRenderNodeDrawable> RSUifirstManager::GetSurfaceDrawableByID(NodeId id)
{
    if (const auto cacheIt = subthreadProcessingNode_.find(id); cacheIt != subthreadProcessingNode_.end()) {
        const auto ptr = cacheIt->second;
        if (ptr && ptr->GetNodeType() == RSRenderNodeType::SURFACE_NODE) {
            return std::static_pointer_cast<DrawableV2::RSSurfaceRenderNodeDrawable>(ptr);
        }
    }
    // unlikely
    auto ptr = DrawableV2::RSRenderNodeDrawableAdapter::GetDrawableById(id);
    if (ptr && ptr->GetNodeType() == RSRenderNodeType::SURFACE_NODE) {
        return std::static_pointer_cast<DrawableV2::RSSurfaceRenderNodeDrawable>(ptr);
    }
    return nullptr;
}

bool RSUifirstManager::SetUifirstNodeEnableParam(RSSurfaceRenderNode& node, MultiThreadCacheType type)
{
    auto ret = node.SetUifirstNodeEnableParam(type); // update drawable param
    auto isType = type == MultiThreadCacheType::LEASH_WINDOW || type == MultiThreadCacheType::NONFOCUS_WINDOW;
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
                surfaceChild->SetIsParentUifirstNodeEnableParam(isType);
                continue;
            }
        }
    }
    return ret;
}

// unref in sub when cache done
void RSUifirstManager::AddProcessDoneNode(NodeId id)
{
    // mutex
    if (id == INVALID_NODEID) {
        return;
    }
    RS_OPTIONAL_TRACE_NAME_FMT("sub done %" PRIu64"", id);
    std::lock_guard<std::mutex> lock(childernDrawableMutex_);
    subthreadProcessDoneNode_.push_back(id);
}

void RSUifirstManager::AddProcessSkippedNode(NodeId id)
{
    if (id == INVALID_NODEID) {
        return;
    }
    RS_OPTIONAL_TRACE_NAME_FMT("sub skipped %" PRIu64, id);
    std::lock_guard<std::mutex> lock(skippedNodeMutex_);
    subthreadProcessSkippedNode_.insert(id);
}

void RSUifirstManager::AddPurgedNode(NodeId id)
{
    if (id == INVALID_NODEID) {
        return;
    }
    RS_TRACE_NAME_FMT("AddPurgedNode %" PRIu64, id);
    std::lock_guard<std::mutex> lock(purgedNodeMutex_);
    purgedNode_.insert(id);
}

bool RSUifirstManager::NeedNextDrawForSkippedNode()
{
    std::lock_guard<std::mutex> lock(skippedNodeMutex_);
    return !subthreadProcessSkippedNode_.empty();
}

void RSUifirstManager::ResetUifirstNode(std::shared_ptr<RSSurfaceRenderNode>& nodePtr)
{
    if (!nodePtr) {
        return;
    }
    RS_TRACE_NAME_FMT("ResetUifirstNode name:%s,id:%" PRIu64 ",isOnTheTree:%d,"
        "toBeCaptured:%d", nodePtr->GetName().c_str(), nodePtr->GetId(), nodePtr->IsOnTheTree(),
        nodePtr->IsNodeToBeCaptured());
    RS_LOGI("ResetUifirstNode name:%{public}s,id:%{public}" PRIu64 ",isOnTheTree:%{public}d,"
        "toBeCaptured:%{public}d", nodePtr->GetName().c_str(), nodePtr->GetId(), nodePtr->IsOnTheTree(),
        nodePtr->IsNodeToBeCaptured());
    nodePtr->SetLastFrameUifirstFlag(MultiThreadCacheType::NONE);
    pendingPostNodes_.erase(nodePtr->GetId());
    pendingPostCardNodes_.erase(nodePtr->GetId());
    nodePtr->SetUifirstUseStarting(false);
    if (SetUifirstNodeEnableParam(*nodePtr, MultiThreadCacheType::NONE)) {
        // enable ->disable
        SetNodeNeedForceUpdateFlag(true);
        pendingForceUpdateNode_.push_back(nodePtr->GetId());
    }
    RSMainThread::Instance()->GetContext().AddPendingSyncNode(nodePtr);

    auto drawable = GetSurfaceDrawableByID(nodePtr->GetId());
    if (!drawable) {
        return;
    }
    auto& rsSubThreadCache = drawable->GetRsSubThreadCache();
    if (!nodePtr->IsOnTheTree() && nodePtr->IsNodeToBeCaptured()) {
        rsSubThreadCache.ResetUifirst(true);
        auto taskName = CLEAR_CACHE_TASK_PREFIX + std::to_string(nodePtr->GetId());
        auto releaseTask = [drawable] {
            auto surfaceParams = static_cast<RSSurfaceRenderParams*>(drawable->GetRenderParams().get());
            if (surfaceParams && surfaceParams->GetUifirstNodeEnableParam() == MultiThreadCacheType::NONE) {
                RS_TRACE_NAME_FMT("ResetUifirstNode clearCache id:%llu", surfaceParams->GetId());
                drawable->GetRsSubThreadCache().ResetUifirst();
            }
        };
        RSUniRenderThread::Instance().PostTask(releaseTask, taskName, CLEAR_CACHE_DELAY);
    } else {
        nodePtr->SetIsNodeToBeCaptured(false);
        rsSubThreadCache.ResetUifirst();
    }
}

void RSUifirstManager::ResetWindowCache(std::shared_ptr<RSSurfaceRenderNode>& nodePtr)
{
    if (!nodePtr) {
        RS_LOGE("ResetWindowCache nodePtr is null");
        return;
    }
    auto drawable = GetSurfaceDrawableByID(nodePtr->GetId());
    if (!drawable) {
        RS_LOGE("ResetWindowCache drawable is null");
        return;
    }
    // run in RT thread
    drawable->GetRsSubThreadCache().ResetWindowCache();
}

void RSUifirstManager::MergeOldDirty(NodeId id)
{
    if (!mainThread_) {
        return;
    }
    auto node = RSBaseRenderNode::ReinterpretCast<RSSurfaceRenderNode>(
        mainThread_->GetContext().GetNodeMap().GetRenderNode(id));
    if (!node) {
        return;
    }
    if (node->IsAppWindow() &&
        !RSBaseRenderNode::ReinterpretCast<RSSurfaceRenderNode>(node->GetParent().lock())) {
        auto& curDirtyManager = node->GetDirtyManagerForUifirst();
        if (curDirtyManager) {
            curDirtyManager->SetUifirstFrameDirtyRect(node->GetOldDirty());
        }
        return;
    }
    bool hasAppWindow = false;
    for (auto& child : * node-> GetSortedChildren()) {
        auto surfaceNode = RSBaseRenderNode::ReinterpretCast<RSSurfaceRenderNode>(child);
        if (surfaceNode && surfaceNode->IsAppWindow()) {
            hasAppWindow = true;
            auto& curDirtyManager = surfaceNode->GetDirtyManagerForUifirst();
            if (curDirtyManager) {
                curDirtyManager->SetUifirstFrameDirtyRect(surfaceNode->GetOldDirty());
            }
            break;
        }
    }
    if (!hasAppWindow) {
        auto& curDirtyManager = node->GetDirtyManagerForUifirst();
        if (curDirtyManager) {
            curDirtyManager->SetUifirstFrameDirtyRect(node->GetOldDirty());
        }
    }
}

void RSUifirstManager::MergeOldDirtyToDirtyManager(std::shared_ptr<RSSurfaceRenderNode>& node)
{
    auto& curDirtyManager = node->GetDirtyManagerForUifirst();
    if (!curDirtyManager) {
        RS_LOGE("MergeOldDirtyToDirtyManager curDirtyManager is nullptr");
        return;
    }
    auto curDirtyRegion = curDirtyManager->GetCurrentFrameDirtyRegion();
    auto uifirstDirtyRegion = curDirtyManager->GetUifirstFrameDirtyRegion();
    curDirtyManager->MergeDirtyRect(uifirstDirtyRegion);
    curDirtyManager->SetUifirstFrameDirtyRect(curDirtyRegion);
    RS_OPTIONAL_TRACE_NAME_FMT("MergeOldDirtyToDirtyManager %" PRIu64","
        " curDirtyRegion[%d %d %d %d], uifirstDirtyRegion[%d %d %d %d]",
        node->GetId(), curDirtyRegion.left_, curDirtyRegion.top_, curDirtyRegion.width_, curDirtyRegion.height_,
        uifirstDirtyRegion.left_, uifirstDirtyRegion.top_, uifirstDirtyRegion.width_, uifirstDirtyRegion.height_);
    if (!uifirstDirtyRegion.IsEmpty()) {
        node->AddToPendingSyncList();
    }
}

void RSUifirstManager::RenderGroupUpdate(std::shared_ptr<DrawableV2::RSSurfaceRenderNodeDrawable> drawable)
{
    if (mainThread_ == nullptr) {
        return;
    }
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

    while (node != nullptr) {
        if (node->GetType() == RSRenderNodeType::SCREEN_NODE) {
            break;
        }
        if (node->IsSuggestedDrawInGroup()) {
            RS_OPTIONAL_TRACE_NAME_FMT("cache_changed by uifirst card %" PRIu64"", node->GetId());
            node->SetDrawingCacheChanged(true);
            node->AddToPendingSyncList();
        }
        node = node->GetParent().lock();
    }
}

void RSUifirstManager::ProcessForceUpdateNode()
{
    if (!mainThread_) {
        return;
    }
    std::vector<std::shared_ptr<RSRenderNode>> toDirtyNodes;
    for (auto id : pendingForceUpdateNode_) {
        auto node = mainThread_->GetContext().GetNodeMap().GetRenderNode(id);
        if (!node || node->GetLastFrameUifirstFlag() != MultiThreadCacheType::ARKTS_CARD) {
            continue;
        }
        toDirtyNodes.push_back(node);
        if (!node->IsDirty() && !node->IsSubTreeDirty()) {
            markForceUpdateByUifirst_.push_back(node);
            node->SetForceUpdateByUifirst(true);
        }
    }
    for (auto& node : toDirtyNodes) {
        node->SetDirty(true);
    }
    pendingForceUpdateNode_.clear();
}

void RSUifirstManager::NotifyUIStartingWindow(NodeId id, bool wait)
{
    if (mainThread_ == nullptr) {
        return;
    }
    auto node = RSBaseRenderNode::ReinterpretCast<RSSurfaceRenderNode>(
        mainThread_->GetContext().GetNodeMap().GetRenderNode(id));
    if (node == nullptr || !node->IsLeashWindow()) {
        return;
    }
    for (auto& child : *node->GetChildren()) {
        if (!child) {
            continue;
        }
        auto surfaceChild = child->ReinterpretCastTo<RSSurfaceRenderNode>();
        if (surfaceChild && surfaceChild->IsMainWindowType()) {
            surfaceChild->SetWaitUifirstFirstFrame(wait);
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
    }
    RS_TRACE_NAME_FMT("ProcessDoneNode num:%zu", tmp.size());
    for (auto& id : tmp) {
        RS_OPTIONAL_TRACE_NAME_FMT("Done %" PRIu64"", id);
        auto drawable = GetSurfaceDrawableByID(id);
        if (drawable && drawable->GetRsSubThreadCache().GetCacheSurfaceNeedUpdated() &&
            drawable->GetRsSubThreadCache().CheckCacheSurface()) {
            drawable->GetRsSubThreadCache().UpdateCompletedCacheSurface();
            RenderGroupUpdate(drawable);
            SetNodeNeedForceUpdateFlag(true);
            pendingForceUpdateNode_.push_back(id);
        }
        NotifyUIStartingWindow(id, false);
        subthreadProcessingNode_.erase(id);
    }
}

void RSUifirstManager::ProcessPurgedNode()
{
    std::unordered_set<NodeId> tmp;
    {
        std::lock_guard<std::mutex> lock(purgedNodeMutex_);
        if (purgedNode_.empty()) {
            return;
        }
        std::swap(tmp, purgedNode_);
    }
    RS_TRACE_NAME_FMT("ProcessPurgedNode num:%zu", tmp.size());
    ProcessSkippedNode(tmp, false);
}

void RSUifirstManager::ProcessSubThreadSkippedNode()
{
    std::unordered_set<NodeId> tmp;
    {
        std::lock_guard<std::mutex> lock(skippedNodeMutex_);
        if (subthreadProcessSkippedNode_.empty()) {
            return;
        }
        std::swap(tmp, subthreadProcessSkippedNode_);
    }
    RS_TRACE_NAME_FMT("ProcessSubThreadSkippedNode num:%zu", tmp.size());
    ProcessSkippedNode(tmp, true);
}

void RSUifirstManager::ProcessSkippedNode(const std::unordered_set<NodeId>& nodes, bool forceDraw)
{
    for (auto& id : nodes) {
        auto surfaceNode = RSBaseRenderNode::ReinterpretCast<RSSurfaceRenderNode>(
            mainThread_->GetContext().GetNodeMap().GetRenderNode(id));
        if (UNLIKELY(!surfaceNode)) {
            continue;
        }
        // If node not on the tree, do not draw it.
        if (UNLIKELY(!surfaceNode->IsOnTheTree())) {
            RS_TRACE_NAME_FMT("ProcessSkippedNode %s %" PRIu64 " not OnTheTree", surfaceNode->GetName().c_str(), id);
            continue;
        }
        // If node not enable uifirst, do not draw it in subThread.
        if (UNLIKELY(surfaceNode->GetLastFrameUifirstFlag() == MultiThreadCacheType::NONE)) {
            RS_TRACE_NAME_FMT("ProcessSkippedNode %s %" PRIu64 " disabled", surfaceNode->GetName().c_str(), id);
            continue;
        }
        if (surfaceNode->GetLastFrameUifirstFlag() == MultiThreadCacheType::ARKTS_CARD) {
            if (pendingPostCardNodes_.find(id) == pendingPostCardNodes_.end()) {
                pendingPostCardNodes_.emplace(id, surfaceNode);
                surfaceNode->SetForceDrawWithSkipped(forceDraw);
                RS_TRACE_NAME_FMT("ProcessSkippedCardNode %" PRIu64 " added", id);
                RS_LOGI("ProcessSkippedCardNode %{public}" PRIu64 " added", id);
            }
        } else {
            if (pendingPostNodes_.find(id) == pendingPostNodes_.end()) {
                pendingPostNodes_.emplace(id, surfaceNode);
                surfaceNode->SetForceDrawWithSkipped(forceDraw);
                RS_TRACE_NAME_FMT("ProcessSkippedNode %s %" PRIu64 " Type %d added", surfaceNode->GetName().c_str(), id,
                    static_cast<int>(surfaceNode->GetLastFrameUifirstFlag()));
            }
        }
    }
}

void RSUifirstManager::ProcessDoneNode()
{
#ifdef RS_ENABLE_PREFETCH
    __builtin_prefetch(&pendingResetNodes_, 0, 1);
#endif
    SetNodeNeedForceUpdateFlag(false);
    ProcessDoneNodeInner();

    // reset node when node is not doing
    for (auto it = capturedNodes_.begin(); it != capturedNodes_.end();) {
        if (mainThread_ && subthreadProcessingNode_.find(*it) == subthreadProcessingNode_.end()) {
            // reset uifirst
            auto node = RSBaseRenderNode::ReinterpretCast<RSSurfaceRenderNode>(
                mainThread_->GetContext().GetNodeMap().GetRenderNode(*it));
            if (node == nullptr) {
                it = capturedNodes_.erase(it);
                continue;
            }
            node->SetIsNodeToBeCaptured(false);
            if (node->GetLastFrameUifirstFlag() == MultiThreadCacheType::NONE) {
                ResetUifirstNode(node);
            }
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
    for (auto& surfaceNode : pendingResetWindowCachedNodes_) {
        ResetWindowCache(surfaceNode);
    }
    pendingResetWindowCachedNodes_.clear();

    for (auto it = subthreadProcessingNode_.begin(); it != subthreadProcessingNode_.end();) {
        auto id = it->first;
        auto drawable = GetSurfaceDrawableByID(id);
        if (!drawable) {
            ++it;
            continue;
        }
        auto cacheStatus = drawable->GetRsSubThreadCache().GetCacheSurfaceProcessedStatus();
        if (cacheStatus == CacheProcessStatus::SKIPPED) {
            it = subthreadProcessingNode_.erase(it);
            continue;
        }
        RS_LOGI("erase processingNode. name:%{public}s, id:%{public}" PRIu64 ", state:%{public}d",
            drawable->GetName().c_str(), id, static_cast<int>(cacheStatus));
        RS_TRACE_NAME_FMT("erase processingNode. name:%s, id:%" PRIu64 ", state:%d",
            drawable->GetName().c_str(), id, static_cast<int>(cacheStatus));
        pendingPostNodes_.erase(it->first); // dele doing node in pendingpostlist
        pendingPostCardNodes_.erase(it->first);
        // skipped by doing, need update cache because the doing cache is too old
        RSUifirstManager::Instance().AddProcessSkippedNode(it->first);
        ++it;
    }
}

bool RSUifirstManager::GetDrawableDirtyRect(const std::shared_ptr<RSSurfaceRenderNode>& node, RectI& rect)
{
    auto surfaceDrawable = std::static_pointer_cast<DrawableV2::RSSurfaceRenderNodeDrawable>(node->GetRenderDrawable());
    if (!surfaceDrawable) {
        RS_LOGE("node id:%{public}" PRIu64" surfaceDrawable is nullptr", node->GetId());
        return false;
    }
    auto surfaceDirtyManager = surfaceDrawable->GetSyncDirtyManager();
    if (!surfaceDirtyManager) {
        RS_LOGE("node id:%{public}" PRIu64" surfaceDirtyManager is nullptr", node->GetId());
        return false;
    }
    rect = surfaceDirtyManager->GetUifirstFrameDirtyRegion();
    return true;
}

bool RSUifirstManager::CurSurfaceHasVisibleDirtyRegion(const std::shared_ptr<RSSurfaceRenderNode>& node)
{
    auto visibleRegion = node->GetVisibleRegion();
    if (visibleRegion.IsEmpty()) {
        RS_OPTIONAL_TRACE_NAME_FMT("curSurface name:%s id:%" PRIu64" visibleRegion is IsEmpty",
            node->GetName().c_str(), node->GetId());
        return false;
    }

    RectI surfaceDirtyRect = {};
    if (!GetDrawableDirtyRect(node, surfaceDirtyRect)) {
        return true;
    }
    RS_TRACE_NAME_FMT("uifirstFrameDirtyRegion %" PRIu64", surfaceDirtyRegion[%d %d %d %d]", node->GetId(),
        surfaceDirtyRect.left_, surfaceDirtyRect.top_, surfaceDirtyRect.width_, surfaceDirtyRect.height_);
    Occlusion::Region surfaceDirtyRegion { { surfaceDirtyRect.left_, surfaceDirtyRect.top_,
        surfaceDirtyRect.GetRight(), surfaceDirtyRect.GetBottom() } };
    Occlusion::Region surfaceVisibleDirtyRegion = surfaceDirtyRegion.And(visibleRegion);
    if (surfaceVisibleDirtyRegion.IsEmpty()) {
        RS_OPTIONAL_TRACE_NAME_FMT("curSurface name:%s id:%" PRIu64" visibleDirtyRegion is IsEmpty",
            node->GetName().c_str(), node->GetId());
        return false;
    }
    return true;
}

bool RSUifirstManager::CheckVisibleDirtyRegionIsEmpty(const std::shared_ptr<RSSurfaceRenderNode>& node)
{
    if (GetUiFirstMode() != UiFirstModeType::MULTI_WINDOW_MODE) {
        return false;
    }
    if (ROSEN_EQ(node->GetGlobalAlpha(), 0.0f) &&
        RSMainThread::Instance()->GetSystemAnimatedScenes() == SystemAnimatedScenes::LOCKSCREEN_TO_LAUNCHER &&
        node->IsLeashWindow()) {
        RS_TRACE_NAME_FMT("Doing LOCKSCREEN_TO_LAUNCHER, fullTransparent node[%s] skips", node->GetName().c_str());
        return true;
    }
    if (node->GetUifirstContentDirty()) {
        return false;
    }
    bool hasSurfaceVisibleDirtyRegion = CurSurfaceHasVisibleDirtyRegion(node);
    std::vector<std::pair<NodeId, std::weak_ptr<RSSurfaceRenderNode>>> allSubSurfaceNodes;
    node->GetAllSubSurfaceNodes(allSubSurfaceNodes);
    for (auto& [id, subSurfaceNode] : allSubSurfaceNodes) {
        if (hasSurfaceVisibleDirtyRegion) {
            break;
        }
        auto subSurfaceNodePtr = subSurfaceNode.lock();
        if (!subSurfaceNodePtr) {
            continue;
        }
        hasSurfaceVisibleDirtyRegion =
            hasSurfaceVisibleDirtyRegion || CurSurfaceHasVisibleDirtyRegion(subSurfaceNodePtr);
    }
    RS_TRACE_NAME_FMT("allSurface name:%s id:%" PRIu64" hasSurfaceVisibleDirtyRegion:%d",
            node->GetName().c_str(), node->GetId(), hasSurfaceVisibleDirtyRegion);
    if (!hasSurfaceVisibleDirtyRegion) {
        return true;
    }
    return false;
}

void RSUifirstManager::SyncHDRDisplayParam(std::shared_ptr<DrawableV2::RSSurfaceRenderNodeDrawable> drawable,
    const GraphicColorGamut& colorGamut)
{
#ifdef RS_ENABLE_GPU
    auto surfaceParams = static_cast<RSSurfaceRenderParams*>(drawable->GetRenderParams().get());
    if (!surfaceParams || !surfaceParams->GetAncestorScreenNode().lock()) {
        return;
    }
    auto ancestor = surfaceParams->GetAncestorScreenNode().lock()->ReinterpretCastTo<RSScreenRenderNode>();
    if (!ancestor) {
        return;
    }
    auto screenParams = static_cast<RSScreenRenderParams*>(ancestor->GetRenderParams().get());
    if (!screenParams) {
        return;
    }
    bool isHdrOn = screenParams->GetHDRPresent();
    ScreenId id = screenParams->GetScreenId();
    auto& rsSubThreadCache = drawable->GetRsSubThreadCache();
    rsSubThreadCache.SetHDRPresent(isHdrOn);
    bool isScRGBEnable = RSSystemParameters::IsNeedScRGBForP3(screenParams->GetNewColorSpace()) &&
        GetUiFirstSwitch();
    bool changeColorSpace = rsSubThreadCache.GetTargetColorGamut() != colorGamut;
    if (isHdrOn || isScRGBEnable || changeColorSpace) {
        // When ScRGB or Adaptive P3 is enabled, some operations may cause the window color gamut to change.
        // In this case, the uifirst cache needs to be cleared.
        if ((isScRGBEnable || ColorGamutParam::IsAdaptiveColorGamutEnabled()) && changeColorSpace) {
            HILOG_COMM_INFO("UIFirstHDR SyncDisplayParam: ColorSpace change, ClearCacheSurface,"
                "nodeID: [%{public}" PRIu64"]", id);
            RS_TRACE_NAME_FMT("UIFirstHDR SyncHDRDisplayParam: ColorSpace change, ClearCacheSurface,"
                "nodeID: [%" PRIu64"]", id);
            drawable->GetRsSubThreadCache().ClearCacheSurfaceInThread();
        }
        rsSubThreadCache.SetScreenId(id);
        rsSubThreadCache.SetTargetColorGamut(colorGamut);
    }
    RS_LOGD("UIFirstHDR SyncDisplayParam:%{public}d, ratio:%{public}f", rsSubThreadCache.GetHDRPresent(),
        surfaceParams->GetBrightnessRatio());
#endif
}

bool RSUifirstManager::SubThreadControlFrameRate(NodeId id,
    std::shared_ptr<DrawableV2::RSSurfaceRenderNodeDrawable>& drawable,
    std::shared_ptr<RSSurfaceRenderNode>& node)
{
    RS_OPTIONAL_TRACE_NAME_FMT("SubThreadControlFrameRate id:%" PRIu64, id);
    if (!RSSystemProperties::GetSubThreadControlFrameRate()) {
        RS_LOGD("SubThread Control FrameRate Switch Status is Off");
        return false;
    }

    auto& rsSubThreadCache = drawable->GetRsSubThreadCache();
    bool hasAvailableTexture = rsSubThreadCache.HasCachedTexture() &&
        rsSubThreadCache.GetCacheSurfaceAlphaInfo() != CACHED_SURFACE_IS_TRANSPARENT &&
        rsSubThreadCache.GetCacheSurfaceProcessedNodes() > SUBTHREAD_CONTROL_FRAMERATE_NODE_LIMIT;
    bool isLeashWindow = node->GetLastFrameUifirstFlag() == MultiThreadCacheType::LEASH_WINDOW;

    return purgeEnable_ && hasAvailableTexture && isLeashWindow &&
        RSUifirstFrameRateControl::Instance().NeedRSUifirstControlFrameDrop(*node) &&
        (subthreadProcessingNode_.find(id) == subthreadProcessingNode_.end()) &&
        !drawable->GetRsSubThreadCache().IsSubThreadSkip();
}

bool RSUifirstManager::NeedPurgeByBehindWindow(NodeId id, bool hasTexture,
    const std::shared_ptr<RSSurfaceRenderNode>& node)
{
    RS_OPTIONAL_TRACE_NAME_FMT("NeedPurgeByBehindWindow id:%" PRIu64, id);
    if (GetUiFirstMode() != UiFirstModeType::MULTI_WINDOW_MODE) {
        return false;
    }
    if (!RSSystemProperties::GetUIFirstBehindWindowEnabled()) {
        RS_LOGD("Behind window control framerate switch is off");
        return false;
    }
    bool isBehindWindowOcclusion = IsBehindWindowOcclusion(node);
    return purgeEnable_ && hasTexture &&
        node->GetLastFrameUifirstFlag() == MultiThreadCacheType::NONFOCUS_WINDOW && isBehindWindowOcclusion;
}

bool RSUifirstManager::HandlePurgeBehindWindow(PendingPostNodeMap::iterator& it)
{
    auto& [id, node] = *it;
    uint64_t currentTime = GetMainThreadVsyncTime();
    uint64_t timeDiffInMilliseconds = GetTimeDiffBehindWindow(currentTime, id);
    // control the frequency of purge as the designed time
    if (timeDiffInMilliseconds >= PURGE_BEHIND_WINDOW_TIME || pendingNodeBehindWindow_[id].isFirst) {
        pendingNodeBehindWindow_[id].curTime = currentTime;
        pendingNodeBehindWindow_[id].isFirst = false;
        RS_OPTIONAL_TRACE_NAME_FMT("Don't Purge by behind window %s", node->GetName().c_str());
        return false;
    } else {
        RS_TRACE_NAME_FMT("Purge by behind window %s", node->GetName().c_str());
        return true;
    }
}

void RSUifirstManager::OnPurgePendingPostNodesInner(std::shared_ptr<RSSurfaceRenderNode>& node, bool staticContent,
    DrawableV2::RsSubThreadCache& subThreadCache)
{
    // save FLN self-dirty rect
    auto tmpRect = node->dirtyManager_->GetCurrentFrameDirtyRegion();
    RS_OPTIONAL_TRACE_NAME_FMT("OnPurgePendingPostNodes node name %s staticContent %d surfaceDirtyRect[%d %d %d %d] ",
        node->GetName().c_str(), staticContent, tmpRect.left_, tmpRect.top_, tmpRect.width_, tmpRect.height_);
    node->MergeSkippedDirtyRect(tmpRect);
    if (GetDrawableDirtyRect(node, tmpRect)) {
        node->MergeSkippedDirtyRect(tmpRect);
    }

    std::vector<std::pair<NodeId, std::weak_ptr<RSSurfaceRenderNode>>> allSubSurfaceNodes;
    node->GetAllSubSurfaceNodes(allSubSurfaceNodes);
    // save FLN all subsurface node self-dirty rect to FLN
    for (auto& [id, subSurfaceNode] : allSubSurfaceNodes) {
        auto subSurfaceNodePtr = subSurfaceNode.lock();
        if (!subSurfaceNodePtr) {
            continue;
        }
        tmpRect = subSurfaceNodePtr->dirtyManager_->GetCurrentFrameDirtyRegion();
        RS_OPTIONAL_TRACE_NAME_FMT("OnPurgePendingPostNodes node name %s surfaceDirtyRect[%d %d %d %d]",
            subSurfaceNodePtr->GetName().c_str(), tmpRect.left_, tmpRect.top_, tmpRect.width_, tmpRect.height_);
        node->MergeSkippedDirtyRect(tmpRect);
        if (GetDrawableDirtyRect(subSurfaceNodePtr, tmpRect)) {
            node->MergeSkippedDirtyRect(tmpRect);
        }
    }

    subThreadCache.SetUifirstSurfaceCacheContentStatic(staticContent);
}

bool RSUifirstManager::CommonPendingNodePurge(PendingPostNodeMap::iterator& it)
{
    auto& [id, node] = *it;
    bool needPurge = RSUniRenderUtil::CheckRenderSkipIfScreenOff();
    if (needPurge) {
        AddPurgedNode(id);
    }
    return needPurge;
}

bool RSUifirstManager::NeedPurgePendingPostNodesInner(
    PendingPostNodeMap::iterator& it, std::shared_ptr<DrawableV2::RSSurfaceRenderNodeDrawable>& drawable,
    bool cachedStaticContent)
{
    auto& [id, node] = *it;
    auto& subThreadCache = drawable->GetRsSubThreadCache();
    bool needPurge = purgeEnable_ && subThreadCache.HasCachedTexture() &&
        (cachedStaticContent || CheckVisibleDirtyRegionIsEmpty(node)) &&
        (subthreadProcessingNode_.find(id) == subthreadProcessingNode_.end()) && !subThreadCache.IsSubThreadSkip();

    needPurge = needPurge || SubThreadControlFrameRate(id, drawable, node);

    needPurge = needPurge ||
        (NeedPurgeByBehindWindow(id, subThreadCache.HasCachedTexture(), node) && HandlePurgeBehindWindow(it));

    needPurge = needPurge || CommonPendingNodePurge(it);
    return needPurge;
}

void RSUifirstManager::DoPurgePendingPostNodes(PendingPostNodeMap& pendingNode)
{
    for (auto it = pendingNode.begin(); it != pendingNode.end();) {
        auto& [id, node] = *it;
        auto drawable = GetSurfaceDrawableByID(id);
        if (!drawable || !node) {
            ++it;
            continue;
        }
        auto forceDraw = node->GetForceDrawWithSkipped();
        node->SetForceDrawWithSkipped(false);

        auto& subThreadCache = drawable->GetRsSubThreadCache();
        bool cachedStaticContent = subThreadCache.GetUifirstSurfaceCacheContentStatic();
        // Reset contentStatic if not purged
        subThreadCache.SetUifirstSurfaceCacheContentStatic(true);

        SyncHDRDisplayParam(drawable, node->GetFirstLevelNodeColorGamut());
        auto surfaceParams = static_cast<RSSurfaceRenderParams*>(drawable->GetRenderParams().get());
        if (!surfaceParams) {
            ++it;
            continue;
        }

        bool staticContent = surfaceParams->GetSurfaceCacheContentStatic();
        cachedStaticContent =  cachedStaticContent && staticContent;
        if (!node->IsOnTheTree() && subthreadProcessingNode_.find(id) == subthreadProcessingNode_.end()) {
            OnPurgePendingPostNodesInner(node, cachedStaticContent, subThreadCache);
            it = pendingNode.erase(it);
            continue;
        }

        if (forceDraw) {
            RS_TRACE_NAME_FMT("Purge GetForceDrawWithSkipped name: %s %" PRIu64,
                node->GetName().c_str(), drawable->GetId());
            ++it;
            continue;
        }
        RS_TRACE_NAME_FMT("Purge node name: %s, PurgeEnable:%d, HasCachedTexture:%d, staticContent: [%d %d] %" PRIu64,
            node->GetName().c_str(), purgeEnable_, subThreadCache.HasCachedTexture(), staticContent,
            cachedStaticContent, drawable->GetId());
        if (NeedPurgePendingPostNodesInner(it, drawable, cachedStaticContent)) {
            OnPurgePendingPostNodesInner(node, cachedStaticContent, subThreadCache);
            it = pendingNode.erase(it);
            continue;
        }

        ++it;
    }
}

bool RSUifirstManager::IsBehindWindowOcclusion(const std::shared_ptr<RSSurfaceRenderNode>& node)
{
    std::vector<std::pair<NodeId, std::weak_ptr<RSSurfaceRenderNode>>> allSubSurfaceNodes;
    node->GetAllSubSurfaceNodes(allSubSurfaceNodes);
    auto nodeVisibleRegion = node->GetVisibleRegion();
    auto nodeVisibleRegionBehindWindow = node->GetVisibleRegionBehindWindow();

    for (const auto &[subId, subSurfaceNode] : allSubSurfaceNodes) {
        const auto subNodePtr = subSurfaceNode.lock();
        if (subNodePtr) {
            auto visibleRegion = nodeVisibleRegion.OrSelf(subNodePtr->GetVisibleRegion());
            auto visibleRegionBehindWindow =
                nodeVisibleRegionBehindWindow.OrSelf(subNodePtr->GetVisibleRegionBehindWindow());
            RS_OPTIONAL_TRACE_NAME_FMT("visibleRegion is [%s], visibleRegionBehindWindow is [%s]",
                visibleRegion.GetRegionInfo().c_str(),
                visibleRegionBehindWindow.GetRegionInfo().c_str());
            
            if (visibleRegionBehindWindow.IsEmpty() && !visibleRegion.IsEmpty()) {
                return true;
            }
        }
    }
    return false;
}

uint64_t RSUifirstManager::GetTimeDiffBehindWindow(uint64_t currentTime, NodeId id)
{
    uint64_t timeDiff = currentTime - pendingNodeBehindWindow_[id].curTime;
    RS_OPTIONAL_TRACE_NAME_FMT("timeDiff is %lu", timeDiff);
    return timeDiff;
}

uint64_t RSUifirstManager::GetMainThreadVsyncTime()
{
    uint64_t mainThreadVsyncTime = RSMainThread::Instance()->GetCurrentVsyncTime();
    uint64_t mainThreadVsyncTimeMS = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::nanoseconds(mainThreadVsyncTime)).count());
    return mainThreadVsyncTimeMS;
}

void RSUifirstManager::PurgePendingPostNodes()
{
    RS_OPTIONAL_TRACE_NAME_FMT("PurgePendingPostNodes");
    DoPurgePendingPostNodes(pendingPostNodes_);
    DoPurgePendingPostNodes(pendingPostCardNodes_);
    ProcessMarkedNodeSubThreadCache();
    for (auto& node : markForceUpdateByUifirst_) {
        node->SetForceUpdateByUifirst(false);
    }
    markForceUpdateByUifirst_.clear();
    for (auto id : pendingForceUpdateNode_) {
        MergeOldDirty(id);
    }
}

void RSUifirstManager::PostSubTask(NodeId id)
{
    RS_TRACE_NAME_FMT("post UpdateCacheSurface %" PRIu64"", id);
    if (subthreadProcessingNode_.find(id) != subthreadProcessingNode_.end()) { // drawable is doing, do not send
        RS_TRACE_NAME_FMT("node %" PRIu64" is doing", id);
        RS_LOGE("RSUifirstManager ERROR: post task twice");
        return;
    }

    // 1.find in cache list(done to dele) 2.find in global list
    auto drawable = DrawableV2::RSRenderNodeDrawableAdapter::GetDrawableById(id);
    if (drawable) {
        auto surfaceNodeDrawable = std::static_pointer_cast<DrawableV2::RSSurfaceRenderNodeDrawable>(drawable);
        if (surfaceNodeDrawable) {
            surfaceNodeDrawable->GetRsSubThreadCache().UpdateUifirstDirtyManager(surfaceNodeDrawable.get());
        }
        // ref drawable
        subthreadProcessingNode_.emplace(id, drawable);
        // post task
        RS_OPTIONAL_TRACE_NAME_FMT("Post_SubTask_s %" PRIu64"", id);
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
    for (auto& cardNode : collectedCardNodes_) {
        PostReleaseCacheSurfaceSubTask(cardNode);
    }
}

void RSUifirstManager::PostReleaseCacheSurfaceSubTask(NodeId id)
{
    RS_OPTIONAL_TRACE_NAME_FMT("post ReleaseCacheSurface %" PRIu64, id);

    if (subthreadProcessingNode_.find(id) != subthreadProcessingNode_.end()) { // drawable is doing, do not send
        RS_TRACE_NAME_FMT("node %" PRIu64" is doing", id);
        RS_LOGE("RSUifirstManager ERROR: try to clean running node");
        return;
    }

    // 1.find in cache list(done to dele) 2.find in global list
    auto drawable = DrawableV2::RSRenderNodeDrawableAdapter::GetDrawableById(id);
    if (drawable) {
        // post task
        RS_OPTIONAL_TRACE_NAME_FMT("Post_SubTask_s %" PRIu64"", id);
        RSSubThreadManager::Instance()->ScheduleReleaseCacheSurfaceOnly(
            std::static_pointer_cast<DrawableV2::RSSurfaceRenderNodeDrawable>(drawable));
    }
}

void RSUifirstManager::UpdateSkipSyncNode()
{
    processingNodeSkipSync_.clear();
    processingNodePartialSync_.clear();
    processingCardNodeSkipSync_.clear();
    RS_OPTIONAL_TRACE_NAME_FMT("UpdateSkipSyncNode doing%zu", subthreadProcessingNode_.size());
    if (subthreadProcessingNode_.size() == 0) {
        return;
    }
    if (!mainThread_) {
        return;
    }
    for (auto it = subthreadProcessingNode_.begin(); it != subthreadProcessingNode_.end(); it++) {
        RS_OPTIONAL_TRACE_NAME_FMT("doning%" PRIu64"", it->first);
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
    ProcessSubThreadSkippedNode(); // try reschedule skipped node
    ProcessPurgedNode(); // try reschedule purged node
    ProcessDoneNode(); // release finish drawable
    UpdateSkipSyncNode();
    RestoreSkipSyncNode();
    ResetCurrentFrameDeletedCardNodes();
}

static inline void SetUifirstSkipPartialSync(const std::shared_ptr<RSRenderNode> &node, bool needSync)
{
    // node not null in caller
    if (!needSync) {
        return;
    }
    node->SetUifirstSkipPartialSync(true);
}

CacheProcessStatus& RSUifirstManager::GetUifirstCachedState(NodeId id)
{
    auto ret = uifirstCacheState_.insert({ id, CacheProcessStatus::UNKNOWN });
    auto& curRootIdState = ret.first->second;
    if (curRootIdState == CacheProcessStatus::UNKNOWN) {
        /* first time to get the state of uifirstRoot, and cache the state for the remaining other times */
        auto uifirstRootNodeDrawable = DrawableV2::RSRenderNodeDrawableAdapter::GetDrawableById(id);
        if (uifirstRootNodeDrawable && uifirstRootNodeDrawable->GetNodeType() == RSRenderNodeType::SURFACE_NODE) {
            auto drawableNode =
                std::static_pointer_cast<DrawableV2::RSSurfaceRenderNodeDrawable>(uifirstRootNodeDrawable);
            curRootIdState = drawableNode->GetRsSubThreadCache().GetCacheSurfaceProcessedStatus();
        }
    }
    return curRootIdState;
}

RSUifirstManager::SkipSyncState RSUifirstManager::CollectSkipSyncNodeWithDrawableState(
    const std::shared_ptr<RSRenderNode>& node)
{
    auto isPreDoing = IsPreFirstLevelNodeDoingAndTryClear(node);
    auto drawable = node->GetRenderDrawable();
    if (UNLIKELY(!drawable || !drawable->GetRenderParams())) {
        RS_LOGE("CollectSkipSyncNode drawable/params nullptr");
        // must not be in the DOING state with the invalid drawable.
        return SkipSyncState::STATE_NOT_SKIP;
    }
    auto& params = drawable->GetRenderParams();
    if (params->GetStartingWindowFlag()) {
        RS_LOGD("starting node %{public}" PRIu64 " not skipsync", params->GetId());
        RS_TRACE_NAME_FMT("starting node %" PRIu64 " not skipsync", params->GetId());
        return SkipSyncState::STATE_NOT_SKIP;
    }
    // if node's UifirstRootNodeId is valid (e.g. ArkTsCard), use it first
    auto uifirstRootId = params->GetUifirstRootNodeId() != INVALID_NODEID ?
        params->GetUifirstRootNodeId() : params->GetFirstLevelNodeId();
    auto& curRootIdState = GetUifirstCachedState(uifirstRootId);
    RS_OPTIONAL_TRACE_NAME_FMT("node[%" PRIu64 " %" PRIu64 "] drawable[%"
        PRIu64 " %" PRIu64 "] and curNodeId [%" PRIu64"] cacheState[%d]",
        node->GetStagingRenderParams()->GetUifirstRootNodeId(), node->GetStagingRenderParams()->GetFirstLevelNodeId(),
        params->GetUifirstRootNodeId(), params->GetFirstLevelNodeId(), node->GetId(), curRootIdState);

    if (curRootIdState == CacheProcessStatus::DOING || curRootIdState == CacheProcessStatus::WAITING ||
        /* unknow state to check prefirstLevelNode */
        (uifirstRootId == INVALID_NODEID && isPreDoing)) {
        pendingSyncForSkipBefore_[uifirstRootId].push_back(node);
        auto isUifirstRootNode = (uifirstRootId == node->GetId());
        RS_OPTIONAL_TRACE_NAME_FMT("%s %" PRIu64 " root%" PRIu64,
            isUifirstRootNode ? "set partial_sync" : "CollectSkipSyncNode", node->GetId(), uifirstRootId);
        SetUifirstSkipPartialSync(node, isUifirstRootNode);
        return isUifirstRootNode ? SkipSyncState::STATE_NOT_SKIP : SkipSyncState::STATE_NEED_SKIP;
    }
    return SkipSyncState::STATE_NEED_CHECK;
}

CM_INLINE bool RSUifirstManager::CollectSkipSyncNode(const std::shared_ptr<RSRenderNode>& node)
{
    if (!node) {
        return false;
    }
    if (pendingPostNodes_.find(node->GetId()) != pendingPostNodes_.end() ||
        pendingPostCardNodes_.find(node->GetId()) != pendingPostCardNodes_.end()) {
        node->SetUifirstSyncFlag(true);
    }

    auto ret = CollectSkipSyncNodeWithDrawableState(node);
    if (ret != SkipSyncState::STATE_NEED_CHECK) {
        return ret == SkipSyncState::STATE_NEED_SKIP;
    }
    if (NodeIsInCardWhiteList(*node) && processingCardNodeSkipSync_.count(node->GetUifirstRootNodeId())) {
        pendingSyncForSkipBefore_[node->GetUifirstRootNodeId()].push_back(node);
        auto isUifirstRootNode = (node->GetUifirstRootNodeId() == node->GetId());
        RS_OPTIONAL_TRACE_NAME_FMT("%s %" PRIu64 " root%" PRIu64,
            isUifirstRootNode ? "set partial_sync card" : "CollectSkipSyncNode card",
            node->GetId(), node->GetInstanceRootNodeId());
        SetUifirstSkipPartialSync(node, isUifirstRootNode);
        return !isUifirstRootNode;
    }
    if (processingNodePartialSync_.count(node->GetInstanceRootNodeId()) > 0) {
        pendingSyncForSkipBefore_[node->GetInstanceRootNodeId()].push_back(node);
        auto isInstanceRootNode = (node->GetInstanceRootNodeId() == node->GetId());
        RS_OPTIONAL_TRACE_NAME_FMT("%s %" PRIu64 " root%" PRIu64,
            isInstanceRootNode ? "set partial_sync" : "CollectSkipSyncNode",
            node->GetId(), node->GetInstanceRootNodeId());
        SetUifirstSkipPartialSync(node, isInstanceRootNode);
        return !isInstanceRootNode;
    } else if (processingNodeSkipSync_.count(node->GetInstanceRootNodeId()) > 0) {
        RS_OPTIONAL_TRACE_NAME_FMT("CollectSkipSyncNode root %" PRIu64", node %" PRIu64,
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
            RS_OPTIONAL_TRACE_NAME_FMT("RestoreSkipSyncNode %" PRIu64" num:%zu", it.first, it.second.size());
            for (auto& node : it.second) {
                node->SetUifirstSkipPartialSync(false);
                node->AddToPendingSyncList();
            }
        }
    }
    for (auto id : todele) {
        pendingSyncForSkipBefore_.erase(id);
        if (!mainThread_) {
            continue;
        }
        auto node = mainThread_->GetContext().GetNodeMap().GetRenderNode(id);
        auto surfaceNode = RSBaseRenderNode::ReinterpretCast<RSSurfaceRenderNode>(node);
        if (!surfaceNode) {
            continue;
        }
        if (surfaceNode->GetLastFrameUifirstFlag() == MultiThreadCacheType::ARKTS_CARD &&
            surfaceNode->GetUifirstRootNodeId() == surfaceNode->GetId() &&
            pendingPostCardNodes_.find(surfaceNode->GetId()) == pendingPostCardNodes_.end()) {
            pendingPostCardNodes_[surfaceNode->GetId()] = surfaceNode;
            RS_OPTIONAL_TRACE_NAME_FMT("RestoreSkipSyncNode AddPendingPostCard %llu", id);
        }
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
}

void RSUifirstManager::ForceClearSubthreadRes()
{
    noUifirstNodeFrameCount_.store(0);
    RSSubThreadManager::Instance()->ReleaseTexture();
}

bool RSUifirstManager::IsPreFirstLevelNodeDoingAndTryClear(std::shared_ptr<RSRenderNode> node)
{
    if (!node) {
        return true;
    }
    auto& preFirstLevelNodeIdSet = node->GetMutablePreFirstLevelNodeIdSet();
    for (auto it = preFirstLevelNodeIdSet.begin(); it != preFirstLevelNodeIdSet.end();
         it = preFirstLevelNodeIdSet.erase(it)) {
        const auto& curRootIdState = GetUifirstCachedState(*it);
        if (curRootIdState == CacheProcessStatus::DOING || curRootIdState == CacheProcessStatus::WAITING) {
            return true;
        }
    }
    return false;
}

void RSUifirstManager::SetNodePriorty(std::list<NodeId>& result, PendingPostNodeMap& pendingNode)
{
    auto isFocusId = RSMainThread::Instance()->GetFocusNodeId();
    auto isLeashId = RSMainThread::Instance()->GetFocusLeashWindowId();
    int32_t postOrder = 0;
    for (auto& item : pendingNode) {
        postOrder++;
        auto const& [id, value] = item;
        if (IsPreFirstLevelNodeDoingAndTryClear(value)) {
            continue;
        }
        auto drawable = GetSurfaceDrawableByID(id);
        if (!drawable) {
            continue;
        }
        auto& rsSubThreadCache = drawable->GetRsSubThreadCache();
        if (rsSubThreadCache.HasCachedTexture()) {
            rsSubThreadCache.SetRenderCachePriority(NodePriorityType::SUB_LOW_PRIORITY);
        } else {
            rsSubThreadCache.SetRenderCachePriority(NodePriorityType::SUB_HIGH_PRIORITY);
        }
        if (rsSubThreadCache.GetCacheSurfaceProcessedStatus() == CacheProcessStatus::WAITING) {
            rsSubThreadCache.SetRenderCachePriority(NodePriorityType::SUB_HIGH_PRIORITY);
        }
        auto surfaceParams = static_cast<RSSurfaceRenderParams*>(drawable->GetRenderParams().get());
        if (surfaceParams && surfaceParams->GetPreSubHighPriorityType()) {
            rsSubThreadCache.SetRenderCachePriority(NodePriorityType::SUB_VIDEO_PRIORITY);
        }
        // focusWindow is highest priority.
        if (!isFocusNodeFound_) {
            if (id == isFocusId || id == isLeashId) {
                // for resolving response latency
                rsSubThreadCache.SetRenderCachePriority(NodePriorityType::SUB_FOCUSNODE_PRIORITY);
                isFocusNodeFound_ = true;
                focusNodeThreadIndex_ = rsSubThreadCache.GetLastFrameUsedThreadIndex();
            }
        }
        if (RSSystemProperties::GetUIFirstOptScheduleEnabled() &&
            rsSubThreadCache.GetSurfaceSkipCount() >= UIFIRST_TASKSKIP_PRIO_THRESHOLD) {
            postOrder += rsSubThreadCache.GetSurfaceSkipPriority();
        }
        rsSubThreadCache.SetUifirstPostOrder(postOrder);
        rsSubThreadCache.SetHighPostPriority(false);
        sortedSubThreadNodeIds_.emplace_back(id);
    }
    RS_TRACE_NAME_FMT("SetNodePriorty result [%zu] pendingNode [%zu]", result.size(), pendingNode.size());
}

void RSUifirstManager::SortSubThreadNodesPriority()
{
    sortedSubThreadNodeIds_.clear();
    isFocusNodeFound_ = false;
    focusNodeThreadIndex_ = UINT32_MAX;
    SetNodePriorty(sortedSubThreadNodeIds_, pendingPostNodes_);
    SetNodePriorty(sortedSubThreadNodeIds_, pendingPostCardNodes_);
    RS_LOGD("SetNodePriorty result [%{public}zu] pendingNode [%{public}zu] pendingCardNode [%{public}zu]",
        sortedSubThreadNodeIds_.size(), pendingPostNodes_.size(), pendingPostCardNodes_.size());
    sortedSubThreadNodeIds_.sort([this](const auto& first, const auto& second) -> bool {
        auto drawable1 = GetSurfaceDrawableByID(first);
        auto drawable2 = GetSurfaceDrawableByID(second);
        if (drawable1 == nullptr || drawable2 == nullptr) {
            ROSEN_LOGE("SortSubThreadNodesPriority sort nullptr found in pendingPostNodes_, "
                "this should not happen");
            return false;
        }
        auto surfaceParams1 = static_cast<RSSurfaceRenderParams*>(drawable1->GetRenderParams().get());
        if (!surfaceParams1) {
            RS_LOGE("sortsubthread params1 is nullptr");
            return false;
        }
        auto surfaceParams2 = static_cast<RSSurfaceRenderParams*>(drawable2->GetRenderParams().get());
        if (!surfaceParams2) {
            RS_LOGE("sortsubthread params2 is nullptr");
            return false;
        }
        auto& rsSubThreadCache1 = drawable1->GetRsSubThreadCache();
        auto& rsSubThreadCache2 = drawable2->GetRsSubThreadCache();
        if (rsSubThreadCache1.GetRenderCachePriority() == rsSubThreadCache2.GetRenderCachePriority()) {
            return rsSubThreadCache1.GetUifirstPostOrder() > rsSubThreadCache2.GetUifirstPostOrder();
        } else {
            return rsSubThreadCache1.GetRenderCachePriority() < rsSubThreadCache2.GetRenderCachePriority();
        }
    });
}

void RSUifirstManager::MarkPostNodesPriority()
{
    if (!RSSystemProperties::GetUIFirstOptScheduleEnabled()) {
        return;
    }
    int postTaskCount = 0;
    for (auto& id : sortedSubThreadNodeIds_) {
        auto drawable = GetSurfaceDrawableByID(id);
        if (!drawable) {
            continue;
        }
        auto& rsSubThreadCache = drawable->GetRsSubThreadCache();
        postTaskCount++;
        if (rsSubThreadCache.GetRenderCachePriority() > NodePriorityType::SUB_LOW_PRIORITY) {
            rsSubThreadCache.SetHighPostPriority(true);
            continue;
        }
        if (!isFocusNodeFound_) {
            if (postTaskCount < UIFIRST_POSTTASK_HIGHPRIO_MAX) {
                rsSubThreadCache.SetHighPostPriority(true);
            } else {
                rsSubThreadCache.SetHighPostPriority(false);
            }
        } else {
            if (focusNodeThreadIndex_ == rsSubThreadCache.GetLastFrameUsedThreadIndex()) {
                rsSubThreadCache.SetHighPostPriority(true);
            } else {
                rsSubThreadCache.SetHighPostPriority(false);
            }
        }
    }
}

// post in drawframe sync time
void RSUifirstManager::PostUifistSubTasks()
{
    PurgePendingPostNodes();
    SortSubThreadNodesPriority();
    MarkPostNodesPriority();
    if (sortedSubThreadNodeIds_.size() > 0) {
        RS_TRACE_NAME_FMT("PostUifistSubTasks %zu", sortedSubThreadNodeIds_.size());
        for (auto& id : sortedSubThreadNodeIds_) {
            PostSubTask(id);
        }
        pendingPostNodes_.clear();
        pendingPostCardNodes_.clear();
        sortedSubThreadNodeIds_.clear();
    } else {
        ClearSubthreadRes();
    }
    UifirstCurStateClear();
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
        RS_TRACE_NAME_FMT("nID:%" PRIu64" , nType:%d, support:%d, canvasNodeNum:%d, mainwindowNum:%d",
            child->GetId(), static_cast<int>(child->GetType()), support, canvasNodeNum, mainwindowNum);
        auto canvasChild = child->ReinterpretCastTo<RSCanvasRenderNode>();
        if (canvasChild && canvasChild->GetChildrenCount() == 0 && mainwindowNum > 0) {
            canvasNodeNum++;
            if (startingWindow != nullptr) {
                startingWindow->SetStartingWindowFlag(false);
            }
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
    RS_TRACE_NAME_FMT("uifirst_node support:%d, canvasNodeNum:%d, mainwindowNum:%d, hasStartingWindow:%d",
        support, canvasNodeNum, mainwindowNum, startingWindow != nullptr);
    if (support && canvasNodeNum == 1 && mainwindowNum > 0 && startingWindow) { // starting window & appwindow
        startingWindow->SetStartingWindowFlag(true);
        return startingWindow->GetId();
    } else {
        if (startingWindow) {
            startingWindow->SetStartingWindowFlag(false);
        }
        return INVALID_NODEID;
    }
}

bool RSUifirstManager::HasStartingWindow(RSSurfaceRenderNode& node)
{
    auto startingWindowId = LeashWindowContainMainWindowAndStarting(node);
    if (startingWindowId != INVALID_NODEID) { // has starting window
        node.SetUifirstUseStarting(startingWindowId);
        // block first frame callback
        NotifyUIStartingWindow(node.GetId(), true);
        return true;
    }
    return false;
}

void RSUifirstManager::AddPendingPostNode(NodeId id, std::shared_ptr<RSSurfaceRenderNode>& node,
    MultiThreadCacheType currentFrameCacheType)
{
    if (id == INVALID_NODEID || !node) {
        return;
    }

    // process for uifirst node
    UpdateChildrenDirtyRect(*node);
    node->SetHwcChildrenDisabledState();
    RS_OPTIONAL_TRACE_FMT("hwc debug: name:%s id:%" PRIu64 " children disabled by uifirst",
        node->GetName().c_str(), node->GetId());
    node->AddToPendingSyncList();

    if (currentFrameCacheType == MultiThreadCacheType::LEASH_WINDOW ||
        currentFrameCacheType == MultiThreadCacheType::NONFOCUS_WINDOW) {
        if (isRecentTaskScene_.load() && !node->IsNodeToBeCaptured() &&
            currentFrameCacheType == MultiThreadCacheType::LEASH_WINDOW) {
            node->SetIsNodeToBeCaptured(true);
        } else if (!isRecentTaskScene_.load()) {
            node->SetIsNodeToBeCaptured(false);
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
        AddPendingNodeBehindWindow(id, node, currentFrameCacheType);
        RS_OPTIONAL_TRACE_NAME_FMT("Add pending id:%" PRIu64 " name:%s size:%zu",
            node->GetId(), node->GetName().c_str(), pendingPostNodes_.size());
    } else if (currentFrameCacheType == MultiThreadCacheType::ARKTS_CARD) {
        pendingPostCardNodes_[id] = node;
    }

    pendingResetNodes_.erase(id); // enable uifirst when waiting for reset
}

void RSUifirstManager::AddPendingNodeBehindWindow(NodeId id, std::shared_ptr<RSSurfaceRenderNode>& node,
    MultiThreadCacheType currentFrameCacheType)
{
    if (currentFrameCacheType == MultiThreadCacheType::NONFOCUS_WINDOW &&
        RSSystemProperties::GetUIFirstBehindWindowEnabled()) {
        auto temp_it = pendingNodeBehindWindow_.find(id);
        if (temp_it == pendingNodeBehindWindow_.end()) {
            RS_OPTIONAL_TRACE_NAME_FMT("Add to pendingNodeBehindWindow id:%" PRIu64 " name:%s", node->GetId(),
                node->GetName().c_str());
            pendingNodeBehindWindow_[id] = NodeDataBehindWindow{.curTime = GetMainThreadVsyncTime()};
        }
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
        return drawable->GetRsSubThreadCache().GetCacheSurfaceProcessedStatus();
    }
    return CacheProcessStatus::UNKNOWN;
}

void RSUifirstManager::UpdateCompletedSurface(NodeId id)
{
    auto drawable = GetSurfaceDrawableByID(id);
    if (drawable) {
        drawable->GetRsSubThreadCache().UpdateCompletedCacheSurface();
    }
}

void RSUifirstManager::OnProcessEventResponse(DataBaseRs& info)
{
    RSReclaimMemoryManager::Instance().InterruptReclaimTask(info.sceneId);
    RS_OPTIONAL_TRACE_NAME_FMT("uifirst uniqueId:%" PRId64", appPid:%" PRId32", sceneId:%s",
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
    if (!mainThread_) {
        mainThread_ = RSMainThread::Instance();
    }
    if (mainThread_) {
        const auto& nodeMap = mainThread_->GetContext().GetNodeMap();
        entryViewNodeId_ = nodeMap.GetEntryViewNodeId();
        negativeScreenNodeId_ = nodeMap.GetNegativeScreenNodeId();
        scbPid_ = ExtractPid(entryViewNodeId_);
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
    RS_TRACE_NAME_FMT("OnProcessAnimateScene systemAnimatedScene:%d", systemAnimatedScene);
    RS_LOGD("OnProcessAnimateScene SystemAnimatedScene:[%{public}d]", systemAnimatedScene);
    switch (systemAnimatedScene) {
        // recent task scene for phone
        case SystemAnimatedScenes::ENTER_RECENTS:
            isRecentTaskScene_.store(true);
            break;
        case SystemAnimatedScenes::EXIT_RECENTS:
            isRecentTaskScene_.store(false);
            break;
        // enter and exit mission center are two independent animations, the same goes for enter and exit split screen
        // enter and exit mission center or enter and exit split screen animation starts for PC
        case SystemAnimatedScenes::ENTER_MISSION_CENTER:
        case SystemAnimatedScenes::EXIT_MISSION_CENTER:
            isMissionCenterScene_.store(true);
            break;
        case SystemAnimatedScenes::ENTER_SPLIT_SCREEN:
        case SystemAnimatedScenes::EXIT_SPLIT_SCREEN:
            isSplitScreenScene_.store(true);
            break;
        case SystemAnimatedScenes::SNAPSHOT_ROTATION:
            isSnapshotRotationScene_.store(true);
            break;
        // enter and exit mission center or enter and exit split screen animation ends for PC
        case SystemAnimatedScenes::OTHERS:
            isMissionCenterScene_.store(false);
            isSplitScreenScene_.store(false);
            isSnapshotRotationScene_.store(false);
            break;
        default:
            isSnapshotRotationScene_.store(false);
            break;
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

// exit uifirst when leash has APP_LIST_FLING event.
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

bool RSUifirstManager::HasBgNodeBelowRootNode(RSSurfaceRenderNode& appNode) const
{
    auto appFirstChildren = appNode.GetFirstChild();
    if (!appFirstChildren) {
        return false;
    }
    auto rootNode = RSBaseRenderNode::ReinterpretCast<RSRootRenderNode>(appFirstChildren);
    if (!rootNode) {
        return false;
    }
    auto rootFirstChildren = rootNode->GetFirstChild();
    if (!rootFirstChildren) {
        return false;
    }
    auto bgColorNode = RSBaseRenderNode::ReinterpretCast<RSCanvasRenderNode>(rootFirstChildren);
    if (!bgColorNode) {
        return false;
    }
    auto backgroundColor =
        static_cast<Drawing::ColorQuad>(bgColorNode->GetRenderProperties().GetBackgroundColor().AsArgbInt());
    if (Drawing::Color::ColorQuadGetA(backgroundColor) != Drawing::Color::COLOR_TRANSPARENT) {
        return true;
    }
    return false;
}

bool RSUifirstManager::CheckHasTransAndFilter(RSSurfaceRenderNode& node)
{
    if (!node.IsLeashWindow()) {
        return false;
    }
    bool childHasVisibleFilter = node.ChildHasVisibleFilter();
    bool hasTransparent = false;
    RectI mainAppSurfaceRect = {};
    bool isMainAppSurface = false;
    bool hasChildOutOfMainAppSurface = false;
    for (auto &child : *node.GetSortedChildren()) {
        auto childSurface = RSBaseRenderNode::ReinterpretCast<RSSurfaceRenderNode>(child);
        if (childSurface == nullptr || hasChildOutOfMainAppSurface) {
            continue;
        }
        if (!isMainAppSurface && childSurface->IsAppWindow()) {
            bool isBgColorTrans = HasBgNodeBelowRootNode(*childSurface);
            hasTransparent |= (childSurface->IsTransparent() && !isBgColorTrans);
            mainAppSurfaceRect = childSurface->GetAbsDrawRect();
            isMainAppSurface = true;
            RS_OPTIONAL_TRACE_NAME_FMT("Id:%" PRIu64 " name[%s] isTrans:%d isBgTrans:%d, hasTrans:%d",
                childSurface->GetId(), childSurface->GetName().c_str(),
                childSurface->IsTransparent(), isBgColorTrans, hasTransparent);
            continue;
        }
        if (childSurface->IsTransparent() && !childSurface->GetAbsDrawRect().IsInsideOf(mainAppSurfaceRect)) {
            RS_OPTIONAL_TRACE_NAME_FMT("Id:%" PRIu64 " name[%s] absDrawRect is outof mainAppNode",
                childSurface->GetId(), childSurface->GetName().c_str());
            hasChildOutOfMainAppSurface = true;
        }
    }
    hasTransparent |= hasChildOutOfMainAppSurface;
    RS_TRACE_NAME_FMT("CheckHasTransAndFilter node:%" PRIu64 " hasTransparent: %d, childHasVisibleFilter: %d",
        node.GetId(), hasTransparent, childHasVisibleFilter);
    return hasTransparent && childHasVisibleFilter;
}

void RSUifirstManager::ProcessFirstFrameCache(RSSurfaceRenderNode& node, MultiThreadCacheType cacheType)
{
    // purpose: to avoid that RT waits uifirst cache long time when switching to uifirst first frame,
    // draw and cache win in RT on first frame, then use RT thread cache to draw until uifirst cache ready.
    if (node.GetLastFrameUifirstFlag() == MultiThreadCacheType::NONE &&
        !node.GetSubThreadAssignable()) {
        RS_TRACE_NAME_FMT("AssignMainThread selfAndParentShouldPaint: %d, skipDraw: %d",
            node.GetSelfAndParentShouldPaint(), node.GetSkipDraw());
        UifirstStateChange(node, MultiThreadCacheType::NONE); // mark as draw win in RT thread
        if (node.GetSelfAndParentShouldPaint() && !node.GetSkipDraw()) {
            node.SetSubThreadAssignable(true); // mark as assignable to uifirst next frame
            node.SetNeedCacheSurface(true); // mark as that needs cache win in RT
            auto parent = node.GetParent().lock();
            if (parent != nullptr && cacheType == MultiThreadCacheType::ARKTS_CARD) {
                // disable render group for card
                parent->SetDrawingCacheType(RSDrawingCacheType::DISABLED_CACHE);
            }
            node.SetHwcChildrenDisabledState();
            RS_OPTIONAL_TRACE_NAME_FMT("name:%s id:%" PRIu64 " children disabled by uifirst first frame",
                node.GetName().c_str(), node.GetId());
            // delte caches when node is not on the tree.
            auto func = &RSUifirstManager::ProcessTreeStateChange;
            node.RegisterTreeStateChangeCallback(func);
        }
    } else {
        UifirstStateChange(node, cacheType);
    }
}

bool RSUifirstManager::IsArkTsCardCache(RSSurfaceRenderNode& node, bool animation)
{
    if (!RSUifirstManager::Instance().isCardUiFirstOn_) {
        return false;
    }
    auto baseNode = node.GetAncestorScreenNode().lock();
    if (!baseNode) {
        RS_LOGE("surfaceNode GetAncestorScreenNode().lock() return nullptr");
        return false;
    }
    auto curScreenNode = baseNode->ReinterpretCastTo<RSScreenRenderNode>();
    if (curScreenNode == nullptr) {
        RS_LOGE("surfaceNode GetAncestorScreenNode().lock() return nullptr");
        return false;
    }
    // card node only enabled uifirst on phone
    if (RSUifirstManager::Instance().GetUiFirstMode() != UiFirstModeType::SINGLE_WINDOW_MODE ||
        node.GetSurfaceNodeType() != RSSurfaceNodeType::ABILITY_COMPONENT_NODE ||
        node.GetName().find(ARKTSCARDNODE_NAME) == std::string::npos) {
        return false;
    }
    bool isWhiteListCard = RSUifirstManager::Instance().NodeIsInCardWhiteList(node);
    bool shouldPaint = node.ShouldPaint();
    bool isNeedAssignToSubThread = isWhiteListCard && shouldPaint;
    RS_TRACE_NAME_FMT("IsArkTsCardCache toSubThread[%d] whiteListCard[%d] shouldPaint[%d]",
        isNeedAssignToSubThread, isWhiteListCard, shouldPaint);
    return isNeedAssignToSubThread;
}

bool RSUifirstManager::IsCacheSizeValid(RSSurfaceRenderNode& node)
{
    auto stagingSurfaceParams = static_cast<RSSurfaceRenderParams*>(node.GetStagingRenderParams().get());
    if (!stagingSurfaceParams) {
        RS_TRACE_NAME_FMT("[%s] cachedSize invalid stagingSurfaceParams is nullptr", node.GetName().c_str());
        RS_LOGE("[%{public}s] cachedSize invalid stagingSurfaceParams is nullptr", node.GetName().c_str());
        return false;
    }

    auto lastUifirstFlag = node.GetLastFrameUifirstFlag();
    if (lastUifirstFlag == MultiThreadCacheType::NONE) {
        RS_OPTIONAL_TRACE_NAME_FMT("[%s] cachedSize valid lastUifirstFlag is %d",
            node.GetName().c_str(), static_cast<int>(lastUifirstFlag));
        return true;
    }

    auto gravity = static_cast<int32_t>(stagingSurfaceParams->GetUIFirstFrameGravity());
    if (gravity >= static_cast<int32_t>(Gravity::RESIZE) &&
        gravity <= static_cast<int32_t>(Gravity::RESIZE_ASPECT_FILL_BOTTOM_RIGHT)) {
        RS_OPTIONAL_TRACE_NAME_FMT("cachedSize valid gravity is resize %d", static_cast<int32_t>(gravity));
        return true;
    }

    const auto& cachedSize = stagingSurfaceParams->GetCacheSize();
    const auto& lastCachedSize = stagingSurfaceParams->GetLastCacheSize();
    if (ROSEN_EQ(cachedSize.x_, 0.f) || ROSEN_EQ(cachedSize.y_, 0.f)) {
        RS_TRACE_NAME_FMT("[%s] cachedSize invalid cur[%f %f]", node.GetName().c_str(), cachedSize.x_, cachedSize.y_);
        RS_LOGW("[%{public}s] cachedSize invalid cur[%{public}f %{public}f]",
            node.GetName().c_str(), cachedSize.x_, cachedSize.y_);
        return true;
    }

    bool cacheSizeStable = ROSEN_EQ(lastCachedSize.x_ / cachedSize.x_,
        lastCachedSize.y_ / cachedSize.y_, CACHE_SIZE_SPIKE_THRESHOLD);
    if (cacheSizeStable) {
        RS_OPTIONAL_TRACE_NAME_FMT("[%s] cacheSizeStable cur[%f %f] last[%f %f]", node.GetName().c_str(),
            cachedSize.x_, cachedSize.y_, lastCachedSize.x_, lastCachedSize.y_);
        return true;
    }

    bool isCacheSizeRotated = !ROSEN_EQ(cachedSize.x_, cachedSize.y_) &&
            ROSEN_EQ(cachedSize.x_, lastCachedSize.y_) && ROSEN_EQ(cachedSize.y_, lastCachedSize.x_);
    // Rotated check will be deleted when threshold has been setted by CCM
    if (!isCacheSizeRotated) {
        RS_OPTIONAL_TRACE_NAME_FMT("[%s] CacheSizeRotated cur[%f %f] last[%f %f]", node.GetName().c_str(),
            cachedSize.x_, cachedSize.y_, lastCachedSize.x_, lastCachedSize.y_);
        return true;
    }

    RS_TRACE_NAME_FMT("[%s] cachedSize invalid cur[%f %f] last[%f %f] gravity %d", node.GetName().c_str(),
        cachedSize.x_, cachedSize.y_, lastCachedSize.x_, lastCachedSize.y_, static_cast<int32_t>(gravity));
    return false;
}

// animation first, may reuse last image cache
bool RSUifirstManager::IsLeashWindowCache(RSSurfaceRenderNode& node, bool animation)
{
    if ((RSUifirstManager::Instance().GetUiFirstMode() == UiFirstModeType::MULTI_WINDOW_MODE) ||
        (node.GetFirstLevelNodeId() != node.GetId()) ||
        (RSUifirstManager::Instance().NodeIsInCardWhiteList(node)) ||
        (RSUifirstManager::Instance().CheckIfAppWindowHasAnimation(node))) {
        return false;
    }
    if (!node.IsLeashWindow()) {
        return false;
    }
#ifdef RS_ENABLE_OVERLAY_DISPLAY
    if (RSOverlayDisplayManager::Instance().IsOverlayDisplayEnableForCurrentVsync()) {
        // only for tv, when overlay display is enabled, force clip hole will be setted which conflict with ui first.
        return false;
    }
#endif
    // check transparent and childHasVisibleFilter
    if (RSUifirstManager::Instance().CheckHasTransAndFilter(node)) {
        return false;
    }

    bool isNeedAssignToSubThread = false;
    bool isScale = node.IsScale();
    bool isRotate = RSUifirstManager::Instance().rotationChanged_ &&
        !RSUifirstManager::Instance().IsSnapshotRotationScene();
    bool isRecentScene = RSUifirstManager::Instance().IsRecentTaskScene();
    if (isRecentScene) {
        isNeedAssignToSubThread = isScale && LeashWindowContainMainWindow(node);
    } else {
        isNeedAssignToSubThread = animation;
    }
    isNeedAssignToSubThread = (isNeedAssignToSubThread ||
        (node.GetForceUIFirst() || node.GetUIFirstSwitch() == RSUIFirstSwitch::FORCE_ENABLE_LIMIT)) && !isRotate;

    isNeedAssignToSubThread = isNeedAssignToSubThread && RSUifirstManager::Instance().IsCacheSizeValid(node);

    bool needFilterSCB = IS_SCB_WINDOW_TYPE(node.GetSurfaceWindowType());
    if (needFilterSCB || node.IsSelfDrawingType()) {
        RS_TRACE_NAME_FMT("IsLeashWindowCache: needFilterSCB [%d]", needFilterSCB);
        return false;
    }
    RS_TRACE_NAME_FMT("IsLeashWindowCache: toSubThread[%d] recent[%d] IsScale[%d] "
        "rotate[%d] captured[%d] snapshotRotation[%d]",
        isNeedAssignToSubThread, isRecentScene, node.IsScale(),
        RSUifirstManager::Instance().rotationChanged_, node.IsNodeToBeCaptured(),
        RSUifirstManager::Instance().IsSnapshotRotationScene());
    RS_LOGD("IsLeashWindowCache: toSubThread[%{public}d] recent[%{public}d] scale[%{public}d] "
        "rotate[%{public}d] snapshotRotation[%{public}d]", isNeedAssignToSubThread, isRecentScene, isScale,
        isRotate, RSUifirstManager::Instance().IsSnapshotRotationScene());
    return isNeedAssignToSubThread;
}

// Vm app not use uifirst when it is focused
bool RSUifirstManager::IsVMSurfaceName(std::string surfaceName)
{
    for (auto& item : vmAppNameSet_) {
        if (surfaceName.find(item) != std::string::npos) {
            return true;
        }
    }

    return false;
}

// NonFocusWindow, may reuse last image cache
bool RSUifirstManager::IsNonFocusWindowCache(RSSurfaceRenderNode& node, bool animation)
{
    if (RSUifirstManager::Instance().IsExceededWindowsThreshold(node)) {
        RS_TRACE_NAME_FMT("exceededThreshold id:%" PRIu64 ", threshold:%d, curUifirstWindowNums:%d", node.GetId(),
            RSUifirstManager::Instance().uifirstWindowsNumThreshold_,
            RSUifirstManager::Instance().curUifirstWindowNums_);
        return false;
    }
    bool isDisplayRotation = RSUifirstManager::Instance().rotationChanged_;
    if ((RSUifirstManager::Instance().GetUiFirstMode() != UiFirstModeType::MULTI_WINDOW_MODE) ||
        (node.GetFirstLevelNodeId() != node.GetId()) ||
        (RSUifirstManager::Instance().NodeIsInCardWhiteList(node))) {
        return false;
    }

    std::string surfaceName = node.GetName();
    bool needFilterSCB = IS_SCB_WINDOW_TYPE(node.GetSurfaceWindowType());
    if (!(node.GetForceUIFirst() || node.GetUIFirstSwitch() == RSUIFirstSwitch::FORCE_ENABLE_LIMIT)
        && (needFilterSCB || node.IsSelfDrawingType())) {
        return false;
    }
    bool focus = RSUifirstManager::Instance().IsFocusedNode(node);
    // open app with modal window animation, close uifirst
    bool modalAnimation = animation && node.GetUIFirstSwitch() == RSUIFirstSwitch::MODAL_WINDOW_CLOSE;
    bool optFocus = focus || UNLIKELY(node.GetUIFirstSwitch() == RSUIFirstSwitch::FORCE_DISABLE_NONFOCUS);
    if (optFocus && (node.GetHasSharedTransitionNode() ||
        (RSUifirstManager::Instance().IsVMSurfaceName(surfaceName) && !animation) ||
        !animation || modalAnimation)) {
        RS_TRACE_NAME_FMT("IsNonFocusWindowCache: surfaceName[%s] focus:%d optFocus:%d animation:%d switch:%d",
            surfaceName.c_str(), focus, optFocus, animation, node.GetUIFirstSwitch());
        return false;
    }
    // disable uifirst when leash window has no app window at recent task scene or split screen scene
    if (node.IsLeashWindow() && node.IsScale() && !LeashWindowContainMainWindow(node) &&
        (RSUifirstManager::Instance().IsMissionCenterScene() || RSUifirstManager::Instance().IsSplitScreenScene())) {
        RS_TRACE_NAME("leash window has no app window, disable uifirst");
        return false;
    }
    return RSUifirstManager::Instance().QuerySubAssignable(node, isDisplayRotation);
}

CM_INLINE bool RSUifirstManager::IsToSubByAppAnimation() const
{
    for (auto& it : currentFrameEvent_) {
        if (std::find(toSubByAppAnimation_.begin(), toSubByAppAnimation_.end(), it.sceneId) !=
            toSubByAppAnimation_.end()) {
            return true;
        }
    }
    return false;
}

bool RSUifirstManager::GetSubNodeIsTransparent(RSSurfaceRenderNode& node, std::string& dfxMsg)
{
    bool hasTransparent = false;
    if (node.IsLeashWindow()) {
        for (auto &child : *node.GetSortedChildren()) {
            auto childSurfaceNode = RSBaseRenderNode::ReinterpretCast<RSSurfaceRenderNode>(child);
            if (childSurfaceNode == nullptr) {
                continue;
            }
            hasTransparent |= childSurfaceNode->IsAlphaTransparent() || (childSurfaceNode->NeedDrawBehindWindow() &&
                !RSSystemProperties::GetUIFirstBehindWindowFilterEnabled());
            if (hasTransparent) {
                dfxMsg = "childSurfaceNode_NeedDrawBehindWindow: " +
                    std::to_string(childSurfaceNode->NeedDrawBehindWindow());
                break;
            }
        }
    } else {
        hasTransparent = node.IsAlphaTransparent() || (node.NeedDrawBehindWindow() &&
            !RSSystemProperties::GetUIFirstBehindWindowFilterEnabled());
        dfxMsg = "NeedDrawBehindWindow: " + std::to_string(node.NeedDrawBehindWindow());
    }
    if (!hasTransparent || !IsToSubByAppAnimation()) {
        // if not transparent, no need to check IsToSubByAppAnimation;
        return hasTransparent;
    }

    bool isAbilityBgColorTransparent = true;
    if (node.IsLeashWindow()) {
        for (auto &child : *node.GetSortedChildren()) {
            auto childSurfaceNode = RSBaseRenderNode::ReinterpretCast<RSSurfaceRenderNode>(child);
            if (childSurfaceNode == nullptr) {
                continue;
            }
            if (childSurfaceNode->GetAbilityBgAlpha() < UINT8_MAX) {
                isAbilityBgColorTransparent = true;
                dfxMsg = "AbBgAlpha: " + std::to_string(childSurfaceNode->GetAbilityBgAlpha());
                break;
            } else {
                isAbilityBgColorTransparent = false;
            }
        }
    } else {
        isAbilityBgColorTransparent = node.GetAbilityBgAlpha() < UINT8_MAX;
        dfxMsg = "AbBgAlpha: " + std::to_string(node.GetAbilityBgAlpha());
    }
    return isAbilityBgColorTransparent;
}

bool RSUifirstManager::QuerySubAssignable(RSSurfaceRenderNode& node, bool isRotation)
{
    if (!node.IsFirstLevelNode()) {
        return false;
    }

    auto childHasVisibleFilter = node.ChildHasVisibleFilter();
    auto globalAlpha = node.GetGlobalAlpha();
    auto hasProtectedLayer = node.GetSpecialLayerMgr().Find(SpecialLayerType::HAS_PROTECTED);
    std::string dfxMsg;
    auto hasTransparentSurface = GetSubNodeIsTransparent(node, dfxMsg);

    bool rotateOptimize = RSSystemProperties::GetCacheOptimizeRotateEnable() ?
        !(isRotation && ROSEN_EQ(globalAlpha, 0.0f)) : !isRotation;
    bool assignable = !(hasTransparentSurface && childHasVisibleFilter) &&
        rotateOptimize && !hasProtectedLayer;
    RS_TRACE_NAME_FMT("SubThreadAssignable node[%" PRIu64 "] assignable[%d] hasTransparent[%d] "
        "childHasVisibleFilter[%d] isRotation:[%d & %d] globalAlpha[%f], hasProtectedLayer[%d] %s",
        node.GetId(), assignable, hasTransparentSurface, childHasVisibleFilter, isRotation,
        RSSystemProperties::GetCacheOptimizeRotateEnable(), globalAlpha, hasProtectedLayer, dfxMsg.c_str());
    return assignable;
}

bool RSUifirstManager::ForceUpdateUifirstNodes(RSSurfaceRenderNode& node)
{
    bool isForceDisabled = (node.GetUIFirstSwitch() == RSUIFirstSwitch::FORCE_DISABLE);
    bool hasProtectedLayer = node.GetSpecialLayerMgr().Find(SpecialLayerType::HAS_PROTECTED);
    if (!isUiFirstOn_ || !node.GetUifirstSupportFlag() || isForceDisabled || hasProtectedLayer) {
        RS_LOGD("uifirst disabled. id:%{public}" PRIu64 ",uifirstOn:%{public}d,support:%{public}d,"
            "forceDisabled:%{public}d,protectLayer:%{public}d",
            node.GetId(), isUiFirstOn_, node.GetUifirstSupportFlag(), isForceDisabled, hasProtectedLayer);
        UifirstStateChange(node, MultiThreadCacheType::NONE);
        // This branch will be discarded
        if (!node.isUifirstNode_) {
            node.isUifirstDelay_++;
            if (node.isUifirstDelay_ > EVENT_STOP_TIMEOUT) {
                node.isUifirstNode_ = true;
            }
        }
        return true;
    }
    // This branch will be discarded
    if (node.isForceFlag_ && node.IsLeashWindow()) {
        RS_OPTIONAL_TRACE_NAME_FMT("ForceUpdateUifirstNodes: isUifirstEnable: %d", node.isUifirstEnable_);
        if (!node.isUifirstEnable_) {
            UifirstStateChange(node, MultiThreadCacheType::NONE);
            return true;
        }
        if (RSUifirstManager::Instance().GetUiFirstMode() == UiFirstModeType::MULTI_WINDOW_MODE) {
            UifirstStateChange(node, MultiThreadCacheType::NONFOCUS_WINDOW);
        } else {
            UifirstStateChange(node, MultiThreadCacheType::LEASH_WINDOW);
        }
        return true;
    }
    if (node.GetUIFirstSwitch() == RSUIFirstSwitch::FORCE_ENABLE && node.IsLeashWindow()) {
        RS_OPTIONAL_TRACE_NAME_FMT("ForceUpdateUifirstNodes: nodeName: %s, uiFirstSwitch: %d",
            node.GetName().c_str(), node.GetUIFirstSwitch());
        if (RSUifirstManager::Instance().GetUiFirstMode() == UiFirstModeType::MULTI_WINDOW_MODE) {
            UifirstStateChange(node, MultiThreadCacheType::NONFOCUS_WINDOW);
        } else {
            UifirstStateChange(node, MultiThreadCacheType::LEASH_WINDOW);
        }
        return true;
    }
    return false;
}

void RSUifirstManager::UpdateUifirstNodes(RSSurfaceRenderNode& node, bool ancestorNodeHasAnimation)
{
    RS_TRACE_NAME_FMT("UpdateUifirstNodes: Id[%" PRIu64 "] name[%s] FLId[%llu] Ani[%d] Support[%d] isUiFirstOn[%d]"
        " isCardOn[%d] isForceFlag[%d], hasProtectedLayer[%d] switch:[%d] curUifirstWindowNum[%d] threshold[%d]",
        node.GetId(), node.GetName().c_str(), node.GetFirstLevelNodeId(), ancestorNodeHasAnimation,
        node.GetUifirstSupportFlag(), isUiFirstOn_, isCardUiFirstOn_, node.isForceFlag_,
        node.GetSpecialLayerMgr().Find(SpecialLayerType::HAS_PROTECTED), node.GetUIFirstSwitch(),
        curUifirstWindowNums_, uifirstWindowsNumThreshold_);
    if (ForceUpdateUifirstNodes(node)) {
        return;
    }
    if (RSUifirstManager::IsLeashWindowCache(node, ancestorNodeHasAnimation)) {
        if (RSSystemParameters::GetUIFirstStartingWindowCacheEnabled()) {
            if (node.GetLastFrameUifirstFlag() == MultiThreadCacheType::NONE && HasStartingWindow(node)) {
                UifirstStateChange(node, MultiThreadCacheType::LEASH_WINDOW);
            } else {
                ProcessFirstFrameCache(node, MultiThreadCacheType::LEASH_WINDOW);
            }
        } else {
            UifirstStateChange(node, MultiThreadCacheType::LEASH_WINDOW);
        }
        return;
    }
    if (RSUifirstManager::IsNonFocusWindowCache(node, ancestorNodeHasAnimation)) {
        ProcessFirstFrameCache(node, MultiThreadCacheType::NONFOCUS_WINDOW);
        return;
    }
    if (RSUifirstManager::IsArkTsCardCache(node, ancestorNodeHasAnimation)) {
        ProcessFirstFrameCache(node, MultiThreadCacheType::ARKTS_CARD);
        return;
    }
    UifirstStateChange(node, MultiThreadCacheType::NONE);
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
            if (!surfaceNode) {
                RS_LOGE("UifirstStateChange surfaceNode is nullptr");
                return;
            }
            RS_TRACE_NAME_FMT("UIFirst_switch disable -> enable %" PRIu64, node.GetId());
            HILOG_COMM_INFO("uifirst disable -> enable. %{public}s id:%{public}" PRIu64, node.GetName().c_str(), node.GetId());
            SetUifirstNodeEnableParam(node, currentFrameCacheType);
            if (currentFrameCacheType == MultiThreadCacheType::ARKTS_CARD) { // now only update ArkTSCardNode
                node.UpdateTreeUifirstRootNodeId(node.GetId());
            }
            auto func = &RSUifirstManager::ProcessTreeStateChange;
            node.RegisterTreeStateChangeCallback(func);
            node.SetUifirstStartTime(GetCurSysTime());
            AddPendingPostNode(node.GetId(), surfaceNode, currentFrameCacheType); // clear pending reset status
            AddCardNodes(node.GetId(), currentFrameCacheType);
            node.SetSubThreadAssignable(true);
            node.SetNeedCacheSurface(false);
            IncreaseUifirstWindowCount(node);
        } else { // keep disable
            RS_OPTIONAL_TRACE_NAME_FMT("UIFirst_keep disable  %" PRIu64, node.GetId());
            node.SetSubThreadAssignable(false);
            node.SetNeedCacheSurface(false);
        }
    } else { // last is enable
        auto surfaceNode = RSBaseRenderNode::ReinterpretCast<RSSurfaceRenderNode>(node.shared_from_this());
        if (currentFrameCacheType != MultiThreadCacheType::NONE) { // keep enable
            RS_OPTIONAL_TRACE_NAME_FMT("UIFirst_keep enable  %" PRIu64, node.GetId());
            RS_LOGD("uifirst keep enable. %{public}s id:%{public}" PRIu64, node.GetName().c_str(), node.GetId());
            AddPendingPostNode(node.GetId(), surfaceNode, currentFrameCacheType);
            IncreaseUifirstWindowCount(node);
        } else { // switch: enable -> disable
            RS_TRACE_NAME_FMT("UIFirst_switch enable -> disable %" PRIu64, node.GetId());
            HILOG_COMM_INFO("uifirst enable -> disable. %{public}s id:%{public}" PRIu64, node.GetName().c_str(), node.GetId());
            node.SetUifirstStartTime(-1); // -1: default start time
            NotifyUIStartingWindow(node.GetId(), false);
            AddPendingResetNode(node.GetId(), surfaceNode); // set false onsync when task done
            RemoveCardNodes(node.GetId());
            node.SetSubThreadAssignable(false);
            node.SetNeedCacheSurface(false);

            auto tempNodeToClear = pendingNodeBehindWindow_.find(node.GetId());
            if (tempNodeToClear != pendingNodeBehindWindow_.end()) {
                RS_OPTIONAL_TRACE_NAME_FMT("clear node in pendingNodeBehindWindow %{public}s id:%{public}" PRIu64,
                    node.GetName().c_str(), node.GetId());
                pendingNodeBehindWindow_.erase(tempNodeToClear);
            }
            DecreaseUifirstWindowCount(node);
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

void RSUifirstManager::ProcessTreeStateChange(RSSurfaceRenderNode& node)
{
    RSUifirstManager::Instance().CheckCurrentFrameHasCardNodeReCreate(node);
    // Planning: do not clear complete image for card
    if (node.IsOnTheTree()) {
        return;
    }
    RSUifirstManager::Instance().DisableUifirstNode(node);
    RSUifirstManager::Instance().ForceClearSubthreadRes();
    RSUifirstManager::Instance().RemoveCardNodes(node.GetId());
}

void RSUifirstManager::DisableUifirstNode(RSSurfaceRenderNode& node)
{
    RS_TRACE_NAME_FMT("DisableUifirstNode node[%lld] %s", node.GetId(), node.GetName().c_str());
    UifirstStateChange(node, MultiThreadCacheType::NONE);

    auto surfaceNode = RSBaseRenderNode::ReinterpretCast<RSSurfaceRenderNode>(node.shared_from_this());
    pendingResetWindowCachedNodes_.emplace_back(surfaceNode);
}

void RSUifirstManager::AddCapturedNodes(NodeId id)
{
    capturedNodes_.push_back(id);
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

bool RSUiFirstProcessStateCheckerHelper::CheckMatchAndWaitNotify(const RSRenderParams& params, bool checkMatch)
{
    if (checkMatch && IsCurFirstLevelMatch(params)) {
        return true;
    }
    return CheckAndWaitPreFirstLevelDrawableNotify(params);
}

bool RSUiFirstProcessStateCheckerHelper::CheckAndWaitPreFirstLevelDrawableNotify(const RSRenderParams& params)
{
    auto firstLevelNodeId = params.GetFirstLevelNodeId();
    auto uifirstRootNodeId = params.GetUifirstRootNodeId();
    auto rootId = uifirstRootNodeId != INVALID_NODEID ? uifirstRootNodeId : firstLevelNodeId;
    if (rootId == INVALID_NODEID) {
        /* uifirst will not draw with no firstlevel node, and there's no need to check and wait for uifirst onDraw */
        RS_LOGD("uifirst node %{public}" PRIu64 " uifirstrootNodeId is INVALID_NODEID", params.GetId());
        return true;
    }

    auto uifirstRootNodeDrawable = DrawableV2::RSRenderNodeDrawableAdapter::GetDrawableById(rootId);
    if (!uifirstRootNodeDrawable) {
        // drawable may release when node off tree
        // uifirst will not draw with null uifirstRootNodeDrawable
        RS_LOGW("uifirstnode %{public}" PRIu64 " uifirstroot %{public}" PRIu64 " nullptr", params.GetId(), rootId);
        return true;
    }

    if (UNLIKELY(uifirstRootNodeDrawable->GetNodeType() != RSRenderNodeType::SURFACE_NODE)) {
        RS_LOGE("uifirst invalid uifirstrootNodeId %{public}" PRIu64, rootId);
        return false;
    }
    auto uifirstRootSurfaceNodeDrawable =
        std::static_pointer_cast<DrawableV2::RSSurfaceRenderNodeDrawable>(uifirstRootNodeDrawable);

    RS_TRACE_NAME_FMT("CheckAndWaitPreFirstLevelDrawableNotify %" PRIu64 " wait for %" PRIu64 "",
        params.GetId(), uifirstRootSurfaceNodeDrawable->GetId());

    static constexpr auto TIME_OUT = std::chrono::milliseconds(500); // 500ms for timeout
    auto pred = [uifirstRootSurfaceNodeDrawable] {
        auto curState = uifirstRootSurfaceNodeDrawable->GetRsSubThreadCache().GetCacheSurfaceProcessedStatus();
        return curState == CacheProcessStatus::DONE || curState == CacheProcessStatus::UNKNOWN ||
            curState == CacheProcessStatus::SKIPPED;
    };
    std::unique_lock<std::mutex> lock(notifyMutex_);
    notifyCv_.wait_for(lock, TIME_OUT, pred);
    auto ret = pred();
    if (!ret) {
        HILOG_COMM_ERROR("uifirst nodeId %{public}" PRIu64
            " wait uifirstrootNodeId %{public}" PRIu64 " until 500ms timeout", params.GetId(), rootId);
    }
    return ret;
}

bool RSUiFirstProcessStateCheckerHelper::IsCurFirstLevelMatch(const RSRenderParams& params)
{
    auto uifirstRootNodeId = params.GetUifirstRootNodeId();
    auto firstLevelNodeId = params.GetFirstLevelNodeId();

    RS_OPTIONAL_TRACE_NAME_FMT("RSUiFirstProcessStateCheckerHelper IsCurFirstLevelMatch In node[%"
        PRIu64 "  %" PRIu64"] cur[%" PRIu64 "  %" PRIu64 "] in nodeId[%" PRIu64 "]",
        uifirstRootNodeId, firstLevelNodeId, curUifirstRootNodeId_, curFirstLevelNodeId_, params.GetId());

    if (curUifirstRootNodeId_ == INVALID_NODEID && curFirstLevelNodeId_ == INVALID_NODEID) {
        // should draw because uifirst may not inited
        return true;
    }
    auto uiFirstCheckRet = uifirstRootNodeId == curUifirstRootNodeId_ && curUifirstRootNodeId_ != INVALID_NODEID;
    auto firstLevelCheckRet = firstLevelNodeId == curFirstLevelNodeId_ && curFirstLevelNodeId_ != INVALID_NODEID;
    if (uiFirstCheckRet || firstLevelCheckRet) {
        return true;
    }
    return false;
}

CacheProcessStatus RSUifirstManager::GetCacheSurfaceProcessedStatus(const RSSurfaceRenderParams& surfaceParams)
{
    CacheProcessStatus curRootIdState = CacheProcessStatus::UNKNOWN;
    auto uifirstRootId = surfaceParams.GetUifirstRootNodeId() != INVALID_NODEID ?
        surfaceParams.GetUifirstRootNodeId() : surfaceParams.GetFirstLevelNodeId();
    auto uifirstRootNodeDrawable = DrawableV2::RSRenderNodeDrawableAdapter::GetDrawableById(uifirstRootId);
    if (uifirstRootNodeDrawable && uifirstRootNodeDrawable->GetNodeType() == RSRenderNodeType::SURFACE_NODE) {
        auto drawableNode = std::static_pointer_cast<DrawableV2::RSSurfaceRenderNodeDrawable>(uifirstRootNodeDrawable);
        curRootIdState = drawableNode->GetRsSubThreadCache().GetCacheSurfaceProcessedStatus();
    }
    return curRootIdState;
}

UiFirstModeType RSUifirstManager::GetUiFirstMode()
{
    if (uifirstType_ == UiFirstCcmType::SINGLE) {
        return UiFirstModeType::SINGLE_WINDOW_MODE;
    }
    if (uifirstType_ == UiFirstCcmType::MULTI) {
        return UiFirstModeType::MULTI_WINDOW_MODE;
    }
    if (uifirstType_ == UiFirstCcmType::HYBRID) {
        return isFreeMultiWindowEnabled_ ? UiFirstModeType::MULTI_WINDOW_MODE : UiFirstModeType::SINGLE_WINDOW_MODE;
    }
    return UiFirstModeType::SINGLE_WINDOW_MODE;
}

void RSUifirstManager::ReadUIFirstCcmParam()
{
#ifdef ROSEN_EMULATOR
    // close uifirst on emulator
    isUiFirstOn_ = false;
    isCardUiFirstOn_ = false;
#else
    isUiFirstOn_ = UIFirstParam::IsUIFirstEnable();
    isCardUiFirstOn_ = UIFirstParam::IsCardUIFirstEnable();
#endif
    SetUiFirstType(UIFirstParam::GetUIFirstType());
    uifirstWindowsNumThreshold_ = UIFirstParam::GetUIFirstEnableWindowThreshold();
    RS_LOGI("ReadUIFirstCcmParam isUiFirstOn_=%{public}d isCardUiFirstOn_=%{public}d"
        " uifirstType_=%{public}d uiFirstEnableWindowThreshold_=%{public}d",
        isUiFirstOn_, isCardUiFirstOn_, static_cast<int>(uifirstType_), uifirstWindowsNumThreshold_);
}

void RSUifirstManager::SetUiFirstType(int type)
{
    if (type < (int)UiFirstCcmType::SINGLE || type > (int)UiFirstCcmType::HYBRID) {
        return;
    }
    if (type == (int)UiFirstCcmType::SINGLE) {
        uifirstType_ = UiFirstCcmType::SINGLE;
    } else if (type == (int)UiFirstCcmType::MULTI) {
        uifirstType_ = UiFirstCcmType::MULTI;
    } else if (type == (int)UiFirstCcmType::HYBRID) {
        uifirstType_ = UiFirstCcmType::HYBRID;
    }
}

void RSUifirstManager::RefreshUIFirstParam()
{
    RSUifirstManager::Instance().SetPurgeEnable(RSSystemParameters::GetUIFirstPurgeEnabled());
    const std::shared_ptr<RSBaseRenderNode> rootNode = RSMainThread::Instance()->GetContext()
        .GetGlobalRootRenderNode();
    if (!rootNode) {
        return;
    }
    auto firstChildren = rootNode->GetFirstChild();
    if (!firstChildren) {
        return;
    }
    auto screenNode = RSBaseRenderNode::ReinterpretCast<RSScreenRenderNode>(firstChildren);
    if (!screenNode) {
        return;
    }
    isUiFirstSupportFlag_ = true;
}

bool RSUifirstManager::IsSubTreeNeedPrepareForSnapshot(RSSurfaceRenderNode& node)
{
    return RSUifirstManager::Instance().IsRecentTaskScene() &&
        (node.IsFocusedNode(RSMainThread::Instance()->GetFocusLeashWindowId()) ||
        node.IsFocusedNode(RSMainThread::Instance()->GetFocusNodeId()));
}

bool RSUifirstManager::IsSubHighPriorityType(RSSurfaceRenderNode& node) const
{
    return node.GetName().find("hipreview") != std::string::npos;
}

void RSUifirstManager::CheckHwcChildrenType(RSSurfaceRenderNode& node, SurfaceHwcNodeType& enabledType)
{
    if (enabledType == SurfaceHwcNodeType::DEFAULT_HWC_ROSENWEB) {
        return;
    }
    if (node.IsAppWindow()) {
        auto hwcNodes = node.GetChildHardwareEnabledNodes();
        if (hwcNodes.empty()) {
            return;
        }
        if (IsSubHighPriorityType(node)) {
            enabledType = SurfaceHwcNodeType::DEFAULT_HWC_VIDEO;
            return;
        }
        if (node.IsRosenWeb()) {
            enabledType = SurfaceHwcNodeType::DEFAULT_HWC_ROSENWEB;
            return;
        }
        for (auto hwcNode : hwcNodes) {
            auto hwcNodePtr = hwcNode.lock();
            if (!hwcNodePtr) {
                continue;
            }
            if (hwcNodePtr->IsRosenWeb()) {
                enabledType = SurfaceHwcNodeType::DEFAULT_HWC_ROSENWEB;
                return;
            }
            if (IsSubHighPriorityType(*hwcNodePtr)) {
                enabledType = SurfaceHwcNodeType::DEFAULT_HWC_VIDEO;
                return;
            }
        }
    } else if (node.IsLeashWindow()) {
        for (auto& child : *(node.GetChildren())) {
            auto surfaceNode = child->ReinterpretCastTo<RSSurfaceRenderNode>();
            if (surfaceNode == nullptr) {
                continue;
            }
            CheckHwcChildrenType(*surfaceNode, enabledType);
        }
    }
}

void RSUifirstManager::MarkSubHighPriorityType(RSSurfaceRenderNode& node)
{
    if (uifirstType_ != UiFirstCcmType::MULTI) {
        return;
    }
    SurfaceHwcNodeType preSubHighPriority = SurfaceHwcNodeType::DEFAULT_HWC_TYPE;
    CheckHwcChildrenType(node, preSubHighPriority);
    RS_OPTIONAL_TRACE_NAME_FMT("SubHighPriorityType::name:[%s] preSub:%d", node.GetName().c_str(), preSubHighPriority);
    node.SetPreSubHighPriorityType(preSubHighPriority == SurfaceHwcNodeType::DEFAULT_HWC_VIDEO);
}

void RSUifirstManager::RecordScreenRect(RSSurfaceRenderNode& node, RectI rect)
{
    auto stagingSurfaceParams = static_cast<RSSurfaceRenderParams*>(node.GetStagingRenderParams().get());
    if (!stagingSurfaceParams) {
        RS_LOGE("RecordScreenRect stagingSurfaceParams is nullptr");
        return;
    }
    stagingSurfaceParams->RecordScreenRect(rect);
    node.AddToPendingSyncList();
}

void RSUifirstManager::RecordDirtyRegionMatrix(RSSurfaceRenderNode& node, const Drawing::Matrix& matrix)
{
    auto stagingSurfaceParams = static_cast<RSSurfaceRenderParams*>(node.GetStagingRenderParams().get());
    if (!stagingSurfaceParams) {
        RS_LOGE("RecordDirtyRegionMatrix stagingSurfaceParams is nullptr");
        return;
    }
    stagingSurfaceParams->RecordDirtyRegionMatrix(matrix);
    node.AddToPendingSyncList();
}

bool RSUifirstManager::IsFocusedNode(const RSSurfaceRenderNode& node) const
{
    return node.IsFocusedNode(RSMainThread::Instance()->GetFocusNodeId()) ||
        node.IsFocusedNode(RSMainThread::Instance()->GetFocusLeashWindowId());
}

void RSUifirstManager::IncreaseUifirstWindowCount(const RSSurfaceRenderNode& node)
{
    if (IsFocusedNode(node) || node.IsAbilityComponent()) {
        return;
    }
    curUifirstWindowNums_++;
}

void RSUifirstManager::DecreaseUifirstWindowCount(const RSSurfaceRenderNode& node)
{
    if (IsFocusedNode(node) || node.IsAbilityComponent()) {
        return;
    }
    if (curUifirstWindowNums_ > 0) {
        curUifirstWindowNums_--;
    }
}

bool RSUifirstManager::IsExceededWindowsThreshold(const RSSurfaceRenderNode& node) const
{
    // no restriction when threshold is less than or equal to 0
    if (uifirstWindowsNumThreshold_ <= 0) {
        return false;
    }

    // do not count focus window
    if (IsFocusedNode(node)) {
        return false;
    }

    // Non-focus window, Z/V sequence control
    if (curUifirstWindowNums_ < uifirstWindowsNumThreshold_) {
        return false;
    }
    return true;
}

void RSUifirstManager::AddMarkedClearCacheNode(NodeId id)
{
    if (id == INVALID_NODEID || markedClearCacheNodes_.size() >= MAX_CLEAR_CACHE_NODE_COUNT) {
        RS_LOGE("AddMarkedClearCacheNode failed. id %{public}" PRIu64 ", size:%{public}zu",
            id, markedClearCacheNodes_.size());
        return;
    }
    
    RS_TRACE_NAME_FMT("AddMarkedClearCacheNode %" PRIu64, id);
    RS_LOGI("AddMarkedClearCacheNode %{public}" PRIu64, id);
    markedClearCacheNodes_.insert(id);
}

void RSUifirstManager::ProcessMarkedNodeSubThreadCache()
{
    RS_OPTIONAL_TRACE_NAME_FMT("ProcessMarkedNodeSubThreadCache size:%zu", markedClearCacheNodes_.size());
    for (auto& markedNode : markedClearCacheNodes_) {
        if (subthreadProcessingNode_.find(markedNode) == subthreadProcessingNode_.end()) {
            auto drawable = GetSurfaceDrawableByID(markedNode);
            if (!drawable) {
                RS_LOGE("ProcessMarkedNodeSubThreadCache drawable is null. id:%{public}" PRIu64, markedNode);
                continue;
            }
            if ((pendingPostNodes_.find(markedNode) != pendingPostNodes_.end()) ||
                (pendingPostCardNodes_.find(markedNode) != pendingPostCardNodes_.end())) {
                continue;
            }
            RS_TRACE_NAME_FMT("ProcessMarkedNodeSubThreadCache id:%" PRIu64, markedNode);
            RS_LOGI("ProcessMarkedNodeSubThreadCache id:%{public}" PRIu64, markedNode);
            auto& rsSubThreadCache = drawable->GetRsSubThreadCache();
            rsSubThreadCache.ClearCacheSurfaceOnly();
        }
    }
    markedClearCacheNodes_.clear();
}
} // namespace Rosen
} // namespace OHOS
