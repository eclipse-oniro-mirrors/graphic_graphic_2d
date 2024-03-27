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
#include "rs_trace.h"
#include "platform/common/rs_log.h"
#include "pipeline/parallel_render/rs_sub_thread_manager.h"
#include "pipeline/rs_uni_render_util.h"
#include "pipeline/rs_main_thread.h"

// use in mainthread, post subthread, not affect renderthread 

namespace OHOS {
namespace Rosen {
#ifdef RS_PARALLEL
RSUifirstManager& RSUifirstManager::Instance()
{
    static RSUifirstManager instance; // store in mainthread instance ?
    return instance;
}

// record RSSurfaceRenderNodeDrawable ptr for postTask
void RSUifirstManager::AddSurfaceDrawable(NodeId id, DrawableV2::RSSurfaceRenderNodeDrawable* drawable)
{
    curAllSurface_[id] = drawable;
}

void RSUifirstManager::DeleSurfaceDrawable(NodeId id)
{
    if (curAllSurface_.find(id) != curAllSurface_.end()) {
        curAllSurface_.erase(id);
    }
}

DrawableV2::RSSurfaceRenderNodeDrawable* RSUifirstManager::GetSurfaceDrawableByID(NodeId id)
{
    if (curAllSurface_.find(id) != curAllSurface_.end()) {
        return curAllSurface_[id];
    }
    return nullptr;
}

// ref RSChildrenDrawable to ref RSSurfaceRenderNodeDrawable in it
// ref in RT when post
void RSUifirstManager::RefChildrenDrawable(NodeId id, Drawing::RecordingCanvas::DrawFunc& func)
{
    subthreadProcessingNode_[id] = func;
}

// unref in sub when cache done
void RSUifirstManager::UnrefChildrenDrawable(NodeId id)
{
    // mutex
    RS_TRACE_NAME_FMT("sub unref %lx", id);
    std::lock_guard<std::mutex> lock(childernDrawableMutex_);
    subthreadProcessDoneNode_.push_back(id);
}

void RSUifirstManager::ProcessDoneNode()
{
    std::vector<NodeId> tmp;
    {
        std::lock_guard<std::mutex> lock(childernDrawableMutex_);
        if (subthreadProcessDoneNode_.size() == 0) {
            RS_TRACE_NAME_FMT("ProcessDoneNode no done");
            return;
        }
        std::swap(tmp, subthreadProcessDoneNode_);
        subthreadProcessDoneNode_.clear();
    }
    RS_TRACE_NAME_FMT("ProcessDoneNode num%d", tmp.size());
    for (auto& id : tmp) {
        RS_TRACE_NAME_FMT("Done %lx", id);
        UpdateCompletedSurface(id); // now not use anyone
        if (pendingResetNodes_.count(id) > 0) { // reset node
            DrawableV2::RSSurfaceRenderNodeDrawable* drawable = GetSurfaceDrawableByID(id);
            if (!drawable) {
                continue;
            }
            // reset uifirst
            drawable->ResetUifirst();
            pendingResetNodes_.erase(id);
            lastFrameDoingNum_ = -1;
            currentFrameDoingNum_ = -1;
        }
        subthreadProcessingNode_.erase(id);
    }

    for (auto it = subthreadProcessingNode_.begin(); it != subthreadProcessingNode_.end(); it++) {
        pendingPostNodes_.erase(it->first); // dele doing node in pendingpostlist
    }
}

void RSUifirstManager::PostSubTask(NodeId id)
{
    RS_TRACE_NAME("post UpdateCacheSurface");

    if (subthreadProcessingNode_.find(id) != subthreadProcessingNode_.end()) { // drawable is doing, do not send
        RS_TRACE_NAME_FMT("node %lx is doning", id);
        return;
    }
    
    DrawableV2::RSSurfaceRenderNodeDrawable* drawable = GetSurfaceDrawableByID(id);
    if (!drawable) {
        RS_TRACE_NAME_FMT("post ret %d", __LINE__);
        return;
    }

    auto node = drawable->getRenderNode();
    if (!node) {
        RS_TRACE_NAME_FMT("post ret %d", __LINE__);
        return;
    }
    auto parent = node->GetParent().lock();
    if (parent) {
        // if (subthreadProcessingNode_.find(id) == subthreadProcessingNode_.end()) {
        // ref self drawable
        std::optional<Drawing::RecordingCanvas::DrawFunc> func = parent->GetChildrenDrawable();
        if (!func.has_value()) {
            RS_LOGE("PostUifistSubTask no func");
            RS_TRACE_NAME_FMT("post ret %d", __LINE__);
            return;
        }
        // ref drawable
        subthreadProcessingNode_[id] = func.value();

        // post task
        RS_TRACE_NAME_FMT("Post_SubTask_s %lx", node->GetRenderParams()->GetId());
        RSSubThreadManager::Instance()->ScheduleRenderNodeDrawable(drawable);
    }
}

void RSUifirstManager::UpdateSkipSyncNode()
{
    processingNodeSkipSync_.clear();
    processingNodePartialSync_.clear();
    RS_TRACE_NAME_FMT("UpdateSkipSyncNode doning%d", subthreadProcessingNode_.size());
    if (subthreadProcessingNode_.size() == 0) {
        return;
    }
    for (auto it = subthreadProcessingNode_.begin(); it != subthreadProcessingNode_.end(); it++) {
        RS_TRACE_NAME_FMT("doning%lx", it->first);
        
        DrawableV2::RSSurfaceRenderNodeDrawable* drawable = GetSurfaceDrawableByID(it->first);
        if (!drawable) {
            continue;
        }
        if (!drawable->getRenderNode()) {
            continue;
        }

        processingNodePartialSync_.insert(it->first); // partial sync
        for (auto& child : *(drawable->getRenderNode()->GetChildren())) {
            if (!child) {
                continue;
            }
            processingNodeSkipSync_.insert(child->GetInstanceRootNodeId()); // skip sync
        }
    }
}

void RSUifirstManager::ProcessSubDoneNode()
{
    RS_TRACE_NAME_FMT("ProcessSubDoneNode");
    ProcessDoneNode(); // release finish drawable
    UpdateSkipSyncNode();
    RestoreSkipSyncNode();
}

bool RSUifirstManager::CollectSkipSyncNode(const std::shared_ptr<RSRenderNode> &node)
{
    if (!node) {
        return false;
    }
    if (pendingPostNodes_.count(node->GetId())) { // only sync root node's uifirstDrawCmdList_
        node->SetUifirstSyncFlag(true);
    }
    if (processingNodePartialSync_.count(node->GetInstanceRootNodeId()) > 0) {
        pendingSyncForSkipBefore_[node->GetInstanceRootNodeId()].push_back(node);
        RS_TRACE_NAME_FMT("set partial_sync %lx root%lx", node->GetId(), node->GetInstanceRootNodeId());
        node->SetUifirstSkipPartialSync(true);
        return false;
    } else if (processingNodeSkipSync_.count(node->GetInstanceRootNodeId()) > 0) {
        RS_TRACE_NAME_FMT("CollectSkipSyncNode root %lx, node %lx", node->GetInstanceRootNodeId(), node->GetId());
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
        if (processingNodeSkipSync_.count(it.first) == 0 && processingNodePartialSync_.count(it.first) == 0) {
            todele.push_back(it.first);
            RS_TRACE_NAME_FMT("RestoreSkipSyncNode %lx num%d", it.first, it.second.size());
            for (auto& node : it.second) {
                node->SetUifirstSkipPartialSync(false);
                node->SetUifirstSyncFlag(true); // child sync but child will not use, TODO, only sync root
                RSMainThread::Instance()->GetContext().AddPendingSyncNode(node);
            }
        }
    }
    for (auto id : todele) {
        pendingSyncForSkipBefore_.erase(id);
    }
}

void RSUifirstManager::ClearSubthreadRes()
{
    int lastFrameBackup = lastFrameDoingNum_;
    lastFrameDoingNum_ = currentFrameDoingNum_;
    currentFrameDoingNum_ = subthreadProcessingNode_.size();
    if (lastFrameBackup > 0 && lastFrameDoingNum_ == 0 && currentFrameDoingNum_ == 0 &&
        pendingSyncForSkipBefore_.size() == 0 && reuseNodes_.size() == 0) {
        // clear res
        RS_TRACE_NAME_FMT(" postclear last_last%d last%d current%d now%d pendsync %d reuse%d pendpost%d", lastFrameBackup, lastFrameDoingNum_,
            currentFrameDoingNum_, (int)subthreadProcessingNode_.size(), (int)pendingSyncForSkipBefore_.size(),
        (int)reuseNodes_.size(),
        (int)pendingPostNodes_.size());
        RSSubThreadManager::Instance()->ResetSubThreadGrContext();
    }
    reuseNodes_.clear();
}

// post in drawframe sync time
void RSUifirstManager::PostUifistSubTasks()
{
    RS_TRACE_NAME_FMT("PostUifistSubTasks num%d", pendingPostNodes_.size());

    if (!(pendingPostNodes_.size() > 0)) {
        ClearSubthreadRes();
        return;
    }
    for (auto id : pendingPostNodes_) {
        PostSubTask(id);
    }

    ClearSubthreadRes();
    pendingPostNodes_.clear();
}

void RSUifirstManager::AddPendingPostNode(NodeId id)
{
    if (id == INVALID_NODEID) {
        return;
    }
    pendingPostNodes_.insert(id);
}

void RSUifirstManager::AddPendingResetNode(NodeId id)
{
    if (id == INVALID_NODEID) {
        return;
    }
    pendingResetNodes_.insert(id);
}

CacheProcessStatus RSUifirstManager::GetNodeStatus(NodeId id)
{
    DrawableV2::RSSurfaceRenderNodeDrawable* drawable = GetSurfaceDrawableByID(id);
    if (drawable) {
        return drawable->GetCacheSurfaceProcessedStatus();
    }
    return CacheProcessStatus::UNKNOWN;
}

void RSUifirstManager::UpdateCompletedSurface(NodeId id)
{
    DrawableV2::RSSurfaceRenderNodeDrawable* drawable = GetSurfaceDrawableByID(id);
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

// TODO: static method, node can use uifirst
bool RSUifirstManager::IsUifirstNode(RSSurfaceRenderNode& node, bool animation)
{
    bool isDisplayRotation = false; // TODO for pc
    bool isPhoneType = RSMainThread::Instance()->GetDeviceType() == DeviceType::PHONE;
    bool isNeedAssignToSubThread = false;
    if (isPhoneType && node.IsLeashWindow()) {
        isNeedAssignToSubThread = (animation || ROSEN_EQ(node.GetGlobalAlpha(), 0.0f) ||
            node.GetForceUIFirst()) && !node.HasFilter();
    }
    std::string surfaceName = node.GetName();
    bool needFilterSCB = surfaceName.substr(0, 3) == "SCB" ||
        surfaceName.substr(0, 13) == "BlurComponent"; // filter BlurComponent, 13 is string len

    if (needFilterSCB || node.IsSelfDrawingType()) {
        return false;
    }

    if (isPhoneType) {
        return isNeedAssignToSubThread;
    } else { // PC or TABLET
        if ((node.IsFocusedNode(RSMainThread::Instance()->GetFocusNodeId()) ||
            node.IsFocusedNode(RSMainThread::Instance()->GetFocusLeashWindowId())) &&
            node.GetHasSharedTransitionNode()) {
            return false;
        }
        return node.QuerySubAssignable(isDisplayRotation);
    }
}

// inline
void RSUifirstManager::UifirstStateChange(RSSurfaceRenderNode& node, bool currentFrameIsUifirstNode)
{
    bool lastFrameIsUifirstNode = node.GetLastFrameUifirstFlag();
    if (!lastFrameIsUifirstNode) { // likely branch: last is disable
        if (currentFrameIsUifirstNode) { // switch: disable -> enable
            RS_TRACE_NAME_FMT("UIFirst_switch disable -> enable %lx", node.GetId());
            node.SetUifirstNodeEnableParam(true); // update drawable param
            CheckIfParentUifirstNodeEnable(node, true);
            AddPendingPostNode(node.GetId());
            RSMainThread::Instance()->GetContext().AddPendingSyncNode(node.shared_from_this());
        } else { // keep disable
           RS_TRACE_NAME_FMT("UIFirst_keep disable  %lx", node.GetId());
        }
    } else { // last is enable
        if (currentFrameIsUifirstNode) { // keep enable
            RS_TRACE_NAME_FMT("UIFirst_keep enable  %lx", node.GetId());
            AddPendingPostNode(node.GetId());
        } else { // switch: enable -> disable
            RS_TRACE_NAME_FMT("UIFirst_switch enable -> disable %lx", node.GetId());
            node.SetUifirstNodeEnableParam(false); // update drawable param
            AddPendingResetNode(node.GetId());
            RSMainThread::Instance()->GetContext().AddPendingSyncNode(node.shared_from_this());
            CheckIfParentUifirstNodeEnable(node, false);
        }
    }
    node.SetLastFrameUifirstFlag(currentFrameIsUifirstNode);
}

void RSUifirstManager::CheckIfParentUifirstNodeEnable(RSSurfaceRenderNode& node, bool parentUifirstNodeEnable)
{
    if (node.IsLeashWindow()) {
        for (auto& child : *(node.GetChildren())) {
            if (!child) {
                continue;
            }
            auto surfaceChild = child->ReinterpretCastTo<RSSurfaceRenderNode>();
            if (!surfaceChild){
                continue;
            }
            if (surfaceChild->IsMainWindowType())
            {
                surfaceChild->SetIsParentUifirstNodeEnableParam(parentUifirstNodeEnable);
                continue;
            }
        }
    }
}

void RSUifirstManager::DisableUifirstNode(RSSurfaceRenderNode& node)
{
    RS_TRACE_NAME_FMT("DisableUifirstNode");
    UifirstStateChange(node, false);
}

void RSUifirstManager::PrepareUifirstNode(RSSurfaceRenderNode& node, bool animation)
{
    RS_TRACE_NAME_FMT("PrepareUifirstNode");
    if (isUiFirstOn_){
        UifirstStateChange(node, IsUifirstNode(node, animation));
    } else {
        DisableUifirstNode(node);
    }
}
#endif
}
}
