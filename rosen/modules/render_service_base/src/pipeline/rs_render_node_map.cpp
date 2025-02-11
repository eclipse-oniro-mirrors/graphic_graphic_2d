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

#include "pipeline/rs_render_node_map.h"
#include "common/rs_common_def.h"
#include "pipeline/rs_canvas_drawing_render_node.h"
#include "pipeline/rs_render_node.h"
#include "pipeline/rs_display_render_node.h"
#include "pipeline/rs_render_node_gc.h"
#include "pipeline/rs_surface_render_node.h"
#include "platform/common/rs_log.h"
#include "gfx/fps_info/rs_surface_fps_manager.h"

namespace OHOS {
namespace Rosen {
namespace {
constexpr const char* ENTRY_VIEW = "SCBDesktop";
constexpr const char* WALLPAPER_VIEW = "SCBWallpaper";
constexpr const char* SCREENLOCK_WINDOW = "SCBScreenLock";
constexpr const char* SYSUI_DROPDOWN = "SCBDropdownPanel";
constexpr const char* NEGATIVE_SCREEN = "SCBNegativeScreen";
};

using ResidentSurfaceNodeMap = std::unordered_map<NodeId, std::shared_ptr<RSSurfaceRenderNode>>;

RSRenderNodeMap::RSRenderNodeMap()
{
    // add animation fallback node, NOTE: this is different from RSContext::globalRootRenderNode_
    renderNodeMap_[0][0] = std::make_shared<RSBaseRenderNode>(0);
}

void RSRenderNodeMap::Initialize(const std::weak_ptr<RSContext>& context)
{
    context_ = context;
}

void RSRenderNodeMap::ObtainLauncherNodeId(const std::shared_ptr<RSSurfaceRenderNode> surfaceNode)
{
    if (surfaceNode == nullptr) {
        return;
    }
    if (surfaceNode->GetName().find(ENTRY_VIEW) != std::string::npos) {
        entryViewNodeId_ = surfaceNode->GetId();
    }
    if (surfaceNode->GetName().find(WALLPAPER_VIEW) != std::string::npos) {
        wallpaperViewNodeId_ = surfaceNode->GetId();
    }
    if (surfaceNode->GetName().find(NEGATIVE_SCREEN) != std::string::npos) {
        negativeScreenNodeId_ = surfaceNode->GetId();
    }
}

void RSRenderNodeMap::ObtainScreenLockWindowNodeId(const std::shared_ptr<RSSurfaceRenderNode> surfaceNode)
{
    if (surfaceNode == nullptr) {
        return;
    }
    if (surfaceNode->GetName().find(SCREENLOCK_WINDOW) != std::string::npos) {
        screenLockWindowNodeId_ = surfaceNode->GetId();
    }
}

NodeId RSRenderNodeMap::GetEntryViewNodeId() const
{
    return entryViewNodeId_;
}

NodeId RSRenderNodeMap::GetWallPaperViewNodeId() const
{
    return wallpaperViewNodeId_;
}

NodeId RSRenderNodeMap::GetScreenLockWindowNodeId() const
{
    return screenLockWindowNodeId_;
}

NodeId RSRenderNodeMap::GetNegativeScreenNodeId() const
{
    return negativeScreenNodeId_;
}

static bool IsResidentProcess(const std::shared_ptr<RSSurfaceRenderNode> surfaceNode)
{
    return surfaceNode->GetName().find(ENTRY_VIEW) != std::string::npos ||
           surfaceNode->GetName().find(SYSUI_DROPDOWN) != std::string::npos ||
           surfaceNode->GetName().find(SCREENLOCK_WINDOW) != std::string::npos ||
           surfaceNode->GetName().find(WALLPAPER_VIEW) != std::string::npos;
}

uint32_t RSRenderNodeMap::GetVisibleLeashWindowCount() const
{
    if (surfaceNodeMap_.empty()) {
        return 0;
    }

    return std::count_if(surfaceNodeMap_.begin(), surfaceNodeMap_.end(),
        [](const auto& pair) -> bool {
            return pair.second && pair.second->IsLeashWindowSurfaceNodeVisible();
        });
}

uint64_t RSRenderNodeMap::GetSize() const
{
    size_t mapSize = 0;
    for (const auto& [_, subMap] : renderNodeMap_) {
        mapSize += subMap.size();
    }
    return static_cast<uint64_t>(mapSize);
}

bool RSRenderNodeMap::IsResidentProcessNode(NodeId id) const
{
    auto nodePid = ExtractPid(id);
    return std::any_of(residentSurfaceNodeMap_.begin(), residentSurfaceNodeMap_.end(),
        [nodePid](const auto& pair) -> bool { return ExtractPid(pair.first) == nodePid; });
}

bool RSRenderNodeMap::IsUIExtensionSurfaceNode(NodeId id) const
{
    std::lock_guard<std::mutex> lock(uiExtensionSurfaceNodesMutex_);
    return uiExtensionSurfaceNodes_.find(id) != uiExtensionSurfaceNodes_.end();
}

void RSRenderNodeMap::AddUIExtensionSurfaceNode(const std::shared_ptr<RSSurfaceRenderNode> surfaceNode)
{
    if (surfaceNode && surfaceNode->IsUIExtension()) {
        std::lock_guard<std::mutex> lock(uiExtensionSurfaceNodesMutex_);
        uiExtensionSurfaceNodes_.insert(surfaceNode->GetId());
    }
}

void RSRenderNodeMap::RemoveUIExtensionSurfaceNode(const std::shared_ptr<RSSurfaceRenderNode> surfaceNode)
{
    if (surfaceNode && surfaceNode->IsUIExtension()) {
        std::lock_guard<std::mutex> lock(uiExtensionSurfaceNodesMutex_);
        uiExtensionSurfaceNodes_.erase(surfaceNode->GetId());
    }
}

bool RSRenderNodeMap::RegisterRenderNode(const std::shared_ptr<RSBaseRenderNode>& nodePtr)
{
    NodeId id = nodePtr->GetId();
    pid_t pid = ExtractPid(id);
    if (!(renderNodeMap_[pid].insert({ id, nodePtr })).second) {
        return false;
    }
    nodePtr->OnRegister(context_);
    if (nodePtr->GetType() == RSRenderNodeType::SURFACE_NODE) {
        auto surfaceNode = nodePtr->ReinterpretCastTo<RSSurfaceRenderNode>();
        surfaceNodeMap_.emplace(id, surfaceNode);
        InsertSelfDrawingNodeOfProcess(surfaceNode);
        if (IsResidentProcess(surfaceNode)) {
            residentSurfaceNodeMap_.emplace(id, surfaceNode);
        }
        AddUIExtensionSurfaceNode(surfaceNode);
        ObtainLauncherNodeId(surfaceNode);
        ObtainScreenLockWindowNodeId(surfaceNode);
        RSSurfaceFpsManager::GetInstance().RegisterSurfaceFps(id, surfaceNode->GetName());
    } else if (nodePtr->GetType() == RSRenderNodeType::CANVAS_DRAWING_NODE) {
        auto canvasDrawingNode = nodePtr->ReinterpretCastTo<RSCanvasDrawingRenderNode>();
        canvasDrawingNodeMap_.emplace(id, canvasDrawingNode);
    }
    return true;
}

bool RSRenderNodeMap::RegisterDisplayRenderNode(const std::shared_ptr<RSDisplayRenderNode>& nodePtr)
{
    NodeId id = nodePtr->GetId();
    pid_t pid = ExtractPid(id);
    if (!(renderNodeMap_[pid].insert({ id, nodePtr })).second) {
        return false;
    }
    displayNodeMap_.emplace(id, nodePtr);
    nodePtr->OnRegister(context_);
    return true;
}

void RSRenderNodeMap::InsertSelfDrawingNodeOfProcess(const std::shared_ptr<RSSurfaceRenderNode> surfaceNode)
{
    NodeId id = surfaceNode->GetId();
    pid_t pid = ExtractPid(id);
    if (surfaceNode->IsSelfDrawingType()) {
        selfDrawingNodeInProcess_[pid].insert({ id, surfaceNode });
    }
}

void RSRenderNodeMap::UnregisterRenderNode(NodeId id)
{
    pid_t pid = ExtractPid(id);
    auto iter = renderNodeMap_.find(pid);
    if (iter != renderNodeMap_.end()) {
        auto& subMap = iter->second;
        subMap.erase(id);
        if (subMap.empty()) {
            renderNodeMap_.erase(iter);
        }
    }

    auto it = surfaceNodeMap_.find(id);
    if (it != surfaceNodeMap_.end()) {
        RemoveUIExtensionSurfaceNode(it->second);
        EraseSelfDrawingNodeOfProcess(id);
        surfaceNodeMap_.erase(id);
        RSSurfaceFpsManager::GetInstance().UnregisterSurfaceFps(id);
    }
    residentSurfaceNodeMap_.erase(id);
    displayNodeMap_.erase(id);
    canvasDrawingNodeMap_.erase(id);
    purgeableNodeMap_.erase(id);
}

void RSRenderNodeMap::EraseSelfDrawingNodeOfProcess(NodeId id)
{
    pid_t pid = ExtractPid(id);
    auto iter = selfDrawingNodeInProcess_.find(pid);
    if (iter != selfDrawingNodeInProcess_.end()) {
        auto& subMap = iter->second;
        auto subIter = subMap.find(id);
        if (subIter != subMap.end()) {
            subMap.erase(id);
            if (subMap.empty()) {
                selfDrawingNodeInProcess_.erase(iter);
            }
        }
    }
}

void RSRenderNodeMap::MoveRenderNodeMap(
    std::shared_ptr<std::unordered_map<NodeId, std::shared_ptr<RSBaseRenderNode>>> subRenderNodeMap, pid_t pid)
{
    if (!subRenderNodeMap) {
        return;
    }
    auto iter = renderNodeMap_.find(pid);
    if (iter != renderNodeMap_.end()) {
        auto& subMap = iter->second;
        // remove node from tree
        for (auto subIter = subMap.begin(); subIter != subMap.end();) {
            subIter->second->RemoveFromTree(false);
            subRenderNodeMap->emplace(subIter->first, subIter->second);
            subIter = subMap.erase(subIter);
        }
        renderNodeMap_.erase(iter);
    }
}

void RSRenderNodeMap::FilterNodeByPid(pid_t pid)
{
    ROSEN_LOGD("RSRenderNodeMap::FilterNodeByPid removing all nodes belong to pid %{public}llu",
        (unsigned long long)pid);
    bool useBatchRemoving =
        RSUniRenderJudgement::IsUniRender() && RSSystemProperties::GetBatchRemovingOnRemoteDiedEnabled();
    // remove all nodes belong to given pid (by matching higher 32 bits of node id)
    auto iter = renderNodeMap_.find(pid);
    if (iter != renderNodeMap_.end()) {
        auto& subMap = iter->second;
        for (auto subIter = subMap.begin(); subIter != subMap.end();) {
            if (subIter->second == nullptr) {
                subIter = subMap.erase(subIter);
                continue;
            }
            if (useBatchRemoving) {
                RSRenderNodeGC::Instance().AddToOffTreeNodeBucket(subIter->second);
            } else if (auto parent = subIter->second->GetParent().lock()) {
                parent->RemoveChildFromFulllist(subIter->second->GetId());
                subIter->second->RemoveFromTree(false);
            } else {
                subIter->second->RemoveFromTree(false);
            }
            subIter->second->GetAnimationManager().FilterAnimationByPid(pid);
            subIter = subMap.erase(subIter);
        }
        renderNodeMap_.erase(iter);
    }
    EraseIf(surfaceNodeMap_, [pid, useBatchRemoving, this](const auto& pair) -> bool {
        bool shouldErase = (ExtractPid(pair.first) == pid);
        if (shouldErase) {
            RSSurfaceFpsManager::GetInstance().UnregisterSurfaceFps(pair.first);
            RemoveUIExtensionSurfaceNode(pair.second);
        }
        if (shouldErase && pair.second && useBatchRemoving) {
            if (auto parent = pair.second->GetParent().lock()) {
                parent->RemoveChildFromFulllist(pair.second->GetId());
            }
            pair.second->RemoveFromTree(false);
        }
        return shouldErase;
    });

    EraseIf(residentSurfaceNodeMap_, [pid](const auto& pair) -> bool {
        return ExtractPid(pair.first) == pid;
    });

    EraseIf(canvasDrawingNodeMap_, [pid](const auto& pair) -> bool {
        return ExtractPid(pair.first) == pid;
    });

    EraseIf(selfDrawingNodeInProcess_, [pid](const auto& pair) -> bool {
        return pair.first == pid;
    });

    EraseIf(displayNodeMap_, [pid](const auto& pair) -> bool {
        if (ExtractPid(pair.first) != pid && pair.second) {
            ROSEN_LOGD("RSRenderNodeMap::FilterNodeByPid removing all nodes belong to pid %{public}llu",
                (unsigned long long)pid);
            pair.second->FilterModifiersByPid(pid);
        }
        return ExtractPid(pair.first) == pid;
    });

    if (auto fallbackNode = GetAnimationFallbackNode()) {
        // remove all fallback animations belong to given pid
        fallbackNode->GetAnimationManager().FilterAnimationByPid(pid);
    }
}

void RSRenderNodeMap::TraversalNodes(std::function<void (const std::shared_ptr<RSBaseRenderNode>&)> func) const
{
    for (const auto& [_, subMap] : renderNodeMap_) {
        for (const auto& [_, node] : subMap) {
            func(node);
        }
    }
}

void RSRenderNodeMap::TraversalNodesByPid(int pid,
    std::function<void (const std::shared_ptr<RSBaseRenderNode>&)> func) const
{
    const auto& itr = renderNodeMap_.find(pid);
    if (itr != renderNodeMap_.end()) {
        for (const auto& [_, node] : itr->second) {
            func(node);
        }
    }
}

void RSRenderNodeMap::TraverseCanvasDrawingNodes(
    std::function<void(const std::shared_ptr<RSCanvasDrawingRenderNode>&)> func) const
{
    for (const auto& [_, node] : canvasDrawingNodeMap_) {
        func(node);
    }
}

void RSRenderNodeMap::TraverseSurfaceNodes(std::function<void (const std::shared_ptr<RSSurfaceRenderNode>&)> func) const
{
    for (const auto& [_, node] : surfaceNodeMap_) {
        func(node);
    }
}

void RSRenderNodeMap::TraverseSurfaceNodesBreakOnCondition(
    std::function<bool (const std::shared_ptr<RSSurfaceRenderNode>&)> func) const
{
    for (const auto& [_, node] : surfaceNodeMap_) {
        if(func(node)) {
            break;
        }
    }
}

bool RSRenderNodeMap::ContainPid(pid_t pid) const
{
    return std::any_of(surfaceNodeMap_.begin(), surfaceNodeMap_.end(),
        [pid](const auto& pair) -> bool { return ExtractPid(pair.first) == pid; });
}

void RSRenderNodeMap::TraverseDisplayNodes(std::function<void (const std::shared_ptr<RSDisplayRenderNode>&)> func) const
{
    for (const auto& [_, node] : displayNodeMap_) {
        func(node);
    }
}

const ResidentSurfaceNodeMap& RSRenderNodeMap::GetResidentSurfaceNodeMap() const
{
    return residentSurfaceNodeMap_;
}

template<>
const std::shared_ptr<RSBaseRenderNode> RSRenderNodeMap::GetRenderNode(NodeId id) const
{
    pid_t pid = ExtractPid(id);
    auto iter = renderNodeMap_.find(pid);
    if (iter != renderNodeMap_.end()) {
        auto subIter = (iter->second).find(id);
        if (subIter != (iter->second).end()) {
            return subIter->second;
        }
    }
    return nullptr;
}

const std::shared_ptr<RSRenderNode> RSRenderNodeMap::GetAnimationFallbackNode() const
{
    auto iter = renderNodeMap_.find(0);
    if (iter != renderNodeMap_.cend()) {
        if (auto subIter = iter->second.find(0); subIter != iter->second.end()) {
            return subIter->second;
        }
    }
    return nullptr;
}

void RSRenderNodeMap::AddOffTreeNode(NodeId nodeId)
{
    purgeableNodeMap_.insert(std::pair(nodeId, true));
}

void RSRenderNodeMap::RemoveOffTreeNode(NodeId nodeId)
{
    purgeableNodeMap_.insert(std::pair(nodeId, false));
}

std::unordered_map<NodeId, bool>&& RSRenderNodeMap::GetAndClearPurgeableNodeIds()
{
    return std::move(purgeableNodeMap_);
}

std::unordered_map<NodeId, std::shared_ptr<RSSurfaceRenderNode>> RSRenderNodeMap::GetSelfDrawingNodeInProcess(pid_t pid)
{
    auto iter = selfDrawingNodeInProcess_.find(pid);
    if (iter != selfDrawingNodeInProcess_.end()) {
        return iter->second;
    }
    return std::unordered_map<NodeId, std::shared_ptr<RSSurfaceRenderNode>>();
}

const std::string RSRenderNodeMap::GetSelfDrawSurfaceNameByPid(pid_t nodePid) const
{
    for (auto &t : surfaceNodeMap_) {
        if (ExtractPid(t.first) == nodePid && t.second->IsSelfDrawingType()) {
            return t.second->GetName();
        }
    }
    ROSEN_LOGD("RSRenderNodeMap::GetSurfaceNameByPid no self drawing nodes belong to pid %{public}d",
        static_cast<int32_t>(nodePid));
    return "";
}

} // namespace Rosen
} // namespace OHOS
