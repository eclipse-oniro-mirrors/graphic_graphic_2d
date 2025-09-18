/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "pipeline/rs_context.h"

#include "pipeline/rs_render_node.h"
#include "platform/common/rs_log.h"

namespace OHOS::Rosen {
void RSContext::RegisterAnimatingRenderNode(const std::shared_ptr<RSRenderNode>& nodePtr)
{
    NodeId id = nodePtr->GetId();
    animatingNodeList_.emplace(id, nodePtr);
    nodePtr->ActivateDisplaySync();
    ROSEN_LOGD("RSContext::RegisterAnimatingRenderNode, register node id: %{public}" PRIu64, id);
}

void RSContext::UnregisterAnimatingRenderNode(NodeId id)
{
    animatingNodeList_.erase(id);
    ROSEN_LOGD("RSContext::UnregisterAnimatingRenderNode, unregister node id: %{public}" PRIu64, id);
}

void RSContext::AddActiveNode(const std::shared_ptr<RSRenderNode>& node)
{
    if (node == nullptr || node->GetId() == INVALID_NODEID) {
        return;
    }
    auto rootNodeId = node->GetInstanceRootNodeId();
    std::lock_guard<std::mutex> lock(activeNodesInRootMutex_);
    activeNodesInRoot_[rootNodeId].emplace(node->GetId(), node);
}

// replication method takes long
std::unordered_map<NodeId, std::unordered_map<NodeId, std::weak_ptr<RSRenderNode>>> RSContext::GetActiveNodes()
{
    std::lock_guard<std::mutex> lock(activeNodesInRootMutex_);
    return activeNodesInRoot_;
}

bool RSContext::HasActiveNode(const std::shared_ptr<RSRenderNode>& node)
{
    if (node == nullptr || node->GetId() == INVALID_NODEID) {
        return false;
    }
    auto rootNodeId = node->GetInstanceRootNodeId();
    std::lock_guard<std::mutex> lock(activeNodesInRootMutex_);
    return activeNodesInRoot_[rootNodeId].count(node->GetId()) > 0;
}

void RSContext::AddPendingSyncNode(const std::shared_ptr<RSRenderNode> node)
{
    if (node == nullptr || node->GetId() == INVALID_NODEID) {
        return;
    }
    pendingSyncNodes_.emplace(node->GetId(), node);
}

void RSContext::MarkNeedPurge(ClearMemoryMoment moment, PurgeType purgeType)
{
    clearMoment_ = moment;
    purgeType_ = purgeType;
}

void RSContext::SetClearMoment(ClearMemoryMoment moment)
{
    clearMoment_ = moment;
}

ClearMemoryMoment RSContext::GetClearMoment() const
{
    return clearMoment_;
}

void RSContext::Initialize()
{
    nodeMap.Initialize(weak_from_this());
    globalRootRenderNode_->OnRegister(weak_from_this());
}

void RSContext::AddSyncFinishAnimationList(NodeId nodeId, AnimationId animationId, uint64_t token)
{
    needSyncFinishAnimationList_.push_back({nodeId, animationId, token});
}
} // namespace OHOS::Rosen
