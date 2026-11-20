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

#include "command/rs_display_node_command.h"

#include <cmath>
#include "pipeline/rs_screen_render_node.h"
#include "pipeline/rs_logical_display_render_node.h"
#include "pipeline/rs_render_node_gc.h"
#include "platform/common/rs_log.h"
#include "rs_trace.h"

namespace OHOS {
namespace Rosen {

/**
 * @brief This function is used to set the display node by screen id.
 * @param context The context of the render service.
 * @param id The screen id of the display node.
 * @param lambda The lambda function to set the display node.
 * @return Returns true if the display node is set successfully, otherwise returns false.
 */
template <class Lambda>
bool TrySetScreenNodeByScreenId(RSContext& context, ScreenId id, Lambda&& lambda)
{
    auto& nodeMap = context.GetMutableNodeMap();
    bool nodeExists = false;
    nodeMap.TraverseScreenNodes([&lambda, &nodeExists, id](auto& node) {
        if (!node || node->GetScreenId() != id) {
            return;
        }
        nodeExists = true;
        lambda(node);
    });
    return nodeExists;
}

void DisplayNodeCommandHelper::Create(RSContext& context, NodeId id, const RSDisplayNodeConfig& config,
    uint64_t token)
{
    if (config.mirrorSourceRotation > static_cast<uint32_t>(ScreenRotation::INVALID_SCREEN_ROTATION)) {
        RS_LOGE("DisplayNodeCommandHelper::Create invalid mirrorSourceRotation[%{public}" PRIu32 "]",
            config.mirrorSourceRotation);
        return;
    }
    RS_TRACE_NAME_FMT("DisplayNodeCommandHelper::%s displayNodeId[%" PRIu64 "], %s", __func__, id,
        config.ToString().c_str());

    const bool isSceneBoard = token != 0 && context.IsSceneBoardToken(ExtractPid(id), token);
    auto node = std::shared_ptr<RSLogicalDisplayRenderNode>(new RSLogicalDisplayRenderNode(id,
        config, context.weak_from_this()), RSRenderNodeGC::NodeDestructor);
    node->ApplyInstanceIdentity(token, isSceneBoard);
    auto& nodeMap = context.GetMutableNodeMap();
    nodeMap.RegisterRenderNode(node);

    AddDisplayNodeToTree(context, id);
    SetDisplayMode(context, id, config);
}

std::shared_ptr<RSLogicalDisplayRenderNode> DisplayNodeCommandHelper::CreateWithConfigInRS(
    RSContext& context, NodeId id, const RSDisplayNodeConfig& config)
{
    auto node = std::shared_ptr<RSLogicalDisplayRenderNode>(new RSLogicalDisplayRenderNode(id, config,
        context.weak_from_this()), RSRenderNodeGC::NodeDestructor);
    return node;
}

void DisplayNodeCommandHelper::AddDisplayNodeToTree(RSContext& context, NodeId id)
{
    auto& nodeMap = context.GetMutableNodeMap();
    auto logicalDisplayNode = nodeMap.GetRenderNode<RSLogicalDisplayRenderNode>(id);
    if (logicalDisplayNode == nullptr) {
        RS_LOGE("%{public}s Invalid NodeId curNodeId: %{public}" PRIu64, __func__, id);
        return;
    }
    auto screenId = logicalDisplayNode->GetScreenId();
    if (screenId == INVALID_SCREEN_ID) {
        RS_LOGE("%{public}s failed, screenId must be set before display node add to tree", __func__);
        return;
    }
    auto lambda = [&logicalDisplayNode](const std::shared_ptr<RSScreenRenderNode>& screenRenderNode) {
        screenRenderNode->AddChild(logicalDisplayNode);
    };
    if (!TrySetScreenNodeByScreenId(context, screenId, lambda)) {
        RS_LOGE("%{public}s: displayNode[%{public}" PRIu64 "] failed to AddToTree, can't find ScreenId[%{public}" PRIu64
            "]", __func__, id, screenId);
        logicalDisplayNode->NotifySetOnTreeFlag();
    } else {
        logicalDisplayNode->ResetSetOnTreeFlag();
    }
}

void DisplayNodeCommandHelper::RemoveDisplayNodeFromTree(RSContext& context, NodeId id)
{
    auto& nodeMap = context.GetMutableNodeMap();
    auto logicalDisplayNode = nodeMap.GetRenderNode<RSLogicalDisplayRenderNode>(id);
    if (logicalDisplayNode == nullptr) {
        RS_LOGE("%{public}s Invalid NodeId curNodeId: %{public}" PRIu64, __func__, id);
        return;
    }

    // End an active record session while the old parent is still reachable: the counted release
    // needs that output screen to drop the mirror relation derived from this display.
    logicalDisplayNode->EndWindowRecordSession();

    auto lambda = [&logicalDisplayNode](const std::shared_ptr<RSScreenRenderNode>& screenRenderNode) {
        screenRenderNode->RemoveChild(logicalDisplayNode);
    };
    auto screenId = logicalDisplayNode->GetScreenId();
    if (!TrySetScreenNodeByScreenId(context, screenId, lambda)) {
        RS_LOGE("%{public}s Invalid ScreenId NodeId: %{public}" PRIu64
            ", curNodeId: %{public}" PRIu64, __func__, screenId, id);
    }
    logicalDisplayNode->ResetSetOnTreeFlag();
}

void DisplayNodeCommandHelper::SetScreenId(RSContext& context, NodeId id, uint64_t screenId)
{
    const auto& nodeMap = context.GetNodeMap();
    auto logicalDisplayNode = nodeMap.GetRenderNode<RSLogicalDisplayRenderNode>(id);
    if (logicalDisplayNode == nullptr) {
        RS_LOGE("DisplayNodeCommandHelper::%{public}s, displayNode not found, id:[%{public}" PRIu64
            "], screenId:[%{public}" PRIu64 "]", __func__, id, screenId);
        return;
    }

    logicalDisplayNode->NotifyScreenSwitchFinish(logicalDisplayNode->GetScreenId());
    if (logicalDisplayNode->GetScreenId() != screenId) {
        // An active record session cannot carry its source relation to the new screen, so end it
        // and release both layers before the display attaches to its new parent.
        logicalDisplayNode->EndWindowRecordSession();
    }
    logicalDisplayNode->SetScreenId(screenId);
    for (auto& child : *(logicalDisplayNode->GetChildren())) {
        if (!child) {
            continue;
        }
        auto surfaceChild = child->ReinterpretCastTo<RSSurfaceRenderNode>();
        if (!surfaceChild) {
            continue;
        }
        auto& info = surfaceChild->GetAttachedInfo();
        if (info.has_value()) {
            info->first = screenId;
        }
    }
    logicalDisplayNode->RemoveFromTree();
    auto lambda = [&logicalDisplayNode](auto& screenRenderNode) {
        screenRenderNode->AddChild(logicalDisplayNode);
    };
    if (!TrySetScreenNodeByScreenId(context, screenId, lambda)) {
        RS_LOGE("%{public}s Invalid ScreenId NodeId: %{public}" PRIu64
            ", curNodeId: %{public}" PRIu64, __func__, screenId, id);
    }
}

void DisplayNodeCommandHelper::SetDisplayContentRect(RSContext& context, NodeId id,
    const Rect& contentRect)
{
    RS_LOGI("DisplayNodeCommandHelper::SetDisplayContentRect node:[%{public}" PRIu64 "], "
             "rect:[%{public}d,%{public}d,%{public}d,%{public}d]",
             id, contentRect.x, contentRect.y, contentRect.w, contentRect.h);
    if (auto node = context.GetNodeMap().GetRenderNode<RSLogicalDisplayRenderNode>(id)) {
        node->SetDisplayContentRect(contentRect);
    } else {
        RS_LOGE("%{public}s Invalid NodeId curNodeId: %{public}" PRIu64, __func__, id);
    }
}

void DisplayNodeCommandHelper::SetScreenRotation(RSContext& context, NodeId id, const ScreenRotation& screenRotation)
{
    RS_TRACE_NAME_FMT("DisplayNodeCommandHelper::SetScreenRotation displayNodeId[%" PRIu64
        "], screenRotation[%" PRIu32 "]", id, static_cast<uint32_t>(screenRotation));
    if (auto node = context.GetNodeMap().GetRenderNode<RSLogicalDisplayRenderNode>(id)) {
        node->SetScreenRotation(screenRotation);
    } else {
        RS_LOGE("%{public}s Invalid NodeId curNodeId: %{public}" PRIu64, __func__, id);
    }
}

void DisplayNodeCommandHelper::SetSecurityDisplay(RSContext& context, NodeId id, bool isSecurityDisplay)
{
    if (auto node = context.GetNodeMap().GetRenderNode<RSLogicalDisplayRenderNode>(id)) {
        node->SetSecurityDisplay(isSecurityDisplay);
    } else {
        RS_LOGE("%{public}s Invalid NodeId curNodeId: %{public}" PRIu64, __func__, id);
    }
}

void DisplayNodeCommandHelper::SetDisplayMode(RSContext& context, NodeId id, const RSDisplayNodeConfig& config)
{
    if (config.mirrorSourceRotation > static_cast<uint32_t>(ScreenRotation::INVALID_SCREEN_ROTATION)) {
        RS_LOGE("DisplayNodeCommandHelper::SetDisplayMode invalid mirrorSourceRotation[%{public}" PRIu32 "]",
            config.mirrorSourceRotation);
        return;
    }
    RS_LOGI("DisplayNodeCommandHelper::%{public}s, NodeId[%{public}" PRIu64 "], %{public}s", __func__, id,
        config.ToString().c_str());
    auto node = context.GetNodeMap().GetRenderNode<RSLogicalDisplayRenderNode>(id);
    if (node == nullptr) {
        RS_LOGE("%{public}s Invalid NodeId curNodeId: %{public}" PRIu64, __func__, id);
        return;
    }

    if (!std::isfinite(config.positionZ)) {
        RS_LOGE("DisplayNodeCommandHelper::%{public}s invalid positionZ", __func__);
        return;
    }

    auto screenRenderNode = RSRenderNode::ReinterpretCast<RSScreenRenderNode>(node->GetParent().lock());
    if (!screenRenderNode) {
        RS_LOGE("DisplayNodeCommandHelper::%{public}s parent of displayNodeId[%{public}" PRIu64 "] is invalid",
            __func__, id);
    } else if (!ROSEN_EQ(screenRenderNode->GetRenderProperties().GetPositionZ(), config.positionZ)) {
        screenRenderNode->GetMutableRenderProperties().SetPositionZ(config.positionZ);
        screenRenderNode->MarkParentNeedRegenerateChildren();
    }

    DisplayMode mode = config.displayMode;
    const bool wasRecordActive = node->IsWindowRecordActive();
    node->SetDisplayMode(mode);
    if (wasRecordActive) {
        // Explicit DMS ends the session and releases both record-owned relations before the
        // requested source is applied.
        node->EndWindowRecordSession();
    }
    if (mode == DisplayMode::MIRROR) {
        NodeId mirroredNodeId = config.mirrorNodeId;
        auto& nodeMap = context.GetNodeMap();
        auto mirrorSourceNode = nodeMap.GetRenderNode<RSLogicalDisplayRenderNode>(mirroredNodeId);
        if (mirrorSourceNode == nullptr) {
            // An active record session was already ended above, which released both record-owned
            // relations; keep that paused empty+no-source result. Without an active record this is
            // just a rejected DMS selection, so the existing mirror source must be retained.
            RS_LOGW("DisplayNodeCommandHelper::%{public}s fail, displayNodeId[%{public}" PRIu64
                    "], mirroredNodeId[%{public}" PRIu64 "]", __func__, id, mirroredNodeId);
            return;
        }
        node->SetMirrorSource(mirrorSourceNode);
        node->SetMirrorSourceRotation(static_cast<ScreenRotation>(config.mirrorSourceRotation));
    } else {
        node->ResetMirrorSource();
    }
}

void DisplayNodeCommandHelper::SetBootAnimation(RSContext& context, NodeId nodeId, bool isBootAnimation)
{
    if (auto node = context.GetNodeMap().GetRenderNode<RSLogicalDisplayRenderNode>(nodeId)) {
        node->SetBootAnimation(isBootAnimation);
    } else {
        RS_LOGE("%{public}s Invalid NodeId curNodeId: %{public}" PRIu64, __func__, nodeId);
    }
}

void DisplayNodeCommandHelper::ClearModifiersByPid(RSContext& context, NodeId nodeId, int32_t pid)
{
    if (auto node = context.GetNodeMap().GetRenderNode<RSLogicalDisplayRenderNode>(nodeId)) {
        RS_LOGI(
            "ClearModifiersByPid NodeId:[%{public}" PRIu64 "] pid:[%{public}u]", nodeId, static_cast<uint32_t>(pid));
        node->ClearModifiersByPid(pid);
    } else {
        RS_LOGE("%{public}s Invalid NodeId curNodeId: %{public}" PRIu64, __func__, nodeId);
    }
}

void DisplayNodeCommandHelper::SetVirtualScreenMuteStatus(RSContext& context, NodeId nodeId,
    bool virtualScreenMuteStatus)
{
    if (auto node = context.GetNodeMap().GetRenderNode<RSLogicalDisplayRenderNode>(nodeId)) {
        RS_LOGI("SetVirtualScreenMuteStatus NodeId:[%{public}" PRIu64 "]"
            " screenId: %{public}" PRIu64 " virtualScreenMuteStatus: %{public}d",
            nodeId, node->GetScreenId(), virtualScreenMuteStatus);
        node->SetVirtualScreenMuteStatus(virtualScreenMuteStatus);
    } else {
        RS_LOGE("%{public}s Invalid NodeId curNodeId: %{public}" PRIu64, __func__, nodeId);
    }
}

void DisplayNodeCommandHelper::SetWindowRecordConfig(RSContext& context, NodeId id,
    const RSWindowRecordConfig& config)
{
    auto node = context.GetNodeMap().GetRenderNode<RSLogicalDisplayRenderNode>(id);
    if (node == nullptr) {
        RS_LOGE("DisplayNodeCommandHelper::%{public}s Invalid NodeId: %{public}" PRIu64, __func__, id);
        return;
    }
    if (!node->IsOnVirtualScreen()) {
        RS_LOGE("DisplayNodeCommandHelper::%{public}s NodeId: %{public}" PRIu64
            " is not on a virtual screen, config ignored", __func__, id);
        return;
    }
    const bool isStart = !config.surfaceNodeIds.empty();
    const bool wasActive = node->IsWindowRecordActive();
    if (isStart) {
        if (!node->IsMirrorDisplay()) {
            // Validate the whole start before mutation: record requires a virtual MIRROR output.
            // A pre-existing live source is not required; early publication selects the window.
            RS_LOGE("DisplayNodeCommandHelper::%{public}s NodeId: %{public}" PRIu64
                " is not a MIRROR output, record ignored", __func__, id);
            return;
        }
        // The node setter stays the server authority for the surface-count bound and keeps the
        // previous config when the limit is exceeded.
        node->SetWindowRecordConfig(config);
        return;
    }
    // Empty config stops recording. An inactive empty config leaves ordinary mirror untouched.
    if (wasActive) {
        node->EndWindowRecordSession();
    }
}

} // namespace Rosen
} // namespace OHOS
