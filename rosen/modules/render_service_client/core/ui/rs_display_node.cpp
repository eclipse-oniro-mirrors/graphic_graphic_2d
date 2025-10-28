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

#include "ui/rs_display_node.h"

#include "rs_trace.h"
#ifdef ROSEN_OHOS
#include "hisysevent.h"
#include "sandbox_utils.h"
#endif
#include "command/rs_display_node_command.h"
#include "pipeline/rs_node_map.h"
#include "platform/common/rs_log.h"
#include "transaction/rs_render_service_client.h"
#include "transaction/rs_transaction_proxy.h"
#include "ui/rs_ui_context.h"
namespace OHOS {
namespace Rosen {

RSDisplayNode::SharedPtr RSDisplayNode::Create(
    const RSDisplayNodeConfig& displayNodeConfig, std::shared_ptr<RSUIContext> rsUIContext)
{
    SharedPtr node(new RSDisplayNode(displayNodeConfig, rsUIContext));
    if (rsUIContext != nullptr) {
        rsUIContext->GetMutableNodeMap().RegisterNode(node);
    } else {
        RSNodeMap::MutableInstance().RegisterNode(node);
    }

    if (LIKELY(!displayNodeConfig.isSync)) {
        std::unique_ptr<RSCommand> command = std::make_unique<RSDisplayNodeCreate>(node->GetId(), displayNodeConfig);
        if (node->GetRSUIContext() != nullptr) {
            auto transaction = node->GetRSUIContext()->GetRSTransaction();
            if (transaction != nullptr) {
                transaction->AddCommand(command, true);
            }
        } else {
            auto transactionProxy = RSTransactionProxy::GetInstance();
            if (transactionProxy != nullptr) {
                transactionProxy->AddCommand(command, true);
            }
        }
    } else {
        if (!node->CreateNode(displayNodeConfig, node->GetId())) {
            ROSEN_LOGE("RSDisplayNode::Create: CreateNode Failed.");
            return nullptr;
        }
    }
    HILOG_COMM_INFO("RSDisplayNode::Create, id:%{public}" PRIu64 " config[screenId=%{public}" PRIu64
        ", isMirror=%{public}d, mirroredNodeId=%{public}" PRIu64 ", isSync=%{public}d, "
        "mirrorSourceRotation: %{public}" PRIu32 "]", node->GetId(), displayNodeConfig.screenId,
        displayNodeConfig.isMirrored, displayNodeConfig.mirrorNodeId, displayNodeConfig.isSync,
        displayNodeConfig.mirrorSourceRotation);
    node->SetUIContextToken();
    return node;
}

bool RSDisplayNode::CreateNode(const RSDisplayNodeConfig& displayNodeConfig, NodeId nodeId)
{
    return std::static_pointer_cast<RSRenderServiceClient>(RSIRenderClient::CreateRenderServiceClient())->
        CreateNode(displayNodeConfig, nodeId);
}

void RSDisplayNode::RegisterNodeMap()
{
    auto rsContext = GetRSUIContext();
    if (rsContext == nullptr) {
        return;
    }
    auto& nodeMap = rsContext->GetMutableNodeMap();
    nodeMap.RegisterNode(shared_from_this());
}

void RSDisplayNode::AddDisplayNodeToTree()
{
    std::unique_ptr<RSCommand> command = std::make_unique<RSDisplayNodeAddToTree>(GetId());
    AddCommand(command, true);
    SetIsOnTheTree(true);
    HILOG_COMM_INFO("RSDisplayNode::AddDisplayNodeToTree, id:%{public}" PRIu64, GetId());
}

void RSDisplayNode::RemoveDisplayNodeFromTree()
{
    std::unique_ptr<RSCommand> command = std::make_unique<RSDisplayNodeRemoveFromTree>(GetId());
    AddCommand(command, true);
    SetIsOnTheTree(false);
    HILOG_COMM_INFO("RSDisplayNode::RemoveDisplayNodeFromTree, id:%{public}" PRIu64, GetId());
}

bool RSDisplayNode::Marshalling(Parcel& parcel) const
{
    bool success = parcel.WriteUint64(GetId()) && parcel.WriteUint64(screenId_) && parcel.WriteBool(isMirrorDisplay_);
    if (!success) {
        ROSEN_LOGE("RSDisplayNode::Marshalling failed");
    }
    return success;
}

RSDisplayNode::SharedPtr RSDisplayNode::Unmarshalling(Parcel& parcel)
{
    uint64_t id = UINT64_MAX;
    uint64_t screenId = UINT64_MAX;
    bool isMirror = false;
    if (!(parcel.ReadUint64(id) && parcel.ReadUint64(screenId) && parcel.ReadBool(isMirror))) {
        ROSEN_LOGE("RSDisplayNode::Unmarshalling, read param failed");
        return nullptr;
    }

    if (auto prevNode = RSNodeMap::Instance().GetNode(id)) { // delete
        // if the node id is already in the map, we should not create a new node
        return prevNode->ReinterpretCastTo<RSDisplayNode>();
    }

    RSDisplayNodeConfig config { .screenId = screenId, .isMirrored = isMirror };

    SharedPtr displayNode(new RSDisplayNode(config, id));
    RSNodeMap::MutableInstance().RegisterNode(displayNode);

    // for nodes constructed by unmarshalling, we should not destroy the corresponding render node on destruction
    displayNode->skipDestroyCommandInDestructor_ = true;

    return displayNode;
}

void RSDisplayNode::SetSecurityDisplay(bool isSecurityDisplay)
{
    isSecurityDisplay_ = isSecurityDisplay;
    std::unique_ptr<RSCommand> command = std::make_unique<RSDisplayNodeSetSecurityDisplay>(GetId(), isSecurityDisplay);
    AddCommand(command, true);
    ROSEN_LOGD("RSDisplayNode::SetSecurityDisplay, displayNodeId:[%{public}" PRIu64 "]"
        " isSecurityDisplay:[%{public}s]", GetId(), isSecurityDisplay ? "true" : "false");
}

bool RSDisplayNode::GetSecurityDisplay() const
{
    return isSecurityDisplay_;
}

void RSDisplayNode::ClearChildren()
{
    auto children = GetChildren();
    for (auto child : children) {
        if (auto childPtr = child.lock()) {
            RemoveChild(childPtr);
        }
    }
}

void RSDisplayNode::SetScreenId(uint64_t screenId)
{
    std::unique_ptr<RSCommand> command = std::make_unique<RSDisplayNodeSetScreenId>(GetId(), screenId);
    AddCommand(command, true);
#ifdef ROSEN_OHOS
    RS_TRACE_NAME_FMT("RSDisplayNode::SetScreenId HiSysEventWrite, DisplayNode: %" PRIu64 ", ScreenId: %" PRIu64,
        GetId(), screenId);
    int32_t ret = HiSysEventWrite(
        OHOS::HiviewDFX::HiSysEvent::Domain::GRAPHIC,
        "SET_SCREENID",
        OHOS::HiviewDFX::HiSysEvent::EventType::BEHAVIOR,
        "CURRENT_SCREENID", screenId);
    if (ret != 0) {
        ROSEN_LOGE("SET_SCREENID Write HiSysEvent error, ret: %{public}d" PRIu64, ret);
    }
#endif
    HILOG_COMM_INFO(
        "RSDisplayNode::SetScreenId, DisplayNode: %{public}" PRIu64 ", ScreenId: %{public}" PRIu64, GetId(), screenId);
    RS_TRACE_NAME_FMT("RSDisplayNode::SetScreenId, DisplayNode: %" PRIu64 ", ScreenId: %" PRIu64, GetId(), screenId);
}

void RSDisplayNode::SetForceCloseHdr(bool isForceCloseHdr)
{
    std::unique_ptr<RSCommand> command = std::make_unique<RSDisplayNodeForceCloseHdr>(GetId(), isForceCloseHdr);
    if (AddCommand(command, true)) {
        ROSEN_LOGD("RSDisplayNode::SetForceCloseHdr: [%{public}s], displayNodeId:[%{public}" PRIu64 "]",
            isForceCloseHdr ? "true" : "false", GetId());
    }
}

void RSDisplayNode::SetDisplayNodeMirrorConfig(const RSDisplayNodeConfig& displayNodeConfig)
{
    isMirrorDisplay_ = displayNodeConfig.isMirrored;
    std::unique_ptr<RSCommand> command = std::make_unique<RSDisplayNodeSetDisplayMode>(GetId(), displayNodeConfig);
    AddCommand(command, true);
    ROSEN_LOGD("RSDisplayNode::SetDisplayNodeMirrorConfig, displayNodeId:[%{public}" PRIu64 "]"
        " isMirror:[%{public}d]", GetId(), displayNodeConfig.isMirrored);
}

bool RSDisplayNode::IsMirrorDisplay() const
{
    return isMirrorDisplay_;
}

void RSDisplayNode::SetScreenRotation(const uint32_t& rotation)
{
    ScreenRotation screenRotation = ScreenRotation::ROTATION_0;
    switch (rotation) {
        case 0: // Rotation::ROTATION_0
            screenRotation = ScreenRotation::ROTATION_0;
            break;
        case 1: // Rotation::ROTATION_90
            screenRotation = ScreenRotation::ROTATION_90;
            break;
        case 2: // Rotation::ROTATION_180
            screenRotation = ScreenRotation::ROTATION_180;
            break;
        case 3: // Rotation::ROTATION_270
            screenRotation = ScreenRotation::ROTATION_270;
            break;
        default:
            screenRotation = ScreenRotation::INVALID_SCREEN_ROTATION;
            break;
    }
    std::unique_ptr<RSCommand> command = std::make_unique<RSDisplayNodeSetScreenRotation>(GetId(), screenRotation);
    AddCommand(command, true);
    ROSEN_LOGI("RSDisplayNode::SetScreenRotation, displayNodeId:[%{public}" PRIu64 "]"
               " screenRotation:[%{public}u]", GetId(), rotation);
}

RSDisplayNode::RSDisplayNode(const RSDisplayNodeConfig& config, std::shared_ptr<RSUIContext> rsUIContext)
    : RSNode(true, false, rsUIContext, true), screenId_(config.screenId), isMirrorDisplay_(config.isMirrored)
{}

RSDisplayNode::RSDisplayNode(const RSDisplayNodeConfig& config, NodeId id, std::shared_ptr<RSUIContext> rsUIContext)
    : RSNode(true, id, false, rsUIContext, true), screenId_(config.screenId), isMirrorDisplay_(config.isMirrored)
{}

void RSDisplayNode::SetBootAnimation(bool isBootAnimation)
{
    isBootAnimation_ = isBootAnimation;
    std::unique_ptr<RSCommand> command = std::make_unique<RSDisplayNodeSetBootAnimation>(GetId(), isBootAnimation);
    AddCommand(command, true);
}

bool RSDisplayNode::GetBootAnimation() const
{
    return isBootAnimation_;
}

void RSDisplayNode::ClearModifierByPid(pid_t pid)
{
    std::unique_ptr<RSCommand> command = std::make_unique<RSDisplayNodeClearModifiersByPid>(GetId(), pid);
    AddCommand(command, true);
    ROSEN_LOGI("RSDisplayNode::ClearModifierByPid %{public}u", static_cast<uint32_t>(pid));
}

void RSDisplayNode::SetVirtualScreenMuteStatus(bool virtualScreenMuteStatus)
{
    std::unique_ptr<RSCommand> command =
        std::make_unique<RSDisplayNodeSetVirtualScreenMuteStatus>(GetId(), virtualScreenMuteStatus);
    AddCommand(command, true);
    ROSEN_LOGI("RSDisplayNode::SetVirtualScreenMuteStatus, displayNodeId:[%{public}" PRIu64 "] "
        "virtualScreenMuteStatus: %{public}d", GetId(), virtualScreenMuteStatus);
}

void RSDisplayNode::OnBoundsSizeChanged() const
{
    auto bounds = GetStagingProperties().GetBounds();
    ROSEN_LOGI("RSDisplayNode::%{public}s, screenId:[%{public}" PRIu64 "], displayNodeId:[%{public}" PRIu64 "], "
               "bounds:[%{public}.2f, %{public}.2f, %{public}.2f, %{public}.2f]",
               __func__, screenId_, GetId(), bounds.x_, bounds.y_, bounds.z_, bounds.w_);
}

RSDisplayNode::~RSDisplayNode()
{
    RS_LOGI("%{public}s, NodeId:[%{public}" PRIu64 "]", __func__, GetId());
}
} // namespace Rosen
} // namespace OHOS
