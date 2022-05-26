/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "pipeline/rs_surface_render_node.h"

#include "command/rs_surface_node_command.h"
#include "common/rs_obj_abs_geometry.h"
#include "display_type.h"
#include "include/core/SkRect.h"
#include "common/rs_rect.h"
#include "common/rs_vector2.h"
#include "pipeline/rs_render_node.h"
#include "pipeline/rs_root_render_node.h"
#include "platform/common/rs_log.h"
#include "property/rs_properties_painter.h"
#include "property/rs_transition_properties.h"
#include "transaction/rs_transaction_proxy.h"
#include "transaction/rs_render_service_client.h"
#include "visitor/rs_node_visitor.h"

namespace OHOS {
namespace Rosen {
static const int rectBounds = 2;

RSSurfaceRenderNode::RSSurfaceRenderNode(const RSSurfaceRenderNodeConfig& config, std::weak_ptr<RSContext> context)
    : RSRenderNode(config.id, context),
      RSSurfaceHandler(config.id),
      name_(config.name)
{
}

RSSurfaceRenderNode::RSSurfaceRenderNode(NodeId id, std::weak_ptr<RSContext> context)
    : RSSurfaceRenderNode(RSSurfaceRenderNodeConfig{id, "SurfaceNode"}, context)
{
}

RSSurfaceRenderNode::~RSSurfaceRenderNode() {}

void RSSurfaceRenderNode::SetConsumer(const sptr<Surface>& consumer)
{
    consumer_ = consumer;
}

void RSSurfaceRenderNode::ProcessRenderBeforeChildren(RSPaintFilterCanvas& canvas)
{
    canvas.SaveAlpha();
    canvas.MultiplyAlpha(GetRenderProperties().GetAlpha() * GetContextAlpha());
    SkIRect clipBounds = canvas.getDeviceClipBounds();  // this clip region from parent node from render service
    clipRegionFromParent_.SetAll(clipBounds.left(), clipBounds.top(), clipBounds.width(), clipBounds.height());
    RectI clipRegion = CalculateClipRegion(canvas);
    SkRect rect;
    SkPoint points[] = {{clipRegion.left_, clipRegion.top_}, {clipRegion.GetRight(), clipRegion.GetBottom()}};
    rect.setBounds(points, rectBounds);
    canvas.clipRect(rect);
    auto currentClipRegion = canvas.getDeviceClipBounds();
    SetDstRect({ currentClipRegion.left(), currentClipRegion.top(), currentClipRegion.width(),
        currentClipRegion.height() });
    SetGlobalAlpha(canvas.GetAlpha());
}

RectI RSSurfaceRenderNode::CalculateClipRegion(RSPaintFilterCanvas& canvas)
{
    const Vector4f& clipRegionFromRT = GetContextClipRegion(); // this clip region from render thread, it`s relative position
    RectI clipRegion(clipRegionFromRT.x_, clipRegionFromRT.y_, clipRegionFromRT.z_, clipRegionFromRT.w_);
    clipRegion.left_ = clipRegionFromRT.x_ + clipRegionFromParent_.left_;
    clipRegion.top_ = clipRegionFromRT.y_ + clipRegionFromParent_.top_;
    clipRegion.SetRight(clipRegion.IsEmpty() ? clipRegionFromParent_.GetRight() :
        std::min(clipRegion.GetRight(), clipRegionFromParent_.GetRight()));
    clipRegion.SetBottom(clipRegion.IsEmpty() ? clipRegionFromParent_.GetBottom() :
        std::min(clipRegion.GetBottom(), clipRegionFromParent_.GetBottom()));
    auto geoPtr = std::static_pointer_cast<RSObjAbsGeometry>(GetRenderProperties().GetBoundsGeometry());
    if (geoPtr == nullptr) {
        RS_LOGE("RsDebug RSSurfaceRenderNode::ProcessRenderBeforeChildren geoPtr == nullptr");
        return RectI();
    }
    RectI originDstRect(geoPtr->GetAbsRect().left_ - offsetX_, geoPtr->GetAbsRect().top_ - offsetY_,
            geoPtr->GetAbsRect().width_, geoPtr->GetAbsRect().height_);
    RectI resClipRegion = clipRegion.IntersectRect(originDstRect);
    auto transitionProperties = GetAnimationManager().GetTransitionProperties();
    Vector2f center(resClipRegion.width_ * 0.5f, resClipRegion.height_ * 0.5f);
    RSPropertiesPainter::DrawTransitionProperties(transitionProperties, center, canvas);
    return resClipRegion;
}

void RSSurfaceRenderNode::ProcessRenderAfterChildren(RSPaintFilterCanvas& canvas)
{
    canvas.RestoreAlpha();
}

void RSSurfaceRenderNode::Prepare(const std::shared_ptr<RSNodeVisitor>& visitor)
{
    if (!visitor) {
        return;
    }
    visitor->PrepareSurfaceRenderNode(*this);
}

void RSSurfaceRenderNode::Process(const std::shared_ptr<RSNodeVisitor>& visitor)
{
    if (!visitor) {
        return;
    }
    visitor->ProcessSurfaceRenderNode(*this);
}

void RSSurfaceRenderNode::SetContextMatrix(const SkMatrix& matrix, bool sendMsg)
{
    if (contextMatrix_ == matrix) {
        return;
    }
    contextMatrix_ = matrix;
    if (!sendMsg) {
        return;
    }
    // send a Command
    std::unique_ptr<RSCommand> command = std::make_unique<RSSurfaceNodeSetContextMatrix>(GetId(), matrix);
    SendCommandFromRT(command);
}

const SkMatrix& RSSurfaceRenderNode::GetContextMatrix() const
{
    return contextMatrix_;
}

void RSSurfaceRenderNode::SetContextAlpha(float alpha, bool sendMsg)
{
    if (contextAlpha_ == alpha) {
        return;
    }
    contextAlpha_ = alpha;
    if (!sendMsg) {
        return;
    }
    // send a Command
    std::unique_ptr<RSCommand> command = std::make_unique<RSSurfaceNodeSetContextAlpha>(GetId(), alpha);
    SendCommandFromRT(command);
}

float RSSurfaceRenderNode::GetContextAlpha() const
{
    return contextAlpha_;
}

void RSSurfaceRenderNode::SetContextClipRegion(Vector4f clipRegion, bool sendMsg)
{
    if (contextClipRect_ == clipRegion) {
        return;
    }
    contextClipRect_ = clipRegion;
    if (!sendMsg) {
        return;
    }
    // send a Command
    std::unique_ptr<RSCommand> command = std::make_unique<RSSurfaceNodeSetContextClipRegion>(GetId(), clipRegion);
    SendCommandFromRT(command);
}

const Vector4f& RSSurfaceRenderNode::GetContextClipRegion() const
{
    return contextClipRect_;
}

void RSSurfaceRenderNode::SetSecurityLayer(bool isSecurityLayer)
{
    isSecurityLayer_ = isSecurityLayer;
}

bool RSSurfaceRenderNode::GetSecurityLayer() const
{
    return isSecurityLayer_;
}

void RSSurfaceRenderNode::SetParentId(NodeId parentId, bool sendMsg)
{
    parentId_ = parentId;
    if (!sendMsg) {
        return;
    }
    // find parent surface
    auto node = GetParent().lock();
    std::unique_ptr<RSCommand> command;
    while (true) {
        if (node == nullptr) {
            return;
        } else if (auto rootnode = node->ReinterpretCastTo<RSRootRenderNode>()) {
            command = std::make_unique<RSSurfaceNodeSetParentSurface>(GetId(), rootnode->GetRSSurfaceNodeId());
            break;
        } else if (auto surfaceNode = node->ReinterpretCastTo<RSSurfaceRenderNode>()) {
            command = std::make_unique<RSSurfaceNodeSetParentSurface>(GetId(), surfaceNode->GetId());
            break;
        } else {
            node = node->GetParent().lock();
        }
    }
    // send a Command
    if (command) {
        SendCommandFromRT(command);
    }
}

NodeId RSSurfaceRenderNode::GetParentId() const
{
    return parentId_;
}

void RSSurfaceRenderNode::UpdateSurfaceDefaultSize(float width, float height)
{
    if (consumer_ != nullptr) {
        consumer_->SetDefaultWidthAndHeight(width, height);
    }  
}

void RSSurfaceRenderNode::SendCommandFromRT(std::unique_ptr<RSCommand>& command)
{
    auto transactionProxy = RSTransactionProxy::GetInstance();
    if (transactionProxy != nullptr) {
        transactionProxy->AddCommandFromRT(command);
    }
}

BlendType RSSurfaceRenderNode::GetBlendType()
{
    return blendType_;
}

void RSSurfaceRenderNode::SetBlendType(BlendType blendType)
{
    blendType_ = blendType;
}

void RSSurfaceRenderNode::RegisterBufferAvailableListener(
    sptr<RSIBufferAvailableCallback> callback, bool isFromRenderThread)
{
    if (isFromRenderThread) {
        std::lock_guard<std::mutex> lock(mutexRT_);
        callbackFromRT_ = callback;
    } else {
        std::lock_guard<std::mutex> lock(mutexUI_);
        callbackFromUI_ = callback;
    }
}

void RSSurfaceRenderNode::ConnectToNodeInRenderService()
{
    ROSEN_LOGI("RSSurfaceRenderNode::ConnectToNodeInRenderService nodeId = %llu", GetId());
    auto renderServiceClient =
        std::static_pointer_cast<RSRenderServiceClient>(RSIRenderClient::CreateRenderServiceClient());
    if (renderServiceClient != nullptr) {
        renderServiceClient->RegisterBufferAvailableListener(
            GetId(), [weakThis = weak_from_this()]() {
                auto node = RSBaseRenderNode::ReinterpretCast<RSSurfaceRenderNode>(weakThis.lock());
                if (node == nullptr) {
                    return;
                }
                node->NotifyRTBufferAvailable();
            }, true);
    }
}

void RSSurfaceRenderNode::NotifyRTBufferAvailable()
{
    // In RS, "isNotifyRTBufferAvailable_ = true" means buffer is ready and need to trigger ipc callback.
    // In RT, "isNotifyRTBufferAvailable_ = true" means RT know that RS have had available buffer
    // and ready to trigger "callbackForRenderThreadRefresh_" to "clip" on parent surface.
    if (isNotifyRTBufferAvailable_) {
        return;
    }
    isNotifyRTBufferAvailable_ = true;

    if (callbackForRenderThreadRefresh_) {
        ROSEN_LOGI("RSSurfaceRenderNode::NotifyRTBufferAvailable nodeId = %llu RenderThread", GetId());
        callbackForRenderThreadRefresh_();
    }

    {
        std::lock_guard<std::mutex> lock(mutexRT_);
        if (callbackFromRT_) {
            ROSEN_LOGI("RSSurfaceRenderNode::NotifyRTBufferAvailable nodeId = %llu RenderService", GetId());
            callbackFromRT_->OnBufferAvailable();
        }
        if (!callbackForRenderThreadRefresh_ && !callbackFromRT_) {
            isNotifyRTBufferAvailable_ = false;
        }
    }
}

void RSSurfaceRenderNode::NotifyUIBufferAvailable()
{
    if (isNotifyUIBufferAvailable_) {
        return;
    }
    isNotifyUIBufferAvailable_ = true;
    {
        std::lock_guard<std::mutex> lock(mutexUI_);
        if (callbackFromUI_) {
            ROSEN_LOGI("RSSurfaceRenderNode::NotifyUIBufferAvailable nodeId = %llu", GetId());
            callbackFromUI_->OnBufferAvailable();
        } else {
            isNotifyUIBufferAvailable_ = false;
        }
    }
}

bool RSSurfaceRenderNode::IsNotifyRTBufferAvailable() const
{
    return isNotifyRTBufferAvailable_;
}

bool RSSurfaceRenderNode::IsNotifyUIBufferAvailable() const
{
    return isNotifyUIBufferAvailable_;
}

void RSSurfaceRenderNode::SetCallbackForRenderThreadRefresh(std::function<void(void)> callback)
{
    callbackForRenderThreadRefresh_ = callback;
}

bool RSSurfaceRenderNode::NeedSetCallbackForRenderThreadRefresh()
{
    return (callbackForRenderThreadRefresh_ == nullptr);
}

} // namespace Rosen
} // namespace OHOS
