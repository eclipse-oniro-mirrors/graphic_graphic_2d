/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "ui/rs_canvas_drawing_node.h"

#include "command/rs_canvas_drawing_node_command.h"
#include "common/rs_obj_geometry.h"
#include "pipeline/rs_canvas_drawing_render_node.h"
#include "pipeline/rs_node_map.h"
#include "pipeline/rs_render_thread.h"
#include "platform/common/rs_log.h"
#include "transaction/rs_render_service_client.h"
#include "transaction/rs_transaction_proxy.h"

namespace OHOS {
namespace Rosen {
namespace {
    constexpr int EDGE_WIDTH_LIMIT = 1000;
}
RSCanvasDrawingNode::RSCanvasDrawingNode(bool isRenderServiceNode, bool isTextureExportNode)
    : RSCanvasNode(isRenderServiceNode, isTextureExportNode) {}

RSCanvasDrawingNode::~RSCanvasDrawingNode() {}

RSCanvasDrawingNode::SharedPtr RSCanvasDrawingNode::Create(bool isRenderServiceNode, bool isTextureExportNode)
{
    SharedPtr node(new RSCanvasDrawingNode(isRenderServiceNode, isTextureExportNode));
    RSNodeMap::MutableInstance().RegisterNode(node);

    auto transactionProxy = RSTransactionProxy::GetInstance();
    if (!transactionProxy) {
        return node;
    }

    std::unique_ptr<RSCommand> command =
        std::make_unique<RSCanvasDrawingNodeCreate>(node->GetId(), isTextureExportNode);
    transactionProxy->AddCommand(command, node->IsRenderServiceNode());
    return node;
}

bool RSCanvasDrawingNode::ResetSurface(int width, int height)
{
    auto transactionProxy = RSTransactionProxy::GetInstance();
    if (!transactionProxy) {
        return false;
    }
    if (width > EDGE_WIDTH_LIMIT) {
        ROSEN_LOGI("RSCanvasDrawingNode::ResetSurface id:%{public}" PRIu64 " width:%{public}d height:%{public}d",
            GetId(), width, height);
    }
    std::unique_ptr<RSCommand> command = std::make_unique<RSCanvasDrawingNodeResetSurface>(GetId(), width, height);
    transactionProxy->AddCommand(command, IsRenderServiceNode());
    return true;
}

void RSCanvasDrawingNode::CreateRenderNodeForTextureExportSwitch()
{
    auto transactionProxy = RSTransactionProxy::GetInstance();
    if (transactionProxy == nullptr) {
        return;
    }
    std::unique_ptr<RSCommand> command = std::make_unique<RSCanvasDrawingNodeCreate>(GetId(), isTextureExportNode_);
    if (IsRenderServiceNode()) {
        hasCreateRenderNodeInRS_ = true;
    } else {
        hasCreateRenderNodeInRT_ = true;
    }
    transactionProxy->AddCommand(command, IsRenderServiceNode());
}

bool RSCanvasDrawingNode::GetBitmap(Drawing::Bitmap& bitmap,
    std::shared_ptr<Drawing::DrawCmdList> drawCmdList, const Drawing::Rect* rect)
{
    if (IsRenderServiceNode()) {
        auto renderServiceClient =
            std::static_pointer_cast<RSRenderServiceClient>(RSIRenderClient::CreateRenderServiceClient());
        if (renderServiceClient == nullptr) {
            ROSEN_LOGE("RSCanvasDrawingNode::GetBitmap renderServiceClient is nullptr!");
            return false;
        }
        bool ret = renderServiceClient->GetBitmap(GetId(), bitmap);
        if (!ret) {
            ROSEN_LOGE("RSCanvasDrawingNode::GetBitmap GetBitmap failed");
            return ret;
        }
    } else {
        auto node =
            RSRenderThread::Instance().GetContext().GetNodeMap().GetRenderNode<RSCanvasDrawingRenderNode>(GetId());
        if (node == nullptr) {
            RS_LOGE("RSCanvasDrawingNode::GetBitmap cannot find NodeId: [%{public}" PRIu64 "]", GetId());
            return false;
        }
        if (node->GetType() != RSRenderNodeType::CANVAS_DRAWING_NODE) {
            RS_LOGE("RSCanvasDrawingNode::GetBitmap RenderNodeType != RSRenderNodeType::CANVAS_DRAWING_NODE");
            return false;
        }
        auto getBitmapTask = [&node, &bitmap]() { bitmap = node->GetBitmap(); };
        RSRenderThread::Instance().PostSyncTask(getBitmapTask);
        if (bitmap.IsValid()) {
            return false;
        }
    }
    if (drawCmdList == nullptr) {
        RS_LOGD("RSCanvasDrawingNode::GetBitmap drawCmdList == nullptr");
    } else {
        Drawing::Canvas canvas;
        canvas.Bind(bitmap);
        drawCmdList->Playback(canvas, rect);
    }
    return true;
}

bool RSCanvasDrawingNode::GetPixelmap(std::shared_ptr<Media::PixelMap> pixelmap,
    std::shared_ptr<Drawing::DrawCmdList> drawCmdList, const Drawing::Rect* rect)
{
    if (!pixelmap) {
        RS_LOGE("RSCanvasDrawingNode::GetPixelmap: pixelmap is nullptr");
        return false;
    }
    if (IsRenderServiceNode()) {
        auto renderServiceClient =
            std::static_pointer_cast<RSRenderServiceClient>(RSIRenderClient::CreateRenderServiceClient());
        if (renderServiceClient == nullptr) {
            ROSEN_LOGE("RSCanvasDrawingNode::GetPixelmap: renderServiceClient is nullptr!");
            return false;
        }
        bool ret = renderServiceClient->GetPixelmap(GetId(), pixelmap, rect, drawCmdList);
        if (!ret || !pixelmap) {
            ROSEN_LOGD("RSCanvasDrawingNode::GetPixelmap: GetPixelmap failed");
            return false;
        }
    } else {
        auto node =
            RSRenderThread::Instance().GetContext().GetNodeMap().GetRenderNode<RSCanvasDrawingRenderNode>(GetId());
        if (node == nullptr) {
            RS_LOGE("RSCanvasDrawingNode::GetPixelmap: cannot find NodeId: [%{public}" PRIu64 "]", GetId());
            return false;
        }
        if (node->GetType() != RSRenderNodeType::CANVAS_DRAWING_NODE) {
            RS_LOGE("RSCanvasDrawingNode::GetPixelmap: RenderNodeType != RSRenderNodeType::CANVAS_DRAWING_NODE");
            return false;
        }
        bool ret = false;
        auto getPixelmapTask = [&node, &pixelmap, rect, &ret, &drawCmdList]() {
            ret = node->GetPixelmap(pixelmap, rect);
        };
        RSRenderThread::Instance().PostSyncTask(getPixelmapTask);
        if (!ret || !pixelmap) {
            return false;
        }
    }
    return true;
}
} // namespace Rosen
} // namespace OHOS