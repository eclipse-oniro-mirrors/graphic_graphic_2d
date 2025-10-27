/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include <algorithm>
#include "feature/watermark/rs_surface_watermark.h"
#include "pipeline/rs_screen_render_node.h"
namespace OHOS {
namespace Rosen {
constexpr uint32_t MAX_LIMIT_SURFACE_WATER_MARK_IMG = 1000;

uint32_t RSSurfaceWatermarkHelper::SetSurfaceWatermark(pid_t pid,
    const std::string& name, std::shared_ptr<Media::PixelMap> pixelMap, const std::vector<NodeId>& nodeIdList,
    SurfaceWatermarkType watermarkType,
    RSContext& mainContext, bool isSystemCalling)
{
    // 0. Clear history residual node and get maxSize for same watermark name
    RS_LOGI("RSSurfaceWatermarkHelper::SetSurfaceWatermark pid:[%{public}d], watermarkType:[%{public}d]",
        pid, static_cast<int32_t>(watermarkType));
    std::unordered_set<NodeId> historyWatermarkNode =
        (watermarkNameMapNodeId_.find(name) != watermarkNameMapNodeId_.end()) ?
        watermarkNameMapNodeId_[name].first : std::unordered_set<NodeId>{};
    RSSurfaceWatermarkSpecialParam param;
    TraverseAndOperateNodeList(pid, name, historyWatermarkNode,
        mainContext, [&param, &mainContext, this](const std::string& name,
        std::shared_ptr<RSSurfaceRenderNode> node) {
            auto screenInfo = GetScreenInfo(node, mainContext);
            param.maxWidth_ = std::max(node->GetRenderProperties().GetBoundsWidth(),
                std::max(param.maxWidth_, static_cast<float>(screenInfo.width)));
            param.maxHeight_ = std::max(node->GetRenderProperties().GetBoundsHeight(),
                std::max(param.maxHeight_, static_cast<float>(screenInfo.height)));
            return WATER_MARK_SUCCESS;
        },
        isSystemCalling, watermarkType);
    // 1. Check the conditions for setting the watermark
    auto iter = surfaceWatermarks_.find(name);
    if (iter == surfaceWatermarks_.end() && pixelMap == nullptr) {
        return WATER_MARK_PIXELMAP_INVALID;
    }
    // When SCB is restored, the pixelMap is passed as a null pointer.
    param.isWatermarkChange_ = (pixelMap == nullptr) ? false : true;
    std::shared_ptr<Drawing::Image> tmpImagePtr = (!param.isWatermarkChange_) ? iter->second.first :
        RSPixelMapUtil::ExtractDrawingImage(pixelMap);

    // 2.Check pixelMap is Invaild
    if (tmpImagePtr == nullptr) {
        RS_LOGE("RSSurfaceWatermarkHelper::SetSurfaceWatermark tmpImagePtr is nullptr");
        return WATER_MARK_RS_CONNECTION_ERROR;
    }

    auto checkfunc = [&tmpImagePtr, &watermarkType, &mainContext,
        &isSystemCalling, this, &param](const std::string& name, std::shared_ptr<RSSurfaceRenderNode> node) {
        // CUSTOM_WATER_MARK need limit screen size and surface size
        if (watermarkType == CUSTOM_WATER_MARK) {
            return CheckCustomWatermarkCondition(tmpImagePtr, mainContext, node, param);
        }
        return static_cast<uint32_t>(WATER_MARK_SUCCESS);
    };
    // 3.Check watermarkType == CUSTOM_WATER_MARK condition
    auto [errocode, hasNodeOperationSuccess] = TraverseAndOperateNodeList(pid, name, nodeIdList,
        mainContext, checkfunc, isSystemCalling, watermarkType);
    // As long as one watermark is successfully applied to the node, the watermark image can be stored.
    if (!hasNodeOperationSuccess) {
        return errocode;
    }
    // Adding a new watermark image requires verification to check if the limit has been reached.
    if (iter == surfaceWatermarks_.end()) {
        if (registerSurfaceWatermarkCount_ >= MAX_LIMIT_SURFACE_WATER_MARK_IMG) {
            RS_LOGE("RSSurfaceWatermarkHelper::SetSurfaceWatermark max limit surface water mark img");
            return WATER_MARK_RS_CONNECTION_ERROR;
        }
        registerSurfaceWatermarkCount_++;
    }
    errocode &= ~(static_cast<uint32_t>(WATER_MARK_IMG_SIZE_ERROR));
    // 4. Enable watermark
    auto doFunc = [this, &watermarkType](const std::string& name,
        std::shared_ptr<RSSurfaceRenderNode> node) {
        node->SetWatermarkEnabled(name, true, watermarkType);
        AddWatermarkNameMapNodeId(name, node->GetId(), watermarkType);
        return WATER_MARK_SUCCESS;
    };

    auto [newErrocode, _] = TraverseAndOperateNodeList(pid, name,
        nodeIdList, mainContext, doFunc, isSystemCalling, watermarkType);
    errocode |= newErrocode;
    surfaceWatermarks_[name] = {tmpImagePtr, pid};
    return errocode;
}

template<typename Container>
std::pair<uint32_t, bool> RSSurfaceWatermarkHelper::TraverseAndOperateNodeList(const pid_t& pid,
    const std::string& name,
    const Container& nodeIdList, RSContext& mainContext,
    std::function<uint32_t(const std::string& name, std::shared_ptr<RSSurfaceRenderNode>)> func,
    const bool& isSystemCalling, const SurfaceWatermarkType& watermarkType)
{
    uint32_t returnErrorCode = 0;
    bool hasNodeOperationSuccess = false;
    if (watermarkType == SYSTEM_WATER_MARK) {
        return {WATER_MARK_SUCCESS, true};
    }
    for (const auto& nodeId : nodeIdList) {
        // Not System calls must have the same pid.
        bool isErrorPermission = (!isSystemCalling && pid != ExtractPid(nodeId));
        if (isErrorPermission) {
            returnErrorCode |= static_cast<uint32_t>(WATER_MARK_PERMISSION_ERROR);
            continue;
        }

        auto surfaceNode = mainContext.GetNodeMap().GetRenderNode<RSSurfaceRenderNode>(nodeId);
        if (!surfaceNode) {
            RemoveNodeIdForWatermarkNameMapNodeId(name, nodeId);
            RS_LOGE("RSSurfaceWatermarkHelper::TraverseAndOperateNodeList not find node"
                "nodeId:[%{public}" PRIu64 "]", nodeId);
            returnErrorCode |= static_cast<uint32_t>(WATER_MARK_NOT_SURFACE_NODE_ERROR);
            continue;
        }
         
        auto errorCode = func(name, surfaceNode);
        if (errorCode > 0) {
            returnErrorCode |= errorCode;
        } else {
            hasNodeOperationSuccess = true;
        }
    }
    return {returnErrorCode, hasNodeOperationSuccess};
}

ScreenInfo RSSurfaceWatermarkHelper::GetScreenInfo(const std::shared_ptr<RSSurfaceRenderNode>& node,
    RSContext& mainContext)
{
    ScreenInfo info;
    auto screenNodeId = node->GetScreenNodeId();
    auto screenNode = mainContext.GetNodeMap().GetRenderNode<RSScreenRenderNode>(screenNodeId);
    if (!screenNode) {
        RS_LOGE("RSSurfaceWatermarkHelper::GetScreenInfo not find node"
            "nodeId:[%{public}" PRIu64 "]", node->GetId());
        return info;
    }
    info = screenNode->GetScreenInfo();
    return info;
}

void RSSurfaceWatermarkHelper::ClearSurfaceWatermarkForNodes(pid_t pid, const std::string& name,
    const std::vector<NodeId>& nodeIdList, RSContext& mainContext, bool isSystemCalling)
{
    auto watermarkType = GetWatermarkType(name);
    if (watermarkType == INVALID_WATER_MARK) {
        return;
    }
    auto func = [&watermarkType, this](const std::string& name, std::shared_ptr<RSSurfaceRenderNode> node) {
        node->ClearWatermarkEnabled(name, watermarkType);
        RemoveNodeIdForWatermarkNameMapNodeId(name, node->GetId());
        return WATER_MARK_SUCCESS;
    };
    TraverseAndOperateNodeList(pid, name, nodeIdList, mainContext, func, isSystemCalling, watermarkType);
}

void RSSurfaceWatermarkHelper::ClearSurfaceWatermark(pid_t pid, const std::string& name,
    RSContext& mainContext, bool isSystemCalling, bool isDeathMonitor)
{
    auto iter = surfaceWatermarks_.find(name);
    auto watermarkType = GetWatermarkType(name);
    if (watermarkType == INVALID_WATER_MARK && iter == surfaceWatermarks_.end()) {
        return;
    }
    if (!CheckClearWatermarkPermission(pid, name, isSystemCalling)) {
        return;
    }
    // currently, system watermark has not been transmitted to the node. Unified incorporation in the future
    std::unordered_set<NodeId> nodeIdList = (watermarkType != INVALID_WATER_MARK) ?
        watermarkNameMapNodeId_[name].first : std::unordered_set<NodeId>{};
    auto func = [&watermarkType](const std::string& name, std::shared_ptr<RSSurfaceRenderNode> node) {
        node->ClearWatermarkEnabled(name, watermarkType);
        return WATER_MARK_SUCCESS;
    };
    std::vector<NodeId> vecNodeIdList(nodeIdList.begin(), nodeIdList.end()); // compiler adapter
    TraverseAndOperateNodeList(pid, name, vecNodeIdList, mainContext, func, isSystemCalling, watermarkType);
    registerSurfaceWatermarkCount_ = (registerSurfaceWatermarkCount_ > 0) ? --registerSurfaceWatermarkCount_ : 0;
    if (!isDeathMonitor) {
        surfaceWatermarks_.erase(name);
    }
    RS_LOGI("RSSurfaceWatermarkHelper::ClearSurfaceWatermark pid:[%{public}d], watermarkType:[%{public}d]",
        pid, static_cast<int32_t>(watermarkType));
}

void RSSurfaceWatermarkHelper::ClearSurfaceWatermark(pid_t pid, RSContext& mainContext)
{
    EraseIf(surfaceWatermarks_, [pid, this, &mainContext](const auto& pair) {
        if (pair.second.second != pid) {
            return false;
        }
        auto name = pair.first;
        ClearSurfaceWatermark(pid, name, mainContext, true, true);
        return true;
    });
}

void RSSurfaceWatermarkHelper::AddWatermarkNameMapNodeId(std::string name, NodeId id,
    SurfaceWatermarkType watermarkType)
{
    auto iter = watermarkNameMapNodeId_.find(name);
    if (iter == watermarkNameMapNodeId_.end()) {
        std::unordered_set<NodeId> setNodeId = {id};
        watermarkNameMapNodeId_[name] = {setNodeId, watermarkType};
    } else {
        iter->second.first.insert(id);
    }
}

uint32_t RSSurfaceWatermarkHelper::CheckCustomWatermarkCondition(const std::shared_ptr<Drawing::Image>& tmpImagePtr,
    RSContext& mainContext, std::shared_ptr<RSSurfaceRenderNode> node, RSSurfaceWatermarkSpecialParam& param)
{
            auto imgHeight = tmpImagePtr->GetHeight();
            auto imgWidth = tmpImagePtr->GetWidth();
            auto screenInfo = GetScreenInfo(node, mainContext);
            auto pixelMapSize = imgHeight * imgWidth;

            float nodeWidth = (node->GetRenderProperties().GetBoundsWidth() < 0 ?
                0.0 : node->GetRenderProperties().GetBoundsWidth());
            float nodeHeight = (node->GetRenderProperties().GetBoundsHeight() < 0 ?
                0.0 : node->GetRenderProperties().GetBoundsHeight());

            nodeWidth = (nodeWidth == 0 && !param.isWatermarkChange_) ? param.maxWidth_ : nodeWidth;
            nodeHeight = (nodeHeight == 0 && !param.isWatermarkChange_) ? param.maxHeight_ : nodeHeight;
            
            bool upperNodeSize = (pixelMapSize > nodeWidth * nodeHeight);

            bool upperscreenSize = (pixelMapSize > (static_cast<int32_t>(screenInfo.height) *
                static_cast<int32_t>(screenInfo.width)));
            RS_LOGI("RSSurfaceWatermarkHelper::SetSurfaceWatermark watermark size imgWidth:[%{public}d],"
                    "imgHeight:[%{public}d] nodeWidth:[%{public}d], nodeHeight:[%{public}d],"
                    "screenWidth:[%{public}d], scrrenHeight:[%{public}d], nodeId:[%{public}" PRIu64 "]",
                    imgWidth, imgHeight,
                    static_cast<int32_t>(nodeWidth),
                    static_cast<int32_t>(nodeHeight),
                    static_cast<int32_t>(screenInfo.width),
                    static_cast<int32_t>(screenInfo.height),
                    node->GetId()
            );
            if (upperNodeSize && upperscreenSize) {
                return WATER_MARK_IMG_SIZE_ERROR;
            }
            return WATER_MARK_SUCCESS;
}
}
}