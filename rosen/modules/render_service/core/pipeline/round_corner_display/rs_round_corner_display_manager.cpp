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

#include "rs_round_corner_display_manager.h"
#include "platform/common/rs_system_properties.h"
#include "common/rs_optional_trace.h"
#include "common/rs_singleton.h"
#include "rs_trace.h"

namespace OHOS {
namespace Rosen {
RoundCornerDisplayManager::RoundCornerDisplayManager()
{
    RS_LOGD_IF(DEBUG_PIPELINE, "[%{public}s] Created \n", __func__);
}

RoundCornerDisplayManager::~RoundCornerDisplayManager()
{
    RS_LOGD_IF(DEBUG_PIPELINE, "[%{public}s] Destroy \n", __func__);
}

bool RoundCornerDisplayManager::CheckExist(NodeId id) const
{
    auto it = rcdMap_.find(id);
    if (rcdMap_.end() == it) {
        return false;
    }
    return true;
}

void RoundCornerDisplayManager::AddLayer(const std::string& name, NodeId id,
    RoundCornerDisplayManager::RCDLayerType type)
{
    std::lock_guard<std::mutex> lock(rcdMapMut_);
    rcdlayerMap_[name] = {id, type};
    RS_LOGI_IF(DEBUG_PIPELINE, "[%{public}s] rendertargetNodeId:%{public}" PRIu64 " with rcd layer name %{public}s \n",
        __func__, id, name.c_str());
}

std::pair<NodeId, RoundCornerDisplayManager::RCDLayerType> RoundCornerDisplayManager::GetNodeId(
    const std::string& layerName) const
{
    auto it = rcdlayerMap_.find(layerName);
    if (rcdlayerMap_.end() == it) {
        return {0, RoundCornerDisplayManager::RCDLayerType::INVALID};
    }
    return rcdlayerMap_.at(layerName);
}

void RoundCornerDisplayManager::AddRoundCornerDisplay(NodeId id)
{
    std::lock_guard<std::mutex> lock(rcdMapMut_);
    if (CheckExist(id)) {
        RS_LOGD_IF(DEBUG_PIPELINE,
            "[%{public}s] nodeId:%{public}" PRIu64 " rcd module already exist, size:%{public}zd \n",
            __func__, id, rcdMap_.size());
        return;
    }
    auto rcd = std::make_shared<RoundCornerDisplay>(id);
    rcdMap_[id] = rcd;
    if (rcdMap_[id] == nullptr) {
        RS_LOGE_IF(DEBUG_PIPELINE, "[%{public}s] nodeId:%{public}" PRIu64 " rcd module create failed \n", __func__, id);
        return;
    }
    rcdMap_[id]->InitOnce();
    RS_LOGI_IF(DEBUG_PIPELINE, "[%{public}s] size:%{public}zd rcd module after added for screen \n", __func__,
        rcdMap_.size());
}

void RoundCornerDisplayManager::RemoveRoundCornerDisplay(NodeId id)
{
    std::lock_guard<std::mutex> lock(rcdMapMut_);
    if (!CheckExist(id)) {
        RS_LOGE_IF(DEBUG_PIPELINE, "[%{public}s] nodeId:%{public}" PRIu64 " rcd module not exist \n", __func__, id);
        return;
    }
    rcdMap_.erase(id);
    RS_LOGI_IF(DEBUG_PIPELINE, "[%{public}s] nodeId:%{public}" PRIu64 " rcd module removed for screen \n", __func__,
        id);
}

void RoundCornerDisplayManager::RemoveRCDLayerInfo(NodeId id)
{
    std::lock_guard<std::mutex> lock(rcdMapMut_);
    const auto& it = std::find_if(rcdlayerMap_.begin(), rcdlayerMap_.end(),
        [id](const std::pair<std::string, std::pair<NodeId, RCDLayerType>>& p) {
            return p.second.first == id;
        });
    if (rcdlayerMap_.end() == it) {
        RS_LOGE_IF(DEBUG_PIPELINE, "[%{public}s] nodeId:%{public}" PRIu64 " rcd layer not exist \n", __func__, id);
        return;
    }
    rcdlayerMap_.erase(it->first);
    RS_LOGI_IF(DEBUG_PIPELINE, "[%{public}s] nodeId:%{public}" PRIu64 " rcd layer removed for screen \n", __func__,
        id);
}

void RoundCornerDisplayManager::UpdateDisplayParameter(NodeId id, uint32_t width, uint32_t height)
{
    if (!CheckExist(id)) {
        RS_LOGE_IF(DEBUG_PIPELINE, "[%{public}s] nodeId:%{public}" PRIu64 " rcd module not exist \n", __func__, id);
        return;
    }
    if (rcdMap_[id] == nullptr) {
        RS_LOGE_IF(DEBUG_PIPELINE, "[%{public}s] nodeId:%{public}" PRIu64 " rcd module is null \n", __func__, id);
        RemoveRoundCornerDisplay(id);
        return;
    }
    rcdMap_[id]->UpdateDisplayParameter(width, height);
}

void RoundCornerDisplayManager::UpdateNotchStatus(NodeId id, int status)
{
    if (!CheckExist(id)) {
        RS_LOGE_IF(DEBUG_PIPELINE, "[%{public}s] nodeId:%{public}" PRIu64 " rcd module not exist \n", __func__, id);
        return;
    }
    if (rcdMap_[id] == nullptr) {
        RS_LOGE_IF(DEBUG_PIPELINE, "[%{public}s] nodeId:%{public}" PRIu64 " rcd module is null \n", __func__, id);
        RemoveRoundCornerDisplay(id);
        return;
    }
    rcdMap_[id]->UpdateNotchStatus(status);
}

void RoundCornerDisplayManager::UpdateOrientationStatus(NodeId id, ScreenRotation orientation)
{
    if (!CheckExist(id)) {
        RS_LOGE_IF(DEBUG_PIPELINE, "[%{public}s] nodeId:%{public}" PRIu64 " rcd module not exist \n", __func__, id);
        return;
    }
    if (rcdMap_[id] == nullptr) {
        RS_LOGE_IF(DEBUG_PIPELINE, "[%{public}s] nodeId:%{public}" PRIu64 " rcd module is null \n", __func__, id);
        RemoveRoundCornerDisplay(id);
        return;
    }
    rcdMap_[id]->UpdateOrientationStatus(orientation);
}

void RoundCornerDisplayManager::DrawRoundCorner(const RoundCornerDisplayManager::RCDLayerInfoVec& layerInfos,
    RSPaintFilterCanvas* canvas)
{
    for (const auto& layerInfo : layerInfos) {
        if (layerInfo.second == RoundCornerDisplayManager::RCDLayerType::TOP) {
            DrawTopRoundCorner(layerInfo.first, canvas);
        }
        if (layerInfo.second == RoundCornerDisplayManager::RCDLayerType::BOTTOM) {
            DrawBottomRoundCorner(layerInfo.first, canvas);
        }
    }
}

void RoundCornerDisplayManager::DrawTopRoundCorner(NodeId id, RSPaintFilterCanvas* canvas)
{
    if (!CheckExist(id)) {
        RS_LOGE_IF(DEBUG_PIPELINE, "[%{public}s] nodeId:%{public}" PRIu64 " rcd module not exist \n", __func__, id);
        return;
    }
    if (rcdMap_[id] == nullptr) {
        RS_LOGE_IF(DEBUG_PIPELINE, "[%{public}s] nodeId:%{public}" PRIu64 " rcd module is null \n", __func__, id);
        RemoveRoundCornerDisplay(id);
        return;
    }
    rcdMap_[id]->DrawTopRoundCorner(canvas);
}

void RoundCornerDisplayManager::DrawBottomRoundCorner(NodeId id, RSPaintFilterCanvas* canvas)
{
    if (!CheckExist(id)) {
        RS_LOGE_IF(DEBUG_PIPELINE, "[%{public}s] nodeId:%{public}" PRIu64 " rcd module not exist \n", __func__, id);
        return;
    }
    if (rcdMap_[id] == nullptr) {
        RS_LOGE_IF(DEBUG_PIPELINE, "[%{public}s] nodeId:%{public}" PRIu64 " rcd module is null \n", __func__, id);
        RemoveRoundCornerDisplay(id);
        return;
    }
    rcdMap_[id]->DrawBottomRoundCorner(canvas);
}

void RoundCornerDisplayManager::RunHardwareTask(NodeId id, const std::function<void()>& task)
{
    if (!CheckExist(id)) {
        RS_LOGE_IF(DEBUG_PIPELINE, "[%{public}s] nodeId:%{public}" PRIu64 " rcd module not exist \n", __func__, id);
        return;
    }
    if (rcdMap_[id] == nullptr) {
        RS_LOGE_IF(DEBUG_PIPELINE, "[%{public}s] nodeId:%{public}" PRIu64 " rcd module is null \n", __func__, id);
        RemoveRoundCornerDisplay(id);
        return;
    }
    rcdMap_[id]->RunHardwareTask(task);
}

rs_rcd::RoundCornerHardware RoundCornerDisplayManager::GetHardwareInfo(NodeId id) const
{
    rs_rcd::RoundCornerHardware rcdhardinfo{};
    if (!CheckExist(id)) {
        RS_LOGE_IF(DEBUG_PIPELINE, "[%{public}s] nodeId:%{public}" PRIu64 " rcd module not exist \n", __func__, id);
        return rcdhardinfo;
    }
    if (rcdMap_.at(id) == nullptr) {
        RS_LOGE_IF(DEBUG_PIPELINE, "[%{public}s] nodeId:%{public}" PRIu64 " rcd module is null \n", __func__, id);
        return rcdhardinfo;
    }
    return rcdMap_.at(id)->GetHardwareInfo();
}

bool RoundCornerDisplayManager::GetRcdEnable() const
{
    return RSSystemProperties::GetRSScreenRoundCornerEnable();
}

bool RoundCornerDisplayManager::IsNotchNeedUpdate(NodeId id, bool notchStatus)
{
    if (!CheckExist(id)) {
        RS_LOGE_IF(DEBUG_PIPELINE, "[%{public}s] nodeId:%{public}" PRIu64 " rcd module not exist \n", __func__, id);
        return false;
    }
    if (rcdMap_[id] == nullptr) {
        RS_LOGE_IF(DEBUG_PIPELINE, "[%{public}s] nodeId:%{public}" PRIu64 " rcd module is null \n", __func__, id);
        RemoveRoundCornerDisplay(id);
        return false;
    }
    return rcdMap_[id]->IsNotchNeedUpdate(notchStatus);
}
} // namespace Rosen
} // namespace OHOS