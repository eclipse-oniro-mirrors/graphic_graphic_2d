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

#include "hdi_output.h"

namespace OHOS {
namespace Rosen {

std::shared_ptr<HdiOutput> HdiOutput::CreateHdiOutput(uint32_t screenId)
{
    return std::make_shared<HdiOutput>(screenId);
}

HdiOutput::HdiOutput(uint32_t screenId) : screenId_(screenId)
{
}

HdiOutput::~HdiOutput()
{
}

RosenError HdiOutput::Init()
{
    if (fbSurface_ != nullptr) {
        return ROSEN_ERROR_OK;
    }

    fbSurface_ = HdiFramebufferSurface::CreateFramebufferSurface();
    if (fbSurface_ == nullptr) {
        HLOGE("Create framebuffer surface failed");
        return ROSEN_ERROR_NOT_INIT;
    }

    return ROSEN_ERROR_OK;
}

void HdiOutput::SetLayerInfo(const std::vector<LayerInfoPtr> &layerInfos)
{
    for (auto &layerInfo : layerInfos) {
        uint64_t surfaceId = layerInfo->GetSurface()->GetUniqueId();
        auto iter = surfaceIdMap_.find(surfaceId);
        if (iter != surfaceIdMap_.end()) {
            const LayerPtr &layer = iter->second;
            const LayerInfoPtr &info = layer->GetLayerInfo();
            if (info->GetLayerSize().w == layerInfo->GetLayerSize().w &&
                info->GetLayerSize().h == layerInfo->GetLayerSize().h)
            {
                layer->UpdateLayerInfo(layerInfo);
                continue;
            }
        }

        int32_t ret = CreateLayer(surfaceId, layerInfo);
        if (ret != DISPLAY_SUCCESS) {
            return;
        }
    }

    ClosePrevLayers();
    ResetLayerStatus();
}

void HdiOutput::ClosePrevLayers()
{
    auto surfaceIter = surfaceIdMap_.begin();
    while (surfaceIter != surfaceIdMap_.end()) {
        LayerPtr &layer = surfaceIter->second;
        if (!layer->GetLayerStatus()) {
            CloseLayer(layer);
            surfaceIdMap_.erase(surfaceIter++);
        } else {
            ++surfaceIter;
        }
    }

    auto layerIter = layerIdMap_.begin();
    while (layerIter != layerIdMap_.end()) {
        LayerPtr &layer = layerIter->second;
        if (!layer->GetLayerStatus()) {
            layerIdMap_.erase(layerIter++);
        } else {
            ++layerIter;
        }
    }
}

void HdiOutput::ResetLayerStatus()
{
    for (auto iter = surfaceIdMap_.begin(); iter != surfaceIdMap_.end(); ++iter) {
        iter->second->SetLayerStatus(false);
    }
}

int32_t HdiOutput::CreateLayer(uint64_t surfaceId, const LayerInfoPtr &layerInfo)
{
    LayerInfo hdiLayerInfo = {
        .width = layerInfo->GetLayerSize().w,
        .height = layerInfo->GetLayerSize().h,
        .type = LAYER_TYPE_GRAPHIC,
        .pixFormat = PIXEL_FMT_RGBA_8888,
    };

    uint32_t layerId = 0;
    int32_t ret = HdiDevice::GetInstance()->CreateLayer(screenId_, hdiLayerInfo, layerId);
    if (ret != DISPLAY_SUCCESS) {
        HLOGE("Create hwc layer failed, ret is %{public}d", ret);
        return ret;
    }

    HLOGD("Create hwc layer succeed, layerId is %{public}u", layerId);

    LayerPtr layer = HdiLayer::CreateHdiLayer(layerId);
    layer->Init();
    layer->UpdateLayerInfo(layerInfo);

    layerIdMap_[layerId] = layer;
    surfaceIdMap_[surfaceId] = layer;

    return DISPLAY_SUCCESS;
}

void HdiOutput::CloseLayer(std::shared_ptr<HdiLayer> &layer)
{
    uint32_t layerId = layer->GetLayerId();
    if (layerId == INT_MAX) {
        HLOGI("this layer has not been created");
        return;
    }

    int32_t ret = HdiDevice::GetInstance()->CloseLayer(screenId_, layerId);
    if (ret != DISPLAY_SUCCESS) {
        HLOGE("Close hwc layer[%{public}u] failed, ret is %{public}d", layerId, ret);
    }
}

void HdiOutput::SetOutputDamage(uint32_t num, const IRect &outputDamage)
{
    outputDamageNum_ = num;
    outputDamage_ = outputDamage;
}

/* const */ IRect& HdiOutput::GetOutputDamage()
{
    return outputDamage_;
}

uint32_t HdiOutput::GetOutputDamageNum() const
{
    return outputDamageNum_;
}

const std::unordered_map<uint32_t, std::shared_ptr<HdiLayer>>& HdiOutput::GetLayers()
{
    return layerIdMap_;
}

uint32_t HdiOutput::GetScreenId() const
{
    return screenId_;
}

sptr<Surface> HdiOutput::GetProducerSurface()
{
    if (!CheckFbSurface()) {
        return nullptr;
    }

    return fbSurface_->GetProducerSurface();
}

sptr<SurfaceBuffer> HdiOutput::GetFramebuffer()
{
    if (!CheckFbSurface()) {
        return nullptr;
    }

    return fbSurface_->GetFramebuffer();
}

sptr<SyncFence> HdiOutput::GetFramebufferFence()
{
    if (!CheckFbSurface()) {
        return SyncFence::INVALID_FENCE;
    }

    return fbSurface_->GetFramebufferFence();
}

int32_t HdiOutput::ReleaseFramebuffer(const sptr<SyncFence> &releaseFence)
{
    if (!CheckFbSurface()) {
        return -1;
    }

    return fbSurface_->ReleaseFramebuffer(releaseFence);
}

void HdiOutput::FramebufferSemWait()
{
    if (!CheckFbSurface()) {
        return;
    }

    fbSurface_->FramebufferSemWait();
}

bool HdiOutput::CheckFbSurface()
{
    if (fbSurface_ == nullptr) {
        HLOGE("fbSurface is nullptr");
        return false;
    }

    return true;
}

} // namespace Rosen
} // namespace OHOS
