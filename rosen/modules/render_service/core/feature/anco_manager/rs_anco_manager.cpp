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

#include "rs_anco_manager.h"

#include <parameters.h>
#include "param/sys_param.h"
#include "params/rs_surface_render_params.h"
#include "platform/common/rs_system_properties.h"

namespace OHOS::Rosen {
RSAncoManager* RSAncoManager::Instance()
{
    static RSAncoManager instance;
    return &instance;
}

static bool AncoDisableHebcProperty()
{
    // Dynamically disable unified rendering layer hebc if persist.sys.graphic.anco.disableHebc equal 1
    static bool result =
        std::atoi((system::GetParameter("persist.sys.graphic.anco.disableHebc", "0")).c_str()) != 0;
    return result;
}

AncoHebcStatus RSAncoManager::GetAncoHebcStatus() const
{
    if (!AncoDisableHebcProperty()) {
        return AncoHebcStatus::INITIAL;
    }
    return static_cast<AncoHebcStatus>(ancoHebcStatus_.load());
}

void RSAncoManager::SetAncoHebcStatus(AncoHebcStatus hebcStatus)
{
    ancoHebcStatus_.store(static_cast<int32_t>(hebcStatus));
}

bool RSAncoManager::AncoOptimizeCheck(bool isHebc, int nodesCnt, int sfvNodesCnt)
{
    constexpr int minOptimizeAncoNums = 3;
    constexpr int minOptimizeAncoSfvNums = 2;
    bool numsMatch = nodesCnt == minOptimizeAncoNums && sfvNodesCnt == minOptimizeAncoSfvNums;
    if (numsMatch && isHebc) {
        RS_LOGI("doDirect anco disable hebc");
        SetAncoHebcStatus(AncoHebcStatus::NOT_USE_HEBC);
        return true;
    }
    if (!numsMatch && !isHebc) {
        RS_LOGI("doDirect anco enable hebc");
        SetAncoHebcStatus(AncoHebcStatus::USE_HEBC);
        return true;
    }
    return false;
}

bool RSAncoManager::IsAncoOptimize(ScreenRotation rotation)
{
    if (!AncoDisableHebcProperty() || !RSSurfaceRenderNode::GetOriAncoForceDoDirect() ||
        rotation != ScreenRotation::ROTATION_0) {
        return false;
    }
    return true;
}

bool RSAncoManager::AncoOptimizeScreenNode(std::shared_ptr<RSSurfaceHandler>& surfaceHandler,
    std::vector<std::shared_ptr<RSSurfaceRenderNode>>& hardwareEnabledNodes,
    ScreenRotation rotation, uint32_t width, uint32_t height)
{
    SetAncoHebcStatus(AncoHebcStatus::INITIAL);
    if (!IsAncoOptimize(rotation)) {
        return false;
    }

    if (surfaceHandler == nullptr || surfaceHandler->GetBuffer() == nullptr) {
        return false;
    }
    bool isHebc = true;
    if ((surfaceHandler->GetBuffer()->GetUsage() & BUFFER_USAGE_CPU_READ) ||
        (surfaceHandler->GetBuffer()->GetUsage() & BUFFER_USAGE_CPU_WRITE)) {
        isHebc = false;
    }

    // process ScreenNode rect
    uint32_t minArea = width * height / 2;
    if (minArea == 0) {
        return false;
    }

    int nodesCnt = 0;
    int sfvNodesCnt = 0;
    for (auto& surfaceNode : hardwareEnabledNodes) {
        if ((surfaceNode->GetAncoFlags() & static_cast<uint32_t>(AncoFlags::IS_ANCO_NODE)) == 0) {
            continue;
        }
        auto alpha = surfaceNode->GetGlobalAlpha();
        if (ROSEN_EQ(alpha, 0.0f) || !surfaceNode->GetRSSurfaceHandler() ||
            !surfaceNode->GetRSSurfaceHandler()->GetBuffer()) {
            continue;
        }
#ifdef RS_ENABLE_GPU
        auto params = static_cast<RSSurfaceRenderParams*>(surfaceNode->GetStagingRenderParams().get());
        if (params == nullptr) {
            continue;
        }
        auto& layerInfo = params->GetLayerInfo().dstRect;
        if (layerInfo.w <= 0 || layerInfo.h <= 0) {
            continue;
        }
        if (static_cast<uint32_t>(layerInfo.w * layerInfo.h) >= minArea) {
            nodesCnt++;
            if ((surfaceNode->GetAncoFlags() & static_cast<uint32_t>(AncoFlags::ANCO_SFV_NODE)) ==
                static_cast<uint32_t>(AncoFlags::ANCO_SFV_NODE)) {
                sfvNodesCnt++;
            }
        }
#endif
    }

    return AncoOptimizeCheck(isHebc, nodesCnt, sfvNodesCnt);
}

void RSAncoManager::UpdateCropRectForAnco(const uint32_t ancoFlags, const Rect& cropRect,
    const sptr<SurfaceBuffer>& buffer, Drawing::Rect& outSrcRect)
{
    // The buffer is already determined to be non-empty before the call
    GraphicIRect srcCrop{cropRect.x, cropRect.y, cropRect.w, cropRect.h};
    UpdateCropRectForAnco(ancoFlags, srcCrop, buffer, outSrcRect);
}

void RSAncoManager::UpdateCropRectForAnco(const uint32_t ancoFlags, const GraphicIRect& cropRect,
    const sptr<SurfaceBuffer>& buffer, Drawing::Rect& outSrcRect)
{
    // The buffer is already determined to be non-empty before the call
    if (IsAncoSfv(ancoFlags) && ValidCropRect(cropRect)) {
        ShrinkAmountIfNeed(buffer, cropRect, outSrcRect);
    }
}

void RSAncoManager::UpdateLayerSrcRectForAnco(const uint32_t ancoFlags, const GraphicIRect& cropRect,
    const sptr<SurfaceBuffer>& buffer, GraphicIRect& outSrcRect)
{
    // The buffer is already determined to be non-empty before the call
    if (IsAncoSfv(ancoFlags) && ValidCropRect(cropRect)) {
        outSrcRect = {0, 0, buffer->GetSurfaceBufferWidth(), buffer->GetSurfaceBufferHeight()};
        int32_t left = std::max(outSrcRect.x, cropRect.x);
        int32_t top = std::max(outSrcRect.y, cropRect.y);
        int32_t right = std::min(outSrcRect.x + outSrcRect.w, cropRect.x + cropRect.w);
        int32_t bottom = std::min(outSrcRect.y + outSrcRect.h, cropRect.y + cropRect.h);
        int32_t width = right - left;
        int32_t height = bottom - top;
        if (width <= 0 || height <= 0) {
            return;
        }
        outSrcRect = { left, top, width, height };
    }
}

bool RSAncoManager::IsAncoSfv(const uint32_t ancoFlags)
{
    return (ancoFlags & static_cast<uint32_t>(AncoFlags::ANCO_SFV_NODE)) ==
           static_cast<uint32_t>(AncoFlags::ANCO_SFV_NODE);
}

void RSAncoManager::ShrinkAmountIfNeed(const sptr<SurfaceBuffer>& buffer,
    const GraphicIRect& cropRect, Drawing::Rect& outSrcRect)
{
    // The buffer is already determined to be non-empty before the call
    // cropRect has also been verified
    float shrinkAmount = 0.0f;
    constexpr float GENERALLY_SHRINK_AMOUNT = 0.5f;
    constexpr float WORST_SHRINK_AMOUNT = 1.0f;
    constexpr float DB = 2.0f;
    switch (buffer->GetFormat()) {
        case GRAPHIC_PIXEL_FMT_RGBA_8888:
        case GRAPHIC_PIXEL_FMT_RGBX_8888:
        case GRAPHIC_PIXEL_FMT_RGBA16_FLOAT:
        case GRAPHIC_PIXEL_FMT_RGBA_1010102:
        case GRAPHIC_PIXEL_FMT_RGB_888:
        case GRAPHIC_PIXEL_FMT_RGB_565:
        case GRAPHIC_PIXEL_FMT_BGRA_8888:
            shrinkAmount = GENERALLY_SHRINK_AMOUNT;
            break;
        default:
            shrinkAmount = WORST_SHRINK_AMOUNT;
            break;
    }
    int32_t bufferWidth = buffer->GetSurfaceBufferWidth();
    int32_t bufferHeight = buffer->GetSurfaceBufferHeight();
    outSrcRect = Drawing::Rect(0, 0, bufferWidth, bufferHeight);
    if (bufferWidth > cropRect.w) {
        if (static_cast<float>(cropRect.w) - DB * shrinkAmount > 0) {
            outSrcRect.left_ = static_cast<float>(cropRect.x) + shrinkAmount;
            outSrcRect.right_ = outSrcRect.left_ + static_cast<float>(cropRect.w) - DB * shrinkAmount;
        } else {
            outSrcRect.left_ = static_cast<float>(cropRect.x);
            outSrcRect.right_ = outSrcRect.left_ + static_cast<float>(cropRect.w);
        }
    }
    if (bufferHeight > cropRect.h) {
        if (static_cast<float>(cropRect.h) - DB * shrinkAmount > 0) {
            outSrcRect.top_ = static_cast<float>(cropRect.y) + shrinkAmount;
            outSrcRect.bottom_ = outSrcRect.top_ + static_cast<float>(cropRect.h) - DB * shrinkAmount;
        } else {
            outSrcRect.top_ = static_cast<float>(cropRect.y);
            outSrcRect.bottom_ = outSrcRect.top_ + static_cast<float>(cropRect.h);
        }
    }
}

bool RSAncoManager::ValidCropRect(const GraphicIRect& cropRect)
{
    if (cropRect.w > 0 && cropRect.h > 0 && cropRect.x >= 0 && cropRect.y >= 0) {
        return true;
    }
    return false;
}
} // namespace OHOS::Rosen
