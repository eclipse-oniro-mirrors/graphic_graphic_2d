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

#include "pipeline/rs_uni_hwc_prevalidate_util.h"

#include <dlfcn.h>
#include <functional>
#include <string>

#include "rs_base_render_util.h"
#include "rs_uni_render_util.h"

#include "common/rs_common_hook.h"
#include "common/rs_obj_abs_geometry.h"
#include "drawable/rs_display_render_node_drawable.h"
#include "pipeline/rs_surface_render_node.h"
#include "pipeline/rs_uifirst_manager.h"
#include "platform/common/rs_log.h"

namespace OHOS {
namespace Rosen {
namespace {
constexpr uint32_t ROTATION_360 = 360;
constexpr uint64_t USAGE_HARDWARE_CURSOR = 1ULL << 61;
constexpr uint64_t USAGE_UNI_LAYER = 1ULL << 60;
}
RSUniHwcPrevalidateUtil& RSUniHwcPrevalidateUtil::GetInstance()
{
    static RSUniHwcPrevalidateUtil instance;
    return instance;
}

RSUniHwcPrevalidateUtil::RSUniHwcPrevalidateUtil()
{
    preValidateHandle_ = dlopen("libdss_enhance.z.so", RTLD_LAZY);
    if (preValidateHandle_ == nullptr) {
        RS_LOGW("[%{public}s_%{public}d]:load library failed, reason: %{public}s", __func__, __LINE__, dlerror());
        return;
    }
    preValidateFunc_ = reinterpret_cast<PreValidateFunc>(dlsym(preValidateHandle_, "RequestLayerStrategy"));
    if (preValidateFunc_ == nullptr) {
        RS_LOGW("[%{public}s_%{public}d]:load func failed, reason: %{public}s", __func__, __LINE__, dlerror());
        dlclose(preValidateHandle_);
        preValidateHandle_ = nullptr;
        return;
    }
    RS_LOGI("[%{public}s_%{public}d]:load success", __func__, __LINE__);
    loadSuccess_ = true;
    isPrevalidateHwcNodeEnable_ = RSSystemParameters::GetPrevalidateHwcNodeEnabled();
}

RSUniHwcPrevalidateUtil::~RSUniHwcPrevalidateUtil()
{
    if (preValidateHandle_) {
        dlclose(preValidateHandle_);
        preValidateHandle_ = nullptr;
    }
}

bool RSUniHwcPrevalidateUtil::IsPrevalidateEnable(const ScreenId& screenId)
{
    if (!loadSuccess_) {
        return false;
    }
    if (!isPrevalidateHwcNodeEnable_) {
        return false;
    }
    auto screenManager = CreateOrGetScreenManager();
    if (screenManager && screenManager->GetDefaultScreenId() != screenId) {
        RS_LOGD_IF(DEBUG_PREVALIDATE, "RSUniHwcPrevalidateUtil::IsPrevalidateEnable"
            " %{public}" PRIu64 " isn't default screen", screenId);
        return false;
    }
    return true;
}

bool RSUniHwcPrevalidateUtil::PreValidate(
    ScreenId id, std::vector<RequestLayerInfo> infos, std::map<uint64_t, RequestCompositionType> &strategy)
{
    if (!preValidateFunc_) {
        RS_LOGI_IF(DEBUG_PREVALIDATE, "RSUniHwcPrevalidateUtil::PreValidate preValidateFunc is null");
        return false;
    }
    int32_t ret = preValidateFunc_(id, infos, strategy);
    return ret == 0;
}

bool RSUniHwcPrevalidateUtil::CreateSurfaceNodeLayerInfo(uint32_t zorder,
    RSSurfaceRenderNode::SharedPtr node, GraphicTransformType transform, uint32_t fps, RequestLayerInfo &info)
{
    if (!node || !node->GetRSSurfaceHandler()->GetConsumer() || !node->GetRSSurfaceHandler()->GetBuffer()) {
        return false;
    }
    info.id = node->GetId();
    auto src = node->GetSrcRect();
    info.srcRect = {src.left_, src.top_, src.width_, src.height_};
    auto dst = node->GetDstRect();
    info.dstRect = {dst.left_, dst.top_, dst.width_, dst.height_};
    info.zOrder = zorder;
    auto usage = node->GetRSSurfaceHandler()->GetBuffer()->GetUsage();
    info.usage = node->IsHardwareEnabledTopSurface() && RSSystemProperties::IsPcType() ?
        usage | USAGE_HARDWARE_CURSOR : usage;
    info.format = node->GetRSSurfaceHandler()->GetBuffer()->GetFormat();
    info.fps = fps;
    info.transform = static_cast<int>(transform);

    if (RsCommonHook::Instance().GetVideoSurfaceFlag() && IsYUVBufferFormat(node)) {
        info.perFrameParameters["SourceCropTuning"] = std::vector<int8_t> {1};
    } else {
        info.perFrameParameters["SourceCropTuning"] = std::vector<int8_t> {0};
    }

    if (CheckIfDoArsrPre(node)) {
        info.perFrameParameters["ArsrDoEnhance"] = std::vector<int8_t> {1};
        node->SetArsrTag(true);
    }
    RS_LOGD_IF(DEBUG_PREVALIDATE, "RSUniHwcPrevalidateUtil::CreateSurfaceNodeLayerInfo %{public}s,"
        " %{public}" PRIu64 ", src: %{public}s, dst: %{public}s, z: %{public}" PRIu32 ","
        " usage: %{public}" PRIu64 ", format: %{public}d, transform: %{public}d, fps: %{public}d",
        node->GetName().c_str(), node->GetId(),
        node->GetSrcRect().ToString().c_str(), node->GetDstRect().ToString().c_str(),
        zorder, info.usage, info.format, info.transform, fps);
    return true;
}

bool RSUniHwcPrevalidateUtil::IsYUVBufferFormat(RSSurfaceRenderNode::SharedPtr node) const
{
    if (node->GetRSSurfaceHandler()->GetBuffer() == nullptr) {
        return false;
    }
    auto format = node->GetRSSurfaceHandler()->GetBuffer()->GetFormat();
    if (format < GRAPHIC_PIXEL_FMT_YUV_422_I || format == GRAPHIC_PIXEL_FMT_RGBA_1010102 ||
        format > GRAPHIC_PIXEL_FMT_YCRCB_P010) {
        return false;
    }
    return true;
}

bool RSUniHwcPrevalidateUtil::CreateDisplayNodeLayerInfo(uint32_t zorder,
    RSDisplayRenderNode::SharedPtr node, const ScreenInfo &screenInfo, uint32_t fps, RequestLayerInfo &info)
{
    if (!node) {
        return false;
    }
    auto drawable = node->GetRenderDrawable();
    if (!drawable) {
        return false;
    }
    auto displayDrawable = std::static_pointer_cast<DrawableV2::RSDisplayRenderNodeDrawable>(drawable);
    auto surfaceHandler = displayDrawable->GetRSSurfaceHandlerOnDraw();
    if (!surfaceHandler->GetConsumer() || !surfaceHandler->GetBuffer()) {
        return false;
    }
    auto buffer = surfaceHandler->GetBuffer();
    info.id = node->GetId();
    info.srcRect = {0, 0, buffer->GetSurfaceBufferWidth(), buffer->GetSurfaceBufferHeight()};
    info.dstRect = {0, 0, screenInfo.GetRotatedPhyWidth(), screenInfo.GetRotatedPhyHeight()};
    info.zOrder = zorder;
    info.usage = buffer->GetUsage() | USAGE_UNI_LAYER;
    info.format = buffer->GetFormat();
    info.fps = fps;
    LayerRotate(info, surfaceHandler->GetConsumer(), screenInfo);
    RS_LOGD_IF(DEBUG_PREVALIDATE, "RSUniHwcPrevalidateUtil::CreateDisplayNodeLayerInfo %{public}" PRIu64 ","
        " src: %{public}d,%{public}d,%{public}d,%{public}d"
        " dst: %{public}d,%{public}d,%{public}d,%{public}d, z: %{public}" PRIu32 ","
        " usage: %{public}" PRIu64 ", format: %{public}d, transform: %{public}d, fps: %{public}d",
        node->GetId(), info.srcRect.x, info.srcRect.y, info.srcRect.w, info.srcRect.h,
        info.dstRect.x, info.dstRect.y, info.dstRect.w, info.dstRect.h,
        zorder, info.usage, info.format, info.transform, fps);
    return true;
}

bool RSUniHwcPrevalidateUtil::CreateUIFirstLayerInfo(
    RSSurfaceRenderNode::SharedPtr node, GraphicTransformType transform, uint32_t fps, RequestLayerInfo &info)
{
    if (!node) {
        return false;
    }
    info.id = node->GetId();
    auto src = node->GetSrcRect();
    info.srcRect = {src.left_, src.top_, src.width_, src.height_};
    auto dst = node->GetDstRect();
    info.dstRect = {dst.left_, dst.top_, dst.width_, dst.height_};
    info.zOrder = static_cast<uint32_t>(node->GetRSSurfaceHandler()->GetGlobalZOrder());
    info.format = GRAPHIC_PIXEL_FMT_RGBA_8888;
    info.usage = BUFFER_USAGE_HW_RENDER | BUFFER_USAGE_HW_TEXTURE | BUFFER_USAGE_HW_COMPOSER | BUFFER_USAGE_MEM_DMA;
    info.fps = fps;
    info.transform = static_cast<int>(transform);
    RS_LOGD_IF(DEBUG_PREVALIDATE, "RSUniHwcPrevalidateUtil::CreateUIFirstLayerInfo %{public}s, %{public}" PRIu64 ","
        " src: %{public}s, dst: %{public}s, z: %{public}" PRIu32 ","
        " usage: %{public}" PRIu64 ", format: %{public}d, transform: %{public}d, fps: %{public}d",
        node->GetName().c_str(), node->GetId(),
        node->GetSrcRect().ToString().c_str(), node->GetDstRect().ToString().c_str(),
        info.zOrder, info.usage, info.format, info.transform, fps);
    return true;
}

bool RSUniHwcPrevalidateUtil::CreateRCDLayerInfo(
    RSRcdSurfaceRenderNode::SharedPtr node, const ScreenInfo &screenInfo, uint32_t fps, RequestLayerInfo &info)
{
    if (!node || !node->GetConsumer() || !node->GetBuffer()) {
        return false;
    }
    
    info.id = node->GetId();
    auto src = node->GetSrcRect();
    info.srcRect = {src.left_, src.top_, src.width_, src.height_};
    auto dst = node->GetDstRect();
    info.dstRect.x = static_cast<uint32_t>(static_cast<float>(dst.left_) * screenInfo.GetRogWidthRatio());
    info.dstRect.y = static_cast<uint32_t>(static_cast<float>(dst.top_) * screenInfo.GetRogHeightRatio());
    info.dstRect.w = static_cast<uint32_t>(static_cast<float>(dst.width_) * screenInfo.GetRogWidthRatio());
    info.dstRect.h = static_cast<uint32_t>(static_cast<float>(dst.height_) * screenInfo.GetRogHeightRatio());
    info.zOrder = static_cast<uint32_t>(node->GetGlobalZOrder());
    info.usage = node->GetBuffer()->GetUsage();
    info.format = node->GetBuffer()->GetFormat();
    info.fps = fps;
    CopyCldInfo(node->GetCldInfo(), info);
    LayerRotate(info, node->GetConsumer(), screenInfo);
    RS_LOGD_IF(DEBUG_PREVALIDATE, "RSUniHwcPrevalidateUtil::CreateRCDLayerInfo %{public}" PRIu64 ","
        " src: %{public}d,%{public}d,%{public}d,%{public}d"
        " dst: %{public}d,%{public}d,%{public}d,%{public}d, z: %{public}" PRIu32 ","
        " usage: %{public}" PRIu64 ", format: %{public}d, transform: %{public}d, fps: %{public}d",
        node->GetId(),
        info.srcRect.x, info.srcRect.y, info.srcRect.w, info.srcRect.h,
        info.dstRect.x, info.dstRect.y, info.dstRect.w, info.dstRect.h,
        info.zOrder, info.usage, info.format, info.transform, fps);
    return true;
}

void RSUniHwcPrevalidateUtil::CollectSurfaceNodeLayerInfo(
    std::vector<RequestLayerInfo>& prevalidLayers, std::vector<RSBaseRenderNode::SharedPtr>& surfaceNodes,
    uint32_t curFps, uint32_t &zOrder, const ScreenInfo& screenInfo)
{
    std::shared_ptr<RSSurfaceRenderNode> pointerWindow = nullptr;
    for (auto it = surfaceNodes.rbegin(); it != surfaceNodes.rend(); it++) {
        auto surfaceNode = RSBaseRenderNode::ReinterpretCast<RSSurfaceRenderNode>(*it);
        if (!surfaceNode) {
            continue;
        }
        const auto& hwcNodes = surfaceNode->GetChildHardwareEnabledNodes();
        if (hwcNodes.empty()) {
            continue;
        }
        for (auto& hwcNode : hwcNodes) {
            auto hwcNodePtr = hwcNode.lock();
            if (!RSUniHwcPrevalidateUtil::CheckHwcNodeAndGetPointerWindow(hwcNodePtr, pointerWindow)) {
                continue;
            }
            RSUniHwcPrevalidateUtil::EmplaceSurfaceNodeLayer(prevalidLayers, hwcNodePtr, curFps, zOrder, screenInfo);
        }
    }
    if (pointerWindow && pointerWindow->ShouldPaint()) {
        RSUniHwcPrevalidateUtil::EmplaceSurfaceNodeLayer(prevalidLayers, pointerWindow, curFps, zOrder, screenInfo);
    }
}

void RSUniHwcPrevalidateUtil::EmplaceSurfaceNodeLayer(
    std::vector<RequestLayerInfo>& prevalidLayers, RSSurfaceRenderNode::SharedPtr node,
    uint32_t curFps, uint32_t& zOrder, const ScreenInfo& screenInfo)
{
    auto transform = RSUniRenderUtil::GetLayerTransform(*node, screenInfo);
    RequestLayerInfo surfaceLayer;
    if (RSUniHwcPrevalidateUtil::GetInstance().CreateSurfaceNodeLayerInfo(
        zOrder++, node, transform, curFps, surfaceLayer)) {
        prevalidLayers.emplace_back(surfaceLayer);
    }
}

bool RSUniHwcPrevalidateUtil::CheckHwcNodeAndGetPointerWindow(
    const RSSurfaceRenderNode::SharedPtr& node, RSSurfaceRenderNode::SharedPtr& pointerWindow)
{
    if (!node || !node->IsOnTheTree()) {
        return false;
    }
    if (node->IsHardwareEnabledTopSurface()) {
        pointerWindow = node;
        return false;
    }
    if (node->IsHardwareForcedDisabled() || node->GetAncoForceDoDirect()) {
        return false;
    }
    return true;
}

void RSUniHwcPrevalidateUtil::CollectUIFirstLayerInfo(std::vector<RequestLayerInfo>& uiFirstLayers,
    uint32_t curFps, float zOrder, const ScreenInfo& screenInfo)
{
    auto pendingNodes = RSUifirstManager::Instance().GetPendingPostNodes();
    for (auto iter : pendingNodes) {
        if (!iter.second || iter.second->IsHardwareForcedDisabled() ||
            !RSUifirstManager::Instance().GetUseDmaBuffer(iter.second->GetName())) {
            continue;
        }
        iter.second->GetMutableRSSurfaceHandler()->SetGlobalZOrder(zOrder++);
        auto transform = RSUniRenderUtil::GetLayerTransform(*iter.second, screenInfo);
        RequestLayerInfo uiFirstLayer;
        if (RSUniHwcPrevalidateUtil::GetInstance().CreateUIFirstLayerInfo(
            iter.second, transform, curFps, uiFirstLayer)) {
            uiFirstLayers.emplace_back(uiFirstLayer);
        }
    }
}

void RSUniHwcPrevalidateUtil::LayerRotate(
    RequestLayerInfo& info, const sptr<IConsumerSurface>& surface, const ScreenInfo &screenInfo)
{
    if (!surface) {
        return;
    }
    const auto screenWidth = static_cast<int32_t>(screenInfo.width);
    const auto screenHeight = static_cast<int32_t>(screenInfo.height);
    const auto screenRotation = screenInfo.rotation;
    const auto rect = info.dstRect;
    switch (screenRotation) {
        case ScreenRotation::ROTATION_90: {
            info.dstRect = {rect.y, screenHeight - rect.x - rect.w, rect.h, rect.w};
            break;
        }
        case ScreenRotation::ROTATION_180: {
            info.dstRect = {screenWidth - rect.x - rect.w, screenHeight - rect.y - rect.h, rect.w, rect.h};
            break;
        }
        case ScreenRotation::ROTATION_270: {
            info.dstRect = {screenWidth - rect.y - rect.h, rect.x, rect.h, rect.w};
            break;
        }
        default: {
            break;
        }
    }
    int totalRotation = (RSBaseRenderUtil::RotateEnumToInt(screenRotation) + RSBaseRenderUtil::RotateEnumToInt(
        RSBaseRenderUtil::GetRotateTransform(surface->GetTransform()))) % ROTATION_360;
    GraphicTransformType rotateEnum = RSBaseRenderUtil::RotateEnumToInt(totalRotation,
        RSBaseRenderUtil::GetFlipTransform(surface->GetTransform()));
    info.transform = rotateEnum;
}

void RSUniHwcPrevalidateUtil::CopyCldInfo(CldInfo src, RequestLayerInfo& info)
{
    info.cldInfo = new CldInfo();
    info.cldInfo->cldDataOffset = src.cldDataOffset;
    info.cldInfo->cldSize = src.cldSize;
    info.cldInfo->cldWidth = src.cldWidth;
    info.cldInfo->cldHeight = src.cldHeight;
    info.cldInfo->cldStride = src.cldStride;
    info.cldInfo->exWidth = src.exWidth;
    info.cldInfo->exHeight = src.exHeight;
    info.cldInfo->baseColor = src.baseColor;
}

bool RSUniHwcPrevalidateUtil::CheckIfDoArsrPre(const RSSurfaceRenderNode::SharedPtr node)
{
    if (node->GetRSSurfaceHandler()->GetBuffer() == nullptr) {
        return false;
    }
    static const std::unordered_set<std::string> videoLayers {
        "xcomponentIdSurface",
        "componentIdSurface",
    };
    if (IsYUVBufferFormat(node) || (videoLayers.count(node->GetName()) > 0)) {
        return true;
    }
    return false;
}
} //Rosen
} //OHOS