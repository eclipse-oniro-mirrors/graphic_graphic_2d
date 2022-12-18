/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "rs_uni_render_composer_adapter.h"

#include "common/rs_common_def.h"
#include "common/rs_obj_abs_geometry.h"
#include "platform/common/rs_log.h"
#include "rs_divided_render_util.h"
#include "rs_trace.h"
#include "string_utils.h"

namespace OHOS {
namespace Rosen {
using namespace std;
bool RSUniRenderComposerAdapter::Init(const ScreenInfo& screenInfo, int32_t offsetX, int32_t offsetY,
    float mirrorAdaptiveCoefficient)
{
    hdiBackend_ = HdiBackend::GetInstance();
    if (hdiBackend_ == nullptr) {
        RS_LOGE("RSUniRenderComposerAdapter::Init: hdiBackend is nullptr");
        return false;
    }
    auto screenManager = CreateOrGetScreenManager();
    if (screenManager == nullptr) {
        RS_LOGE("RSUniRenderComposerAdapter::Init: ScreenManager is nullptr");
        return false;
    }
    output_ = screenManager->GetOutput(ToScreenPhysicalId(screenInfo.id));
    if (output_ == nullptr) {
        RS_LOGE("RSUniRenderComposerAdapter::Init: output_ is nullptr");
        return false;
    }

    offsetX_ = offsetX;
    offsetY_ = offsetY;
    mirrorAdaptiveCoefficient_ = mirrorAdaptiveCoefficient;
    screenInfo_ = screenInfo;

    GraphicIRect damageRect {0, 0, static_cast<int32_t>(screenInfo_.width), static_cast<int32_t>(screenInfo_.height)};
    output_->SetOutputDamage(1, damageRect);
    bool directClientCompEnableStatus = RSSystemProperties::GetDirectClientCompEnableStatus();
    output_->SetDirectClientCompEnableStatus(directClientCompEnableStatus);

#if (defined RS_ENABLE_GL) && (defined RS_ENABLE_EGLIMAGE)
    // enable direct GPU composition.
    output_->SetLayerCompCapacity(LAYER_COMPOSITION_CAPACITY);
#else // (defined RS_ENABLE_GL) && (defined RS_ENABLE_EGLIMAGE)
    output_->SetLayerCompCapacity(LAYER_COMPOSITION_CAPACITY_INVALID);
#endif // (defined RS_ENABLE_GL) && (defined RS_ENABLE_EGLIMAGE)
    return true;
}

void RSUniRenderComposerAdapter::CommitLayers(const std::vector<LayerInfoPtr>& layers)
{
    if (hdiBackend_ == nullptr) {
        RS_LOGE("RSUniRenderComposerAdapter::CommitLayers: backend is nullptr");
        return;
    }

    if (output_ == nullptr) {
        RS_LOGE("RSUniRenderComposerAdapter::CommitLayers: output is nullptr");
        return;
    }
    RSHardwareThread::Instance().CommitAndReleaseLayers(output_, layers);
}

// private func, for RSDisplayRenderNode
ComposeInfo RSUniRenderComposerAdapter::BuildComposeInfo(RSDisplayRenderNode& node) const
{
    const auto& buffer = node.GetBuffer(); // we guarantee the buffer is valid.
    ComposeInfo info {};
    info.srcRect = GraphicIRect {0, 0, buffer->GetSurfaceBufferWidth(), buffer->GetSurfaceBufferHeight()};
    info.dstRect = GraphicIRect {
        0,
        0,
        static_cast<int32_t>(static_cast<float>(screenInfo_.GetRotatedWidth()) * mirrorAdaptiveCoefficient_),
        static_cast<int32_t>(static_cast<float>(screenInfo_.GetRotatedHeight()) * mirrorAdaptiveCoefficient_)
    };
    info.visibleRect = GraphicIRect {info.dstRect.x, info.dstRect.y, info.dstRect.w, info.dstRect.h};
    info.zOrder = static_cast<int32_t>(node.GetGlobalZOrder());
    info.alpha.enGlobalAlpha = false;
    info.preBuffer = node.GetPreBuffer().buffer;
    info.buffer = buffer;
    info.fence = node.GetAcquireFence();
    info.blendType = GRAPHIC_BLEND_NONE;
    info.needClient = false;
    return info;
}

void RSUniRenderComposerAdapter::SetComposeInfoToLayer(
    const LayerInfoPtr& layer,
    const ComposeInfo& info,
    const sptr<Surface>& surface,
    RSBaseRenderNode* node) const
{
    if (layer == nullptr) {
        return;
    }
    layer->SetSurface(surface);
    layer->SetBuffer(info.buffer, info.fence);
    layer->SetPreBuffer(info.preBuffer);
    layer->SetZorder(info.zOrder);
    layer->SetAlpha(info.alpha);
    layer->SetLayerSize(info.dstRect);
    layer->SetCompositionType(info.needClient ?
        GraphicCompositionType::GRAPHIC_COMPOSITION_CLIENT : GraphicCompositionType::GRAPHIC_COMPOSITION_DEVICE);
    layer->SetVisibleRegion(1, info.visibleRect);
    layer->SetDirtyRegion(info.srcRect);
    layer->SetBlendType(info.blendType);
    layer->SetCropRect(info.srcRect);
    if (node -> GetTunnelHandleChange()) {
        layer->SetTunnelHandleChange(true);
        layer->SetTunnelHandle(surface->GetTunnelHandle());
        node ->SetTunnelHandleChange(false);
    }
    HDRMetaDataType type;
    if (surface->QueryMetaDataType(info.buffer->GetSeqNum(), type) != GSERROR_OK) {
        RS_LOGE("RSUniRenderComposerAdapter::SetComposeInfoToLayer: QueryMetaDataType failed");
        return;
    }
    switch (type) {
        case HDRMetaDataType::HDR_META_DATA: {
            std::vector<GraphicHDRMetaData> metaData;
            if (surface->GetMetaData(info.buffer->GetSeqNum(), metaData) != GSERROR_OK) {
                RS_LOGE("RSComposerAdapter::SetComposeInfoToLayer: GetMetaData failed");
                return;
            }
            layer->SetMetaData(metaData);
            break;
        }
        case HDRMetaDataType::HDR_META_DATA_SET: {
            GraphicHDRMetadataKey key;
            std::vector<uint8_t> metaData;
            if (surface->GetMetaDataSet(info.buffer->GetSeqNum(), key, metaData) != GSERROR_OK) {
                RS_LOGE("RSComposerAdapter::SetComposeInfoToLayer: GetMetaDataSet failed");
                return;
            }
            GraphicHDRMetaDataSet metaDataSet;
            metaDataSet.key = key;
            metaDataSet.metaData = metaData;
            layer->SetMetaDataSet(metaDataSet);
            break;
        }
        case HDRMetaDataType::HDR_NOT_USED: {
            RS_LOGD("RSComposerAdapter::SetComposeInfoToLayer: HDR is not used");
            break;
        }
        default:  {
            break;
        }
    }
}

LayerInfoPtr RSUniRenderComposerAdapter::CreateLayer(RSDisplayRenderNode& node)
{
    RS_TRACE_NAME("RSUniRenderComposerAdapter::CreateLayer");
    if (output_ == nullptr) {
        RS_LOGE("RSUniRenderComposerAdapter::CreateLayer: output is nullptr");
        return nullptr;
    }

    RS_LOGD("RSUniRenderComposerAdapter::CreateLayer displayNode id:%" PRIu64 " available buffer:%d", node.GetId(),
        node.GetAvailableBufferCount());
    if (!RSBaseRenderUtil::ConsumeAndUpdateBuffer(node)) {
        RS_LOGE("RSUniRenderComposerAdapter::CreateLayer consume buffer failed.");
        return nullptr;
    }

    ComposeInfo info = BuildComposeInfo(node);
    RS_LOGD("RSUniRenderComposerAdapter::ProcessSurface displayNode id:%" PRIu64 " dst [%d %d %d %d]"
            "SrcRect [%d %d] rawbuffer [%d %d] surfaceBuffer [%d %d] buffaddr:%p, globalZOrder:%d, blendType = %d",
        node.GetId(), info.dstRect.x, info.dstRect.y, info.dstRect.w, info.dstRect.h, info.srcRect.w, info.srcRect.h,
        info.buffer->GetWidth(), info.buffer->GetHeight(), info.buffer->GetSurfaceBufferWidth(),
        info.buffer->GetSurfaceBufferHeight(), info.buffer.GetRefPtr(), info.zOrder, info.blendType);
    LayerInfoPtr layer = HdiLayerInfo::CreateHdiLayerInfo();
    SetComposeInfoToLayer(layer, info, node.GetConsumer(), &node);
    LayerRotate(layer, node);
    // do not crop or scale down for displayNode's layer.
    return layer;
}

static void SetLayerTransform(const LayerInfoPtr& layer, RSBaseRenderNode& node,
    const sptr<Surface>& surface, ScreenRotation screenRotation)
{
    // screenRotation: anti-clockwise, surfaceTransform: anti-clockwise
    // layerTransform: clockwise
    int totalRotation = (RotateEnumToInt(screenRotation) + RotateEnumToInt(surface->GetTransform())) % 360;
    GraphicTransformType rotateEnum = RotateEnumToInt(totalRotation);
    layer->SetTransform(rotateEnum);
}

static void SetLayerSize(const LayerInfoPtr& layer, const ScreenInfo& screenInfo)
{
    const auto screenWidth = static_cast<int32_t>(screenInfo.width);
    const auto screenHeight = static_cast<int32_t>(screenInfo.height);
    const auto screenRotation = screenInfo.rotation;
    const auto rect = layer->GetLayerSize();
    // screenRotation: anti-clockwise, surfaceTransform: anti-clockwise, layerTransform: clockwise
    switch (screenRotation) {
        case ScreenRotation::ROTATION_90: {
            RS_LOGD("RsDebug ScreenRotation 90, Before Rotate layer size [%d %d %d %d]",
                rect.x, rect.y, rect.w, rect.h);
            layer->SetLayerSize(GraphicIRect {rect.y, screenHeight - rect.x - rect.w, rect.h, rect.w});
            RS_LOGD("RsDebug ScreenRotation 90, After Rotate layer size [%d %d %d %d]",
                layer->GetLayerSize().x, layer->GetLayerSize().y, layer->GetLayerSize().w, layer->GetLayerSize().h);
            break;
        }
        case ScreenRotation::ROTATION_180: {
            RS_LOGD("RsDebug ScreenRotation 180, Before Rotate layer size [%d %d %d %d]",
                rect.x, rect.y, rect.w, rect.h);
            layer->SetLayerSize(
                GraphicIRect {screenWidth - rect.x - rect.w, screenHeight - rect.y - rect.h, rect.w, rect.h});
            RS_LOGD("RsDebug ScreenRotation 180, After Rotate layer size [%d %d %d %d]",
                layer->GetLayerSize().x, layer->GetLayerSize().y, layer->GetLayerSize().w, layer->GetLayerSize().h);
            break;
        }
        case ScreenRotation::ROTATION_270: {
            RS_LOGD("RsDebug ScreenRotation 270, Before Rotate layer size [%d %d %d %d]",
                rect.x, rect.y, rect.w, rect.h);
            layer->SetLayerSize(GraphicIRect {screenWidth - rect.y - rect.h, rect.x, rect.h, rect.w});
            RS_LOGD("RsDebug ScreenRotation 270, After Rotate layer size [%d %d %d %d]",
                layer->GetLayerSize().x, layer->GetLayerSize().y, layer->GetLayerSize().w, layer->GetLayerSize().h);
            break;
        }
        default:  {
            break;
        }
    }
}

// private func, guarantee the layer is valid
void RSUniRenderComposerAdapter::LayerRotate(const LayerInfoPtr& layer, RSBaseRenderNode& node) const
{
    auto surface = layer->GetSurface();
    if (surface == nullptr) {
        return;
    }
    SetLayerSize(layer, screenInfo_);
    SetLayerTransform(layer, node, surface, screenInfo_.rotation);
}

} // namespace Rosen
} // namespace OHOS
