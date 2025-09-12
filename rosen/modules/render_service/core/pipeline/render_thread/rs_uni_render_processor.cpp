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

#include "rs_uni_render_processor.h"

#include <vector>

#include "hdi_layer.h"
#include "hdi_layer_info.h"
#include "rs_trace.h"
#include "rs_uni_render_util.h"
#include "string_utils.h"
#include "surface_type.h"

#include "common/rs_optional_trace.h"
#include "display_engine/rs_luminance_control.h"
#include "drawable/rs_display_render_node_drawable.h"
#include "drawable/rs_surface_render_node_drawable.h"
#include "params/rs_display_render_params.h"
#include "params/rs_surface_render_params.h"
#include "feature/round_corner_display/rs_rcd_surface_render_node.h"
#include "feature/round_corner_display/rs_rcd_surface_render_node_drawable.h"
#include "platform/common/rs_log.h"

namespace OHOS {
namespace Rosen {
constexpr uint32_t HIGHEST_Z_ORDER = 999;
RSUniRenderProcessor::RSUniRenderProcessor()
    : uniComposerAdapter_(std::make_unique<RSUniRenderComposerAdapter>())
{
}

RSUniRenderProcessor::~RSUniRenderProcessor() noexcept
{
}

bool RSUniRenderProcessor::Init(RSDisplayRenderNode& node, int32_t offsetX, int32_t offsetY, ScreenId mirroredId,
                                std::shared_ptr<RSBaseRenderEngine> renderEngine)
{
    if (!RSProcessor::Init(node, offsetX, offsetY, mirroredId, renderEngine)) {
        return false;
    }
    // In uni render mode, we can handle screen rotation in the rendering process,
    // so we do not need to handle rotation in composer adapter any more,
    // just pass the buffer to composer straightly.
    screenInfo_.rotation = ScreenRotation::ROTATION_0;
    return uniComposerAdapter_->Init(screenInfo_, offsetX_, offsetY_, mirrorAdaptiveCoefficient_);
}

bool RSUniRenderProcessor::InitForRenderThread(DrawableV2::RSDisplayRenderNodeDrawable& displayDrawable,
    ScreenId mirroredId, std::shared_ptr<RSBaseRenderEngine> renderEngine)
{
    if (!RSProcessor::InitForRenderThread(displayDrawable, mirroredId, renderEngine)) {
        return false;
    }
    // In uni render mode, we can handle screen rotation in the rendering process,
    // so we do not need to handle rotation in composer adapter any more,
    // just pass the buffer to composer straightly.
    screenInfo_.rotation = ScreenRotation::ROTATION_0;
    return uniComposerAdapter_->Init(screenInfo_, offsetX_, offsetY_, mirrorAdaptiveCoefficient_);
}

void RSUniRenderProcessor::PostProcess()
{
    uniComposerAdapter_->CommitLayers(layers_);
    RS_LOGD("RSUniRenderProcessor::PostProcess layers_:%{public}zu", layers_.size());
}

void RSUniRenderProcessor::CreateLayer(const RSSurfaceRenderNode& node, RSSurfaceRenderParams& params)
{
    auto surfaceHandler = node.GetRSSurfaceHandler();
    auto buffer = surfaceHandler->GetBuffer();
    if (buffer == nullptr || surfaceHandler->GetConsumer() == nullptr) {
        return;
    }
    auto& layerInfo = params.GetLayerInfo();
    const Rect& dirtyRect = params.GetBufferDamage();
    RS_OPTIONAL_TRACE_NAME_FMT(
        "CreateLayer name:%s zorder:%d src:[%d, %d, %d, %d] dst:[%d, %d, %d, %d] dirty:[%d, %d, %d, %d] "
        "buffer:[%d, %d] alpha:[%f] type:[%d]",
        node.GetName().c_str(), layerInfo.zOrder,
        layerInfo.srcRect.x, layerInfo.srcRect.y, layerInfo.srcRect.w, layerInfo.srcRect.h,
        layerInfo.dstRect.x, layerInfo.dstRect.y, layerInfo.dstRect.w, layerInfo.dstRect.h,
        dirtyRect.x, dirtyRect.y, dirtyRect.w, dirtyRect.h,
        buffer->GetSurfaceBufferWidth(), buffer->GetSurfaceBufferHeight(), layerInfo.alpha, layerInfo.layerType);
    RS_LOGD_IF(DEBUG_PIPELINE,
        "CreateLayer name:%{public}s zorder:%{public}d src:[%{public}d, %{public}d, %{public}d, %{public}d] "
        "dst:[%{public}d, %{public}d, %{public}d, %{public}d] "
        "drity:[%{public}d, %{public}d, %{public}d, %{public}d] "
        "buffer:[%{public}d, %{public}d] alpha:[%{public}f]",
        node.GetName().c_str(), layerInfo.zOrder, layerInfo.srcRect.x, layerInfo.srcRect.y, layerInfo.srcRect.w,
        layerInfo.srcRect.h, layerInfo.dstRect.x, layerInfo.dstRect.y, layerInfo.dstRect.w, layerInfo.dstRect.h,
        dirtyRect.x, dirtyRect.y, dirtyRect.w, dirtyRect.h, buffer->GetSurfaceBufferWidth(),
        buffer->GetSurfaceBufferHeight(), layerInfo.alpha);
    auto preBuffer = params.GetPreBuffer();
    LayerInfoPtr layer = GetLayerInfo(
        params, buffer, preBuffer, surfaceHandler->GetConsumer(), params.GetAcquireFence());
    layer->SetSdrNit(params.GetSdrNit());
    layer->SetDisplayNit(params.GetDisplayNit());
    layer->SetBrightnessRatio(params.GetBrightnessRatio());
    layer->SetLayerLinearMatrix(params.GetLayerLinearMatrix());

    uniComposerAdapter_->SetMetaDataInfoToLayer(layer, params.GetBuffer(), surfaceHandler->GetConsumer());
    CreateSolidColorLayer(layer, params);
    layers_.emplace_back(layer);
    params.SetLayerCreated(true);
}

void RSUniRenderProcessor::CreateLayerForRenderThread(DrawableV2::RSSurfaceRenderNodeDrawable& surfaceDrawable)
{
    auto& paramsSp = surfaceDrawable.GetRenderParams();
    if (!paramsSp) {
        return;
    }
    auto& params = *(static_cast<RSSurfaceRenderParams*>(paramsSp.get()));
    auto buffer = params.GetBuffer();
    if (buffer == nullptr) {
        return;
    }
    auto& layerInfo = params.GetLayerInfo();
    const Rect& dirtyRect = params.GetBufferDamage();
    RS_OPTIONAL_TRACE_NAME_FMT(
        "CreateLayer name:%s zorder:%d src:[%d, %d, %d, %d] dst:[%d, %d, %d, %d] dirty:[%d, %d, %d, %d] "
        "buffer:[%d, %d] alpha:[%f] type:[%d]",
        surfaceDrawable.GetName().c_str(), layerInfo.zOrder,
        layerInfo.srcRect.x, layerInfo.srcRect.y, layerInfo.srcRect.w, layerInfo.srcRect.h,
        layerInfo.dstRect.x, layerInfo.dstRect.y, layerInfo.dstRect.w, layerInfo.dstRect.h,
        dirtyRect.x, dirtyRect.y, dirtyRect.w, dirtyRect.h,
        buffer->GetSurfaceBufferWidth(), buffer->GetSurfaceBufferHeight(), layerInfo.alpha, layerInfo.layerType);
    RS_LOGD("CreateLayer name:%{public}s zorder:%{public}d src:[%{public}d, %{public}d, %{public}d, %{public}d] "
            "dst:[%{public}d, %{public}d, %{public}d, %{public}d] "
            "drity:[%{public}d, %{public}d, %{public}d, %{public}d] "
            "buffer:[%{public}d, %{public}d] alpha:[%{public}f] type:%{public}d]",
        surfaceDrawable.GetName().c_str(), layerInfo.zOrder,
        layerInfo.srcRect.x, layerInfo.srcRect.y, layerInfo.srcRect.w, layerInfo.srcRect.h,
        layerInfo.dstRect.x, layerInfo.dstRect.y, layerInfo.dstRect.w, layerInfo.dstRect.h,
        dirtyRect.x, dirtyRect.y, dirtyRect.w, dirtyRect.h,
        buffer->GetSurfaceBufferWidth(), buffer->GetSurfaceBufferHeight(), layerInfo.alpha, layerInfo.layerType);
    auto preBuffer = params.GetPreBuffer();
    LayerInfoPtr layer = GetLayerInfo(static_cast<RSSurfaceRenderParams&>(params), buffer, preBuffer,
        surfaceDrawable.GetConsumerOnDraw(), params.GetAcquireFence());
    layer->SetNodeId(surfaceDrawable.GetId());
    auto& renderParams = static_cast<RSSurfaceRenderParams&>(params);
    layer->SetSdrNit(renderParams.GetSdrNit());
    layer->SetDisplayNit(renderParams.GetDisplayNit());
    layer->SetBrightnessRatio(renderParams.GetBrightnessRatio());
    layer->SetLayerLinearMatrix(renderParams.GetLayerLinearMatrix());
    uniComposerAdapter_->SetMetaDataInfoToLayer(layer, params.GetBuffer(), surfaceDrawable.GetConsumerOnDraw());
    CreateSolidColorLayer(layer, params);
    layers_.emplace_back(layer);
    params.SetLayerCreated(true);
}

void RSUniRenderProcessor::CreateSolidColorLayer(LayerInfoPtr layer, RSSurfaceRenderParams& params)
{
    auto color = params.GetBackgroundColor();
    if (!params.GetIsHwcEnabledBySolidLayer()) {
        auto solidColorLayer = HdiLayerInfo::CreateHdiLayerInfo();
        solidColorLayer->CopyLayerInfo(layer);
        if (layer->GetZorder() > 0) {
            solidColorLayer->SetZorder(layer->GetZorder() - 1);
        }
        solidColorLayer->SetTransform(GraphicTransformType::GRAPHIC_ROTATE_NONE);
        auto dstRect = params.layerInfo_.dstRect;
        GraphicIRect layerRect = {dstRect.x, dstRect.y, dstRect.w, dstRect.h};
        solidColorLayer->SetLayerSize(layerRect);
        solidColorLayer->SetCompositionType(GraphicCompositionType::GRAPHIC_COMPOSITION_SOLID_COLOR);
        solidColorLayer->SetLayerColor({color.GetRed(), color.GetGreen(), color.GetBlue(), color.GetAlpha()});
        solidColorLayer->SetSurface({});
        solidColorLayer->SetBuffer({}, {});
        solidColorLayer->SetPreBuffer({});
        solidColorLayer->SetMetaData({});
        layers_.emplace_back(solidColorLayer);
    }
}

bool RSUniRenderProcessor::GetForceClientForDRM(RSSurfaceRenderParams& params)
{
    if (params.GetSpecialLayerMgr().Find(SpecialLayerType::PROTECTED) == false) {
        return false;
    }
    if (params.GetAnimateState() == true ||
        RSUniRenderUtil::GetRotationDegreeFromMatrix(params.GetTotalMatrix()) % RS_ROTATION_90 != 0) {
        return true;
    }
    if (!params.GetCornerRadiusInfoForDRM().empty()) {
        return true;
    }
    if (params.GetIsOutOfScreen() == true) {
        return true;
    }
    bool forceClientForDRM = false;
    auto ancestorDisplayDrawable =
        std::static_pointer_cast<DrawableV2::RSDisplayRenderNodeDrawable>(params.GetAncestorDisplayDrawable().lock());
    auto& uniParam = RSUniRenderThread::Instance().GetRSRenderThreadParams();
    if (ancestorDisplayDrawable == nullptr || ancestorDisplayDrawable->GetRenderParams() == nullptr ||
        uniParam == nullptr) {
        RS_LOGE("%{public}s ancestorDisplayDrawable/ancestorDisplayDrawableParams/uniParam is nullptr", __func__);
        return false;
    } else {
        auto displayParams = static_cast<RSDisplayRenderParams*>(ancestorDisplayDrawable->GetRenderParams().get());
        forceClientForDRM = displayParams->IsRotationChanged() || uniParam->GetCacheEnabledForRotation();
    }
    return forceClientForDRM;
}

LayerInfoPtr RSUniRenderProcessor::GetLayerInfo(RSSurfaceRenderParams& params, sptr<SurfaceBuffer>& buffer,
    sptr<SurfaceBuffer>& preBuffer, const sptr<IConsumerSurface>& consumer, const sptr<SyncFence>& acquireFence)
{
    LayerInfoPtr layer = HdiLayerInfo::CreateHdiLayerInfo();
    auto& layerInfo = params.layerInfo_;
    layer->SetNeedBilinearInterpolation(params.NeedBilinearInterpolation());
    layer->SetSurface(consumer);
    layer->SetBuffer(buffer, acquireFence);
    layer->SetPreBuffer(preBuffer);
    params.SetPreBuffer(nullptr);
    layer->SetZorder(layerInfo.zOrder);
    layer->SetType(layerInfo.layerType);
    layer->SetRotationFixed(params.GetFixRotationByUser());

    GraphicLayerAlpha alpha;
    alpha.enGlobalAlpha = true;
    // Alpha of 255 indicates opacity
    alpha.gAlpha = static_cast<uint8_t>(std::clamp(layerInfo.alpha, 0.0f, 1.0f) * RGBA_MAX);
    layer->SetAlpha(alpha);
    GraphicIRect dstRect = layerInfo.dstRect;
    if (layerInfo.layerType == GraphicLayerType::GRAPHIC_LAYER_TYPE_CURSOR &&
        ((layerInfo.dstRect.w != layerInfo.srcRect.w) || (layerInfo.dstRect.h != layerInfo.srcRect.h))) {
        dstRect = {layerInfo.dstRect.x, layerInfo.dstRect.y, layerInfo.srcRect.w, layerInfo.srcRect.h};
    }
    layer->SetLayerSize(dstRect);
    layer->SetBoundSize(layerInfo.boundRect);
    bool forceClientForDRM = GetForceClientForDRM(params);
    RS_OPTIONAL_TRACE_NAME_FMT("%s nodeName[%s] forceClientForDRM[%d]",
        __func__, params.GetName().c_str(), forceClientForDRM);
    RS_LOGD("%{public}s nodeName[%{public}s] forceClientForDRM[%{public}d]",
        __func__, params.GetName().c_str(), forceClientForDRM);
    bool forceClient = RSSystemProperties::IsForceClient() || forceClientForDRM;
    layer->SetCompositionType(forceClient ? GraphicCompositionType::GRAPHIC_COMPOSITION_CLIENT :
        GraphicCompositionType::GRAPHIC_COMPOSITION_DEVICE);
    layer->SetCornerRadiusInfoForDRM(params.GetCornerRadiusInfoForDRM());
    auto bufferBackgroundColor = params.GetBackgroundColor();
    GraphicLayerColor backgroundColor = {
        .r = bufferBackgroundColor.GetRed(),
        .g = bufferBackgroundColor.GetGreen(),
        .b = bufferBackgroundColor.GetBlue(),
        .a = bufferBackgroundColor.GetAlpha()
    };
    layer->SetBackgroundColor(backgroundColor);

    std::vector<GraphicIRect> visibleRegions;
    visibleRegions.emplace_back(layerInfo.dstRect);
    layer->SetVisibleRegions(visibleRegions);
    std::vector<GraphicIRect> dirtyRegions;
    if (RSSystemProperties::GetHwcDirtyRegionEnabled()) {
        const auto& bufferDamage = params.GetBufferDamage();
        GraphicIRect dirtyRect = params.GetIsBufferFlushed() ? GraphicIRect { bufferDamage.x, bufferDamage.y,
            bufferDamage.w, bufferDamage.h } : GraphicIRect { 0, 0, 0, 0 };
        auto intersectRect = RSUniRenderUtil::IntersectRect(layerInfo.srcRect, dirtyRect);
        RS_OPTIONAL_TRACE_NAME_FMT("intersectRect:[%d, %d, %d, %d]",
            intersectRect.x, intersectRect.y, intersectRect.w, intersectRect.h);
        dirtyRegions.emplace_back(intersectRect);
    } else {
        dirtyRegions.emplace_back(layerInfo.srcRect);
    }
    layer->SetDirtyRegions(dirtyRegions);

    layer->SetBlendType(layerInfo.blendType);
    layer->SetCropRect(layerInfo.srcRect);
    layer->SetGravity(layerInfo.gravity);
    layer->SetTransform(layerInfo.transformType);
    if (layerInfo.layerType == GraphicLayerType::GRAPHIC_LAYER_TYPE_CURSOR) {
        layer->SetTransform(GraphicTransformType::GRAPHIC_ROTATE_NONE);
        //Set the highest z-order for hardCursor
        layer->SetZorder(HIGHEST_Z_ORDER);
    }
    auto matrix = GraphicMatrix {layerInfo.matrix.Get(Drawing::Matrix::Index::SCALE_X),
        layerInfo.matrix.Get(Drawing::Matrix::Index::SKEW_X), layerInfo.matrix.Get(Drawing::Matrix::Index::TRANS_X),
        layerInfo.matrix.Get(Drawing::Matrix::Index::SKEW_Y), layerInfo.matrix.Get(Drawing::Matrix::Index::SCALE_Y),
        layerInfo.matrix.Get(Drawing::Matrix::Index::TRANS_Y), layerInfo.matrix.Get(Drawing::Matrix::Index::PERSP_0),
        layerInfo.matrix.Get(Drawing::Matrix::Index::PERSP_1), layerInfo.matrix.Get(Drawing::Matrix::Index::PERSP_2)};
    layer->SetMatrix(matrix);
    layer->SetLayerSourceTuning(params.GetLayerSourceTuning());
    layer->SetLayerArsr(layerInfo.arsrTag);
    return layer;
}

void RSUniRenderProcessor::ProcessSurface(RSSurfaceRenderNode &node)
{
    RS_LOGE("It is update to DrawableV2 to process node now!!");
}

void RSUniRenderProcessor::ProcessSurfaceForRenderThread(DrawableV2::RSSurfaceRenderNodeDrawable& surfaceDrawable)
{
    auto layer = uniComposerAdapter_->CreateLayer(surfaceDrawable);
    if (layer == nullptr) {
        RS_LOGE("RSUniRenderProcessor::ProcessSurface: failed to createLayer for node(id: %{public}" PRIu64 ")",
            surfaceDrawable.GetId());
        return;
    }
    layers_.emplace_back(layer);
}

void RSUniRenderProcessor::ProcessDisplaySurface(RSDisplayRenderNode& node)
{
    auto layer = uniComposerAdapter_->CreateLayer(node);
    if (layer == nullptr) {
        RS_LOGE("RSUniRenderProcessor::ProcessDisplaySurface: failed to createLayer for node(id: %{public}" PRIu64 ")",
            node.GetId());
        return;
    }
    if (node.GetFingerprint()) {
        layer->SetLayerMaskInfo(HdiLayerInfo::LayerMask::LAYER_MASK_HBM_SYNC);
        RS_LOGD("RSUniRenderProcessor::ProcessDisplaySurface, set layer mask hbm sync");
    } else {
        layer->SetLayerMaskInfo(HdiLayerInfo::LayerMask::LAYER_MASK_NORMAL);
    }
    layers_.emplace_back(layer);
    auto drawable = node.GetRenderDrawable();
    if (!drawable) {
        return;
    }
    auto displayDrawable = std::static_pointer_cast<DrawableV2::RSDisplayRenderNodeDrawable>(drawable);
    auto surfaceHandler = displayDrawable->GetRSSurfaceHandlerOnDraw();
    RSUniRenderThread::Instance().SetAcquireFence(surfaceHandler->GetAcquireFence());
}

void RSUniRenderProcessor::ProcessDisplaySurfaceForRenderThread(
    DrawableV2::RSDisplayRenderNodeDrawable& displayDrawable)
{
    auto layer = uniComposerAdapter_->CreateLayer(displayDrawable);
    if (layer == nullptr) {
        RS_LOGE("RSUniRenderProcessor::ProcessDisplaySurface: failed to createLayer for node(id: %{public}" PRIu64 ")",
            displayDrawable.GetId());
        return;
    }
    auto& params = displayDrawable.GetRenderParams();
    if (!params) {
        return;
    }
    if (params->GetFingerprint()) {
        layer->SetLayerMaskInfo(HdiLayerInfo::LayerMask::LAYER_MASK_HBM_SYNC);
        RS_LOGD("RSUniRenderProcessor::ProcessDisplaySurface, set layer mask hbm sync");
    } else {
        layer->SetLayerMaskInfo(HdiLayerInfo::LayerMask::LAYER_MASK_NORMAL);
    }
    layers_.emplace_back(layer);
    auto surfaceHandler = displayDrawable.GetRSSurfaceHandlerOnDraw();
    if (!surfaceHandler) {
        return;
    }
    RSUniRenderThread::Instance().SetAcquireFence(surfaceHandler->GetAcquireFence());
}

void RSUniRenderProcessor::ProcessRcdSurface(RSRcdSurfaceRenderNode& node)
{
    auto layer = uniComposerAdapter_->CreateLayer(node);
    if (layer == nullptr) {
        RS_LOGE("RSUniRenderProcessor::ProcessRcdSurface: failed to createLayer for node(id: %{public}" PRIu64 ")",
            node.GetId());
        return;
    }
    layers_.emplace_back(layer);
}

void RSUniRenderProcessor::ProcessRcdSurfaceForRenderThread(DrawableV2::RSRcdSurfaceRenderNodeDrawable &rcdDrawable)
{
    auto layer = uniComposerAdapter_->CreateLayer(rcdDrawable);
    if (layer == nullptr) {
        RS_LOGE("RSUniRenderProcessor::ProcessRcdSurfaceForRenderThread: failed to createLayer for node(id: "
                "%{public}" PRIu64 ")",
            rcdDrawable.GetId());
        return;
    }
    layers_.emplace_back(layer);
}

#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
std::vector<LayerInfoPtr> RSUniRenderProcessor::GetLayers() const
{
    return layers_;
}
#endif
} // namespace Rosen
} // namespace OHOS
