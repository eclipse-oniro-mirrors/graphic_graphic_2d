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
#include "luminance/rs_luminance_control.h"
#include "rs_trace.h"
#include "string_utils.h"
#include "surface_type.h"

#include "common/rs_optional_trace.h"
#include "drawable/rs_display_render_node_drawable.h"
#include "drawable/rs_surface_render_node_drawable.h"
#include "params/rs_display_render_params.h"
#include "params/rs_surface_render_params.h"
#include "pipeline/parallel_render/rs_sub_thread_manager.h"
#include "pipeline/round_corner_display/rs_rcd_surface_render_node.h"
#include "platform/common/rs_log.h"
#ifdef USE_VIDEO_PROCESSING_ENGINE
#include "metadata_helper.h"
#endif
namespace OHOS {
namespace Rosen {
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
    isPhone_ = RSMainThread::Instance()->GetDeviceType() == DeviceType::PHONE;
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
    isPhone_ = RSMainThread::Instance()->GetDeviceType() == DeviceType::PHONE;
    return uniComposerAdapter_->Init(screenInfo_, offsetX_, offsetY_, mirrorAdaptiveCoefficient_);
}

void RSUniRenderProcessor::PostProcess()
{
    uniComposerAdapter_->CommitLayers(layers_);
    if (!isPhone_) {
        MultiLayersPerf(layerNum_);
    }
    RS_LOGD("RSUniRenderProcessor::PostProcess layers_:%{public}zu", layers_.size());
}

#ifdef USE_VIDEO_PROCESSING_ENGINE
void RSUniRenderProcessor::DealWithHdr(RSSurfaceRenderNode& node, LayerInfoPtr& layer, sptr<SurfaceBuffer> buffer)
{
    auto ancestorNode = node.GetAncestorDisplayNode().lock();
    auto ancestorDisplayNode = ancestorNode ? ancestorNode->ReinterpretCastTo<RSDisplayRenderNode>() : nullptr;
    if (!ancestorDisplayNode) {
        RS_LOGE("ancestorDisplayNode return nullptr");
        return;
    }
    auto screenId = ancestorDisplayNode->GetScreenId();
    if (!RSLuminanceControl::Get().IsHdrOn(screenId)) {
        return;
    }
    Media::VideoProcessingEngine::CM_ColorSpaceInfo colorSpaceInfo;
    if (MetadataHelper::GetColorSpaceInfo(buffer, colorSpaceInfo) != GSERROR_OK) {
        return;
    }
    bool isHdrBuffer = colorSpaceInfo.transfunc == HDI::Display::Graphic::Common::V1_0::TRANSFUNC_PQ ||
        colorSpaceInfo.transfunc == HDI::Display::Graphic::Common::V1_0::TRANSFUNC_HLG;

    node.SetDisplayNit(RSLuminanceControl::Get().GetHdrDisplayNits(screenId));
    node.SetBrightnessRatio(isHdrBuffer ? 1.0f : RSLuminanceControl::Get().GetHdrBrightnessRatio(screenId, 0));
}
#endif

void RSUniRenderProcessor::CreateLayer(const RSSurfaceRenderNode& node, RSSurfaceRenderParams& params)
{
    auto surfaceHandler = node.GetRSSurfaceHandler();
    auto buffer = surfaceHandler->GetBuffer();
    if (buffer == nullptr || surfaceHandler->GetConsumer() == nullptr) {
        return;
    }
    auto& layerInfo = params.GetLayerInfo();
    RS_OPTIONAL_TRACE_NAME_FMT(
        "CreateLayer name:%s zorder:%d src:[%d, %d, %d, %d] dst:[%d, %d, %d, %d] buffer:[%d, %d] alpha:[%f] type:[%d]",
        node.GetName().c_str(), layerInfo.zOrder,
        layerInfo.srcRect.x, layerInfo.srcRect.y, layerInfo.srcRect.w, layerInfo.srcRect.h,
        layerInfo.dstRect.x, layerInfo.dstRect.y, layerInfo.dstRect.w, layerInfo.dstRect.h,
        buffer->GetSurfaceBufferWidth(), buffer->GetSurfaceBufferHeight(), layerInfo.alpha, layerInfo.layerType);
    RS_LOGI("CreateLayer name:%{public}s zorder:%{public}d src:[%{public}d, %{public}d, %{public}d, %{public}d] "
            "dst:[%{public}d, %{public}d, %{public}d, %{public}d] buffer:[%{public}d, %{public}d] alpha:[%{public}f]",
        node.GetName().c_str(), layerInfo.zOrder,
        layerInfo.srcRect.x, layerInfo.srcRect.y, layerInfo.srcRect.w, layerInfo.srcRect.h,
        layerInfo.dstRect.x, layerInfo.dstRect.y, layerInfo.dstRect.w, layerInfo.dstRect.h,
        buffer->GetSurfaceBufferWidth(), buffer->GetSurfaceBufferHeight(), layerInfo.alpha);
    auto& preBuffer = surfaceHandler->GetPreBuffer();
    ScalingMode scalingMode = params.GetPreScalingMode();
    if (surfaceHandler->GetConsumer()->GetScalingMode(buffer->GetSeqNum(), scalingMode) == GSERROR_OK) {
        params.SetPreScalingMode(scalingMode);
    }
    LayerInfoPtr layer = GetLayerInfo(
        params, buffer, preBuffer.buffer, surfaceHandler->GetConsumer(), surfaceHandler->GetAcquireFence());
#ifdef USE_VIDEO_PROCESSING_ENGINE
    DealWithHdr(node, layer, buffer);
#endif
    layer->SetDisplayNit(node.GetDisplayNit());
    layer->SetBrightnessRatio(node.GetBrightnessRatio());

    uniComposerAdapter_->SetMetaDataInfoToLayer(layer, surfaceHandler->GetBuffer(), surfaceHandler->GetConsumer());
    layers_.emplace_back(layer);
    params.SetLayerCreated(true);
}

void RSUniRenderProcessor::CreateLayerForRenderThread(DrawableV2::RSSurfaceRenderNodeDrawable& surfaceDrawable)
{
    auto& paramsSp = surfaceDrawable.GetRenderParams();
    if (!paramsSp) {
        return;
    }
    auto& params = *paramsSp;
    auto buffer = params.GetBuffer();
    if (buffer == nullptr) {
        return;
    }
    auto& layerInfo = params.GetLayerInfo();
    RS_OPTIONAL_TRACE_NAME_FMT(
        "CreateLayer name:%s zorder:%d src:[%d, %d, %d, %d] dst:[%d, %d, %d, %d] buffer:[%d, %d] alpha:[%f] type:[%d]",
        surfaceDrawable.GetName().c_str(), layerInfo.zOrder,
        layerInfo.srcRect.x, layerInfo.srcRect.y, layerInfo.srcRect.w, layerInfo.srcRect.h,
        layerInfo.dstRect.x, layerInfo.dstRect.y, layerInfo.dstRect.w, layerInfo.dstRect.h,
        buffer->GetSurfaceBufferWidth(), buffer->GetSurfaceBufferHeight(), layerInfo.alpha, layerInfo.layerType);
    RS_LOGI("CreateLayer name:%{public}s zorder:%{public}d src:[%{public}d, %{public}d, %{public}d, %{public}d] "
            "dst:[%{public}d, %{public}d, %{public}d, %{public}d] buffer:[%{public}d, %{public}d] alpha:[%{public}f]",
        surfaceDrawable.GetName().c_str(), layerInfo.zOrder,
        layerInfo.srcRect.x, layerInfo.srcRect.y, layerInfo.srcRect.w, layerInfo.srcRect.h,
        layerInfo.dstRect.x, layerInfo.dstRect.y, layerInfo.dstRect.w, layerInfo.dstRect.h,
        buffer->GetSurfaceBufferWidth(), buffer->GetSurfaceBufferHeight(), layerInfo.alpha);
    auto preBuffer = params.GetPreBuffer();
    LayerInfoPtr layer = GetLayerInfo(static_cast<RSSurfaceRenderParams&>(params), buffer, preBuffer,
        surfaceDrawable.GetConsumerOnDraw(), params.GetAcquireFence());
    layer->SetNodeId(surfaceDrawable.GetId());
    layer->SetDisplayNit(surfaceDrawable.GetDisplayNit());
    layer->SetBrightnessRatio(surfaceDrawable.GetBrightnessRatio());
    uniComposerAdapter_->SetMetaDataInfoToLayer(layer, params.GetBuffer(), surfaceDrawable.GetConsumerOnDraw());
    layers_.emplace_back(layer);
    params.SetLayerCreated(true);
}

void RSUniRenderProcessor::CreateUIFirstLayer(DrawableV2::RSSurfaceRenderNodeDrawable& drawable,
    RSSurfaceRenderParams& params)
{
    auto surfaceHandler = drawable.GetMutableRSSurfaceHandlerUiFirstOnDraw();
    auto buffer = surfaceHandler->GetBuffer();
    if (buffer == nullptr && surfaceHandler->GetAvailableBufferCount() <= 0) {
        RS_TRACE_NAME_FMT("HandleSubThreadNode wait %" PRIu64 "", params.GetId());
        RSSubThreadManager::Instance()->WaitNodeTask(params.GetId());
    }
    if (!RSBaseRenderUtil::ConsumeAndUpdateBuffer(*surfaceHandler, true) || !surfaceHandler->GetBuffer()) {
        RS_LOGE("CreateUIFirstLayer ConsumeAndUpdateBuffer or GetBuffer return  false");
        return;
    }
    buffer = surfaceHandler->GetBuffer();
    auto preBuffer = surfaceHandler->GetPreBuffer();
    LayerInfoPtr layer = GetLayerInfo(
        params, buffer, preBuffer.buffer, surfaceHandler->GetConsumer(), surfaceHandler->GetAcquireFence());
    uniComposerAdapter_->SetMetaDataInfoToLayer(layer, params.GetBuffer(), surfaceHandler->GetConsumer());
    layers_.emplace_back(layer);
    auto& layerInfo = params.layerInfo_;
    RS_LOGD("RSUniRenderProcessor::CreateUIFirstLayer: [%{public}s-%{public}" PRIu64 "] "
        "src: %{public}d %{public}d %{public}d %{public}d, "
        "dst: %{public}d %{public}d %{public}d %{public}d, zOrder: %{public}d, layerType: %{public}d",
        drawable.GetName().c_str(), drawable.GetId(),
        layerInfo.srcRect.x, layerInfo.srcRect.y, layerInfo.srcRect.w, layerInfo.srcRect.h,
        layerInfo.dstRect.x, layerInfo.dstRect.y, layerInfo.dstRect.w, layerInfo.dstRect.h, layerInfo.zOrder,
        static_cast<int>(layerInfo.layerType));
}

LayerInfoPtr RSUniRenderProcessor::GetLayerInfo(RSSurfaceRenderParams& params, sptr<SurfaceBuffer>& buffer,
    sptr<SurfaceBuffer>& preBuffer, const sptr<IConsumerSurface>& consumer, const sptr<SyncFence>& acquireFence)
{
    LayerInfoPtr layer = HdiLayerInfo::CreateHdiLayerInfo();
    auto& layerInfo = params.layerInfo_;
    layer->SetSurface(consumer);
    layer->SetBuffer(buffer, acquireFence);
    layer->SetPreBuffer(preBuffer);
    params.SetPreBuffer(nullptr);
    layer->SetZorder(layerInfo.zOrder);
    layer->SetType(layerInfo.layerType);

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
    bool forceClient = RSSystemProperties::IsForceClient() ||
        (params.GetIsProtectedLayer() && params.GetAnimateState());
    layer->SetCompositionType(forceClient ? GraphicCompositionType::GRAPHIC_COMPOSITION_CLIENT :
        GraphicCompositionType::GRAPHIC_COMPOSITION_DEVICE);

    std::vector<GraphicIRect> visibleRegions;
    visibleRegions.emplace_back(layerInfo.dstRect);
    layer->SetVisibleRegions(visibleRegions);
    std::vector<GraphicIRect> dirtyRegions;
    dirtyRegions.emplace_back(layerInfo.srcRect);
    layer->SetDirtyRegions(dirtyRegions);

    layer->SetBlendType(layerInfo.blendType);
    layer->SetCropRect(layerInfo.srcRect);
    layer->SetGravity(layerInfo.gravity);
    layer->SetTransform(layerInfo.transformType);
    auto matrix = GraphicMatrix {layerInfo.matrix.Get(Drawing::Matrix::Index::SCALE_X),
        layerInfo.matrix.Get(Drawing::Matrix::Index::SKEW_X), layerInfo.matrix.Get(Drawing::Matrix::Index::TRANS_X),
        layerInfo.matrix.Get(Drawing::Matrix::Index::SKEW_Y), layerInfo.matrix.Get(Drawing::Matrix::Index::SCALE_Y),
        layerInfo.matrix.Get(Drawing::Matrix::Index::TRANS_Y), layerInfo.matrix.Get(Drawing::Matrix::Index::PERSP_0),
        layerInfo.matrix.Get(Drawing::Matrix::Index::PERSP_1), layerInfo.matrix.Get(Drawing::Matrix::Index::PERSP_2)};
    layer->SetMatrix(matrix);
    layer->SetScalingMode(params.GetPreScalingMode());
    layer->SetLayerSourceTuning(params.GetLayerSourceTuning());
    layer->SetClearCacheSet(params.GetBufferClearCacheSet());
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
    layerNum_ = node.GetSurfaceCountForMultiLayersPerf();
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
    auto displayParams = static_cast<RSDisplayRenderParams*>(params.get());
    for (const auto& drawable : displayParams->GetAllMainAndLeashSurfaceDrawables()) {
        auto surfaceDrawable = std::static_pointer_cast<DrawableV2::RSSurfaceRenderNodeDrawable>(drawable);
        if (!surfaceDrawable || !surfaceDrawable->GetRenderParams() ||
            !surfaceDrawable->GetRenderParams()->GetOcclusionVisible() ||
            surfaceDrawable->GetRenderParams()->IsLeashWindow()) {
            continue;
        }
        layerNum_++;
    }
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

#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
std::vector<LayerInfoPtr> RSUniRenderProcessor::GetLayers() const
{
    return layers_;
}
#endif
} // namespace Rosen
} // namespace OHOS
