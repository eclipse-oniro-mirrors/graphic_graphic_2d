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
#include <memory>

#include "common/rs_common_def.h"
#include "common/rs_obj_abs_geometry.h"
#include "common/rs_optional_trace.h"
#include "drawable/rs_display_render_node_drawable.h"
#include "drawable/rs_render_node_drawable_adapter.h"
#include "drawable/rs_surface_render_node_drawable.h"
#include "params/rs_render_params.h"
#include "pipeline/rs_uni_render_util.h"
#include "pipeline/rs_uni_render_listener.h"
#include "platform/common/rs_log.h"
#include "rs_divided_render_util.h"
#include "rs_trace.h"
#include "string_utils.h"
#include "metadata_helper.h"
#include "surface_type.h"
#include "third_party/libdrm/include/drm/drm.h"

#include "pipeline/round_corner_display/rs_rcd_surface_render_node.h"

namespace OHOS {
namespace Rosen {
using namespace std;
constexpr uint32_t FLAT_ANGLE = 180;
constexpr int32_t DEFAULT_BRIGHTNESS = 500;
constexpr float NO_RATIO = 1.0f;
static const int GLOBAL_ALPHA_MAX = 255;
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
    std::vector<GraphicIRect> damageRects;
    damageRects.emplace_back(damageRect);
    output_->SetOutputDamages(damageRects);
    bool directClientCompEnableStatus = RSSystemProperties::GetDirectClientCompEnableStatus();
    output_->SetDirectClientCompEnableStatus(directClientCompEnableStatus);

#if (defined (RS_ENABLE_GL) || defined (RS_ENABLE_VK))
    // enable direct GPU composition.
    output_->SetLayerCompCapacity(LAYER_COMPOSITION_CAPACITY);
#else // (defined RS_ENABLE_GL)
    output_->SetLayerCompCapacity(LAYER_COMPOSITION_CAPACITY_INVALID);
#endif // (defined RS_ENABLE_GL)
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

void RSUniRenderComposerAdapter::SetPreBufferInfo(RSSurfaceHandler& surfaceHandler, ComposeInfo& info) const
{
    auto& preBuffer = surfaceHandler.GetPreBuffer();
    info.preBuffer = preBuffer.buffer;
    preBuffer.Reset();
}

// private func, for RSDisplayRenderNode
ComposeInfo RSUniRenderComposerAdapter::BuildComposeInfo(DrawableV2::RSDisplayRenderNodeDrawable& displayDrawable)
{
    ComposeInfo info {};
    SetBufferColorSpace(displayDrawable);
    auto surfaceHandler = displayDrawable.GetMutableRSSurfaceHandlerOnDraw();
    auto& params = displayDrawable.GetRenderParams();
    if (!surfaceHandler || !params) {
        return info;
    }
    const auto& buffer = surfaceHandler->GetBuffer(); // we guarantee the buffer is valid.
    info.srcRect = GraphicIRect {0, 0, buffer->GetSurfaceBufferWidth(), buffer->GetSurfaceBufferHeight()};
    info.dstRect = GraphicIRect { 0, 0, static_cast<int32_t>(screenInfo_.GetRotatedPhyWidth()),
        static_cast<int32_t>(screenInfo_.GetRotatedPhyHeight()) };
    auto bound = params->GetBounds();
    info.boundRect = { 0, 0,
        static_cast<int32_t>(bound.GetWidth()), static_cast<int32_t>(bound.GetHeight())};
    info.visibleRect = GraphicIRect {info.dstRect.x, info.dstRect.y, info.dstRect.w, info.dstRect.h};
    std::vector<GraphicIRect> dirtyRects;
    // layer damage always relative to the top-left, no matter gl or vk
    std::vector<RectI> flipDirtyRects =
        RSUniRenderUtil::GetFilpDirtyRects(displayDrawable.GetDirtyRects(), screenInfo_);
    for (const auto& rect : flipDirtyRects) {
        dirtyRects.emplace_back(GraphicIRect {rect.left_, rect.top_, rect.width_, rect.height_});
    }
    if (dirtyRects.empty()) {
        dirtyRects.emplace_back(info.srcRect);
    }
    info.dirtyRects = dirtyRects;
    auto displayParams = static_cast<RSDisplayRenderParams*>(params.get());
    info.zOrder = static_cast<int32_t>(displayParams->GetGlobalZOrder());
    info.alpha.enGlobalAlpha = true;
    info.alpha.gAlpha = GLOBAL_ALPHA_MAX;
    SetPreBufferInfo(*surfaceHandler, info);
    info.buffer = buffer;
    info.fence = surfaceHandler->GetAcquireFence();
    info.blendType = GRAPHIC_BLEND_SRCOVER;
    info.needClient = RSSystemProperties::IsForceClient();
    auto matrix = params->GetMatrix();
    info.matrix = GraphicMatrix {matrix.Get(Drawing::Matrix::Index::SCALE_X),
        matrix.Get(Drawing::Matrix::Index::SKEW_X), matrix.Get(Drawing::Matrix::Index::TRANS_X),
        matrix.Get(Drawing::Matrix::Index::SKEW_Y), matrix.Get(Drawing::Matrix::Index::SCALE_Y),
        matrix.Get(Drawing::Matrix::Index::TRANS_Y), matrix.Get(Drawing::Matrix::Index::PERSP_0),
        matrix.Get(Drawing::Matrix::Index::PERSP_1), matrix.Get(Drawing::Matrix::Index::PERSP_2)};
    info.gravity = static_cast<int32_t>(Gravity::RESIZE);

    info.displayNit = DEFAULT_BRIGHTNESS;
    info.brightnessRatio = NO_RATIO;
    return info;
}

ComposeInfo RSUniRenderComposerAdapter::BuildComposeInfo(RSRcdSurfaceRenderNode& node) const
{
    const auto& buffer = node.GetBuffer(); // we guarantee the buffer is valid.
    const RectI& dstRect = node.GetDstRect();
    const auto& srcRect = node.GetSrcRect();
    ComposeInfo info {};
    info.srcRect = GraphicIRect {srcRect.left_, srcRect.top_, srcRect.width_, srcRect.height_};
    info.dstRect = GraphicIRect {static_cast<int32_t>(dstRect.left_ * screenInfo_.GetRogWidthRatio()),
        static_cast<int32_t>(dstRect.top_ * screenInfo_.GetRogHeightRatio()),
        static_cast<int32_t>(dstRect.width_ * screenInfo_.GetRogWidthRatio()),
        static_cast<int32_t>(dstRect.height_ * screenInfo_.GetRogHeightRatio())};
    info.boundRect = info.dstRect;
    info.visibleRect = info.dstRect;
    std::vector<GraphicIRect> dirtyRects;
    dirtyRects.emplace_back(GraphicIRect {0, 0, 0, 0});
    info.dirtyRects = dirtyRects;
    info.zOrder = static_cast<int32_t>(node.GetGlobalZOrder());
    info.alpha.enGlobalAlpha = true;
    info.alpha.gAlpha = 255; // 255 means not transparent
    SetPreBufferInfo(node, info);
    info.buffer = buffer;
    info.fence = node.GetAcquireFence();
    info.blendType = GRAPHIC_BLEND_SRCOVER;
    info.needClient = false;
    info.matrix = GraphicMatrix {1.f, 0.f, 0.f, 0.f, 1.f, 0.f, 0.f, 0.f, 1.f};
    info.gravity = static_cast<int32_t>(Gravity::RESIZE);

    info.displayNit = DEFAULT_BRIGHTNESS;
    info.brightnessRatio = NO_RATIO;
    return info;
}

void RSUniRenderComposerAdapter::SetComposeInfoToLayer(
    const LayerInfoPtr& layer,
    const ComposeInfo& info,
    const sptr<IConsumerSurface>& surface) const
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
    layer->SetBoundSize(info.boundRect);
    layer->SetCompositionType(info.needClient ?
        GraphicCompositionType::GRAPHIC_COMPOSITION_CLIENT : GraphicCompositionType::GRAPHIC_COMPOSITION_DEVICE);
    std::vector<GraphicIRect> visibleRegions;
    visibleRegions.emplace_back(info.visibleRect);
    layer->SetVisibleRegions(visibleRegions);
    layer->SetDirtyRegions(info.dirtyRects);
    layer->SetBlendType(info.blendType);
    layer->SetCropRect(info.srcRect);
    layer->SetMatrix(info.matrix);
    layer->SetGravity(info.gravity);
    SetMetaDataInfoToLayer(layer, info.buffer, surface);
    layer->SetDisplayNit(info.displayNit);
    layer->SetBrightnessRatio(info.brightnessRatio);
}

void RSUniRenderComposerAdapter::SetBufferColorSpace(DrawableV2::RSDisplayRenderNodeDrawable& displayDrawable)
{
    sptr<SurfaceBuffer> buffer = displayDrawable.GetRSSurfaceHandlerOnDraw()->GetBuffer();
    if (buffer == nullptr) {
        RS_LOGE("RSUniRenderComposerAdapter::SetBufferColorSpace SurfaceBuffer is null");
        return;
    }

    auto rsSurface = displayDrawable.GetRSSurface();
    if (rsSurface == nullptr) {
        RS_LOGE("RSUniRenderComposerAdapter::SetBufferColorSpace RSSurface is null");
        return;
    }

    using namespace HDI::Display::Graphic::Common::V1_0;
    static const std::map<GraphicColorGamut, CM_ColorSpaceType> RS_TO_COMMON_COLOR_SPACE_TYPE_MAP {
        {GRAPHIC_COLOR_GAMUT_STANDARD_BT601, CM_BT601_EBU_FULL},
        {GRAPHIC_COLOR_GAMUT_STANDARD_BT709, CM_BT709_FULL},
        {GRAPHIC_COLOR_GAMUT_SRGB, CM_SRGB_FULL},
        {GRAPHIC_COLOR_GAMUT_ADOBE_RGB, CM_ADOBERGB_FULL},
        {GRAPHIC_COLOR_GAMUT_DISPLAY_P3, CM_P3_FULL},
        {GRAPHIC_COLOR_GAMUT_BT2020, CM_DISPLAY_BT2020_SRGB},
        {GRAPHIC_COLOR_GAMUT_BT2100_PQ, CM_BT2020_PQ_FULL},
        {GRAPHIC_COLOR_GAMUT_BT2100_HLG, CM_BT2020_HLG_FULL},
        {GRAPHIC_COLOR_GAMUT_DISPLAY_BT2020, CM_DISPLAY_BT2020_SRGB},
    };

    GraphicColorGamut rsColorSpace = rsSurface->GetColorSpace();
    CM_ColorSpaceType colorSpace;
    if (RS_TO_COMMON_COLOR_SPACE_TYPE_MAP.find(rsColorSpace) != RS_TO_COMMON_COLOR_SPACE_TYPE_MAP.end()) {
        colorSpace = RS_TO_COMMON_COLOR_SPACE_TYPE_MAP.at(rsColorSpace);
    } else {
        RS_LOGW("RSUniRenderComposerAdapter::SetBufferColorSpace unknown color space");
        colorSpace = CM_COLORSPACE_NONE;
    }

    if (MetadataHelper::SetColorSpaceType(buffer, colorSpace) != GSERROR_OK) {
        RS_LOGE("RSUniRenderComposerAdapter::SetBufferColorSpace set color space fail");
    }
}

void RSUniRenderComposerAdapter::SetMetaDataInfoToLayer(const LayerInfoPtr& layer, const sptr<SurfaceBuffer>& buffer,
                                                        const sptr<IConsumerSurface>& surface) const
{
    HDRMetaDataType type;
    if (!surface || !buffer) {
        return;
    }
    if (surface->QueryMetaDataType(buffer->GetSeqNum(), type) != GSERROR_OK) {
        RS_LOGD("RSUniRenderComposerAdapter::SetComposeInfoToLayer: QueryMetaDataType failed");
        return;
    }
    switch (type) {
        case HDRMetaDataType::HDR_META_DATA: {
            std::vector<GraphicHDRMetaData> metaData;
            if (surface->GetMetaData(buffer->GetSeqNum(), metaData) != GSERROR_OK) {
                RS_LOGE("RSUniRenderComposerAdapter::SetComposeInfoToLayer: GetMetaData failed");
                return;
            }
            layer->SetMetaData(metaData);
            break;
        }
        case HDRMetaDataType::HDR_META_DATA_SET: {
            GraphicHDRMetadataKey key;
            std::vector<uint8_t> metaData;
            if (surface->GetMetaDataSet(buffer->GetSeqNum(), key, metaData) != GSERROR_OK) {
                RS_LOGE("RSUniRenderComposerAdapter::SetComposeInfoToLayer: GetMetaDataSet failed");
                return;
            }
            GraphicHDRMetaDataSet metaDataSet;
            metaDataSet.key = key;
            metaDataSet.metaData = metaData;
            layer->SetMetaDataSet(metaDataSet);
            break;
        }
        case HDRMetaDataType::HDR_NOT_USED: {
            break;
        }
        default:  {
            break;
        }
    }
}

void RSUniRenderComposerAdapter::GetComposerInfoSrcRect(ComposeInfo &info, const RSSurfaceRenderNode& node)
{
    auto consumer = node.GetRSSurfaceHandler()->GetConsumer();
    if (!consumer || !info.buffer) {
        return;
    }
    const auto& property = node.GetRenderProperties();
    const auto bufferWidth = info.buffer->GetSurfaceBufferWidth();
    const auto bufferHeight = info.buffer->GetSurfaceBufferHeight();
    auto boundsWidth = property.GetBoundsWidth();
    auto boundsHeight = property.GetBoundsHeight();
    GraphicTransformType transformType =
        RSBaseRenderUtil::GetRotateTransform(consumer->GetTransform());
    if (transformType == GraphicTransformType::GRAPHIC_ROTATE_270 ||
        transformType == GraphicTransformType::GRAPHIC_ROTATE_90) {
        std::swap(boundsWidth, boundsHeight);
    }
    if ((bufferWidth != boundsWidth || bufferHeight != boundsHeight) &&
        node.GetRenderProperties().GetFrameGravity() != Gravity::TOP_LEFT) {
        float xScale = (ROSEN_EQ(boundsWidth, 0.0f) ? 1.0f : bufferWidth / boundsWidth);
        float yScale = (ROSEN_EQ(boundsHeight, 0.0f) ? 1.0f : bufferHeight / boundsHeight);

        const auto nodeParams = static_cast<RSSurfaceRenderParams*>(node.GetRenderParams().get());
        // If the scaling mode is SCALING_MODE_SCALE_TO_WINDOW, the scale should use smaller one.
        ScalingMode scalingMode = nodeParams->GetPreScalingMode();
        if (consumer->GetScalingMode(info.buffer->GetSeqNum(), scalingMode) == GSERROR_OK) {
            nodeParams->SetPreScalingMode(scalingMode);
        }
        if (scalingMode == ScalingMode::SCALING_MODE_SCALE_CROP) {
            float scale = std::min(xScale, yScale);
            info.srcRect.x = info.srcRect.x * scale;
            info.srcRect.y = info.srcRect.y * scale;
            if (ROSEN_EQ(scale, 0.f)) {
                return;
            }
            info.srcRect.w = (bufferWidth / scale - (boundsWidth - info.srcRect.w)) * scale;
            info.srcRect.h = (bufferHeight / scale - (boundsHeight - info.srcRect.h)) * scale;
        } else {
            if (property.GetBoundsGeometry()->GetAbsRect() == node.GetDstRect()) {
                // If the SurfaceRenderNode is completely in the DisplayRenderNode,
                // we do not need to crop the buffer.
                info.srcRect.w = bufferWidth;
                info.srcRect.h = bufferHeight;
            } else {
                info.srcRect.x = info.srcRect.x * xScale;
                info.srcRect.y = info.srcRect.y * yScale;
                info.srcRect.w = std::min(static_cast<int32_t>(std::ceil(info.srcRect.w * xScale)), bufferWidth);
                info.srcRect.h = std::min(static_cast<int32_t>(std::ceil(info.srcRect.h * yScale)), bufferHeight);
            }
        }
    }
    Drawing::RectI srcRect(
        info.srcRect.x, info.srcRect.y, info.srcRect.w + info.srcRect.x, info.srcRect.h + info.srcRect.y);
    Drawing::RectI bufferRect(0, 0, bufferWidth, bufferHeight);
    if (srcRect.Intersect(bufferRect)) {
        info.srcRect.x = srcRect.GetLeft();
        info.srcRect.y = srcRect.GetTop();
        info.srcRect.w = srcRect.GetWidth();
        info.srcRect.h = srcRect.GetHeight();
    } else {
        info.srcRect = { 0, 0, 0, 0 };
    }

    RS_LOGD("RsDebug RSUniRenderComposerAdapter::GetComposerInfoSrcRect surfaceNode id:%{public}" PRIu64 ","\
            "srcRect [%{public}d %{public}d %{public}d %{public}d]",
            node.GetId(), info.srcRect.x, info.srcRect.y, info.srcRect.w, info.srcRect.h);
}

void RSUniRenderComposerAdapter::GetComposerInfoSrcRect(
    ComposeInfo& info, const DrawableV2::RSSurfaceRenderNodeDrawable& surfaceDrawable)
{
    auto& params = surfaceDrawable.GetRenderParams();
    if (!params || !info.buffer || !surfaceDrawable.GetConsumerOnDraw()) {
        return;
    }
    const auto bufferWidth = info.buffer->GetSurfaceBufferWidth();
    const auto bufferHeight = info.buffer->GetSurfaceBufferHeight();
    auto boundsWidth = params->GetBounds().GetWidth();
    auto boundsHeight = params->GetBounds().GetHeight();
    GraphicTransformType transformType =
        RSBaseRenderUtil::GetRotateTransform(surfaceDrawable.GetConsumerOnDraw()->GetTransform());
    if (transformType == GraphicTransformType::GRAPHIC_ROTATE_270 ||
        transformType == GraphicTransformType::GRAPHIC_ROTATE_90) {
        std::swap(boundsWidth, boundsHeight);
    }
    if ((bufferWidth != boundsWidth || bufferHeight != boundsHeight) &&
        params->GetFrameGravity() != Gravity::TOP_LEFT) {
        float xScale = (ROSEN_EQ(boundsWidth, 0.0f) ? 1.0f : bufferWidth / boundsWidth);
        float yScale = (ROSEN_EQ(boundsHeight, 0.0f) ? 1.0f : bufferHeight / boundsHeight);

        // If the scaling mode is SCALING_MODE_SCALE_TO_WINDOW, the scale should use smaller one.
        ScalingMode scalingMode = params->GetPreScalingMode();
        if (surfaceDrawable.GetConsumerOnDraw()->GetScalingMode(info.buffer->GetSeqNum(), scalingMode) == GSERROR_OK) {
            params->SetPreScalingMode(scalingMode);
        }
        if (scalingMode == ScalingMode::SCALING_MODE_SCALE_CROP) {
            float scale = std::min(xScale, yScale);
            info.srcRect.x = info.srcRect.x * scale;
            info.srcRect.y = info.srcRect.y * scale;
            if (ROSEN_EQ(scale, 0.f)) {
                return;
            }
            info.srcRect.w = (bufferWidth / scale - (boundsWidth - info.srcRect.w)) * scale;
            info.srcRect.h = (bufferHeight / scale - (boundsHeight - info.srcRect.h)) * scale;
        } else {
            RectI layerInfoSrcRect = { params->GetLayerInfo().srcRect.x, params->GetLayerInfo().srcRect.y,
                params->GetLayerInfo().srcRect.w, params->GetLayerInfo().srcRect.h };
            if (params->GetAbsDrawRect() == layerInfoSrcRect) {
                // If the SurfaceRenderNode is completely in the DisplayRenderNode,
                // we do not need to crop the buffer.
                info.srcRect.w = bufferWidth;
                info.srcRect.h = bufferHeight;
            } else {
                info.srcRect.x = info.srcRect.x * xScale;
                info.srcRect.y = info.srcRect.y * yScale;
                info.srcRect.w = std::min(static_cast<int32_t>(std::ceil(info.srcRect.w * xScale)), bufferWidth);
                info.srcRect.h = std::min(static_cast<int32_t>(std::ceil(info.srcRect.h * yScale)), bufferHeight);
            }
        }
    }
    Drawing::RectI srcRect(
        info.srcRect.x, info.srcRect.y, info.srcRect.w + info.srcRect.x, info.srcRect.h + info.srcRect.y);
    Drawing::RectI bufferRect(0, 0, bufferWidth, bufferHeight);
    if (srcRect.Intersect(bufferRect)) {
        info.srcRect.x = srcRect.GetLeft();
        info.srcRect.y = srcRect.GetTop();
        info.srcRect.w = srcRect.GetWidth();
        info.srcRect.h = srcRect.GetHeight();
    } else {
        info.srcRect = { 0, 0, 0, 0 };
    }

    RS_LOGD("RsDebug RSUniRenderComposerAdapter::GetComposerInfoSrcRect surfaceNode id:%{public}" PRIu64 ","\
            "srcRect [%{public}d %{public}d %{public}d %{public}d]",
            surfaceDrawable.GetId(), info.srcRect.x, info.srcRect.y, info.srcRect.w, info.srcRect.h);
}

bool RSUniRenderComposerAdapter::GetComposerInfoNeedClient(const ComposeInfo& info, RSRenderParams& params) const
{
    bool needClient = params.GetNeedClient();
    if (info.buffer->GetSurfaceBufferColorGamut() != static_cast<GraphicColorGamut>(screenInfo_.colorGamut)) {
        needClient = true;
    }
    return needClient;
}

void RSUniRenderComposerAdapter::DealWithNodeGravity(const RSSurfaceRenderNode& node, ComposeInfo& info) const
{
    const auto& property = node.GetRenderProperties();
    const float frameWidth = info.buffer->GetSurfaceBufferWidth();
    const float frameHeight = info.buffer->GetSurfaceBufferHeight();
    const float boundsWidth = property.GetBoundsWidth();
    const float boundsHeight = property.GetBoundsHeight();
    const Gravity frameGravity = property.GetFrameGravity();
    info.gravity = static_cast<int32_t>(frameGravity);
    // we do not need to do additional works for Gravity::RESIZE and if frameSize == boundsSize.
    if (frameGravity == Gravity::RESIZE || frameGravity == Gravity::TOP_LEFT ||
        (frameWidth == boundsWidth && frameHeight == boundsHeight)) {
        return;
    }
    auto traceInfo = node.GetName() + " DealWithNodeGravity " + std::to_string(static_cast<int>(frameGravity));
    RS_TRACE_NAME(traceInfo.c_str());
    // get current node's translate matrix and calculate gravity matrix.
    auto translateMatrix = Drawing::Matrix();
    translateMatrix.Translate(node.GetTotalMatrix().Get(Drawing::Matrix::Index::TRANS_X),
        std::ceil(node.GetTotalMatrix().Get(Drawing::Matrix::Index::TRANS_Y)));
    Drawing::Matrix gravityMatrix;
    (void)RSPropertiesPainter::GetGravityMatrix(frameGravity,
        RectF {0.0f, 0.0f, boundsWidth, boundsHeight}, frameWidth, frameHeight, gravityMatrix);
    // create a canvas to calculate new dstRect and new srcRect
    int32_t screenWidth = screenInfo_.phyWidth;
    int32_t screenHeight = screenInfo_.phyHeight;
    const auto screenRotation = screenInfo_.rotation;
    if (screenRotation == ScreenRotation::ROTATION_90 || screenRotation == ScreenRotation::ROTATION_270) {
        std::swap(screenWidth, screenHeight);
    }
    auto canvas = std::make_unique<Drawing::Canvas>(screenWidth, screenHeight);
    canvas->ConcatMatrix(translateMatrix);
    canvas->ConcatMatrix(gravityMatrix);
    Drawing::Rect clipRect;
    gravityMatrix.MapRect(clipRect, Drawing::Rect(0, 0, frameWidth, frameHeight));
    canvas->ClipRect(Drawing::Rect(0, 0, clipRect.GetWidth(), clipRect.GetHeight()), Drawing::ClipOp::INTERSECT);
    Drawing::RectI newDstRect = canvas->GetDeviceClipBounds();
    // we make the newDstRect as the intersection of new and old dstRect,
    // to deal with the situation that frameSize > boundsSize.
    newDstRect.Intersect(Drawing::RectI(
        info.dstRect.x, info.dstRect.y, info.dstRect.w + info.dstRect.x, info.dstRect.h + info.dstRect.y));
    auto localRect = canvas->GetLocalClipBounds();
    int left = std::clamp<int>(localRect.GetLeft(), 0, frameWidth);
    int top = std::clamp<int>(localRect.GetTop(), 0, frameHeight);
    int width = std::clamp<int>(localRect.GetWidth(), 0, frameWidth - left);
    int height = std::clamp<int>(localRect.GetHeight(), 0, frameHeight - top);
    GraphicIRect newSrcRect = {left, top, width, height};

    // log and apply new dstRect and srcRect
    RS_LOGD("RsDebug DealWithNodeGravity: name[%{public}s], gravity[%{public}d], oldDstRect[%{public}d %{public}d"
        " %{public}d %{public}d], newDstRect[%{public}d %{public}d %{public}d %{public}d], oldSrcRect[%{public}d"
        " %{public}d %{public}d %{public}d], newSrcRect[%{public}d %{public}d %{public}d %{public}d].",
        node.GetName().c_str(), static_cast<int>(frameGravity),
        info.dstRect.x, info.dstRect.y, info.dstRect.w, info.dstRect.h,
        newDstRect.GetLeft(), newDstRect.GetTop(), newDstRect.GetWidth(), newDstRect.GetHeight(),
        info.srcRect.x, info.srcRect.y, info.srcRect.w, info.srcRect.h,
        newSrcRect.x, newSrcRect.y, newSrcRect.w, newSrcRect.h);
    info.dstRect = {newDstRect.GetLeft(), newDstRect.GetTop(), newDstRect.GetWidth(), newDstRect.GetHeight()};
    info.srcRect = newSrcRect;
}

void RSUniRenderComposerAdapter::DealWithNodeGravity(
    const DrawableV2::RSSurfaceRenderNodeDrawable& surfaceDrawable, ComposeInfo& info) const
{
    auto& params = surfaceDrawable.GetRenderParams();
    if (!params) {
        return;
    }
    const float frameWidth = info.buffer->GetSurfaceBufferWidth();
    const float frameHeight = info.buffer->GetSurfaceBufferHeight();
    const float boundsWidth = params->GetBounds().GetWidth();
    const float boundsHeight = params->GetBounds().GetHeight();
    const Gravity frameGravity = params->GetFrameGravity();
    info.gravity = static_cast<int32_t>(frameGravity);
    // we do not need to do additional works for Gravity::RESIZE and if frameSize == boundsSize.
    if (frameGravity == Gravity::RESIZE || frameGravity == Gravity::TOP_LEFT ||
        (frameWidth == boundsWidth && frameHeight == boundsHeight)) {
        return;
    }

    auto traceInfo =
        surfaceDrawable.GetName() + " DealWithNodeGravity " + std::to_string(static_cast<int>(frameGravity));
    RS_TRACE_NAME(traceInfo.c_str());

    // get current node's translate matrix and calculate gravity matrix.
    auto translateMatrix = Drawing::Matrix();
    translateMatrix.Translate(params->GetTotalMatrix().Get(Drawing::Matrix::Index::TRANS_X),
        std::ceil(params->GetTotalMatrix().Get(Drawing::Matrix::Index::TRANS_Y)));
    Drawing::Matrix gravityMatrix;
    (void)RSPropertiesPainter::GetGravityMatrix(frameGravity,
        RectF {0.0f, 0.0f, boundsWidth, boundsHeight}, frameWidth, frameHeight, gravityMatrix);
    // create a canvas to calculate new dstRect and new srcRect
    int32_t screenWidth = screenInfo_.phyWidth;
    int32_t screenHeight = screenInfo_.phyHeight;
    const auto screenRotation = screenInfo_.rotation;
    if (screenRotation == ScreenRotation::ROTATION_90 || screenRotation == ScreenRotation::ROTATION_270) {
        std::swap(screenWidth, screenHeight);
    }
    auto canvas = std::make_unique<Drawing::Canvas>(screenWidth, screenHeight);
    canvas->ConcatMatrix(translateMatrix);
    canvas->ConcatMatrix(gravityMatrix);
    Drawing::Rect clipRect;
    gravityMatrix.MapRect(clipRect, Drawing::Rect(0, 0, frameWidth, frameHeight));
    canvas->ClipRect(Drawing::Rect(0, 0, clipRect.GetWidth(), clipRect.GetHeight()), Drawing::ClipOp::INTERSECT);
    Drawing::RectI newDstRect = canvas->GetDeviceClipBounds();
    // we make the newDstRect as the intersection of new and old dstRect,
    // to deal with the situation that frameSize > boundsSize.
    newDstRect.Intersect(Drawing::RectI(
        info.dstRect.x, info.dstRect.y, info.dstRect.w + info.dstRect.x, info.dstRect.h + info.dstRect.y));
    auto localRect = canvas->GetLocalClipBounds();
    int left = std::clamp<int>(localRect.GetLeft(), 0, frameWidth);
    int top = std::clamp<int>(localRect.GetTop(), 0, frameHeight);
    int width = std::clamp<int>(localRect.GetWidth(), 0, frameWidth - left);
    int height = std::clamp<int>(localRect.GetHeight(), 0, frameHeight - top);
    GraphicIRect newSrcRect = {left, top, width, height};

    // log and apply new dstRect and srcRect
    RS_LOGD("RsDebug DealWithNodeGravity: name[%{public}s], gravity[%{public}d], oldDstRect[%{public}d %{public}d"
        " %{public}d %{public}d], newDstRect[%{public}d %{public}d %{public}d %{public}d], oldSrcRect[%{public}d"
        " %{public}d %{public}d %{public}d], newSrcRect[%{public}d %{public}d %{public}d %{public}d].",
        surfaceDrawable.GetName().c_str(), static_cast<int>(frameGravity),
        info.dstRect.x, info.dstRect.y, info.dstRect.w, info.dstRect.h,
        newDstRect.GetLeft(), newDstRect.GetTop(), newDstRect.GetWidth(), newDstRect.GetHeight(),
        info.srcRect.x, info.srcRect.y, info.srcRect.w, info.srcRect.h,
        newSrcRect.x, newSrcRect.y, newSrcRect.w, newSrcRect.h);
    info.dstRect = {newDstRect.GetLeft(), newDstRect.GetTop(), newDstRect.GetWidth(), newDstRect.GetHeight()};
    info.srcRect = newSrcRect;
}

RectI RSUniRenderComposerAdapter::SrcRectRotateTransform(RSSurfaceRenderNode& node)
{
    auto consumer = node.GetRSSurfaceHandler()->GetConsumer();
    if (!consumer) {
        return node.GetSrcRect();
    }
    RectI srcRect = node.GetSrcRect();
    int left = srcRect.GetLeft();
    int top = srcRect.GetTop();
    int width = srcRect.GetWidth();
    int height = srcRect.GetHeight();
    GraphicTransformType transformType =
        RSBaseRenderUtil::GetRotateTransform(consumer->GetTransform());
    int boundsWidth = static_cast<int>(node.GetRenderProperties().GetBoundsWidth());
    int boundsHeight = static_cast<int>(node.GetRenderProperties().GetBoundsHeight());
    // Left > 0 means move xComponent to the left outside of the screen
    // Top > 0 means move xComponent to the top outside of the screen
    // The left and top should recalculate when transformType is not GRAPHIC_ROTATE_NONE
    // The width and height should exchange when transformType is GRAPHIC_ROTATE_270 and GRAPHIC_ROTATE_90
    switch (transformType) {
        case GraphicTransformType::GRAPHIC_ROTATE_270: {
            left = std::max(top, 0);
            top = std::max(boundsWidth - width - srcRect.GetLeft(), 0);
            srcRect = RectI {left, top, height, width};
            break;
        }
        case GraphicTransformType::GRAPHIC_ROTATE_180: {
            left = std::max(boundsWidth - width - left, 0);
            top = std::max(boundsHeight - height - top, 0);
            srcRect = RectI {left, top, width, height};
            break;
        }
        case GraphicTransformType::GRAPHIC_ROTATE_90: {
            left = std::max(boundsHeight - height - top, 0);
            top = std::max(srcRect.GetLeft(), 0);
            srcRect = RectI {left, top, height, width};
            break;
        }
        default: {
            break;
        }
    }
    RS_LOGD("BuildComposeInfo: srcRect transformed info NodeId:%{public}" PRIu64 ", XYWH:%{public}u,"
        "%{public}u,%{public}u,%{public}u", node.GetId(),
        srcRect.GetLeft(), srcRect.GetTop(), srcRect.GetWidth(), srcRect.GetHeight());
    return srcRect;
}

RectI RSUniRenderComposerAdapter::SrcRectRotateTransform(DrawableV2::RSSurfaceRenderNodeDrawable& surfaceDrawable)
{
    auto& params = surfaceDrawable.GetRenderParams();
    auto consumer = surfaceDrawable.GetConsumerOnDraw();
    if (!params || !consumer) {
        return {};
    }
    const auto& srcGraphicRect = params->GetLayerInfo().srcRect;
    RectI srcRect = {srcGraphicRect.x, srcGraphicRect.y, srcGraphicRect.w, srcGraphicRect.h};
    if (surfaceDrawable.GetConsumerOnDraw() == nullptr) {
        return srcRect;
    }
    int left = srcRect.GetLeft();
    int top = srcRect.GetTop();
    int width = srcRect.GetWidth();
    int height = srcRect.GetHeight();
    GraphicTransformType transformType =
        RSBaseRenderUtil::GetRotateTransform(consumer->GetTransform());
    const auto& bounds = params->GetBounds();
    int boundsWidth = static_cast<int>(bounds.GetWidth());
    int boundsHeight = static_cast<int>(bounds.GetHeight());
    // Left > 0 means move xComponent to the left outside of the screen
    // Top > 0 means move xComponent to the top outside of the screen
    // The left and top should recalculate when transformType is not GRAPHIC_ROTATE_NONE
    // The width and height should exchange when transformType is GRAPHIC_ROTATE_270 and GRAPHIC_ROTATE_90
    switch (transformType) {
        case GraphicTransformType::GRAPHIC_ROTATE_270: {
            left = std::max(top, 0);
            top = std::max(boundsWidth - width - srcRect.GetLeft(), 0);
            srcRect = RectI {left, top, height, width};
            break;
        }
        case GraphicTransformType::GRAPHIC_ROTATE_180: {
            left = std::max(boundsWidth - width - left, 0);
            top = std::max(boundsHeight - height - top, 0);
            srcRect = RectI {left, top, width, height};
            break;
        }
        case GraphicTransformType::GRAPHIC_ROTATE_90: {
            left = std::max(boundsHeight - height - top, 0);
            top = std::max(srcRect.GetLeft(), 0);
            srcRect = RectI {left, top, height, width};
            break;
        }
        default: {
            break;
        }
    }
    RS_LOGD("BuildComposeInfo: srcRect transformed info NodeId:%{public}" PRIu64 ", XYWH:%{public}u,"
        "%{public}u,%{public}u,%{public}u", surfaceDrawable.GetId(),
        srcRect.GetLeft(), srcRect.GetTop(), srcRect.GetWidth(), srcRect.GetHeight());
    return srcRect;
}

// private func, for RSSurfaceRenderNode.
ComposeInfo RSUniRenderComposerAdapter::BuildComposeInfo(RSSurfaceRenderNode& node) const
{
    ComposeInfo info {};

    auto surfaceHandler = node.GetRSSurfaceHandler();
    const auto& dstRect = node.GetDstRect();
    const auto srcRect = SrcRectRotateTransform(node);
    info.srcRect = GraphicIRect {srcRect.left_, srcRect.top_, srcRect.width_, srcRect.height_};
    info.dstRect = GraphicIRect {
        static_cast<int32_t>(static_cast<float>(dstRect.left_) * screenInfo_.GetRogWidthRatio()),
        static_cast<int32_t>(static_cast<float>(dstRect.top_) * screenInfo_.GetRogHeightRatio()),
        static_cast<int32_t>(static_cast<float>(dstRect.width_) * screenInfo_.GetRogWidthRatio()),
        static_cast<int32_t>(static_cast<float>(dstRect.height_) * screenInfo_.GetRogHeightRatio())
    };
    info.zOrder = surfaceHandler->GetGlobalZOrder();
    info.alpha.enGlobalAlpha = true;
    info.alpha.gAlpha = node.GetGlobalAlpha() * 255; // map gAlpha from float(0, 1) to uint8_t(0, 255).
    info.fence = surfaceHandler->GetAcquireFence();
    info.blendType = node.GetBlendType();
    const auto& buffer = surfaceHandler->GetBuffer();
    info.buffer = buffer;
    SetPreBufferInfo(*surfaceHandler, info);
    GetComposerInfoSrcRect(info, node);
    info.needClient = GetComposerInfoNeedClient(info, *node.GetRenderParams());
    DealWithNodeGravity(node, info);

    info.dstRect.x -= offsetX_;
    info.dstRect.y -= offsetY_;
    info.visibleRect = info.dstRect;
    std::vector<GraphicIRect> dirtyRects;
    const Rect& dirtyRect = surfaceHandler->GetDamageRegion();
    dirtyRects.emplace_back(GraphicIRect {dirtyRect.x, dirtyRect.y, dirtyRect.w, dirtyRect.h});
    info.dirtyRects = dirtyRects;
    auto totalMatrix = node.GetTotalMatrix();
    info.matrix = GraphicMatrix {totalMatrix.Get(Drawing::Matrix::Index::SCALE_X),
        totalMatrix.Get(Drawing::Matrix::Index::SKEW_X), totalMatrix.Get(Drawing::Matrix::Index::TRANS_X),
        totalMatrix.Get(Drawing::Matrix::Index::SKEW_Y), totalMatrix.Get(Drawing::Matrix::Index::SCALE_Y),
        totalMatrix.Get(Drawing::Matrix::Index::TRANS_Y), totalMatrix.Get(Drawing::Matrix::Index::PERSP_0),
        totalMatrix.Get(Drawing::Matrix::Index::PERSP_1), totalMatrix.Get(Drawing::Matrix::Index::PERSP_2)};

    const auto& property = node.GetRenderProperties();
    info.boundRect = { 0, 0,
        static_cast<int32_t>(property.GetBoundsWidth()), static_cast<int32_t>(property.GetBoundsHeight())};

    info.displayNit = node.GetDisplayNit();
    info.brightnessRatio = node.GetBrightnessRatio();
    return info;
}

ComposeInfo RSUniRenderComposerAdapter::BuildComposeInfo(DrawableV2::RSSurfaceRenderNodeDrawable& surfaceDrawable) const
{
    ComposeInfo info {};
    auto& params = surfaceDrawable.GetRenderParams();
    if (!params) {
        return info;
    }
    const auto& dstRect = params->GetLayerInfo().dstRect;
    const auto srcRect = SrcRectRotateTransform(surfaceDrawable);
    info.srcRect = GraphicIRect {srcRect.left_, srcRect.top_, srcRect.width_, srcRect.height_};
    info.dstRect = GraphicIRect { static_cast<int32_t>(static_cast<float>(dstRect.x) * screenInfo_.GetRogWidthRatio()),
        static_cast<int32_t>(static_cast<float>(dstRect.y) * screenInfo_.GetRogHeightRatio()),
        static_cast<int32_t>(static_cast<float>(dstRect.w) * screenInfo_.GetRogWidthRatio()),
        static_cast<int32_t>(static_cast<float>(dstRect.h) * screenInfo_.GetRogHeightRatio()) };
    info.zOrder = params->GetLayerInfo().zOrder;
    info.alpha.enGlobalAlpha = true;
    info.alpha.gAlpha = params->GetGlobalAlpha() * 255; // map gAlpha from float(0, 1) to uint8_t(0, 255).
    info.fence = params->GetAcquireFence();
    info.blendType = params->GetLayerInfo().blendType;
    const auto& buffer = params->GetBuffer();
    info.buffer = buffer;
    info.preBuffer = params->GetPreBuffer();
    GetComposerInfoSrcRect(info, surfaceDrawable);
    info.needClient = GetComposerInfoNeedClient(info, *params);
    DealWithNodeGravity(surfaceDrawable, info);

    info.dstRect.x -= offsetX_;
    info.dstRect.y -= offsetY_;
    info.visibleRect = info.dstRect;
    std::vector<GraphicIRect> dirtyRects;
    const Rect& dirtyRect = params->GetBufferDamage();
    dirtyRects.emplace_back(GraphicIRect {dirtyRect.x, dirtyRect.y, dirtyRect.w, dirtyRect.h});
    info.dirtyRects = dirtyRects;
    auto totalMatrix = params->GetTotalMatrix();
    info.matrix = GraphicMatrix {totalMatrix.Get(Drawing::Matrix::Index::SCALE_X),
        totalMatrix.Get(Drawing::Matrix::Index::SKEW_X), totalMatrix.Get(Drawing::Matrix::Index::TRANS_X),
        totalMatrix.Get(Drawing::Matrix::Index::SKEW_Y), totalMatrix.Get(Drawing::Matrix::Index::SCALE_Y),
        totalMatrix.Get(Drawing::Matrix::Index::TRANS_Y), totalMatrix.Get(Drawing::Matrix::Index::PERSP_0),
        totalMatrix.Get(Drawing::Matrix::Index::PERSP_1), totalMatrix.Get(Drawing::Matrix::Index::PERSP_2)};

    info.boundRect = { 0, 0,
        static_cast<int32_t>(params->GetBounds().GetWidth()), static_cast<int32_t>(params->GetBounds().GetHeight())};

    info.displayNit = surfaceDrawable.GetDisplayNit();
    info.brightnessRatio = surfaceDrawable.GetBrightnessRatio();
    return info;
}

bool RSUniRenderComposerAdapter::CheckStatusBeforeCreateLayer(RSSurfaceRenderNode& node) const
{
    if (output_ == nullptr) {
        RS_LOGE("RSUniRenderComposerAdapter::CheckStatusBeforeCreateLayer: output is nullptr");
        return false;
    }
    auto surfaceHandler = node.GetRSSurfaceHandler();
    if (!surfaceHandler) {
        return false;
    }
    const auto& buffer = surfaceHandler->GetBuffer();
    if (buffer == nullptr) {
        RS_LOGD("RsDebug RSUniRenderComposerAdapter::CheckStatusBeforeCreateLayer:"\
            " node(%{public}" PRIu64 ") has no available buffer.", node.GetId());
        return false;
    }
    const auto& dstRect = node.GetDstRect();
    const auto& srcRect = node.GetSrcRect();

    // check if the node's srcRect and dstRect are valid.
    if (srcRect.width_ <= 0 || srcRect.height_ <= 0 || dstRect.width_ <= 0 || dstRect.height_ <= 0) {
        return false;
    }

    auto& geoPtr = (node.GetRenderProperties().GetBoundsGeometry());
    if (geoPtr == nullptr) {
        RS_LOGW("RsDebug RSUniRenderComposerAdapter::CheckStatusBeforeCreateLayer:"\
            " node(%{public}" PRIu64 ")'s geoPtr is nullptr!", node.GetId());
        return false;
    }
    return true;
}

bool RSUniRenderComposerAdapter::CheckStatusBeforeCreateLayer(
    DrawableV2::RSSurfaceRenderNodeDrawable& surfaceDrawable) const
{
    if (output_ == nullptr) {
        RS_LOGE("RSUniRenderComposerAdapter::CheckStatusBeforeCreateLayer: output is nullptr");
        return false;
    }

    auto& params = surfaceDrawable.GetRenderParams();
    if (!params) {
        return false;
    }
    const auto& buffer = params->GetBuffer();
    if (buffer == nullptr) {
        RS_LOGD("RsDebug RSUniRenderComposerAdapter::CheckStatusBeforeCreateLayer:"\
            " node(%{public}" PRIu64 ") has no available buffer.", surfaceDrawable.GetId());
        return false;
    }
    const auto& dstRect = params->GetLayerInfo().dstRect;
    const auto& srcRect = params->GetLayerInfo().srcRect;
    // check if the node's srcRect and dstRect are valid.
    if (srcRect.w <= 0 || srcRect.h <= 0 || dstRect.w <= 0 || dstRect.h <= 0) {
        return false;
    }

    return true;
}

// private func, guarantee the layer is valid
void RSUniRenderComposerAdapter::LayerCrop(const LayerInfoPtr& layer) const
{
    GraphicIRect dstRect = layer->GetLayerSize();
    GraphicIRect srcRect = layer->GetCropRect();
    GraphicIRect originSrcRect = srcRect;

    RectI dstRectI(dstRect.x, dstRect.y, dstRect.w, dstRect.h);
    RectI screenRectI(0, 0, static_cast<int32_t>(screenInfo_.phyWidth),
        static_cast<int32_t>(screenInfo_.phyHeight));
    RectI resDstRect = dstRectI.IntersectRect(screenRectI);
    if (resDstRect == dstRectI) {
        return;
    }
    dstRect = {resDstRect.left_, resDstRect.top_, resDstRect.width_, resDstRect.height_};
    srcRect.x = resDstRect.IsEmpty() ? 0 : std::ceil((resDstRect.left_ - dstRectI.left_) *
        originSrcRect.w / dstRectI.width_);
    srcRect.y = resDstRect.IsEmpty() ? 0 : std::ceil((resDstRect.top_ - dstRectI.top_) *
        originSrcRect.h / dstRectI.height_);
    srcRect.w = dstRectI.IsEmpty() ? 0 : originSrcRect.w * resDstRect.width_ / dstRectI.width_;
    srcRect.h = dstRectI.IsEmpty() ? 0 : originSrcRect.h * resDstRect.height_ / dstRectI.height_;
    layer->SetLayerSize(dstRect);
    std::vector<GraphicIRect> dirtyRegions;
    dirtyRegions.emplace_back(srcRect);
    layer->SetDirtyRegions(dirtyRegions);
    layer->SetCropRect(srcRect);
    RS_LOGD("RsDebug RSUniRenderComposerAdapter::LayerCrop layer has been cropped dst[%{public}d %{public}d %{public}d"
        " %{public}d] src[%{public}d %{public}d %{public}d %{public}d]",
        dstRect.x, dstRect.y, dstRect.w, dstRect.h, srcRect.x, srcRect.y, srcRect.w, srcRect.h);
}

// private func, guarantee the layer is valid
void RSUniRenderComposerAdapter::LayerScaleDown(const LayerInfoPtr& layer, RSSurfaceRenderNode& node)
{
    const auto& buffer = layer->GetBuffer();
    const auto& surface = layer->GetSurface();
    if (buffer == nullptr || surface == nullptr) {
        return;
    }

    GraphicIRect dstRect = layer->GetLayerSize();
    GraphicIRect srcRect = layer->GetCropRect();

    uint32_t newWidth = static_cast<uint32_t>(srcRect.w);
    uint32_t newHeight = static_cast<uint32_t>(srcRect.h);
    uint32_t dstWidth = static_cast<uint32_t>(dstRect.w);
    uint32_t dstHeight = static_cast<uint32_t>(dstRect.h);

    // If surfaceRotation is not a multiple of 180, need to change the correspondence between width & height.
    // ScreenRotation has been processed in SetLayerSize, and do not change the width & height correspondence.
    int surfaceRotation = RSUniRenderUtil::GetRotationFromMatrix(node.GetTotalMatrix()) +
        RSBaseRenderUtil::RotateEnumToInt(RSBaseRenderUtil::GetRotateTransform(surface->GetTransform()));
    if (surfaceRotation % FLAT_ANGLE != 0) {
        std::swap(dstWidth, dstHeight);
    }

    uint32_t newWidthDstHeight = newWidth * dstHeight;
    uint32_t newHeightDstWidth = newHeight * dstWidth;
    if (newWidthDstHeight > newHeightDstWidth) {
        // too wide
        newWidth = dstWidth * newHeight / dstHeight;
    } else if (newWidthDstHeight < newHeightDstWidth) {
        // too tall
        newHeight = dstHeight * newWidth / dstWidth;
    } else {
        return;
    }

    uint32_t currentWidth = static_cast<uint32_t>(srcRect.w);
    uint32_t currentHeight = static_cast<uint32_t>(srcRect.h);
    if (newWidth < currentWidth) {
        // the crop is too wide
        uint32_t dw = currentWidth - newWidth;
        auto halfdw = dw / 2;
        srcRect.x += static_cast<int32_t>(halfdw);
        srcRect.w = static_cast<int32_t>(newWidth);
    } else {
        // thr crop is too tall
        uint32_t dh = currentHeight - newHeight;
        auto halfdh = dh / 2;
        srcRect.y += static_cast<int32_t>(halfdh);
        srcRect.h = static_cast<int32_t>(newHeight);
    }
    std::vector<GraphicIRect> dirtyRegions;
    dirtyRegions.emplace_back(srcRect);
    layer->SetDirtyRegions(dirtyRegions);
    layer->SetCropRect(srcRect);
    RS_LOGD("RsDebug RSUniRenderComposerAdapter::LayerScaleDown layer has been scaledown dst[%{public}d %{public}d"
        " %{public}d %{public}d] src[%{public}d %{public}d %{public}d %{public}d]",
        dstRect.x, dstRect.y, dstRect.w, dstRect.h, srcRect.x, srcRect.y, srcRect.w, srcRect.h);
}

void RSUniRenderComposerAdapter::LayerScaleDown(
    const LayerInfoPtr& layer, DrawableV2::RSSurfaceRenderNodeDrawable& surfaceDrawable)
{
    auto& params = surfaceDrawable.GetRenderParams();
    const auto& buffer = layer->GetBuffer();
    const auto& surface = layer->GetSurface();
    if (!params || !buffer || !surface) {
        return;
    }

    GraphicIRect dstRect = layer->GetLayerSize();
    GraphicIRect srcRect = layer->GetCropRect();

    uint32_t newWidth = static_cast<uint32_t>(srcRect.w);
    uint32_t newHeight = static_cast<uint32_t>(srcRect.h);
    uint32_t dstWidth = static_cast<uint32_t>(dstRect.w);
    uint32_t dstHeight = static_cast<uint32_t>(dstRect.h);

    // If surfaceRotation is not a multiple of 180, need to change the correspondence between width & height.
    // ScreenRotation has been processed in SetLayerSize, and do not change the width & height correspondence.
    int surfaceRotation = RSUniRenderUtil::GetRotationFromMatrix(params->GetTotalMatrix()) +
        RSBaseRenderUtil::RotateEnumToInt(RSBaseRenderUtil::GetRotateTransform(surface->GetTransform()));
    if (surfaceRotation % FLAT_ANGLE != 0) {
        std::swap(dstWidth, dstHeight);
    }

    uint32_t newWidthDstHeight = newWidth * dstHeight;
    uint32_t newHeightDstWidth = newHeight * dstWidth;

    if (newWidthDstHeight > newHeightDstWidth) {
        // too wide
        newWidth = dstWidth * newHeight / dstHeight;
    } else if (newWidthDstHeight < newHeightDstWidth) {
        // too tall
        newHeight = dstHeight * newWidth / dstWidth;
    } else {
        return;
    }

    uint32_t currentWidth = static_cast<uint32_t>(srcRect.w);
    uint32_t currentHeight = static_cast<uint32_t>(srcRect.h);

    if (newWidth < currentWidth) {
        // the crop is too wide
        uint32_t dw = currentWidth - newWidth;
        auto halfdw = dw / 2;
        srcRect.x += static_cast<int32_t>(halfdw);
        srcRect.w = static_cast<int32_t>(newWidth);
    } else {
        // thr crop is too tall
        uint32_t dh = currentHeight - newHeight;
        auto halfdh = dh / 2;
        srcRect.y += static_cast<int32_t>(halfdh);
        srcRect.h = static_cast<int32_t>(newHeight);
    }
    std::vector<GraphicIRect> dirtyRegions;
    dirtyRegions.emplace_back(srcRect);
    layer->SetDirtyRegions(dirtyRegions);
    layer->SetCropRect(srcRect);
    RS_LOGD("RsDebug RSUniRenderComposerAdapter::LayerScaleDown layer has been scaledown dst[%{public}d %{public}d"
        " %{public}d %{public}d] src[%{public}d %{public}d %{public}d %{public}d]",
        dstRect.x, dstRect.y, dstRect.w, dstRect.h, srcRect.x, srcRect.y, srcRect.w, srcRect.h);
}

// private func, guarantee the layer is valid
void RSUniRenderComposerAdapter::LayerScaleFit(const LayerInfoPtr& layer) const
{
    const auto& buffer = layer->GetBuffer();
    const auto& surface = layer->GetSurface();
    if (buffer == nullptr || surface == nullptr) {
        RS_LOGE("buffer or surface is nullptr");
        return;
    }

    GraphicIRect srcRect = layer->GetCropRect();
    GraphicIRect dstRect = layer->GetLayerSize();

    ScreenRotation rotation = screenInfo_.rotation;
    if (rotation == ScreenRotation::ROTATION_90 || rotation == ScreenRotation::ROTATION_270) {
        std::swap(srcRect.w, srcRect.h);
    }

    uint32_t newWidth = static_cast<uint32_t>(srcRect.w);
    uint32_t newHeight = static_cast<uint32_t>(srcRect.h);
    uint32_t dstWidth = static_cast<uint32_t>(dstRect.w);
    uint32_t dstHeight = static_cast<uint32_t>(dstRect.h);

    uint32_t newWidthDstHeight = newWidth * dstHeight;
    uint32_t newHeightDstWidth = newHeight * dstWidth;

    if (newWidthDstHeight > newHeightDstWidth) {
        newHeight = newHeight * dstWidth / newWidth;
        newWidth = dstWidth;
    } else if (newWidthDstHeight < newHeightDstWidth) {
        newWidth = newWidth * dstHeight / newHeight;
        newHeight = dstHeight;
    } else {
        newHeight = dstHeight;
        newWidth = dstWidth;
    }

    if (newWidth < dstWidth) {
        uint32_t dw = dstWidth - newWidth;
        auto halfdw = dw / 2;
        dstRect.x += static_cast<int32_t>(halfdw);
    } else if (newHeight < dstHeight) {
        uint32_t dh = dstHeight - newHeight;
        auto halfdh = dh / 2;
        dstRect.y += static_cast<int32_t>(halfdh);
    }
    dstRect.h = static_cast<int32_t>(newHeight);
    dstRect.w = static_cast<int32_t>(newWidth);
    layer->SetLayerSize(dstRect);
    RS_LOGD("RsDebug RSUniRenderComposerAdapter::LayerScaleFit layer has been scalefit dst[%{public}d %{public}d"
        " %{public}d %{public}d] src[%{public}d %{public}d %{public}d %{public}d]",
        dstRect.x, dstRect.y, dstRect.w, dstRect.h, srcRect.x, srcRect.y, srcRect.w, srcRect.h);
}

// private func
bool RSUniRenderComposerAdapter::IsOutOfScreenRegion(const ComposeInfo& info) const
{
    int32_t boundWidth = static_cast<int32_t>(screenInfo_.phyWidth);
    int32_t boundHeight = static_cast<int32_t>(screenInfo_.phyHeight);
    ScreenRotation rotation = screenInfo_.rotation;
    if (rotation == ScreenRotation::ROTATION_90 || rotation == ScreenRotation::ROTATION_270) {
        std::swap(boundWidth, boundHeight);
    }

    const auto& dstRect = info.dstRect;
    if (dstRect.x + dstRect.w <= 0 ||
        dstRect.x >= boundWidth ||
        dstRect.y + dstRect.h <= 0 ||
        dstRect.y >= boundHeight) {
        return true;
    }

    return false;
}

LayerInfoPtr RSUniRenderComposerAdapter::CreateBufferLayer(
    DrawableV2::RSSurfaceRenderNodeDrawable& surfaceDrawable) const
{
    auto& params = surfaceDrawable.GetRenderParams();
    if (!params) {
        return nullptr;
    }

    if (!CheckStatusBeforeCreateLayer(surfaceDrawable)) {
        return nullptr;
    }
    ComposeInfo info = BuildComposeInfo(surfaceDrawable);
    if (IsOutOfScreenRegion(info)) {
        RS_LOGD("RsDebug RSUniRenderComposerAdapter::CreateBufferLayer: node(%{public}" PRIu64
                ") out of screen region, no need to composite.",
            surfaceDrawable.GetId());
        return nullptr;
    }
    RS_TRACE_NAME_FMT("CreateLayer:%s XYWH[%d %d %d %d]", surfaceDrawable.GetName().c_str(),
        info.dstRect.x, info.dstRect.y, info.dstRect.w, info.dstRect.h);
    RS_LOGD("RsDebug RSUniRenderComposerAdapter::CreateBufferLayer surfaceNode id:%{public}" PRIu64 " name:[%{public}s]"
            " dst [%{public}d %{public}d %{public}d %{public}d] SrcRect [%{public}d %{public}d] rawbuffer [%{public}d"
            " %{public}d] surfaceBuffer [%{public}d %{public}d], z:%{public}d,"
            " globalZOrder:%{public}d, blendType = %{public}d",
        surfaceDrawable.GetId(), surfaceDrawable.GetName().c_str(), info.dstRect.x, info.dstRect.y, info.dstRect.w,
        info.dstRect.h, info.srcRect.w, info.srcRect.h, info.buffer->GetWidth(), info.buffer->GetHeight(),
        info.buffer->GetSurfaceBufferWidth(), info.buffer->GetSurfaceBufferHeight(), params->GetLayerInfo().zOrder,
        info.zOrder, info.blendType);
    LayerInfoPtr layer = HdiLayerInfo::CreateHdiLayerInfo();
    // planning surfaceNode prebuffer is set to hdilayerInfo, enable release prebuffer when HWC composition is ready
    SetComposeInfoToLayer(layer, info, surfaceDrawable.GetConsumerOnDraw());
    LayerRotate(layer, surfaceDrawable);
    LayerCrop(layer);
    ScalingMode scalingMode = params->GetPreScalingMode();
    const auto& buffer = layer->GetBuffer();
    const auto& surface = layer->GetSurface();
    if (buffer == nullptr || surface == nullptr) {
        RS_LOGE("buffer or surface is nullptr");
        return layer;
    }

    if (surface->GetScalingMode(buffer->GetSeqNum(), scalingMode) == GSERROR_OK) {
        params->SetPreScalingMode(scalingMode);
    }
    if (scalingMode == ScalingMode::SCALING_MODE_SCALE_CROP) {
        LayerScaleDown(layer, surfaceDrawable);
    } else if (scalingMode == ScalingMode::SCALING_MODE_SCALE_FIT) {
        LayerScaleFit(layer);
    }
    return layer;
}

LayerInfoPtr RSUniRenderComposerAdapter::CreateBufferLayer(RSSurfaceRenderNode& node) const
{
    if (!CheckStatusBeforeCreateLayer(node)) {
        return nullptr;
    }
    auto surfaceHandler = node.GetRSSurfaceHandler();
    if (!surfaceHandler) {
        return nullptr;
    }
    ComposeInfo info = BuildComposeInfo(node);
    if (IsOutOfScreenRegion(info)) {
        RS_LOGD("RsDebug RSUniRenderComposerAdapter::CreateBufferLayer: node(%{public}" PRIu64
                ") out of screen region, no need to composite.",
            node.GetId());
        return nullptr;
    }
    RS_TRACE_NAME_FMT("CreateLayer:%s XYWH[%d %d %d %d]", node.GetName().c_str(),
        info.dstRect.x, info.dstRect.y, info.dstRect.w, info.dstRect.h);
    RS_LOGD(
        "RsDebug RSUniRenderComposerAdapter::CreateBufferLayer surfaceNode id:%{public}" PRIu64 " name:[%{public}s]"
        " dst [%{public}d %{public}d %{public}d %{public}d] SrcRect [%{public}d %{public}d] rawbuffer [%{public}d"
        " %{public}d] surfaceBuffer [%{public}d %{public}d], z:%{public}f,"
        " globalZOrder:%{public}d, blendType = %{public}d",
        node.GetId(), node.GetName().c_str(), info.dstRect.x, info.dstRect.y, info.dstRect.w, info.dstRect.h,
        info.srcRect.w, info.srcRect.h, info.buffer->GetWidth(), info.buffer->GetHeight(),
        info.buffer->GetSurfaceBufferWidth(), info.buffer->GetSurfaceBufferHeight(),
        surfaceHandler->GetGlobalZOrder(), info.zOrder, info.blendType);
    LayerInfoPtr layer = HdiLayerInfo::CreateHdiLayerInfo();
    // planning surfaceNode prebuffer is set to hdilayerInfo, enable release prebuffer when HWC composition is ready
    SetComposeInfoToLayer(layer, info, surfaceHandler->GetConsumer());
    LayerRotate(layer, node);
    LayerCrop(layer);
    layer->SetNodeId(node.GetId());
    const auto nodeParams = static_cast<RSSurfaceRenderParams*>(node.GetRenderParams().get());
    ScalingMode scalingMode = nodeParams->GetPreScalingMode();
    const auto& buffer = layer->GetBuffer();
    const auto& surface = layer->GetSurface();
    if (buffer == nullptr || surface == nullptr) {
        RS_LOGE("buffer or surface is nullptr");
        return layer;
    }
    if (surface->GetScalingMode(buffer->GetSeqNum(), scalingMode) == GSERROR_OK) {
        nodeParams->SetPreScalingMode(scalingMode);
    }
    if (scalingMode == ScalingMode::SCALING_MODE_SCALE_CROP) {
        LayerScaleDown(layer, node);
    } else if (scalingMode == ScalingMode::SCALING_MODE_SCALE_FIT) {
        LayerScaleFit(layer);
    }
    return layer;
}

LayerInfoPtr RSUniRenderComposerAdapter::CreateLayer(DrawableV2::RSDisplayRenderNodeDrawable& displayDrawable)
{
    if (output_ == nullptr) {
        RS_LOGE("RSUniRenderComposerAdapter::CreateLayer: output is nullptr");
        return nullptr;
    }
    auto surfaceHandler = displayDrawable.GetMutableRSSurfaceHandlerOnDraw();
    if (!surfaceHandler) {
        return nullptr;
    }
    RS_LOGD("RSUniRenderComposerAdapter::CreateLayer displayNode id:%{public}" PRIu64 " available buffer:%{public}d",
        displayDrawable.GetId(), surfaceHandler->GetAvailableBufferCount());
    if (!displayDrawable.IsSurfaceCreated()) {
        sptr<IBufferConsumerListener> listener = new RSUniRenderListener(surfaceHandler);
        if (!displayDrawable.CreateSurface(listener)) {
            RS_LOGE("RSUniRenderComposerAdapter::CreateLayer CreateSurface failed");
            return nullptr;
        }
    }
    if (!RSBaseRenderUtil::ConsumeAndUpdateBuffer(*surfaceHandler) ||
        !surfaceHandler->GetBuffer()) {
        RS_LOGE("RSUniRenderComposerAdapter::CreateLayer RSDisplayRenderNodeDrawable consume buffer failed. %{public}d",
            !surfaceHandler->GetBuffer());
        return nullptr;
    }
    ComposeInfo info = BuildComposeInfo(displayDrawable);
    RS_OPTIONAL_TRACE_NAME_FMT("CreateLayer displayDrawable zorder:%d bufferFormat:%d", info.zOrder,
        surfaceHandler->GetBuffer()->GetFormat());
    RS_LOGD("RSUniRenderComposerAdapter::CreateLayer displayDrawable id:%{public}" PRIu64 " dst [%{public}d %{public}d"
            " %{public}d %{public}d] SrcRect [%{public}d %{public}d] rawbuffer [%{public}d %{public}d] surfaceBuffer"
            " [%{public}d %{public}d], globalZOrder:%{public}d, blendType = %{public}d, bufferFormat:%d",
        displayDrawable.GetId(), info.dstRect.x, info.dstRect.y, info.dstRect.w, info.dstRect.h,
        info.srcRect.w, info.srcRect.h,
        info.buffer->GetWidth(), info.buffer->GetHeight(), info.buffer->GetSurfaceBufferWidth(),
        info.buffer->GetSurfaceBufferHeight(), info.zOrder, info.blendType, surfaceHandler->GetBuffer()->GetFormat());
    LayerInfoPtr layer = HdiLayerInfo::CreateHdiLayerInfo();
    layer->SetUniRenderFlag(true);
    SetComposeInfoToLayer(layer, info, surfaceHandler->GetConsumer());
    LayerRotate(layer, displayDrawable);
    // do not crop or scale down for displayNode's layer.
    return layer;
}

LayerInfoPtr RSUniRenderComposerAdapter::CreateLayer(RSDisplayRenderNode& node)
{
    if (output_ == nullptr) {
        RS_LOGE("RSUniRenderComposerAdapter::CreateLayer: output is nullptr");
        return nullptr;
    }
    auto drawable = node.GetRenderDrawable();
    if (!drawable) {
        return nullptr;
    }
    auto displayDrawable = std::static_pointer_cast<DrawableV2::RSDisplayRenderNodeDrawable>(drawable);
    auto surfaceHandler = displayDrawable->GetMutableRSSurfaceHandlerOnDraw();
    RS_OPTIONAL_TRACE_NAME("RSUniRenderComposerAdapter::CreateLayer DisplayNode");
    if (!displayDrawable->IsSurfaceCreated()) {
        return nullptr;
    }
    RS_LOGD("RSUniRenderComposerAdapter::CreateLayer displayNode id:%{public}" PRIu64 " available buffer:%{public}d",
        node.GetId(), surfaceHandler->GetAvailableBufferCount());
    if (!RSBaseRenderUtil::ConsumeAndUpdateBuffer(*surfaceHandler) ||
        !surfaceHandler->GetBuffer()) {
        RS_LOGE("RSUniRenderComposerAdapter::CreateLayer consume buffer failed.");
        return nullptr;
    }
    ComposeInfo info = BuildComposeInfo(*displayDrawable);
    RS_OPTIONAL_TRACE_NAME_FMT("CreateLayer displayNode zorder:%d bufferFormat:%d", info.zOrder,
        surfaceHandler->GetBuffer()->GetFormat());
    RS_LOGD("RSUniRenderComposerAdapter::CreateLayer displayNode id:%{public}" PRIu64 " dst [%{public}d %{public}d"
        " %{public}d %{public}d] SrcRect [%{public}d %{public}d] rawbuffer [%{public}d %{public}d] surfaceBuffer"
        " [%{public}d %{public}d], globalZOrder:%{public}d, blendType = %{public}d, bufferFormat:%d",
        node.GetId(), info.dstRect.x, info.dstRect.y, info.dstRect.w, info.dstRect.h, info.srcRect.w, info.srcRect.h,
        info.buffer->GetWidth(), info.buffer->GetHeight(), info.buffer->GetSurfaceBufferWidth(),
        info.buffer->GetSurfaceBufferHeight(), info.zOrder, info.blendType, surfaceHandler->GetBuffer()->GetFormat());
    LayerInfoPtr layer = HdiLayerInfo::CreateHdiLayerInfo();
    layer->SetNodeId(node.GetId());
    layer->SetUniRenderFlag(true);
    SetComposeInfoToLayer(layer, info, surfaceHandler->GetConsumer());
    LayerRotate(layer, *displayDrawable);
    // do not crop or scale down for displayNode's layer.
    return layer;
}

LayerInfoPtr RSUniRenderComposerAdapter::CreateLayer(RSSurfaceRenderNode& node) const
{
    const auto& consumer = node.GetRSSurfaceHandler()->GetConsumer();
    if (consumer == nullptr) {
        RS_LOGE("RSUniRenderComposerAdapter::CreateLayer get consumer fail");
        return nullptr;
    }
    return CreateBufferLayer(node);
}

LayerInfoPtr RSUniRenderComposerAdapter::CreateLayer(DrawableV2::RSSurfaceRenderNodeDrawable& surfaceDrawable) const
{
    const auto consumer = surfaceDrawable.GetConsumerOnDraw();
    if (consumer == nullptr) {
        RS_LOGE("RSUniRenderComposerAdapter::CreateLayer get consumer fail");
        return nullptr;
    }
    return CreateBufferLayer(surfaceDrawable);
}

LayerInfoPtr RSUniRenderComposerAdapter::CreateLayer(RSRcdSurfaceRenderNode& node)
{
    if (output_ == nullptr) {
        RS_LOGE("RSUniRenderComposerAdapter::CreateLayer: output is nullptr");
        return nullptr;
    }

    if (node.GetBuffer() == nullptr) {
        RS_LOGE("RSUniRenderComposerAdapter::CreateLayer buffer is nullptr!");
        return nullptr;
    }

    ComposeInfo info = BuildComposeInfo(node);
    RS_LOGD("RSUniRenderComposerAdapter::ProcessRcdSurface rcdSurfaceNode id:%{public}" PRIu64 " DstRect"
        " [%{public}d %{public}d %{public}d %{public}d] SrcRect [%{public}d %{public}d %{public}d %{public}d]"
        " rawbuffer [%{public}d %{public}d] surfaceBuffer [%{public}d %{public}d], z-Order:%{public}d,"
        " blendType = %{public}d",
        node.GetId(), info.dstRect.x, info.dstRect.y, info.dstRect.w, info.dstRect.h,
        info.srcRect.x, info.srcRect.y, info.srcRect.w, info.srcRect.h,
        info.buffer->GetWidth(), info.buffer->GetHeight(), info.buffer->GetSurfaceBufferWidth(),
        info.buffer->GetSurfaceBufferHeight(), info.zOrder, info.blendType);
    LayerInfoPtr layer = HdiLayerInfo::CreateHdiLayerInfo();
    SetComposeInfoToLayer(layer, info, node.GetConsumer());
    auto drawable = node.GetRenderDrawable();
    if (drawable) {
        LayerRotate(layer, *drawable);
    }
    layer->SetNodeId(node.GetId());
    return layer;
}

static int GetSurfaceNodeRotation(RSBaseRenderNode& node)
{
    // only surface render node has the ability to rotate
    // the rotation of display render node is calculated as screen rotation
    if (node.GetType() != RSRenderNodeType::SURFACE_NODE) {
        return 0;
    }
    auto& surfaceNode = static_cast<RSSurfaceRenderNode&>(node);
    return RSUniRenderUtil::GetRotationFromMatrix(surfaceNode.GetTotalMatrix());
}

static int GetSurfaceNodeRotation(DrawableV2::RSRenderNodeDrawableAdapter& drawable)
{
    // only surface render node has the ability to rotate
    // the rotation of display render node is calculated as screen rotation
    if (drawable.GetNodeType() != RSRenderNodeType::SURFACE_NODE) {
        return 0;
    }

    auto& params = drawable.GetRenderParams();
    return params ? RSUniRenderUtil::GetRotationFromMatrix(params->GetTotalMatrix()) : 0;
}

static void SetLayerTransform(const LayerInfoPtr& layer, RSSurfaceRenderNode& node,
    const sptr<IConsumerSurface>& surface, ScreenRotation screenRotation)
{
    // screenRotation: anti-clockwise, surfaceNodeRotation: anti-clockwise, surfaceTransform: anti-clockwise
    // layerTransform: clockwise
    int surfaceNodeRotation = GetSurfaceNodeRotation(node);
    int totalRotation = (RSBaseRenderUtil::RotateEnumToInt(screenRotation) + surfaceNodeRotation +
        RSBaseRenderUtil::RotateEnumToInt(RSBaseRenderUtil::GetRotateTransform(surface->GetTransform()))) % 360;
    GraphicTransformType rotateEnum = RSBaseRenderUtil::RotateEnumToInt(totalRotation,
        RSBaseRenderUtil::GetFlipTransform(surface->GetTransform()));
    layer->SetTransform(rotateEnum);
}

static void SetLayerTransform(const LayerInfoPtr& layer, DrawableV2::RSRenderNodeDrawableAdapter& drawable,
    const sptr<IConsumerSurface>& surface, ScreenRotation screenRotation)
{
    // screenRotation: anti-clockwise, surfaceNodeRotation: anti-clockwise, surfaceTransform: anti-clockwise
    // layerTransform: clockwise
    int surfaceNodeRotation = GetSurfaceNodeRotation(drawable);
    int totalRotation = (RSBaseRenderUtil::RotateEnumToInt(screenRotation) + surfaceNodeRotation +
        RSBaseRenderUtil::RotateEnumToInt(RSBaseRenderUtil::GetRotateTransform(surface->GetTransform()))) % 360;
    GraphicTransformType rotateEnum = RSBaseRenderUtil::RotateEnumToInt(totalRotation,
        RSBaseRenderUtil::GetFlipTransform(surface->GetTransform()));
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
            RS_LOGD("RsDebug ScreenRotation 90,Before Rotate layer size [%{public}d %{public}d %{public}d %{public}d]",
                rect.x, rect.y, rect.w, rect.h);
            layer->SetLayerSize(GraphicIRect {rect.y, screenHeight - rect.x - rect.w, rect.h, rect.w});
            RS_LOGD("RsDebug ScreenRotation 90, After Rotate layer size [%{public}d %{public}d %{public}d %{public}d]",
                layer->GetLayerSize().x, layer->GetLayerSize().y, layer->GetLayerSize().w, layer->GetLayerSize().h);
            break;
        }
        case ScreenRotation::ROTATION_180: {
            RS_LOGD("RsDebug ScreenRotation 180, Before Rotate layer size [%{public}d %{public}d %{public}d"
                " %{public}d]", rect.x, rect.y, rect.w, rect.h);
            layer->SetLayerSize(
                GraphicIRect {screenWidth - rect.x - rect.w, screenHeight - rect.y - rect.h, rect.w, rect.h});
            RS_LOGD("RsDebug ScreenRotation 180,After Rotate layer size [%{public}d %{public}d %{public}d %{public}d]",
                layer->GetLayerSize().x, layer->GetLayerSize().y, layer->GetLayerSize().w, layer->GetLayerSize().h);
            break;
        }
        case ScreenRotation::ROTATION_270: {
            RS_LOGD("RsDebug ScreenRotation 270, Before Rotate layer size [%{public}d %{public}d %{public}d"
                " %{public}d]", rect.x, rect.y, rect.w, rect.h);
            layer->SetLayerSize(GraphicIRect {screenWidth - rect.y - rect.h, rect.x, rect.h, rect.w});
            RS_LOGD("RsDebug ScreenRotation 270,After Rotate layer size [%{public}d %{public}d %{public}d %{public}d]",
                layer->GetLayerSize().x, layer->GetLayerSize().y, layer->GetLayerSize().w, layer->GetLayerSize().h);
            break;
        }
        default:  {
            break;
        }
    }
}

// private func, guarantee the layer is valid
void RSUniRenderComposerAdapter::LayerRotate(
    const LayerInfoPtr& layer, RSSurfaceRenderNode& node) const
{
    auto surface = layer->GetSurface();
    if (surface == nullptr) {
        return;
    }
    SetLayerSize(layer, screenInfo_);
    SetLayerTransform(layer, node, surface, screenInfo_.rotation);
}


void RSUniRenderComposerAdapter::LayerRotate(
    const LayerInfoPtr& layer, DrawableV2::RSRenderNodeDrawableAdapter& drawable) const
{
    auto surface = layer->GetSurface();
    if (surface == nullptr) {
        return;
    }
    SetLayerSize(layer, screenInfo_);
    SetLayerTransform(layer, drawable, surface, screenInfo_.rotation);
}

} // namespace Rosen
} // namespace OHOS
