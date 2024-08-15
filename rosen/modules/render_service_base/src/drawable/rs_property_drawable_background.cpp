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

#include "drawable/rs_property_drawable_background.h"

#include "common/rs_background_thread.h"
#include "common/rs_obj_abs_geometry.h"
#include "common/rs_optional_trace.h"
#ifdef ROSEN_OHOS
#include "common/rs_common_tools.h"
#endif
#include "drawable/rs_property_drawable_utils.h"
#include "effect/runtime_blender_builder.h"
#ifdef ROSEN_OHOS
#include "native_buffer_inner.h"
#include "native_window.h"
#endif
#include "pipeline/rs_effect_render_node.h"
#include "pipeline/rs_recording_canvas.h"
#include "pipeline/rs_render_node.h"
#include "pipeline/rs_surface_render_node.h"
#include "pipeline/rs_task_dispatcher.h"
#include "platform/common/rs_log.h"
#if defined(ROSEN_OHOS) && defined(RS_ENABLE_VK)
#include "platform/ohos/backend/native_buffer_utils.h"
#include "platform/ohos/backend/rs_vulkan_context.h"
#endif

#if defined(ROSEN_OHOS) && defined(RS_ENABLE_VK)
#include "include/gpu/GrBackendSemaphore.h"
#endif

namespace OHOS::Rosen {
namespace DrawableV2 {
namespace {
constexpr int TRACE_LEVEL_TWO = 2;
#if defined(ROSEN_OHOS) && (defined(RS_ENABLE_VK))
constexpr uint8_t ASTC_HEADER_SIZE = 16;
#endif
}

RSDrawable::Ptr RSShadowDrawable::OnGenerate(const RSRenderNode& node)
{
    // skip shadow if not valid. ShadowMask is processed by foreground
    if (!node.GetRenderProperties().IsShadowValid() || node.GetRenderProperties().GetShadowMask()) {
        return nullptr;
    }
    RSDrawable::Ptr ret = nullptr;
    if (node.GetRenderProperties().GetShadowElevation() > 0.f ||
        node.GetRenderProperties().GetShadowColorStrategy() != SHADOW_COLOR_STRATEGY::COLOR_STRATEGY_NONE) {
        ret = std::make_shared<RSShadowDrawable>();
    } else {
        ret = std::make_shared<RSMaskShadowDrawable>();
    }
    if (ret->OnUpdate(node)) {
        return ret;
    }
    return nullptr;
};

bool RSShadowDrawable::OnUpdate(const RSRenderNode& node)
{
    const RSProperties& properties = node.GetRenderProperties();
    // skip shadow if not valid. ShadowMask is processed by foreground
    if (!properties.IsShadowValid() || properties.GetShadowMask()) {
        return false;
    }

    stagingPath_ = RSPropertyDrawableUtils::CreateShadowPath(properties.GetShadowPath(),
        properties.GetClipBounds(), properties.GetRRect());
    stagingOffsetX_ = properties.GetShadowOffsetX();
    stagingOffsetY_ = properties.GetShadowOffsetY();
    stagingElevation_ = properties.GetShadowElevation();
    stagingColor_ = properties.GetShadowColor();
    stagingIsFilled_ = properties.GetShadowIsFilled();
    stagingColorStrategy_ = properties.GetShadowColorStrategy();
    stagingRadius_ = properties.GetShadowRadius();
    needSync_ = true;
    return true;
}

void RSShadowDrawable::OnSync()
{
    if (!needSync_) {
        return;
    }
    path_ = std::move(stagingPath_);
    color_ = std::move(stagingColor_);
    offsetX_ = stagingOffsetX_;
    offsetY_ = stagingOffsetY_;
    elevation_ = stagingElevation_;
    isFilled_ = stagingIsFilled_;
    radius_ = stagingRadius_;
    colorStrategy_ = stagingColorStrategy_;
    needSync_ = false;
}

Drawing::RecordingCanvas::DrawFunc RSShadowDrawable::CreateDrawFunc() const
{
    auto ptr = std::static_pointer_cast<const RSShadowDrawable>(shared_from_this());
    return [ptr](Drawing::Canvas* canvas, const Drawing::Rect* rect) {
        // skip shadow if cache is enabled
        if (canvas->GetCacheType() == Drawing::CacheType::ENABLED) {
            ROSEN_LOGD("RSShadowDrawable::CreateDrawFunc cache type enabled.");
            return;
        }
        Drawing::Path path = ptr->path_;
        if (ptr->colorStrategy_ == SHADOW_COLOR_STRATEGY::COLOR_STRATEGY_NONE) {
            RSPropertyDrawableUtils::DrawShadow(canvas, path, ptr->offsetX_, ptr->offsetY_,
                ptr->elevation_, ptr->isFilled_, ptr->color_);
            return;
        }
        Color colorPicked = RSPropertyDrawableUtils::GetColorForShadowSyn(canvas, path,
            ptr->color_, ptr->colorStrategy_);
        if (ptr->radius_ > 0.f) {
            RSPropertyDrawableUtils::DrawShadowMaskFilter(canvas, path, ptr->offsetX_, ptr->offsetY_,
                ptr->radius_, colorPicked);
            return;
        }
        if (ptr->elevation_ > 0.f) {
            RSPropertyDrawableUtils::DrawShadow(canvas, path, ptr->offsetX_, ptr->offsetY_,
                ptr->elevation_, ptr->isFilled_, colorPicked);
            return;
        }
    };
}

bool RSMaskShadowDrawable::OnUpdate(const RSRenderNode& node)
{
    // skip shadow if not valid. ShadowMask is processed by foreground
    if (!node.GetRenderProperties().IsShadowValid() || node.GetRenderProperties().GetShadowMask()) {
        return false;
    }
    RSPropertyDrawCmdListUpdater updater(0, 0, this);
    Drawing::Canvas& canvas = *updater.GetRecordingCanvas();
    // skip shadow if cache is enabled
    if (canvas.GetCacheType() == Drawing::CacheType::ENABLED) {
        ROSEN_LOGD("RSPropertyDrawableUtils::Canvas cache type enabled.");
        return false;
    }

    const RSProperties& properties = node.GetRenderProperties();
    if (Rosen::RSSystemProperties::GetDebugTraceLevel() >= TRACE_LEVEL_TWO) {
        auto shadowRadius = properties.GetShadowRadius();
        auto shadowOffsetX = properties.GetShadowOffsetX();
        auto shadowOffsetY = properties.GetShadowOffsetY();
        RSPropertyDrawable::stagingPropertyDescription_ = "DrawShadow, Radius: " + std::to_string(shadowRadius) +
            " ShadowOffsetX: " + std::to_string(shadowOffsetX) +" ShadowOffsetY: " + std::to_string(shadowOffsetY);
    }
    Drawing::AutoCanvasRestore acr(canvas, true);
    Drawing::Path path = RSPropertyDrawableUtils::CreateShadowPath(properties.GetShadowPath(),
        properties.GetClipBounds(), properties.GetRRect());
    if (!properties.GetShadowIsFilled()) {
        canvas.ClipPath(path, Drawing::ClipOp::DIFFERENCE, true);
    }
    path.Offset(properties.GetShadowOffsetX(), properties.GetShadowOffsetY());
    Color spotColor = properties.GetShadowColor();
    // shadow alpha follow setting
    auto shadowAlpha = spotColor.GetAlpha();
    RSColor colorPicked;
    if (properties.GetColorPickerCacheTaskShadow() != nullptr &&
        properties.GetShadowColorStrategy() != SHADOW_COLOR_STRATEGY::COLOR_STRATEGY_NONE) {
        if (!properties.GetColorPickerCacheTaskShadow()->GetFirstGetColorFinished()) {
            shadowAlpha = 0;
        }
    } else {
        shadowAlpha = spotColor.GetAlpha();
        colorPicked = spotColor;
    }

    Drawing::Brush brush;
    brush.SetColor(Drawing::Color::ColorQuadSetARGB(
        shadowAlpha, colorPicked.GetRed(), colorPicked.GetGreen(), colorPicked.GetBlue()));
    brush.SetAntiAlias(true);
    Drawing::Filter filter;
    filter.SetMaskFilter(
        Drawing::MaskFilter::CreateBlurMaskFilter(Drawing::BlurType::NORMAL, properties.GetShadowRadius()));
    brush.SetFilter(filter);
    canvas.AttachBrush(brush);
    canvas.DrawPath(path);
    canvas.DetachBrush();
    return true;
}

Drawing::RecordingCanvas::DrawFunc RSMaskShadowDrawable::CreateDrawFunc() const
{
    auto ptr = std::static_pointer_cast<const RSMaskShadowDrawable>(shared_from_this());
    return [ptr](Drawing::Canvas* canvas, const Drawing::Rect* rect) {
        RS_OPTIONAL_TRACE_NAME_FMT_LEVEL(TRACE_LEVEL_TWO, "RSMaskShadowDrawable:: %s, bounds: %s",
            ptr->propertyDescription_.c_str(), rect->ToString().c_str());
        Drawing::AutoCanvasRestore rst(*canvas, true);
        if (RSSystemProperties::IsPhoneType()) {
            RSPropertyDrawableUtils::CeilMatrixTrans(canvas);
        }
        ptr->drawCmdList_->Playback(*canvas);
    };
}

RSDrawable::Ptr RSMaskDrawable::OnGenerate(const RSRenderNode& node)
{
    if (auto ret = std::make_shared<RSMaskDrawable>(); ret->OnUpdate(node)) {
        return std::move(ret);
    }
    return nullptr;
};

bool RSMaskDrawable::OnUpdate(const RSRenderNode& node)
{
    const RSProperties& properties = node.GetRenderProperties();
    std::shared_ptr<RSMask> mask = properties.GetMask();
    if (mask == nullptr) {
        ROSEN_LOGE("RSMaskDrawable::OnUpdate null mask");
        return false;
    }
    if (mask->IsSvgMask() && !mask->GetSvgDom() && !mask->GetSvgPicture()) {
        ROSEN_LOGE("RSMaskDrawable::OnUpdate not has Svg Mask property");
        return false;
    }

    RSPropertyDrawCmdListUpdater updater(0, 0, this);
    Drawing::Canvas& canvas = *updater.GetRecordingCanvas();
    Drawing::Rect maskBounds = RSPropertyDrawableUtils::Rect2DrawingRect(properties.GetBoundsRect());
    canvas.Save();
    Drawing::SaveLayerOps slr(&maskBounds, nullptr);
    canvas.SaveLayer(slr);
    uint32_t tmpLayer = canvas.GetSaveCount();

    Drawing::Brush maskfilter;
    Drawing::Filter filter;
    filter.SetColorFilter(Drawing::ColorFilter::CreateComposeColorFilter(
        *(Drawing::ColorFilter::CreateLumaColorFilter()), *(Drawing::ColorFilter::CreateSrgbGammaToLinear())));
    maskfilter.SetFilter(filter);
    Drawing::SaveLayerOps slrMask(&maskBounds, &maskfilter);
    canvas.SaveLayer(slrMask);
    if (mask->IsSvgMask()) {
        Drawing::AutoCanvasRestore maskSave(canvas, true);
        canvas.Translate(maskBounds.GetLeft() + mask->GetSvgX(), maskBounds.GetTop() + mask->GetSvgY());
        canvas.Scale(mask->GetScaleX(), mask->GetScaleY());
        if (mask->GetSvgDom()) {
            canvas.DrawSVGDOM(mask->GetSvgDom());
        } else if (mask->GetSvgPicture()) {
            canvas.DrawPicture(*mask->GetSvgPicture());
        }
    } else if (mask->IsGradientMask()) {
        Drawing::AutoCanvasRestore maskSave(canvas, true);
        canvas.Translate(maskBounds.GetLeft(), maskBounds.GetTop());
        Drawing::Rect rect = Drawing::Rect(0, 0, maskBounds.GetWidth(), maskBounds.GetHeight());
        canvas.AttachBrush(mask->GetMaskBrush());
        canvas.DrawRect(rect);
        canvas.DetachBrush();
    } else if (mask->IsPathMask()) {
        Drawing::AutoCanvasRestore maskSave(canvas, true);
        canvas.Translate(maskBounds.GetLeft(), maskBounds.GetTop());
        canvas.AttachBrush(mask->GetMaskBrush());
        canvas.AttachPen(mask->GetMaskPen());
        canvas.DrawPath(*mask->GetMaskPath());
        canvas.DetachBrush();
        canvas.DetachPen();
    } else if (mask->IsPixelMapMask() && mask->GetImage()) {
        Drawing::AutoCanvasRestore maskSave(canvas, true);
        canvas.DrawImage(*mask->GetImage(), 0.f, 0.f, Drawing::SamplingOptions());
    }

    // back to mask layer
    canvas.RestoreToCount(tmpLayer);
    // create content layer
    Drawing::Brush maskPaint;
    maskPaint.SetBlendMode(Drawing::BlendMode::SRC_IN);
    Drawing::SaveLayerOps slrContent(&maskBounds, &maskPaint);
    canvas.SaveLayer(slrContent);
    canvas.ClipRect(maskBounds, Drawing::ClipOp::INTERSECT, true);
    return true;
}

// ============================================================================
// Background
RSDrawable::Ptr RSBackgroundColorDrawable::OnGenerate(const RSRenderNode& node)
{
    if (auto ret = std::make_shared<RSBackgroundColorDrawable>(); ret->OnUpdate(node)) {
        return std::move(ret);
    }
    return nullptr;
};

bool RSBackgroundColorDrawable::OnUpdate(const RSRenderNode& node)
{
    const RSProperties& properties = node.GetRenderProperties();
    auto bgColor = properties.GetBackgroundColor();
    if (bgColor == RgbPalette::Transparent()) {
        return false;
    }

    // regenerate stagingDrawCmdList_
    RSPropertyDrawCmdListUpdater updater(0, 0, this);
    Drawing::Canvas& canvas = *updater.GetRecordingCanvas();
    Drawing::Brush brush;
    brush.SetColor(Drawing::Color(bgColor.AsArgbInt()));
    if (properties.IsBgBrightnessValid()) {
        if (Rosen::RSSystemProperties::GetDebugTraceLevel() >= TRACE_LEVEL_TWO) {
            RSPropertyDrawable::stagingPropertyDescription_ = properties.GetBgBrightnessDescription();
        }
        auto blender = RSPropertyDrawableUtils::MakeDynamicBrightnessBlender(
            properties.GetBgBrightnessParams().value());
        brush.SetBlender(blender);
    }

    // use drawrrect to avoid texture update in phone screen rotation scene
    if (RSSystemProperties::IsPhoneType() && RSSystemProperties::GetCacheEnabledForRotation()) {
        bool antiAlias = RSPropertiesPainter::GetBgAntiAlias() || !properties.GetCornerRadius().IsZero();
        brush.SetAntiAlias(antiAlias);
        canvas.AttachBrush(brush);
        if (properties.GetBorderColorIsTransparent() ||
            properties.GetBorderStyle().x_ != static_cast<uint32_t>(BorderStyle::SOLID)) {
            canvas.DrawRoundRect(RSPropertyDrawableUtils::RRect2DrawingRRect(properties.GetRRect()));
        } else {
            canvas.DrawRoundRect(RSPropertyDrawableUtils::RRect2DrawingRRect(properties.GetInnerRRect()));
        }
    } else {
        canvas.AttachBrush(brush);
        if (properties.GetBorderColorIsTransparent() ||
            properties.GetBorderStyle().x_ != static_cast<uint32_t>(BorderStyle::SOLID)) {
            canvas.DrawRect(RSPropertiesPainter::Rect2DrawingRect(properties.GetBoundsRect()));
        } else {
            canvas.DrawRect(RSPropertiesPainter::RRect2DrawingRRect(properties.GetInnerRRect()).GetRect());
        }
    }
    canvas.DetachBrush();
    return true;
}

RSDrawable::Ptr RSBackgroundShaderDrawable::OnGenerate(const RSRenderNode& node)
{
    if (auto ret = std::make_shared<RSBackgroundShaderDrawable>(); ret->OnUpdate(node)) {
        return std::move(ret);
    }
    return nullptr;
};

bool RSBackgroundShaderDrawable::OnUpdate(const RSRenderNode& node)
{
    const RSProperties& properties = node.GetRenderProperties();
    const auto& bgShader = properties.GetBackgroundShader();
    if (!bgShader) {
        return false;
    }

    // regenerate stagingDrawCmdList_
    RSPropertyDrawCmdListUpdater updater(0, 0, this);
    Drawing::Canvas& canvas = *updater.GetRecordingCanvas();
    Drawing::Brush brush;
    auto shaderEffect = bgShader->GetDrawingShader();
    brush.SetShaderEffect(shaderEffect);
    // use drawrrect to avoid texture update in phone screen rotation scene
    if (RSSystemProperties::IsPhoneType() && RSSystemProperties::GetCacheEnabledForRotation()) {
        bool antiAlias = RSPropertiesPainter::GetBgAntiAlias() || !properties.GetCornerRadius().IsZero();
        brush.SetAntiAlias(antiAlias);
        canvas.AttachBrush(brush);
        if (properties.GetBorderColorIsTransparent() ||
            properties.GetBorderStyle().x_ != static_cast<uint32_t>(BorderStyle::SOLID)) {
            canvas.DrawRoundRect(RSPropertyDrawableUtils::RRect2DrawingRRect(properties.GetRRect()));
        } else {
            canvas.DrawRoundRect(RSPropertyDrawableUtils::RRect2DrawingRRect(properties.GetInnerRRect()));
        }
    } else {
        canvas.AttachBrush(brush);
        if (properties.GetBorderColorIsTransparent() ||
            properties.GetBorderStyle().x_ != static_cast<uint32_t>(BorderStyle::SOLID)) {
            canvas.DrawRect(RSPropertiesPainter::Rect2DrawingRect(properties.GetBoundsRect()));
        } else {
            canvas.DrawRect(RSPropertiesPainter::RRect2DrawingRRect(properties.GetInnerRRect()).GetRect());
        }
    }
    canvas.DetachBrush();
    return true;
}

RSBackgroundImageDrawable::~RSBackgroundImageDrawable()
{
#if defined(ROSEN_OHOS) && defined(RS_ENABLE_VK)
    ReleaseNativeWindowBuffer();
#endif
}

RSDrawable::Ptr RSBackgroundImageDrawable::OnGenerate(const RSRenderNode& node)
{
    if (auto ret = std::make_shared<RSBackgroundImageDrawable>(); ret->OnUpdate(node)) {
        return std::move(ret);
    }
    return nullptr;
};

#if defined(ROSEN_OHOS) && defined(RS_ENABLE_VK)
Drawing::ColorType GetColorTypeFromVKFormat(VkFormat vkFormat)
{
    if (RSSystemProperties::GetGpuApiType() != GpuApiType::VULKAN &&
        RSSystemProperties::GetGpuApiType() != GpuApiType::DDGR) {
        return Drawing::COLORTYPE_RGBA_8888;
    }
    switch (vkFormat) {
        case VK_FORMAT_R8G8B8A8_UNORM:
            return Drawing::COLORTYPE_RGBA_8888;
        case VK_FORMAT_R16G16B16A16_SFLOAT:
            return Drawing::COLORTYPE_RGBA_F16;
        case VK_FORMAT_R5G6B5_UNORM_PACK16:
            return Drawing::COLORTYPE_RGB_565;
        default:
            return Drawing::COLORTYPE_RGBA_8888;
    }
}
#endif

#if defined(ROSEN_OHOS) && defined(RS_ENABLE_VK)
void RSBackgroundImageDrawable::ReleaseNativeWindowBuffer()
{
    if (RSSystemProperties::GetGpuApiType() == GpuApiType::VULKAN ||
        RSSystemProperties::GetGpuApiType() == GpuApiType::DDGR) {
        if (nativeWindowBuffer_ == nullptr && cleanUpHelper_ == nullptr) {
            return;
        }
        RSTaskDispatcher::GetInstance().PostTask(
            tid_, [nativeWindowBuffer = nativeWindowBuffer_, cleanUpHelper = cleanUpHelper_]() {
                if (nativeWindowBuffer != nullptr) {
                    DestroyNativeWindowBuffer(nativeWindowBuffer);
                }
                if (cleanUpHelper != nullptr) {
                    NativeBufferUtils::DeleteVkImage(cleanUpHelper);
                }
            });
        nativeWindowBuffer_ = nullptr;
        cleanUpHelper_ = nullptr;
    }
}

std::shared_ptr<Drawing::Image> RSBackgroundImageDrawable::MakeFromTextureForVK(
    Drawing::Canvas& canvas, SurfaceBuffer* surfaceBuffer)
{
    if (RSSystemProperties::GetGpuApiType() != GpuApiType::VULKAN &&
        RSSystemProperties::GetGpuApiType() != GpuApiType::DDGR) {
        return nullptr;
    }
    if (surfaceBuffer == nullptr || surfaceBuffer->GetBufferHandle() == nullptr) {
        RS_LOGE("MakeFromTextureForVK surfaceBuffer is nullptr or buffer handle is nullptr");
        return nullptr;
    }
    std::shared_ptr<Media::PixelMap> pixelMap = bgImage_->GetPixelMap();
    if (pixelMapId_ != pixelMap->GetUniqueId()) {
        backendTexture_ = {};
        ReleaseNativeWindowBuffer();
        sptr<SurfaceBuffer> sfBuffer(surfaceBuffer);
        nativeWindowBuffer_ = CreateNativeWindowBufferFromSurfaceBuffer(&sfBuffer);
        if (!nativeWindowBuffer_) {
            RS_LOGE("MakeFromTextureForVK create native window buffer fail");
            return nullptr;
        }
        pixelMapId_ = pixelMap->GetUniqueId();
    }
    bool isProtected = (surfaceBuffer->GetUsage() & BUFFER_USAGE_PROTECTED) != 0;
    if (!backendTexture_.IsValid() || isProtected) {
        backendTexture_ = NativeBufferUtils::MakeBackendTextureFromNativeBuffer(
            nativeWindowBuffer_, surfaceBuffer->GetWidth(), surfaceBuffer->GetHeight(), isProtected);
        if (backendTexture_.IsValid()) {
            auto vkTextureInfo = backendTexture_.GetTextureInfo().GetVKTextureInfo();
            cleanUpHelper_ = new NativeBufferUtils::VulkanCleanupHelper(
                RsVulkanContext::GetSingleton(), vkTextureInfo->vkImage, vkTextureInfo->vkAlloc.memory);
        } else {
            return nullptr;
        }
        tid_ = gettid();
    }

    std::shared_ptr<Drawing::Image> dmaImage = std::make_shared<Drawing::Image>();
    auto vkTextureInfo = backendTexture_.GetTextureInfo().GetVKTextureInfo();
    Drawing::ColorType colorType = GetColorTypeFromVKFormat(vkTextureInfo->format);
    Drawing::BitmapFormat bitmapFormat = { colorType, Drawing::AlphaType::ALPHATYPE_PREMUL };
    if (!dmaImage->BuildFromTexture(*canvas.GetGPUContext(), backendTexture_.GetTextureInfo(),
        Drawing::TextureOrigin::TOP_LEFT, bitmapFormat, nullptr, NativeBufferUtils::DeleteVkImage,
        cleanUpHelper_->Ref())) {
        RS_LOGE("MakeFromTextureForVK build image failed");
        return nullptr;
    }
    return dmaImage;
}

void RSBackgroundImageDrawable::SetCompressedDataForASTC()
{
    std::shared_ptr<Media::PixelMap> pixelMap = bgImage_->GetPixelMap();
    std::shared_ptr<Drawing::Data> fileData = std::make_shared<Drawing::Data>();
    if (!pixelMap || !fileData || !pixelMap->GetFd()) {
        RS_LOGE("SetCompressedDataForASTC fail, data is null");
        return;
    }
    // After RS is switched to Vulkan, the judgment of GpuApiType can be deleted.
    if (pixelMap->GetAllocatorType() == Media::AllocatorType::DMA_ALLOC &&
        RSSystemProperties::GetGpuApiType() == GpuApiType::VULKAN) {
        if (!nativeWindowBuffer_) {
            sptr<SurfaceBuffer> surfaceBuf(reinterpret_cast<SurfaceBuffer *>(pixelMap->GetFd()));
            nativeWindowBuffer_ = CreateNativeWindowBufferFromSurfaceBuffer(&surfaceBuf);
        }
        OH_NativeBuffer* nativeBuffer = OH_NativeBufferFromNativeWindowBuffer(nativeWindowBuffer_);
        if (nativeBuffer == nullptr || !fileData->BuildFromOHNativeBuffer(nativeBuffer, pixelMap->GetCapacity())) {
            RS_LOGE("SetCompressedDataForASTC data BuildFromOHNativeBuffer fail");
            return;
        }
    } else {
        const void* data = pixelMap->GetPixels();
        if (pixelMap->GetCapacity() > ASTC_HEADER_SIZE &&
            (data == nullptr || !fileData->BuildWithoutCopy((void*)((char*) data + ASTC_HEADER_SIZE),
            pixelMap->GetCapacity() - ASTC_HEADER_SIZE))) {
            RS_LOGE("SetCompressedDataForASTC data BuildWithoutCopy fail");
            return;
        }
    }
    bgImage_->SetCompressData(fileData);
}
#endif

bool RSBackgroundImageDrawable::OnUpdate(const RSRenderNode& node)
{
    const RSProperties& properties = node.GetRenderProperties();
    stagingBgImage_ = properties.GetBgImage();
    if (!stagingBgImage_) {
        return false;
    }

    stagingBoundsRect_ = RSPropertyDrawableUtils::Rect2DrawingRect(properties.GetBoundsRect());
    auto innerRect = properties.GetBgImageInnerRect();
    stagingBgImage_->SetDstRect(properties.GetBgImageRect());
    stagingBgImage_->SetInnerRect(std::make_optional<Drawing::RectI>(
        innerRect.x_, innerRect.y_, innerRect.x_ + innerRect.z_, innerRect.y_ + innerRect.w_));
    needSync_ = true;
    return true;
}

void RSBackgroundImageDrawable::OnSync()
{
    if (!needSync_) {
        return;
    }
    bgImage_ = std::move(stagingBgImage_);
    boundsRect_ = stagingBoundsRect_;
    needSync_ = false;
}

Drawing::RecordingCanvas::DrawFunc RSBackgroundImageDrawable::CreateDrawFunc() const
{
    auto ptr = std::const_pointer_cast<RSBackgroundImageDrawable>(
        std::static_pointer_cast<const RSBackgroundImageDrawable>(shared_from_this()));
    return [ptr](Drawing::Canvas* canvas, const Drawing::Rect* rect) {
        Drawing::Brush brush;
        canvas->AttachBrush(brush);
        auto bgImage = ptr->bgImage_;
        if (!bgImage) {
            return;
        }
#if defined(ROSEN_OHOS) && defined(RS_ENABLE_VK)
        if (bgImage->GetPixelMap() && !bgImage->GetPixelMap()->IsAstc() &&
            bgImage->GetPixelMap()->GetAllocatorType() == Media::AllocatorType::DMA_ALLOC) {
            if (!bgImage->GetPixelMap()->GetFd()) {
                return;
            }
            auto dmaImage =
                ptr->MakeFromTextureForVK(*canvas, reinterpret_cast<SurfaceBuffer*>(bgImage->GetPixelMap()->GetFd()));
            bgImage->SetDmaImage(dmaImage);
        }
        if (bgImage->GetPixelMap() && bgImage->GetPixelMap()->IsAstc()) {
            ptr->SetCompressedDataForASTC();
        }
#endif
        bgImage->CanvasDrawImage(*canvas, ptr->boundsRect_, Drawing::SamplingOptions(), true);
        canvas->DetachBrush();
    };
}

RSDrawable::Ptr RSBackgroundFilterDrawable::OnGenerate(const RSRenderNode& node)
{
    auto& rsFilter = node.GetRenderProperties().GetBackgroundFilter();
    if (rsFilter == nullptr) {
        return nullptr;
    }

    RSDrawable::Ptr filterDrawable = nullptr;
    if (node.IsInstanceOf<RSEffectRenderNode>()) {
        filterDrawable = std::make_shared<RSBackgroundEffectDrawable>();
    } else {
        filterDrawable = std::make_shared<RSBackgroundFilterDrawable>();
    }
    if (filterDrawable->OnUpdate(node)) {
        return filterDrawable;
    }
    return nullptr;
}

bool RSBackgroundFilterDrawable::OnUpdate(const RSRenderNode& node)
{
    nodeId_ = node.GetId();
    auto& rsFilter = node.GetRenderProperties().GetBackgroundFilter();
    if (rsFilter == nullptr) {
        return false;
    }
    RecordFilterInfos(rsFilter);
    needSync_ = true;
    stagingFilter_ = rsFilter;
    return true;
}

bool RSBackgroundEffectDrawable::OnUpdate(const RSRenderNode& node)
{
    nodeId_ = node.GetId();
    auto& rsFilter = node.GetRenderProperties().GetBackgroundFilter();
    if (rsFilter == nullptr) {
        return false;
    }
    RecordFilterInfos(rsFilter);
    needSync_ = true;
    stagingFilter_ = rsFilter;
    return true;
}

void RSBackgroundEffectDrawable::OnSync()
{
    RSFilterDrawable::OnSync();
}

Drawing::RecordingCanvas::DrawFunc RSBackgroundEffectDrawable::CreateDrawFunc() const
{
    auto ptr = std::static_pointer_cast<const RSBackgroundEffectDrawable>(shared_from_this());
    return [ptr](Drawing::Canvas* canvas, const Drawing::Rect* rect) {
        if (canvas == nullptr || rect == nullptr) {
            RS_LOGE("RSBackgroundEffectDrawable::DrawBackgroundEffect data error");
            return;
        }
        auto paintFilterCanvas = static_cast<RSPaintFilterCanvas*>(canvas);
        Drawing::AutoCanvasRestore acr(*canvas, true);
        paintFilterCanvas->ClipRect(*rect);
        RS_TRACE_NAME_FMT("RSBackgroundEffectDrawable::DrawBackgroundEffect nodeId[%lld]", ptr->nodeId_);
        RSPropertyDrawableUtils::DrawBackgroundEffect(
            paintFilterCanvas, ptr->filter_, ptr->cacheManager_, ptr->renderClearFilteredCacheAfterDrawing_);
    };
}

RSDrawable::Ptr RSUseEffectDrawable::OnGenerate(const RSRenderNode& node)
{
    if (!node.GetRenderProperties().GetUseEffect()) {
        return nullptr;
    }
    // Find effect render node
    auto parentNode = node.GetParent().lock();
    while (parentNode && !parentNode->IsInstanceOf<RSEffectRenderNode>()) {
        parentNode = parentNode->GetParent().lock();
    }
    DrawableV2::RSRenderNodeDrawableAdapter::SharedPtr effectRenderNodeDrawable = nullptr;
    if (parentNode) {
        effectRenderNodeDrawable = parentNode->GetRenderDrawable();
    } else {
        ROSEN_LOGD("RSUseEffectDrawable::OnGenerate: find EffectRenderNode failed.");
    }
    return std::make_shared<RSUseEffectDrawable>(effectRenderNodeDrawable);
}

bool RSUseEffectDrawable::OnUpdate(const RSRenderNode& node)
{
    if (!node.GetRenderProperties().GetUseEffect()) {
        return false;
    }
    return true;
}

Drawing::RecordingCanvas::DrawFunc RSUseEffectDrawable::CreateDrawFunc() const
{
    auto ptr = std::static_pointer_cast<const RSUseEffectDrawable>(shared_from_this());
    return [ptr](Drawing::Canvas* canvas, const Drawing::Rect* rect) {
        if (!RSSystemProperties::GetEffectMergeEnabled()) {
            return;
        }
        auto paintFilterCanvas = static_cast<RSPaintFilterCanvas*>(canvas);
        if (paintFilterCanvas == nullptr) {
            return;
        }
        const auto& effectData = paintFilterCanvas->GetEffectData();
        if (effectData == nullptr || effectData->cachedImage_ == nullptr) {
            ROSEN_LOGD("RSPropertyDrawableUtils::DrawUseEffect effectData null, try to generate.");
            auto drawable = ptr->effectRenderNodeDrawableWeakRef_.lock();
            if (!drawable) {
                return;
            }
            RS_TRACE_NAME_FMT("RSPropertyDrawableUtils::DrawUseEffect Generate effectData");
            bool disableFilterCache = paintFilterCanvas->GetDisableFilterCache();
            paintFilterCanvas->SetDisableFilterCache(true);
            int8_t index = drawable->drawCmdIndex_.backgroundFilterIndex_;
            drawable->DrawImpl(*paintFilterCanvas, *rect, index);
            paintFilterCanvas->SetDisableFilterCache(disableFilterCache);
        }
        RSPropertyDrawableUtils::DrawUseEffect(paintFilterCanvas);
    };
}

RSDrawable::Ptr RSDynamicLightUpDrawable::OnGenerate(const RSRenderNode& node)
{
    const RSProperties& properties = node.GetRenderProperties();
    if (!properties.IsDynamicLightUpValid()) {
        return nullptr;
    }

    return std::make_shared<RSDynamicLightUpDrawable>(
        properties.GetDynamicLightUpRate().value(), properties.GetDynamicLightUpDegree().value());
};

bool RSDynamicLightUpDrawable::OnUpdate(const RSRenderNode& node)
{
    const RSProperties& properties = node.GetRenderProperties();
    if (!properties.IsDynamicLightUpValid()) {
        return false;
    }

    stagingDynamicLightUpRate_ = properties.GetDynamicLightUpRate().value();
    stagingDynamicLightUpDeg_ = properties.GetDynamicLightUpDegree().value();
    needSync_ = true;

    return true;
}

void RSDynamicLightUpDrawable::OnSync()
{
    if (!needSync_) {
        return;
    }
    dynamicLightUpRate_ = stagingDynamicLightUpRate_;
    dynamicLightUpDeg_ = stagingDynamicLightUpDeg_;
    needSync_ = false;
}

Drawing::RecordingCanvas::DrawFunc RSDynamicLightUpDrawable::CreateDrawFunc() const
{
    auto ptr = std::static_pointer_cast<const RSDynamicLightUpDrawable>(shared_from_this());
    return [ptr](Drawing::Canvas* canvas, const Drawing::Rect* rect) {
        if (canvas->GetUICapture()) {
            return;
        }
        auto paintFilterCanvas = static_cast<RSPaintFilterCanvas*>(canvas);
        auto alpha = paintFilterCanvas->GetAlpha();
        auto blender = RSDynamicLightUpDrawable::MakeDynamicLightUpBlender(
            ptr->dynamicLightUpRate_, ptr->dynamicLightUpDeg_, alpha);
        RS_OPTIONAL_TRACE_NAME_FMT_LEVEL(TRACE_LEVEL_TWO,
            "RSDynamicLightUpDrawable::DrawDynamicLightUp, rate: %f, degree: %f, bounds: %s", ptr->dynamicLightUpRate_,
            ptr->dynamicLightUpDeg_, rect->ToString().c_str());
        Drawing::Brush brush;
        brush.SetBlender(blender);
        paintFilterCanvas->DrawBackground(brush);
    };
}

std::shared_ptr<Drawing::Blender> RSDynamicLightUpDrawable::MakeDynamicLightUpBlender(
    float rate, float degree, float alpha)
{
    static constexpr char prog[] = R"(
        uniform float dynamicLightUpRate;
        uniform float dynamicLightUpDeg;

        vec4 main(vec4 drawing_src, vec4 drawing_dst) {
            float x = 0.299 * drawing_dst.r + 0.587 * drawing_dst.g + 0.114 * drawing_dst.b;
            float y = (0 - dynamicLightUpRate) * x + dynamicLightUpDeg;
            float R = clamp((drawing_dst.r + y), 0.0, 1.0);
            float G = clamp((drawing_dst.g + y), 0.0, 1.0);
            float B = clamp((drawing_dst.b + y), 0.0, 1.0);
            return vec4(R, G, B, 1.0);
        }
    )";
    static std::shared_ptr<Drawing::RuntimeEffect> dynamicLightUpBlenderEffect_ = nullptr;

    if (dynamicLightUpBlenderEffect_ == nullptr) {
        dynamicLightUpBlenderEffect_ = Drawing::RuntimeEffect::CreateForBlender(prog);
        if (dynamicLightUpBlenderEffect_ == nullptr) {
            ROSEN_LOGE("RSDynamicLightUpDrawable::MakeDynamicLightUpBlender effect error!");
            return nullptr;
        }
    }
    auto builder = std::make_shared<Drawing::RuntimeBlenderBuilder>(dynamicLightUpBlenderEffect_);
    builder->SetUniform("dynamicLightUpRate", rate * alpha);
    builder->SetUniform("dynamicLightUpDeg", degree * alpha);
    return builder->MakeBlender();
}
} // namespace DrawableV2
} // namespace OHOS::Rosen
