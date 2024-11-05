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

#include "render/rs_image.h"

#include "common/rs_common_tools.h"
#include "pipeline/rs_recording_canvas.h"
#include "pipeline/sk_resource_manager.h"
#include "platform/common/rs_log.h"
#include "platform/common/rs_system_properties.h"
#include "property/rs_properties_painter.h"
#include "render/rs_image_cache.h"
#include "render/rs_pixel_map_util.h"
#include "rs_trace.h"
#include "sandbox_utils.h"
#include "rs_profiler.h"

#ifdef USE_VIDEO_PROCESSING_ENGINE
#include "render/rs_colorspace_convert.h"
#endif

namespace OHOS {
namespace Rosen {
namespace {
constexpr int32_t CORNER_SIZE = 4;
constexpr float CENTER_ALIGNED_FACTOR = 2.f;
}

RSImage::~RSImage()
{}

inline void ReMapPixelMap(std::shared_ptr<Media::PixelMap>& pixelMap)
{
#ifdef ROSEN_OHOS
    if (pixelMap && pixelMap->IsUnMap()) {
        pixelMap->ReMap();
    }
#endif
}

bool RSImage::IsEqual(const RSImage& other) const
{
    bool radiusEq = true;
    for (auto i = 0; i < CORNER_SIZE; i++) {
        radiusEq &= (radius_[i] == other.radius_[i]);
    }
    return (image_ == other.image_) && (pixelMap_ == other.pixelMap_) &&
           (imageFit_ == other.imageFit_) && (imageRepeat_ == other.imageRepeat_) &&
           (scale_ == other.scale_) && radiusEq && (compressData_ == other.compressData_);
}

bool RSImage::HDRConvert(const Drawing::SamplingOptions& sampling, Drawing::Canvas& canvas)
{
#ifdef USE_VIDEO_PROCESSING_ENGINE
    // HDR disable
    if (!RSSystemProperties::GetHDRImageEnable()) {
        return false;
    }

    if (pixelMap_ == nullptr || image_ == nullptr) {
        RS_LOGE("bhdr pixelMap_ || image_ is nullptr");
        return false;
    }
    if (!pixelMap_->IsHdr()) {
        RS_LOGD("bhdr pixelMap_ is not hdr");
        return false;
    }

    if (canvas.GetDrawingType() != Drawing::DrawingType::PAINT_FILTER) {
        RS_LOGE("bhdr GetDrawingType() != Drawing::DrawingType::PAINT_FILTER");
        return false;
    }

    SurfaceBuffer* surfaceBuffer = reinterpret_cast<SurfaceBuffer*>(pixelMap_->GetFd());

    if (surfaceBuffer == nullptr) {
        RS_LOGE("bhdr ColorSpaceConvertor surfaceBuffer is nullptr");
        return false;
    }

    Drawing::Matrix matrix;  //Identity Matrix
    auto sx = dstRect_.GetWidth() / srcRect_.GetWidth();
    auto sy = dstRect_.GetHeight() / srcRect_.GetHeight();
    auto tx = dstRect_.GetLeft() - srcRect_.GetLeft() * sx;
    auto ty = dstRect_.GetTop() - srcRect_.GetTop() * sy;
    matrix.SetScaleTranslate(sx, sy, tx, ty);

    auto imageShader = Drawing::ShaderEffect::CreateImageShader(
        *image_, Drawing::TileMode::CLAMP, Drawing::TileMode::CLAMP, sampling, matrix);

    sptr<SurfaceBuffer> sfBuffer(surfaceBuffer);
    RSPaintFilterCanvas& rscanvas = static_cast<RSPaintFilterCanvas&>(canvas);
    auto targetColorSpace = GRAPHIC_COLOR_GAMUT_SRGB;
    if (LIKELY(!rscanvas.IsCapture())) {
        RSColorSpaceConvert::Instance().ColorSpaceConvertor(imageShader, sfBuffer, paint_,
            targetColorSpace, rscanvas.GetScreenId(), dynamicRangeMode_);
    } else {
        RSColorSpaceConvert::Instance().ColorSpaceConvertor(imageShader, sfBuffer, paint_,
            targetColorSpace, rscanvas.GetScreenId(), DynamicRangeMode::STANDARD);
    }
    canvas.AttachPaint(paint_);
    return true;
#else
    return false;
#endif
}

void RSImage::CanvasDrawImage(Drawing::Canvas& canvas, const Drawing::Rect& rect,
    const Drawing::SamplingOptions& samplingOptions, bool isBackground)
{
    if (canvas.GetRecordingState() && RSSystemProperties::GetDumpUICaptureEnabled() && pixelMap_) {
        CommonTools::SavePixelmapToFile(pixelMap_, "/data/rsImage_");
    }
    bool isFitMatrixValid = !isBackground && imageFit_ == ImageFit::MATRIX &&
                                fitMatrix_.has_value() && !fitMatrix_.value().IsIdentity();
    if (!isDrawn_ || rect != lastRect_) {
        UpdateNodeIdToPicture(nodeId_);
        Drawing::AutoCanvasRestore acr(canvas, HasRadius());
        if (!canvas.GetOffscreen()) {
            frameRect_.SetAll(rect.GetLeft(), rect.GetTop(), rect.GetWidth(), rect.GetHeight());
        }
        if (!isBackground) {
            ApplyImageFit();
            ApplyCanvasClip(canvas);
        }
        if (isFitMatrixValid) {
            canvas.Save();
            canvas.ConcatMatrix(fitMatrix_.value());
        }
        DrawImageRepeatRect(samplingOptions, canvas);
        if (isFitMatrixValid) {
            canvas.Restore();
        }
    } else {
        bool needCanvasRestore = HasRadius() || (pixelMap_ != nullptr && pixelMap_->IsAstc()) ||
                                 isFitMatrixValid;
        Drawing::AutoCanvasRestore acr(canvas, needCanvasRestore);
        if (pixelMap_ != nullptr && pixelMap_->IsAstc()) {
            RSPixelMapUtil::TransformDataSetForAstc(pixelMap_, src_, dst_, canvas);
        }
        if (isFitMatrixValid) {
            canvas.ConcatMatrix(fitMatrix_.value());
        }
        ReMapPixelMap(pixelMap_);
        if (image_) {
            if (!isBackground) {
                ApplyCanvasClip(canvas);
            }
            if (innerRect_.has_value()) {
                canvas.DrawImageNine(image_.get(), innerRect_.value(), dst_, Drawing::FilterMode::LINEAR);
            } else if (HDRConvert(samplingOptions, canvas)) {
                canvas.DrawRect(dst_);
            } else {
                canvas.DrawImageRect(*image_, src_, dst_, samplingOptions,
                    Drawing::SrcRectConstraint::FAST_SRC_RECT_CONSTRAINT);
            }
        }
    }
    lastRect_ = rect;
}

struct ImageParameter {
    float ratio;
    float srcW;
    float srcH;
    float frameW;
    float frameH;
    float dstW;
    float dstH;
};

RectF ApplyImageFitSwitch(ImageParameter &imageParameter, ImageFit imageFit_, RectF tempRectF)
{
    switch (imageFit_) {
        case ImageFit::MATRIX:
            tempRectF.SetAll(0.f, 0.f, imageParameter.srcW, imageParameter.srcH);
            return tempRectF;
        case ImageFit::TOP_LEFT:
            tempRectF.SetAll(0.f, 0.f, imageParameter.srcW, imageParameter.srcH);
            return tempRectF;
        case ImageFit::TOP:
            tempRectF.SetAll((imageParameter.dstW - imageParameter.srcW) / CENTER_ALIGNED_FACTOR, 0.f,
                imageParameter.srcW, imageParameter.srcH);
            return tempRectF;
        case ImageFit::TOP_RIGHT:
            tempRectF.SetAll(imageParameter.dstW - imageParameter.srcW, 0.f, imageParameter.srcW, imageParameter.srcH);
            return tempRectF;
        case ImageFit::LEFT:
            tempRectF.SetAll(0.f, (imageParameter.dstH - imageParameter.srcH) / CENTER_ALIGNED_FACTOR,
                imageParameter.srcW, imageParameter.srcH);
            return tempRectF;
        case ImageFit::CENTER:
            tempRectF.SetAll((imageParameter.dstW - imageParameter.srcW) / CENTER_ALIGNED_FACTOR,
                (imageParameter.dstH - imageParameter.srcH) / CENTER_ALIGNED_FACTOR,
                imageParameter.srcW, imageParameter.srcH);
            return tempRectF;
        case ImageFit::RIGHT:
            tempRectF.SetAll(imageParameter.dstW - imageParameter.srcW,
                (imageParameter.dstH - imageParameter.srcH) / CENTER_ALIGNED_FACTOR,
                imageParameter.srcW, imageParameter.srcH);
            return tempRectF;
        case ImageFit::BOTTOM_LEFT:
            tempRectF.SetAll(0.f, imageParameter.dstH - imageParameter.srcH, imageParameter.srcW, imageParameter.srcH);
            return tempRectF;
        case ImageFit::BOTTOM:
            tempRectF.SetAll((imageParameter.dstW - imageParameter.srcW) / CENTER_ALIGNED_FACTOR,
                imageParameter.dstH - imageParameter.srcH, imageParameter.srcW, imageParameter.srcH);
            return tempRectF;
        case ImageFit::BOTTOM_RIGHT:
            tempRectF.SetAll(imageParameter.dstW - imageParameter.srcW, imageParameter.dstH - imageParameter.srcH,
                imageParameter.srcW, imageParameter.srcH);
            return tempRectF;
        case ImageFit::FILL:
            break;
        case ImageFit::NONE:
            imageParameter.dstW = imageParameter.srcW;
            imageParameter.dstH = imageParameter.srcH;
            break;
        case ImageFit::COVER:
            imageParameter.dstW = std::max(imageParameter.frameW, imageParameter.frameH * imageParameter.ratio);
            imageParameter.dstH = std::max(imageParameter.frameH, imageParameter.frameW / imageParameter.ratio);
            break;
        case ImageFit::FIT_WIDTH:
            imageParameter.dstH = imageParameter.frameW / imageParameter.ratio;
            break;
        case ImageFit::FIT_HEIGHT:
            imageParameter.dstW = imageParameter.frameH * imageParameter.ratio;
            break;
        case ImageFit::SCALE_DOWN:
            if (imageParameter.srcW < imageParameter.frameW && imageParameter.srcH < imageParameter.frameH) {
                imageParameter.dstW = imageParameter.srcW;
                imageParameter.dstH = imageParameter.srcH;
            } else {
                imageParameter.dstW = std::min(imageParameter.frameW, imageParameter.frameH * imageParameter.ratio);
                imageParameter.dstH = std::min(imageParameter.frameH, imageParameter.frameW / imageParameter.ratio);
            }
            break;
        case ImageFit::COVER_TOP_LEFT:
            imageParameter.dstW = std::max(imageParameter.frameW, imageParameter.frameH * imageParameter.ratio);
            imageParameter.dstH = std::max(imageParameter.frameH, imageParameter.frameW / imageParameter.ratio);
            tempRectF.SetAll(0, 0, std::ceil(imageParameter.dstW), std::ceil(imageParameter.dstH));
            return tempRectF;
        case ImageFit::CONTAIN:
        default:
            imageParameter.dstW = std::min(imageParameter.frameW, imageParameter.frameH * imageParameter.ratio);
            imageParameter.dstH = std::min(imageParameter.frameH, imageParameter.frameW / imageParameter.ratio);
            break;
    }
    constexpr float horizontalAlignmentFactor = 2.f;
    constexpr float verticalAlignmentFactor = 2.f;
    tempRectF.SetAll(std::floor((imageParameter.frameW - imageParameter.dstW) / horizontalAlignmentFactor),
                     std::floor((imageParameter.frameH - imageParameter.dstH) / verticalAlignmentFactor),
                     std::ceil(imageParameter.dstW),
                     std::ceil(imageParameter.dstH));
    return tempRectF;
}

void RSImage::ApplyImageFit()
{
    if (scale_ == 0) {
        RS_LOGE("RSImage::ApplyImageFit failed, scale_ is zero ");
        return;
    }
    const float srcW = srcRect_.width_ / scale_;
    const float srcH = srcRect_.height_ / scale_;
    const float frameW = frameRect_.width_;
    const float frameH = frameRect_.height_;
    float dstW = frameW;
    float dstH = frameH;
    if (srcH == 0) {
        RS_LOGE("RSImage::ApplyImageFit failed, srcH is zero ");
        return;
    }
    float ratio = srcW / srcH;
    if (ratio == 0) {
        RS_LOGE("RSImage::ApplyImageFit failed, ratio is zero ");
        return;
    }
    ImageParameter imageParameter;
    imageParameter.ratio = ratio;
    imageParameter.srcW = srcW;
    imageParameter.srcH = srcH;
    imageParameter.frameW = frameW;
    imageParameter.frameH = frameH;
    imageParameter.dstW = dstW;
    imageParameter.dstH = dstH;
    RectF tempRectF = dstRect_;
    dstRect_ = ApplyImageFitSwitch(imageParameter, imageFit_, tempRectF);
}

ImageFit RSImage::GetImageFit()
{
    return imageFit_;
}

Drawing::AdaptiveImageInfo RSImage::GetAdaptiveImageInfoWithCustomizedFrameRect(const Drawing::Rect& frameRect) const
{
    Drawing::AdaptiveImageInfo imageInfo = {
        .fitNum = static_cast<int32_t>(imageFit_),
        .repeatNum = static_cast<int32_t>(imageRepeat_),
        .radius = { radius_[0], radius_[1], radius_[2], radius_[3] },
        .scale = scale_,
        .uniqueId = 0,
        .width = 0,
        .height = 0,
        .dynamicRangeMode = dynamicRangeMode_,
        .frameRect = frameRect,
        .fitMatrix = fitMatrix_.has_value() ? fitMatrix_.value() : Drawing::Matrix()
    };
    return imageInfo;
}

void RSImage::SetFitMatrix(const Drawing::Matrix& matrix)
{
    fitMatrix_ = matrix;
}

Drawing::Matrix RSImage::GetFitMatrix() const
{
    return fitMatrix_.value();
}

RectF RSImage::GetDstRect()
{
    return dstRect_;
}

void RSImage::SetFrameRect(RectF frameRect)
{
    frameRect_ = frameRect;
}

bool RSImage::HasRadius() const
{
    return hasRadius_;
}

void RSImage::ApplyCanvasClip(Drawing::Canvas& canvas)
{
    if (!HasRadius()) {
        return;
    }
    auto rect = (imageRepeat_ == ImageRepeat::NO_REPEAT) ? dstRect_.IntersectRect(frameRect_) : frameRect_;
    Drawing::RoundRect rrect(RSPropertiesPainter::Rect2DrawingRect(rect), radius_);
    canvas.ClipRoundRect(rrect, Drawing::ClipOp::INTERSECT, true);
}

#if defined(ROSEN_OHOS) && (defined(RS_ENABLE_GL) || defined(RS_ENABLE_VK))
static Drawing::CompressedType PixelFormatToCompressedType(Media::PixelFormat pixelFormat)
{
    switch (pixelFormat) {
        case Media::PixelFormat::ASTC_4x4: return Drawing::CompressedType::ASTC_RGBA8_4x4;
        case Media::PixelFormat::ASTC_6x6: return Drawing::CompressedType::ASTC_RGBA8_6x6;
        case Media::PixelFormat::ASTC_8x8: return Drawing::CompressedType::ASTC_RGBA8_8x8;
        case Media::PixelFormat::UNKNOWN:
        default: return Drawing::CompressedType::NoneType;
    }
}

static std::shared_ptr<Drawing::ColorSpace> ColorSpaceToDrawingColorSpace(ColorManager::ColorSpaceName
 colorSpaceName)
{
    switch (colorSpaceName) {
        case ColorManager::ColorSpaceName::DISPLAY_P3:
            return Drawing::ColorSpace::CreateRGB(
                Drawing::CMSTransferFuncType::SRGB, Drawing::CMSMatrixType::DCIP3);
        case ColorManager::ColorSpaceName::LINEAR_SRGB:
            return Drawing::ColorSpace::CreateSRGBLinear();
        case ColorManager::ColorSpaceName::SRGB:
            return Drawing::ColorSpace::CreateSRGB();
        default:
            return Drawing::ColorSpace::CreateSRGB();
    }
}
#endif

void RSImage::UploadGpu(Drawing::Canvas& canvas)
{
#if defined(ROSEN_OHOS) && (defined(RS_ENABLE_GL) || defined(RS_ENABLE_VK))
    if (compressData_) {
        auto cache = RSImageCache::Instance().GetRenderDrawingImageCacheByPixelMapId(uniqueId_, gettid());
        std::lock_guard<std::mutex> lock(mutex_);
        if (cache) {
            image_ = cache;
        } else {
            if (canvas.GetGPUContext() == nullptr) {
                return;
            }
            Media::ImageInfo imageInfo;
            pixelMap_->GetImageInfo(imageInfo);
            Media::Size realSize;
            pixelMap_->GetAstcRealSize(realSize);
            auto image = std::make_shared<Drawing::Image>();
            std::shared_ptr<Drawing::ColorSpace> colorSpace =
                ColorSpaceToDrawingColorSpace(pixelMap_->InnerGetGrColorSpace().GetColorSpaceName());
            bool result = image->BuildFromCompressed(*canvas.GetGPUContext(), compressData_,
                static_cast<int>(realSize.width), static_cast<int>(realSize.height),
                PixelFormatToCompressedType(imageInfo.pixelFormat), colorSpace);
            if (result) {
                image_ = image;
                SKResourceManager::Instance().HoldResource(image);
                RSImageCache::Instance().CacheRenderDrawingImageByPixelMapId(uniqueId_, image, gettid());
            } else {
                RS_LOGE("make astc image %{public}d (%{public}d, %{public}d) failed",
                    (int)uniqueId_, (int)srcRect_.width_, (int)srcRect_.height_);
            }
            compressData_ = nullptr;
        }
        return;
    }
    if (isYUVImage_) {
        ProcessYUVImage(canvas.GetGPUContext());
    }
#endif
}

void RSImage::DrawImageRepeatRect(const Drawing::SamplingOptions& samplingOptions, Drawing::Canvas& canvas)
{
    ReMapPixelMap(pixelMap_);
    int minX = 0;
    int minY = 0;
    int maxX = 0;
    int maxY = 0;
    CalcRepeatBounds(minX, maxX, minY, maxY);
    // draw repeat rect
    ConvertPixelMapToDrawingImage();
    UploadGpu(canvas);
    bool hdrImageDraw = HDRConvert(samplingOptions, canvas);
    src_ = RSPropertiesPainter::Rect2DrawingRect(srcRect_);
    bool isAstc = pixelMap_ != nullptr && pixelMap_->IsAstc();
    for (int i = minX; i <= maxX; ++i) {
        auto left = dstRect_.left_ + i * dstRect_.width_;
        auto right = left + dstRect_.width_;
        for (int j = minY; j <= maxY; ++j) {
            auto top = dstRect_.top_ + j * dstRect_.height_;
            dst_ = Drawing::Rect(left, top, right, top + dstRect_.height_);
            if (isAstc) {
                canvas.Save();
                RSPixelMapUtil::TransformDataSetForAstc(pixelMap_, src_, dst_, canvas);
            }
            if (image_) {
                DrawImageOnCanvas(samplingOptions, canvas, hdrImageDraw);
            }
            if (isAstc) {
                canvas.Restore();
            }
        }
    }
    if (imageRepeat_ == ImageRepeat::NO_REPEAT) {
        isDrawn_ = true;
    }
}

void RSImage::CalcRepeatBounds(int& minX, int& maxX, int& minY, int& maxY)
{
    float left = frameRect_.left_;
    float right = frameRect_.GetRight();
    float top = frameRect_.top_;
    float bottom = frameRect_.GetBottom();
    // calculate REPEAT_XY
    float eps = 0.01; // set epsilon
    if (ImageRepeat::REPEAT_X == imageRepeat_ || ImageRepeat::REPEAT == imageRepeat_) {
        while (dstRect_.left_ + minX * dstRect_.width_ > left + eps) {
            --minX;
        }
        while (dstRect_.left_ + maxX * dstRect_.width_ < right - eps) {
            ++maxX;
        }
    }
    if (ImageRepeat::REPEAT_Y == imageRepeat_ || ImageRepeat::REPEAT == imageRepeat_) {
        while (dstRect_.top_ + minY * dstRect_.height_ > top + eps) {
            --minY;
        }
        while (dstRect_.top_ + maxY * dstRect_.height_ < bottom - eps) {
            ++maxY;
        }
    }
}

void RSImage::DrawImageOnCanvas(
    const Drawing::SamplingOptions& samplingOptions, Drawing::Canvas& canvas, const bool hdrImageDraw)
{
    if (canvas.GetTotalMatrix().HasPerspective()) {
        // In case of perspective transformation, make dstRect 1px outset to anti-alias
        dst_.MakeOutset(1, 1);
    }
    if (innerRect_.has_value()) {
        canvas.DrawImageNine(image_.get(), innerRect_.value(), dst_, Drawing::FilterMode::LINEAR);
    } else if (hdrImageDraw) {
        canvas.DrawRect(dst_);
    } else {
        canvas.DrawImageRect(
            *image_, src_, dst_, samplingOptions, Drawing::SrcRectConstraint::FAST_SRC_RECT_CONSTRAINT);
    }
}

void RSImage::SetCompressData(
    const std::shared_ptr<Drawing::Data> data, const uint32_t id, const int width, const int height)
{
#ifdef RS_ENABLE_GL
    if (RSSystemProperties::GetGpuApiType() != GpuApiType::OPENGL) {
        return;
    }
    compressData_ = data;
    if (compressData_) {
        srcRect_.SetAll(0.0, 0.0, width, height);
        GenUniqueId(image_ ? image_->GetUniqueID() : id);
        image_ = nullptr;
    }
#endif
}

#if defined(ROSEN_OHOS) && (defined(RS_ENABLE_GL) || defined (RS_ENABLE_VK))
void RSImage::SetCompressData(const std::shared_ptr<Drawing::Data> compressData)
{
    isDrawn_ = false;
    compressData_ = compressData;
    canPurgeShareMemFlag_ = CanPurgeFlag::DISABLED;
}
#endif

void RSImage::SetImageFit(int fitNum)
{
    imageFit_ = static_cast<ImageFit>(fitNum);
}

void RSImage::SetImageRepeat(int repeatNum)
{
    imageRepeat_ = static_cast<ImageRepeat>(repeatNum);
}

void RSImage::SetRadius(const std::vector<Drawing::Point>& radius)
{
    hasRadius_ = false;
    for (auto i = 0; i < CORNER_SIZE; i++) {
        radius_[i] = radius[i];
        hasRadius_ = hasRadius_ || !radius_[i].IsZero();
    }
}

void RSImage::SetScale(double scale)
{
    if (scale > 0.0) {
        scale_ = scale;
    }
}

void RSImage::SetNodeId(NodeId nodeId)
{
    nodeId_ = nodeId;
}

void RSImage::SetPaint(Drawing::Paint paint)
{
    paint_ = paint;
}

void RSImage::SetDynamicRangeMode(uint32_t dynamicRangeMode)
{
    dynamicRangeMode_ = dynamicRangeMode;
}

#ifdef ROSEN_OHOS
static bool UnmarshallingIdAndSize(Parcel& parcel, uint64_t& uniqueId, int& width, int& height)
{
    if (!RSMarshallingHelper::Unmarshalling(parcel, uniqueId)) {
        RS_LOGE("RSImage::Unmarshalling uniqueId fail");
        return false;
    }
    RS_PROFILER_PATCH_NODE_ID(parcel, uniqueId);
    if (!RSMarshallingHelper::Unmarshalling(parcel, width)) {
        RS_LOGE("RSImage::Unmarshalling width fail");
        return false;
    }
    if (!RSMarshallingHelper::Unmarshalling(parcel, height)) {
        RS_LOGE("RSImage::Unmarshalling height fail");
        return false;
    }
    return true;
}

static bool UnmarshallingCompressData(Parcel& parcel, bool skipData, std::shared_ptr<Drawing::Data>& compressData)
{
    if (skipData) {
        if (!RSMarshallingHelper::SkipData(parcel)) {
            RS_LOGE("RSImage::Unmarshalling SkipData fail");
            return false;
        }
    } else {
        if (!RSMarshallingHelper::UnmarshallingWithCopy(parcel, compressData)) {
            RS_LOGE("RSImage::Unmarshalling UnmarshallingWithCopy Data fail");
            return false;
        }
    }
    return true;
}

bool RSImage::Marshalling(Parcel& parcel) const
{
    int imageFit = static_cast<int>(imageFit_);
    int imageRepeat = static_cast<int>(imageRepeat_);

    std::lock_guard<std::mutex> lock(mutex_);
    auto image = image_;
    auto compressData = compressData_;
    if (image && image->IsTextureBacked()) {
        image = nullptr;
        ROSEN_LOGE("RSImage::Marshalling skip texture image");
    }
    RS_PROFILER_MARSHAL_DRAWINGIMAGE(image, compressData);
    uint32_t versionId = pixelMap_ == nullptr ? 0 : pixelMap_->GetVersionId();
    bool success = RSMarshallingHelper::Marshalling(parcel, uniqueId_) &&
                   RSMarshallingHelper::Marshalling(parcel, static_cast<int>(srcRect_.width_)) &&
                   RSMarshallingHelper::Marshalling(parcel, static_cast<int>(srcRect_.height_)) &&
                   RSMarshallingHelper::Marshalling(parcel, nodeId_) &&
                   parcel.WriteBool(pixelMap_ == nullptr) &&
                   RSMarshallingHelper::Marshalling(parcel, versionId) &&
                   RSMarshallingHelper::Marshalling(parcel, image) &&
                   RSMarshallingHelper::Marshalling(parcel, pixelMap_) &&
                   RSMarshallingHelper::Marshalling(parcel, compressData) &&
                   RSMarshallingHelper::Marshalling(parcel, imageFit) &&
                   RSMarshallingHelper::Marshalling(parcel, imageRepeat) &&
                   RSMarshallingHelper::Marshalling(parcel, radius_) &&
                   RSMarshallingHelper::Marshalling(parcel, scale_) &&
                   RSMarshallingHelper::Marshalling(parcel, dynamicRangeMode_) &&
                   parcel.WriteBool(fitMatrix_.has_value()) &&
                   fitMatrix_.has_value() ? RSMarshallingHelper::Marshalling(parcel, fitMatrix_.value()) : true;
    return success;
}

RSImage* RSImage::Unmarshalling(Parcel& parcel)
{
    uint64_t uniqueId;
    int width;
    int height;
    NodeId nodeId;
    if (!UnmarshalIdSizeAndNodeId(parcel, uniqueId, width, height, nodeId)) {
        return nullptr;
    }
    bool useSkImage;
    std::shared_ptr<Drawing::Image> img;
    std::shared_ptr<Media::PixelMap> pixelMap;
    void* imagepixelAddr = nullptr;
    if (!UnmarshallingDrawingImageAndPixelMap(parcel, uniqueId, useSkImage, img, pixelMap, imagepixelAddr)) {
        return nullptr;
    }
    std::shared_ptr<Drawing::Data> compressData;
    bool skipData = img != nullptr || !useSkImage;
    if (!UnmarshallingCompressData(parcel, skipData, compressData)) {
        return nullptr;
    }
    int fitNum;
    int repeatNum;
    std::vector<Drawing::Point> radius(CORNER_SIZE);
    double scale;
    bool hasFitMatrix;
    Drawing::Matrix fitMatrix;
    uint32_t dynamicRangeMode = 0;
    if (!UnmarshalImageProperties(parcel, fitNum, repeatNum, radius, scale,
        hasFitMatrix, fitMatrix, dynamicRangeMode)) {
        return nullptr;
    }
    RSImage* rsImage = new RSImage();
    rsImage->SetImage(img);
    rsImage->SetImagePixelAddr(imagepixelAddr);
    rsImage->SetCompressData(compressData, uniqueId, width, height);
    rsImage->SetPixelMap(pixelMap);
    rsImage->SetImageFit(fitNum);
    rsImage->SetImageRepeat(repeatNum);
    rsImage->SetRadius(radius);
    rsImage->SetScale(scale);
    rsImage->SetDynamicRangeMode(dynamicRangeMode);
    rsImage->SetNodeId(nodeId);
    if (hasFitMatrix && !fitMatrix.IsIdentity()) {
        rsImage->SetFitMatrix(fitMatrix);
    }
    ProcessImageAfterCreation(rsImage, uniqueId, useSkImage, pixelMap);
    return rsImage;
}

bool RSImage::UnmarshalIdSizeAndNodeId(Parcel& parcel, uint64_t& uniqueId, int& width, int& height, NodeId& nodeId)
{
    if (!UnmarshallingIdAndSize(parcel, uniqueId, width, height)) {
        RS_LOGE("RSImage::Unmarshalling UnmarshallingIdAndSize fail");
        return false;
    }
    if (!RSMarshallingHelper::Unmarshalling(parcel, nodeId)) {
        RS_LOGE("RSImage::Unmarshalling nodeId fail");
        return false;
    }
    RS_PROFILER_PATCH_NODE_ID(parcel, nodeId);
    return true;
}

bool RSImage::UnmarshalImageProperties(
    Parcel& parcel, int& fitNum, int& repeatNum, std::vector<Drawing::Point>& radius, double& scale,
    bool& hasFitMatrix, Drawing::Matrix& fitMatrix, uint32_t& dynamicRangeMode)
{
    if (!RSMarshallingHelper::Unmarshalling(parcel, fitNum)) {
        RS_LOGE("RSImage::Unmarshalling fitNum fail");
        return false;
    }

    if (!RSMarshallingHelper::Unmarshalling(parcel, repeatNum)) {
        RS_LOGE("RSImage::Unmarshalling repeatNum fail");
        return false;
    }

    if (!RSMarshallingHelper::Unmarshalling(parcel, radius)) {
        RS_LOGE("RSImage::Unmarshalling radius fail");
        return false;
    }

    if (!RSMarshallingHelper::Unmarshalling(parcel, scale)) {
        RS_LOGE("RSImage::Unmarshalling scale fail");
        return false;
    }

    if (!RSMarshallingHelper::Unmarshalling(parcel, hasFitMatrix)) {
        return false;
    }

    if (!RSMarshallingHelper::Unmarshalling(parcel, dynamicRangeMode)) {
        RS_LOGE("RSImage::Unmarshalling dynamicRangeMode fail");
        return false;
    }

    if (hasFitMatrix) {
        if (!RSMarshallingHelper::Unmarshalling(parcel, fitMatrix)) {
            RS_LOGE("RSImage::Unmarshalling fitMatrix fail");
            return false;
        }
    }

    return true;
}

void RSImage::ProcessImageAfterCreation(
    RSImage* rsImage, const uint64_t uniqueId, const bool useSkImage, const std::shared_ptr<Media::PixelMap>& pixelMap)
{
    rsImage->uniqueId_ = uniqueId;
    rsImage->MarkRenderServiceImage();
    RSImageBase::IncreaseCacheRefCount(uniqueId, useSkImage, pixelMap);
#if defined(ROSEN_OHOS) && defined(RS_ENABLE_GL) && defined(RS_ENABLE_PARALLEL_UPLOAD)
    if (RSSystemProperties::GetGpuApiType() == GpuApiType::OPENGL) {
#if defined(RS_ENABLE_UNI_RENDER)
        if (pixelMap != nullptr && pixelMap->GetAllocatorType() != Media::AllocatorType::DMA_ALLOC) {
            rsImage->ConvertPixelMapToDrawingImage(true);
        }
#endif
    }
#endif
}
#endif
} // namespace Rosen
} // namespace OHOS
