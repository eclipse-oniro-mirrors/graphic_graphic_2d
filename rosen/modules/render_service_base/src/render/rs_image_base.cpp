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

#include "render/rs_image_base.h"

#include <unistd.h>
#include "image/image.h"
#include "common/rs_background_thread.h"
#ifdef RS_ENABLE_PARALLEL_UPLOAD
#include "render/rs_resource_manager.h"
#endif
#include "common/rs_common_def.h"
#include "platform/common/rs_log.h"
#include "pipeline/rs_task_dispatcher.h"
#include "pipeline/sk_resource_manager.h"
#include "property/rs_properties_painter.h"
#include "render/rs_image_cache.h"
#include "render/rs_pixel_map_util.h"
#include "memory/rs_memory_track.h"
#include "rs_trace.h"
#include "sandbox_utils.h"
#include "rs_profiler.h"

#if defined(ROSEN_OHOS) && defined(RS_ENABLE_VK)
#include "native_buffer_inner.h"
#include "native_window.h"
#include "platform/ohos/backend/native_buffer_utils.h"
#include "platform/ohos/backend/rs_vulkan_context.h"
#endif
namespace OHOS::Rosen {
RSImageBase::~RSImageBase()
{
    if (pixelMap_) {
        pixelMap_ = nullptr;
        if (uniqueId_ > 0) {
            if (renderServiceImage_) {
                RSImageCache::Instance().CollectUniqueId(uniqueId_);
            } else {
                RSImageCache::Instance().ReleasePixelMapCache(uniqueId_);
            }
        }
#if defined(ROSEN_OHOS) && defined(RS_ENABLE_VK)
    if (RSSystemProperties::GetGpuApiType() == GpuApiType::VULKAN ||
        RSSystemProperties::GetGpuApiType() == GpuApiType::DDGR) {
        RSTaskDispatcher::GetInstance().PostTask(tid_, [nativeWindowBuffer = nativeWindowBuffer_,
            cleanupHelper = cleanUpHelper_]() {
            if (nativeWindowBuffer != nullptr) {
                DestroyNativeWindowBuffer(nativeWindowBuffer);
            }
            if (cleanupHelper != nullptr) {
                NativeBufferUtils::DeleteVkImage(cleanupHelper);
            }
        });
    }
#endif
    } else { // if pixelMap_ not nullptr, do not release skImage cache
        if (image_) {
            image_ = nullptr;
            if (uniqueId_ > 0) {
                // if image_ is obtained by RSPixelMapUtil::ExtractSkImage, uniqueId_ here is related to pixelMap,
                // image_ is not in SkiaImageCache, but still check it here
                // in this case, the cached image_ will be removed when pixelMap cache is removed
                RSImageCache::Instance().ReleaseDrawingImageCache(uniqueId_);
            }
        }
    }
}

#if defined(ROSEN_OHOS) && defined(RS_ENABLE_VK)
Drawing::ColorType GetColorTypeWithVKFormat(VkFormat vkFormat)
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

void RSImageBase::DrawImage(Drawing::Canvas& canvas, const Drawing::SamplingOptions& samplingOptions)
{
#if defined(ROSEN_OHOS) && defined(RS_ENABLE_VK)
    if (pixelMap_ && pixelMap_->GetAllocatorType() == Media::AllocatorType::DMA_ALLOC) {
        BindPixelMapToDrawingImage(canvas);
    }
#endif
    if (!image_) {
        ConvertPixelMapToDrawingImage();
    }
    auto src = RSPropertiesPainter::Rect2DrawingRect(srcRect_);
    auto dst = RSPropertiesPainter::Rect2DrawingRect(dstRect_);
    if (image_ == nullptr) {
        RS_LOGE("RSImageBase::DrawImage image_ is nullptr");
        return;
    }
    canvas.DrawImageRect(*image_, src, dst, samplingOptions);
}

void RSImageBase::SetImage(const std::shared_ptr<Drawing::Image> image)
{
    isDrawn_ = false;
    image_ = image;
    if (image_) {
#ifndef ROSEN_ARKUI_X
        SKResourceManager::Instance().HoldResource(image);
#endif
        srcRect_.SetAll(0.0, 0.0, image_->GetWidth(), image_->GetHeight());
        GenUniqueId(image_->GetUniqueID());
    }
}

#if defined(ROSEN_OHOS) && (defined(RS_ENABLE_GL) || defined(RS_ENABLE_VK))
void RSImageBase::SetDmaImage(const std::shared_ptr<Drawing::Image> image)
{
    isDrawn_ = false;
    image_ = image;
}

void RSImageBase::MarkYUVImage()
{
    isDrawn_ = false;
    isYUVImage_ = true;
}
#endif

void RSImageBase::SetPixelMap(const std::shared_ptr<Media::PixelMap>& pixelmap)
{
    pixelMap_ = pixelmap;
    if (pixelMap_) {
        srcRect_.SetAll(0.0, 0.0, pixelMap_->GetWidth(), pixelMap_->GetHeight());
        image_ = nullptr;
        GenUniqueId(pixelMap_->GetUniqueId());
    }
}

void RSImageBase::DumpPicture(DfxString& info) const
{
    if (!pixelMap_) {
        return;
    }
    info.AppendFormat("%d    [%d * %d]  %p\n", pixelMap_->GetByteCount(), pixelMap_->GetWidth(), pixelMap_->GetHeight(),
        pixelMap_.get());
}

void RSImageBase::SetSrcRect(const RectF& srcRect)
{
    srcRect_ = srcRect;
}

void RSImageBase::SetDstRect(const RectF& dstRect)
{
    if (dstRect_ != dstRect) {
        isDrawn_ = false;
    }
    dstRect_ = dstRect;
}

void RSImageBase::SetImagePixelAddr(void* addr)
{
    imagePixelAddr_ = addr;
}

void RSImageBase::UpdateNodeIdToPicture(NodeId nodeId)
{
    if (!nodeId) {
        return;
    }
    if (pixelMap_) {
#ifndef ROSEN_ARKUI_X
        MemoryTrack::Instance().UpdatePictureInfo(pixelMap_->GetPixels(), nodeId, ExtractPid(nodeId));
#endif
    }
    if (image_ || imagePixelAddr_) {
#ifndef ROSEN_ARKUI_X
        MemoryTrack::Instance().UpdatePictureInfo(imagePixelAddr_, nodeId, ExtractPid(nodeId));
#endif
    }
}

void RSImageBase::MarkRenderServiceImage()
{
    renderServiceImage_ = true;
}

#ifdef ROSEN_OHOS
static bool UnmarshallingAndCacheDrawingImage(
    Parcel& parcel, std::shared_ptr<Drawing::Image>& img, uint64_t uniqueId, void*& imagepixelAddr)
{
    if (img != nullptr) {
        // match a cached SkImage
        if (!RSMarshallingHelper::SkipImage(parcel)) {
            RS_LOGE("UnmarshalAndCacheSkImage SkipSkImage fail");
            return false;
        }
    } else if (RSMarshallingHelper::Unmarshalling(parcel, img, imagepixelAddr)) {
        // unmarshalling the SkImage and cache it
        RSImageCache::Instance().CacheDrawingImage(uniqueId, img);
    } else {
        RS_LOGE("UnmarshalAndCacheSkImage fail");
        return false;
    }
    return true;
}


static bool UnmarshallingAndCachePixelMap(Parcel& parcel, std::shared_ptr<Media::PixelMap>& pixelMap, uint64_t uniqueId)
{
    if (pixelMap != nullptr) {
        // match a cached pixelMap
        if (!RSMarshallingHelper::SkipPixelMap(parcel)) {
            return false;
        }
    } else if (RSMarshallingHelper::Unmarshalling(parcel, pixelMap)) {
        if (pixelMap && !pixelMap->IsEditable()) {
            // unmarshalling the pixelMap and cache it
            RSImageCache::Instance().CachePixelMap(uniqueId, pixelMap);
        }
    } else {
        return false;
    }
    return true;
}

static bool UnmarshallingIdAndRect(Parcel& parcel, uint64_t& uniqueId, RectF& srcRect, RectF& dstRect)
{
    if (!RSMarshallingHelper::Unmarshalling(parcel, uniqueId)) {
        RS_LOGE("RSImage::Unmarshalling uniqueId fail");
        return false;
    }
    RS_PROFILER_PATCH_NODE_ID(parcel, uniqueId);
    if (!RSMarshallingHelper::Unmarshalling(parcel, srcRect)) {
        RS_LOGE("RSImage::Unmarshalling srcRect fail");
        return false;
    }
    if (!RSMarshallingHelper::Unmarshalling(parcel, dstRect)) {
        RS_LOGE("RSImage::Unmarshalling dstRect fail");
        return false;
    }
    return true;
}

bool RSImageBase::UnmarshallingDrawingImageAndPixelMap(Parcel& parcel, uint64_t uniqueId, bool& useSkImage,
    std::shared_ptr<Drawing::Image>& img, std::shared_ptr<Media::PixelMap>& pixelMap, void*& imagepixelAddr)
{
    if (!RSMarshallingHelper::Unmarshalling(parcel, useSkImage)) {
        return false;
    }
    if (useSkImage) {
        img = RSImageCache::Instance().GetDrawingImageCache(uniqueId);
        RS_TRACE_NAME_FMT("RSImageBase::Unmarshalling Image uniqueId:%lu, size:[%d %d], cached:%d",
            uniqueId, img ? img->GetWidth() : 0, img ? img->GetHeight() : 0, img != nullptr);
        if (!UnmarshallingAndCacheDrawingImage(parcel, img, uniqueId, imagepixelAddr)) {
            RS_LOGE("RSImageBase::Unmarshalling UnmarshalAndCacheSkImage fail");
            return false;
        }
        RSMarshallingHelper::SkipPixelMap(parcel);
    } else {
        if (!RSMarshallingHelper::SkipImage(parcel)) {
            return false;
        }
        pixelMap = RSImageCache::Instance().GetPixelMapCache(uniqueId);
        RS_TRACE_NAME_FMT("RSImageBase::Unmarshalling pixelMap uniqueId:%lu, size:[%d %d], cached:%d",
            uniqueId, pixelMap ? pixelMap->GetWidth() : 0, pixelMap ? pixelMap->GetHeight() : 0, pixelMap != nullptr);
        if (!UnmarshallingAndCachePixelMap(parcel, pixelMap, uniqueId)) {
            RS_LOGE("RSImageBase::Unmarshalling UnmarshalAndCachePixelMap fail");
            return false;
        }
    }
    return true;
}

void RSImageBase::IncreaseCacheRefCount(uint64_t uniqueId, bool useSkImage, std::shared_ptr<Media::PixelMap>
    pixelMap)
{
    if (useSkImage) {
        RSImageCache::Instance().IncreaseDrawingImageCacheRefCount(uniqueId);
    } else if (pixelMap && !pixelMap->IsEditable()) {
        RSImageCache::Instance().IncreasePixelMapCacheRefCount(uniqueId);
    }
}

bool RSImageBase::Marshalling(Parcel& parcel) const
{
    std::lock_guard<std::mutex> lock(mutex_);
    bool success = RSMarshallingHelper::Marshalling(parcel, uniqueId_) &&
                   RSMarshallingHelper::Marshalling(parcel, srcRect_) &&
                   RSMarshallingHelper::Marshalling(parcel, dstRect_) &&
                   parcel.WriteBool(pixelMap_ == nullptr) &&
                   RSMarshallingHelper::Marshalling(parcel, image_) &&
                   RSMarshallingHelper::Marshalling(parcel, pixelMap_);
    return success;
}

RSImageBase* RSImageBase::Unmarshalling(Parcel& parcel)
{
    uint64_t uniqueId;
    RectF srcRect;
    RectF dstRect;
    if (!UnmarshallingIdAndRect(parcel, uniqueId, srcRect, dstRect)) {
        RS_LOGE("RSImage::Unmarshalling UnmarshalIdAndSize fail");
        return nullptr;
    }

    bool useSkImage;
    std::shared_ptr<Drawing::Image> img = std::make_shared<Drawing::Image>();
    std::shared_ptr<Media::PixelMap> pixelMap;
    void* imagepixelAddr = nullptr;
    if (!UnmarshallingDrawingImageAndPixelMap(parcel, uniqueId, useSkImage, img, pixelMap, imagepixelAddr)) {
        return nullptr;
    }

    RSImageBase* rsImage = new RSImageBase();
    rsImage->SetImage(img);
    rsImage->SetImagePixelAddr(imagepixelAddr);
    rsImage->SetPixelMap(pixelMap);
    rsImage->SetSrcRect(srcRect);
    rsImage->SetDstRect(dstRect);
    rsImage->uniqueId_ = uniqueId;
    rsImage->MarkRenderServiceImage();
    IncreaseCacheRefCount(uniqueId, useSkImage, pixelMap);
    return rsImage;
}
#endif

void RSImageBase::ConvertPixelMapToDrawingImage(bool paraUpload)
{
#if defined(ROSEN_OHOS)
    // paraUpload only enable in render_service or UnmarshalThread
    pid_t tid = paraUpload ? getpid() : gettid();
#endif
    if (!image_ && pixelMap_ && !pixelMap_->IsAstc() && !isYUVImage_) {
        if (!pixelMap_->IsEditable()) {
#if defined(ROSEN_OHOS)
            image_ = RSImageCache::Instance().GetRenderDrawingImageCacheByPixelMapId(uniqueId_, tid);
#else
            image_ = RSImageCache::Instance().GetRenderDrawingImageCacheByPixelMapId(uniqueId_);
#endif
        }
        if (!image_) {
            image_ = RSPixelMapUtil::ExtractDrawingImage(pixelMap_);
            if (!pixelMap_->IsEditable()) {
#if defined(ROSEN_OHOS)
                RSImageCache::Instance().CacheRenderDrawingImageByPixelMapId(uniqueId_, image_, tid);
#else
                RSImageCache::Instance().CacheRenderDrawingImageByPixelMapId(uniqueId_, image_);
#endif
            }
#ifdef RS_ENABLE_PARALLEL_UPLOAD
            RSResourceManager::Instance().UploadTexture(paraUpload && renderServiceImage_, image_,
                pixelMap_, uniqueId_);
#endif
        }
    }
}

void RSImageBase::GenUniqueId(uint32_t id)
{
    static uint64_t shiftedPid = static_cast<uint64_t>(GetRealPid()) << 32; // 32 for 64-bit unsignd number shift
    uniqueId_ = shiftedPid | id;
}

#if defined(ROSEN_OHOS) && (defined(RS_ENABLE_GL) || defined(RS_ENABLE_VK))
void RSImageBase::ProcessYUVImage(std::shared_ptr<Drawing::GPUContext> gpuContext)
{
    if (!gpuContext) {
        return;
    }
    auto cache = RSImageCache::Instance().GetRenderDrawingImageCacheByPixelMapId(uniqueId_, gettid());
    std::lock_guard<std::mutex> lock(mutex_);
    if (cache) {
        image_ = cache;
        return;
    }
    RS_TRACE_NAME("make yuv img");
    auto image = RSPixelMapUtil::ConvertYUVPixelMapToDrawingImage(gpuContext, pixelMap_);
    if (image) {
        image_ = image;
        SKResourceManager::Instance().HoldResource(image);
        RSImageCache::Instance().CacheRenderDrawingImageByPixelMapId(uniqueId_, image, gettid());
    } else {
        RS_LOGE("make yuv image %{public}d (%{public}d, %{public}d) failed",
            (int)uniqueId_, (int)srcRect_.width_, (int)srcRect_.height_);
    }
}
#endif

std::shared_ptr<Media::PixelMap> RSImageBase::GetPixelMap() const
{
    return pixelMap_;
}

#if defined(ROSEN_OHOS) && defined(RS_ENABLE_VK)
std::shared_ptr<Drawing::Image> RSImageBase::MakeFromTextureForVK(
    Drawing::Canvas& canvas, SurfaceBuffer* surfaceBuffer)
{
    if (RSSystemProperties::GetGpuApiType() != GpuApiType::VULKAN &&
        RSSystemProperties::GetGpuApiType() != GpuApiType::DDGR) {
        return nullptr;
    }
    if (!surfaceBuffer || !canvas.GetGPUContext()) {
        RS_LOGE("RSImageBase MakeFromTextureForVK surfaceBuffer is nullptr");
        return nullptr;
    }
    if (nativeWindowBuffer_ == nullptr) {
        sptr<SurfaceBuffer> sfBuffer(surfaceBuffer);
        nativeWindowBuffer_ = CreateNativeWindowBufferFromSurfaceBuffer(&sfBuffer);
        if (!nativeWindowBuffer_) {
            RS_LOGE("RSImageBase MakeFromTextureForVK create native window buffer fail");
            return nullptr;
        }
    }
    if (!backendTexture_.IsValid()) {
        backendTexture_ = NativeBufferUtils::MakeBackendTextureFromNativeBuffer(
            nativeWindowBuffer_, surfaceBuffer->GetWidth(), surfaceBuffer->GetHeight(), false);
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
    Drawing::ColorType colorType = GetColorTypeWithVKFormat(vkTextureInfo->format);
    Drawing::BitmapFormat bitmapFormat = { colorType, Drawing::AlphaType::ALPHATYPE_PREMUL };
    if (!dmaImage->BuildFromTexture(*canvas.GetGPUContext(), backendTexture_.GetTextureInfo(),
        Drawing::TextureOrigin::TOP_LEFT, bitmapFormat, nullptr, NativeBufferUtils::DeleteVkImage,
        cleanUpHelper_->Ref())) {
        RS_LOGE("RSImageBase MakeFromTextureForVK build image failed");
        return nullptr;
    }
    return dmaImage;
}

void RSImageBase::BindPixelMapToDrawingImage(Drawing::Canvas& canvas)
{
    if (!image_ && pixelMap_ && !pixelMap_->IsAstc()) {
        if (!pixelMap_->IsEditable()) {
            image_ = RSImageCache::Instance().GetRenderDrawingImageCacheByPixelMapId(uniqueId_, gettid());
        }
        if (!image_) {
            image_ = MakeFromTextureForVK(canvas, reinterpret_cast<SurfaceBuffer*>(pixelMap_->GetFd()));
            if (!pixelMap_->IsEditable() && image_) {
                SKResourceManager::Instance().HoldResource(image_);
                RSImageCache::Instance().CacheRenderDrawingImageByPixelMapId(uniqueId_, image_, gettid());
            }
        }
    }
}
#endif
}
