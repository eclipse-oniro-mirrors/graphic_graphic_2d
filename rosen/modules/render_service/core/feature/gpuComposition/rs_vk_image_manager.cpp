/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include "rs_vk_image_manager.h"

#include <parameter.h>
#include <parameters.h>
#include "include/core/SkColorSpace.h"
#include "native_buffer_inner.h"
#include "platform/common/rs_log.h"
#ifdef USE_M133_SKIA
#include "include/gpu/ganesh/vk/GrVkBackendSurface.h"
#else
#include "include/gpu/GrBackendSurface.h"
#endif
#include "pipeline/hardware_thread/rs_hardware_thread.h"
#include "pipeline/rs_task_dispatcher.h"
#include "rs_trace.h"
#include "common/rs_optional_trace.h"
#include "params/rs_surface_render_params.h"

#ifdef USE_M133_SKIA
#include "src/gpu/ganesh/gl/GrGLDefines.h"
#else
#include "src/gpu/gl/GrGLDefines.h"
#endif

namespace OHOS {
namespace Rosen {
namespace {
void WaitAcquireFence(const sptr<SyncFence>& acquireFence)
{
    if (acquireFence == nullptr) {
        return;
    }
    acquireFence->Wait(3000); // 3000ms
}

constexpr size_t MAX_CACHE_SIZE = 16;
constexpr size_t MAX_CACHE_SIZE_FOR_REUSE = 40;
static const bool ENABLE_VKIMAGE_DFX = system::GetBoolParameter("persist.graphic.enable_vkimage_dfx", false);
static const bool ENABLE_SEMAPHORE =
    system::GetBoolParameter("persist.sys.graphic.rs_vkimgmgr_enable_semaphore", true);

#define DFX_LOG(enableDfx, format, ...) \
    ((enableDfx) ? (void) HILOG_ERROR(LOG_CORE, format, ##__VA_ARGS__) : (void) 0)
#define DFX_LOGD(enableDfx, format, ...) \
    ((enableDfx) ? (void) HILOG_ERROR(LOG_CORE, format, ##__VA_ARGS__) : \
                   (void) HILOG_DEBUG(LOG_CORE, format, ##__VA_ARGS__))
}

VkImageResource::~VkImageResource()
{
    NativeBufferUtils::DeleteVkImage(mVulkanCleanupHelper);
    DestroyNativeWindowBuffer(mNativeWindowBuffer);
}

std::shared_ptr<VkImageResource> VkImageResource::Create(sptr<OHOS::SurfaceBuffer> buffer)
{
    if (buffer == nullptr) {
        ROSEN_LOGE("VkImageResource::Create buffer is nullptr");
        return nullptr;
    }
    auto width = buffer->GetSurfaceBufferWidth();
    auto height = buffer->GetSurfaceBufferHeight();
    NativeWindowBuffer* nativeWindowBuffer = CreateNativeWindowBufferFromSurfaceBuffer(&buffer);
    bool isProtected = (buffer->GetUsage() & BUFFER_USAGE_PROTECTED) != 0;
    auto backendTexture = NativeBufferUtils::MakeBackendTextureFromNativeBuffer(nativeWindowBuffer,
        width, height, isProtected);
    if (!backendTexture.IsValid() || !backendTexture.GetTextureInfo().GetVKTextureInfo()) {
        DestroyNativeWindowBuffer(nativeWindowBuffer);
        return nullptr;
    }
    return std::make_unique<VkImageResource>(
        nativeWindowBuffer,
        backendTexture,
        new NativeBufferUtils::VulkanCleanupHelper(RsVulkanContext::GetSingleton(),
            backendTexture.GetTextureInfo().GetVKTextureInfo()->vkImage,
            backendTexture.GetTextureInfo().GetVKTextureInfo()->vkAlloc.memory));
}

bool RSVkImageManager::WaitVKSemaphore(Drawing::Surface *drawingSurface, const sptr<SyncFence>& acquireFence)
{
    if (drawingSurface == nullptr || acquireFence == nullptr) {
        return false;
    }

    VkSemaphore semaphore = VK_NULL_HANDLE;
    VkSemaphoreCreateInfo semaphoreInfo;
    semaphoreInfo.sType = VK_STRUCTURE_TYPE_SEMAPHORE_CREATE_INFO;
    semaphoreInfo.pNext = nullptr;
    semaphoreInfo.flags = 0;
    auto& vkInterface = RsVulkanContext::GetSingleton().GetRsVulkanInterface();
    auto res = vkInterface.vkCreateSemaphore(vkInterface.GetDevice(), &semaphoreInfo, nullptr, &semaphore);
    if (res != VK_SUCCESS) {
        ROSEN_LOGE("RSVkImageManager: CreateVkSemaphore vkCreateSemaphore failed %{public}d", res);
        return false;
    }

    VkImportSemaphoreFdInfoKHR importSemaphoreFdInfo;
    importSemaphoreFdInfo.sType = VK_STRUCTURE_TYPE_IMPORT_SEMAPHORE_FD_INFO_KHR;
    importSemaphoreFdInfo.pNext = nullptr;
    importSemaphoreFdInfo.semaphore = semaphore;
    importSemaphoreFdInfo.flags = VK_SEMAPHORE_IMPORT_TEMPORARY_BIT;
    importSemaphoreFdInfo.handleType = VK_EXTERNAL_SEMAPHORE_HANDLE_TYPE_SYNC_FD_BIT;
    importSemaphoreFdInfo.fd = acquireFence->Dup();
    res = vkInterface.vkImportSemaphoreFdKHR(vkInterface.GetDevice(), &importSemaphoreFdInfo);
    if (res != VK_SUCCESS) {
        ROSEN_LOGE("RSVkImageManager: CreateVkSemaphore vkImportSemaphoreFdKHR failed %{public}d", res);
        vkInterface.vkDestroySemaphore(vkInterface.GetDevice(), semaphore, nullptr);
        close(importSemaphoreFdInfo.fd);
        return false;
    }

    drawingSurface->Wait(1, semaphore); // 1 means only one VKSemaphore need to wait
    return true;
}

std::shared_ptr<VkImageResource> RSVkImageManager::MapVkImageFromSurfaceBuffer(
    const sptr<OHOS::SurfaceBuffer>& buffer,
    const sptr<SyncFence>& acquireFence,
    pid_t threadIndex, Drawing::Surface *drawingSurface)
{
    if (buffer == nullptr) {
        ROSEN_LOGE("RSVkImageManager::MapVkImageFromSurfaceBuffer buffer is nullptr");
        return nullptr;
    }
    if (!ENABLE_SEMAPHORE || !WaitVKSemaphore(drawingSurface, acquireFence)) {
        WaitAcquireFence(acquireFence);
    }
    std::lock_guard<std::mutex> lock(opMutex_);
    bool isProtectedCondition = (buffer->GetUsage() & BUFFER_USAGE_PROTECTED) ||
        RsVulkanContext::GetSingleton().GetIsProtected();
    auto bufferId = buffer->GetBufferId();
    if (isProtectedCondition || imageCacheSeqs_.find(bufferId) == imageCacheSeqs_.end()) {
        RS_TRACE_NAME_FMT("create vkImage, bufferId=%" PRIu64 "", bufferId);
        return NewImageCacheFromBuffer(buffer, threadIndex, isProtectedCondition);
    } else {
        RS_TRACE_NAME_FMT("find cache vkImage, bufferId=%" PRIu64 "", bufferId);
        return imageCacheSeqs_[bufferId];
    }
}

std::shared_ptr<VkImageResource> RSVkImageManager::CreateImageCacheFromBuffer(const sptr<OHOS::SurfaceBuffer> buffer,
    const sptr<SyncFence>& acquireFence)
{
    WaitAcquireFence(acquireFence);
    if (buffer == nullptr) {
        ROSEN_LOGE("RSVkImageManager::CreateImageCacheFromBuffer buffer is nullptr");
        return nullptr;
    }
    auto bufferId = buffer->GetBufferId();
    auto imageCache = VkImageResource::Create(buffer);
    if (imageCache == nullptr) {
        ROSEN_LOGE(
            "RSVkImageManager::CreateImageCacheFromBuffer: failed to create ImageCache for bufferId:"
            "%{public}" PRIu64 ".", bufferId);
        return nullptr;
    }
    return imageCache;
}

std::shared_ptr<VkImageResource> RSVkImageManager::NewImageCacheFromBuffer(
    const sptr<OHOS::SurfaceBuffer>& buffer, pid_t threadIndex, bool isProtectedCondition)
{
    if (buffer == nullptr) {
        ROSEN_LOGE("RSVkImageManager::NewImageCacheFromBuffer buffer is nullptr");
        return {};
    }
    BufferInfoCache bufferInfoCache{
        .bufferId = buffer->GetBufferId(),
        .width = buffer->GetWidth(),
        .height = buffer->GetHeight(),
        .fd = buffer->GetFileDescriptor(),
        .size = buffer->GetSize(),
        .bufferDeletedFlag = buffer->GetBufferDeletedFlag()
    };
    auto imageCache = VkImageResource::Create(buffer);
    if (imageCache == nullptr) {
        HILOG_COMM_ERROR(
            "RSVkImageManager::NewImageCacheFromBuffer: failed to create ImageCache for buffer id %{public}" PRIu64 ".",
            bufferInfoCache.bufferId);
        return {};
    }

    size_t imageCacheSeqSize = imageCacheSeqs_.size();
    DFX_LOGD(ENABLE_VKIMAGE_DFX,
        "RSVkImageManagerDfx: create image, bufferId=%{public}" PRIu64 ","
        "threadIndex=%{public}d, isProtected=%{public}d,cacheSeq=%{public}lu, bufferDeletedFlag=%{public}u",
        bufferInfoCache.bufferId, threadIndex, isProtectedCondition, imageCacheSeqSize,
        bufferInfoCache.bufferDeletedFlag);
    RS_TRACE_NAME_FMT("RSVkImageManagerDfx: create image, bufferId=%" PRIu64 ", "
                      "isProtected=%d, cacheSeq=%lu, bufferDeletedFlag=%u",
        bufferInfoCache.bufferId, isProtectedCondition, imageCacheSeqSize, bufferInfoCache.bufferDeletedFlag);
    imageCache->SetThreadIndex(threadIndex);
    imageCache->SetBufferInfoCache(bufferInfoCache);
    if (isProtectedCondition) {
        return imageCache;
    }

    RS_LOGD("RSVkImageManager::NewImageCacheFromBuffer %{public}" PRIu64 "", bufferInfoCache.bufferId);
    if (imageCacheSeqSize < MAX_CACHE_SIZE_FOR_REUSE) {
        imageCacheSeqs_.emplace(bufferInfoCache.bufferId, imageCache);
    }

    return imageCache;
}

void RSVkImageManager::UnMapImageFromSurfaceBuffer(uint64_t seqNum)
{
    DFX_LOG(ENABLE_VKIMAGE_DFX, "RSVkImageManagerDfx: tryUnmapImage, bufferId=%{public}" PRIu64 "", seqNum);
    pid_t threadIndex = UNI_RENDER_THREAD_INDEX;
    {
        std::lock_guard<std::mutex> lock(opMutex_);
        if (imageCacheSeqs_.count(seqNum) == 0) {
            return;
        }
        threadIndex = imageCacheSeqs_[seqNum]->GetThreadIndex();
    }
    auto func = [this, seqNum]() {
        std::lock_guard<std::mutex> lock(opMutex_);
        auto iter = imageCacheSeqs_.find(seqNum);
        if (iter == imageCacheSeqs_.end()) {
            return;
        }
        RS_TRACE_NAME_FMT("RSVkImageManagerDfx: unmap image, bufferId=%" PRIu64 "", seqNum);
        imageCacheSeqs_.erase(iter);
        DFX_LOGD(ENABLE_VKIMAGE_DFX, "RSVkImageManagerDfx: UnmapImage, bufferId=%{public}" PRIu64 ", "
            "cacheSeq=[%{public}lu]",
            seqNum, imageCacheSeqs_.size());
    };
    DFX_LOGD(ENABLE_VKIMAGE_DFX, "RSVkImageManagerDfx: findImageToUnmap, bufferId=%{public}" PRIu64 "", seqNum);
    RSTaskDispatcher::GetInstance().PostTask(threadIndex, func);
}

void RSVkImageManager::DumpVkImageInfo(std::string &dumpString)
{
    std::lock_guard<std::mutex> lock(opMutex_);
    dumpString.append("\n---------RSVkImageManager-DumpVkImageInfo-Begin----------\n");
    dumpString.append("imageCacheSeqs size: " + std::to_string(imageCacheSeqs_.size()) + "\n");
    for (auto iter = imageCacheSeqs_.begin(); iter != imageCacheSeqs_.end(); ++iter) {
        auto bufferInfoCache = iter->second->GetBufferInfoCache();
        dumpString.append("vkimageinfo: bufferId=" + std::to_string(iter->first) +
            ", threadIndex=" + std::to_string(iter->second->GetThreadIndex()) +
            ", width=" + std::to_string(bufferInfoCache.width) +
            ", height=" + std::to_string(bufferInfoCache.height) +
            ", fd=" + std::to_string(bufferInfoCache.fd) +
            ", size=" + std::to_string(bufferInfoCache.size) +
            ", bufferDeletedFlag=" + std::to_string(static_cast<uint32_t>(bufferInfoCache.bufferDeletedFlag)) + "\n");
    }
    dumpString.append("\n---------RSVkImageManager-DumpVkImageInfo-End----------\n");
}

std::shared_ptr<Drawing::Image> RSVkImageManager::CreateImageFromBuffer(RSPaintFilterCanvas& canvas,
    const BufferDrawParam& params, const std::shared_ptr<Drawing::ColorSpace>& drawingColorSpace)
{
    const sptr<SurfaceBuffer>& buffer = params.buffer;
    const sptr<SyncFence>& acquireFence = params.acquireFence;
    const pid_t threadIndex = params.threadIndex;
    const Drawing::AlphaType alphaType = params.alphaType;

    auto image = std::make_shared<Drawing::Image>();
    if (buffer == nullptr) {
        RS_LOGE("RSVkImageManager::CreateImageFromBuffer: buffer is nullptr");
        return nullptr;
    }
    auto imageCache = MapVkImageFromSurfaceBuffer(buffer, acquireFence, threadIndex, canvas.GetSurface());
    if (imageCache == nullptr) {
        RS_LOGE("RSVkImageManager::MapImageFromSurfaceBuffer failed!");
        return nullptr;
    }
    if (buffer->IsBufferDeleted()) {
        RS_LOGD_IF(DEBUG_COMPOSER, "  - Buffer %{public}" PRIu64 " marked for deletion from cache, unmapping",
            buffer->GetBufferId());
        UnMapImageFromSurfaceBuffer(buffer->GetBufferId());
        if ((buffer->GetBufferDeletedFlag() & BufferDeletedFlag::DELETED_FROM_CACHE) !=
            static_cast<BufferDeletedFlag>(0)) {
            buffer->ClearBufferDeletedFlag(BufferDeletedFlag::DELETED_FROM_CACHE);
        }
    }
    auto bitmapFormat = RSBaseRenderUtil::GenerateDrawingBitmapFormat(buffer, alphaType);
    auto screenColorSpace = RSBaseRenderEngine::GetCanvasColorSpace(canvas);
    if (screenColorSpace && drawingColorSpace && RSSystemProperties::GetSkipUnpremulEnabled() &&
        drawingColorSpace->IsSRGB() != screenColorSpace->IsSRGB()) {
        bitmapFormat.alphaType = Drawing::AlphaType::ALPHATYPE_OPAQUE;
    }
    RS_LOGD_IF(DEBUG_COMPOSER, "  - Generated bitmap format: colorType = %{public}d, alphaType = %{public}d",
        bitmapFormat.colorType, bitmapFormat.alphaType);
    auto surfaceOrigin = Drawing::TextureOrigin::TOP_LEFT;
    RS_LOGD_IF(DEBUG_COMPOSER, "  - Texture origin: %{public}d", static_cast<int>(surfaceOrigin));
    auto contextDrawingVk = canvas.GetGPUContext();
    if (contextDrawingVk == nullptr) {
        RS_LOGE("contextDrawingVk is nullptr.");
        return nullptr;
    }
    auto& backendTexture = imageCache->GetBackendTexture();
    if (!image->BuildFromTexture(*contextDrawingVk, backendTexture.GetTextureInfo(),
        surfaceOrigin, bitmapFormat, drawingColorSpace,
        NativeBufferUtils::DeleteVkImage, imageCache->RefCleanupHelper(), params.ignoreAlpha)) {
        RS_LOGE("RSVkImageManager::CreateImageFromBuffer: backendTexture is not valid!!!");
        return nullptr;
    }
    return image;
}

std::shared_ptr<Drawing::Image> RSVkImageManager::GetIntersectImage(Drawing::RectI& imgCutRect,
    const std::shared_ptr<Drawing::GPUContext>& context, const BufferDrawParam& params)
{
    if (params.buffer == nullptr) {
        ROSEN_LOGE("RSVkImageManager::GetIntersectImageFromVK context or buffer is nullptr!");
        return nullptr;
    }
    auto imageCache = CreateImageCacheFromBuffer(params.buffer, params.acquireFence);
    if (imageCache == nullptr) {
        ROSEN_LOGE("RSVkImageManager::GetIntersectImageFromVK imageCache == nullptr!");
        return nullptr;
    }
    auto& backendTexture = imageCache->GetBackendTexture();
    Drawing::BitmapFormat bitmapFormat = RSBaseRenderUtil::GenerateDrawingBitmapFormat(params.buffer);

    std::shared_ptr<Drawing::Image> layerImage = std::make_shared<Drawing::Image>();
    if (!layerImage->BuildFromTexture(*context, backendTexture.GetTextureInfo(),
        Drawing::TextureOrigin::TOP_LEFT, bitmapFormat, nullptr,
        NativeBufferUtils::DeleteVkImage, imageCache->RefCleanupHelper(), params.ignoreAlpha)) {
        ROSEN_LOGE("RSVkImageManager::GetIntersectImageFromVK image BuildFromTexture failed.");
        return nullptr;
    }

    std::shared_ptr<Drawing::Image> cutDownImage = std::make_shared<Drawing::Image>();
    bool res = cutDownImage->BuildSubset(layerImage, imgCutRect, *context);
    if (!res) {
        ROSEN_LOGE("RSVkImageManager::GetIntersectImageFromVK cutDownImage BuildSubset failed.");
        return nullptr;
    }
    return cutDownImage;
}
} // namespace Rosen
} // namespace OHOS