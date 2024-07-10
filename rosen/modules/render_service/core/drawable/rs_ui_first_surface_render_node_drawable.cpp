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

#include <memory>

#include "impl_interface/region_impl.h"
#include "rs_trace.h"

#include "common/rs_color.h"
#include "common/rs_common_def.h"
#include "common/rs_obj_abs_geometry.h"
#include "draw/brush.h"
#include "drawable/rs_surface_render_node_drawable.h"
#include "memory/rs_tag_tracker.h"
#include "params/rs_display_render_params.h"
#include "pipeline/parallel_render/rs_sub_thread_manager.h"
#include "pipeline/rs_main_thread.h"
#include "pipeline/rs_paint_filter_canvas.h"
#include "pipeline/rs_surface_render_node.h"
#include "pipeline/rs_uifirst_manager.h"
#include "pipeline/rs_uni_render_thread.h"
#include "pipeline/rs_uni_render_util.h"
#include "pipeline/sk_resource_manager.h"
#include "platform/common/rs_log.h"
#include "rs_profiler.h"
#include "rs_frame_report.h"
#include "utils/rect.h"
#include "utils/region.h"
#ifdef RS_ENABLE_VK
#include "include/gpu/GrBackendSurface.h"
#include "platform/ohos/backend/native_buffer_utils.h"
#include "platform/ohos/backend/rs_vulkan_context.h"
#endif

#ifdef RS_ENABLE_VK
namespace {
uint32_t findMemoryType(uint32_t typeFilter, VkMemoryPropertyFlags properties)
{
    auto& vkContext = OHOS::Rosen::RsVulkanContext::GetSingleton().GetRsVulkanInterface();
    VkPhysicalDevice physicalDevice = vkContext.GetPhysicalDevice();

    VkPhysicalDeviceMemoryProperties memProperties;
    vkContext.vkGetPhysicalDeviceMemoryProperties(physicalDevice, &memProperties);

    for (uint32_t i = 0; i < memProperties.memoryTypeCount; i++) {
        if ((typeFilter & (1 << i)) && (memProperties.memoryTypes[i].propertyFlags & properties) == properties) {
            return i;
        }
    }

    return UINT32_MAX;
}

void SetVkImageInfo(std::shared_ptr<OHOS::Rosen::Drawing::VKTextureInfo> vkImageInfo,
    const VkImageCreateInfo& imageInfo)
{
    vkImageInfo->imageTiling = imageInfo.tiling;
    vkImageInfo->imageLayout = imageInfo.initialLayout;
    vkImageInfo->format = imageInfo.format;
    vkImageInfo->imageUsageFlags = imageInfo.usage;
    vkImageInfo->levelCount = imageInfo.mipLevels;
    vkImageInfo->currentQueueFamily = VK_QUEUE_FAMILY_EXTERNAL;
    vkImageInfo->ycbcrConversionInfo = {};
    vkImageInfo->sharingMode = imageInfo.sharingMode;
}

OHOS::Rosen::Drawing::BackendTexture MakeBackendTexture(uint32_t width, uint32_t height,
    VkFormat format = VK_FORMAT_R8G8B8A8_UNORM)
{
    VkImageTiling tiling = VK_IMAGE_TILING_OPTIMAL;
    VkImageUsageFlags usage = VK_IMAGE_USAGE_TRANSFER_SRC_BIT | VK_IMAGE_USAGE_TRANSFER_DST_BIT |
        VK_IMAGE_USAGE_SAMPLED_BIT | VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT;
    VkImageCreateInfo imageInfo {
        .sType = VK_STRUCTURE_TYPE_IMAGE_CREATE_INFO,
        .pNext = nullptr,
        .flags = 0,
        .imageType = VK_IMAGE_TYPE_2D,
        .format = format,
        .extent = {width, height, 1},
        .mipLevels = 1,
        .arrayLayers = 1,
        .samples = VK_SAMPLE_COUNT_1_BIT,
        .tiling = tiling,
        .usage = usage,
        .sharingMode = VK_SHARING_MODE_EXCLUSIVE,
        .initialLayout = VK_IMAGE_LAYOUT_UNDEFINED
    };

    auto& vkContext = OHOS::Rosen::RsVulkanContext::GetSingleton().GetRsVulkanInterface();
    VkDevice device = vkContext.GetDevice();
    VkImage image = VK_NULL_HANDLE;
    VkDeviceMemory memory = VK_NULL_HANDLE;

    if (vkContext.vkCreateImage(device, &imageInfo, nullptr, &image) != VK_SUCCESS) {
        return {};
    }

    VkMemoryRequirements memRequirements;
    vkContext.vkGetImageMemoryRequirements(device, image, &memRequirements);

    VkMemoryAllocateInfo allocInfo{};
    allocInfo.sType = VK_STRUCTURE_TYPE_MEMORY_ALLOCATE_INFO;
    allocInfo.allocationSize = memRequirements.size;
    allocInfo.memoryTypeIndex = findMemoryType(memRequirements.memoryTypeBits, VK_MEMORY_PROPERTY_DEVICE_LOCAL_BIT);
    if (allocInfo.memoryTypeIndex == UINT32_MAX) {
        return {};
    }

    if (vkContext.vkAllocateMemory(device, &allocInfo, nullptr, &memory) != VK_SUCCESS) {
        return {};
    }

    vkContext.vkBindImageMemory(device, image, memory, 0);

    OHOS::Rosen::Drawing::BackendTexture backendTexture(true);
    OHOS::Rosen::Drawing::TextureInfo textureInfo;
    textureInfo.SetWidth(width);
    textureInfo.SetHeight(height);

    std::shared_ptr<OHOS::Rosen::Drawing::VKTextureInfo> vkImageInfo =
        std::make_shared<OHOS::Rosen::Drawing::VKTextureInfo>();
    vkImageInfo->vkImage = image;
    vkImageInfo->vkAlloc.memory = memory;
    vkImageInfo->vkAlloc.size = memRequirements.size;

    SetVkImageInfo(vkImageInfo, imageInfo);
    textureInfo.SetVKTextureInfo(vkImageInfo);
    backendTexture.SetTextureInfo(textureInfo);
    return backendTexture;
}
} // un-named
#endif // RS_ENABLE_VK
namespace OHOS::Rosen::DrawableV2 {
CacheProcessStatus RSSurfaceRenderNodeDrawable::GetCacheSurfaceProcessedStatus() const
{
    return uiFirstParams.cacheProcessStatus_.load();
}

void RSSurfaceRenderNodeDrawable::SetCacheSurfaceProcessedStatus(CacheProcessStatus cacheProcessStatus)
{
    uiFirstParams.cacheProcessStatus_.store(cacheProcessStatus);
}

std::shared_ptr<Drawing::Surface> RSSurfaceRenderNodeDrawable::GetCacheSurface(uint32_t threadIndex,
    bool needCheckThread, bool releaseAfterGet)
{
    {
        if (releaseAfterGet) {
            return std::move(UIFirstCache_->cacheSurface_);
        }
        if (!needCheckThread || cacheSurfaceThreadIndex_ == threadIndex || !UIFirstCache_->cacheSurface_) {
            return UIFirstCache_->cacheSurface_;
        }
    }

    // freeze cache scene
    ClearCacheSurfaceInThread();
    return nullptr;
}

void RSSurfaceRenderNodeDrawable::ClearCacheSurfaceInThread()
{
    if (UseDmaBuffer()) {
        ClearBufferQueue();
    } else {
        std::scoped_lock<std::recursive_mutex> lock(completeResourceMutex_);
        if (clearCacheSurfaceFunc_) {
            clearCacheSurfaceFunc_(std::move(UIFirstCache_->cacheSurface_),
                std::move(UIFirstCompletedCache_->cacheSurface_),
                cacheSurfaceThreadIndex_, completedSurfaceThreadIndex_);
        }
        ClearCacheSurface();
    }
}

void RSSurfaceRenderNodeDrawable::ClearCacheSurfaceOnly()
{
    RS_TRACE_NAME("ClearCacheSurfaceOnly");
    if (UIFirstCache_->cacheSurface_ == nullptr) {
        return;
    }
    if (clearCacheSurfaceFunc_) {
        clearCacheSurfaceFunc_(
            std::move(UIFirstCache_->cacheSurface_), nullptr,
            cacheSurfaceThreadIndex_, completedSurfaceThreadIndex_);
    }
    ClearCacheSurface(false);
    UIFirstCache_->cacheSurface_.reset();
}

Vector2f RSSurfaceRenderNodeDrawable::GetGravityTranslate(float imgWidth, float imgHeight)
{
    auto surfaceParams = static_cast<RSSurfaceRenderParams*>(GetRenderParams().get());
    if (!surfaceParams) {
        RS_LOGE("RSSurfaceRenderNodeDrawable::GetGravityTranslate surfaceParams is nullptr");
        return Vector2f{};
    }
    auto gravity = surfaceParams->GetUIFirstFrameGravity();
    float boundsWidth = surfaceParams->GetCacheSize().x_;
    float boundsHeight = surfaceParams->GetCacheSize().y_;
    Drawing::Matrix gravityMatrix;
    RSPropertiesPainter::GetGravityMatrix(gravity, RectF {0.0f, 0.0f, boundsWidth, boundsHeight},
        imgWidth, imgHeight, gravityMatrix);
    return {gravityMatrix.Get(Drawing::Matrix::TRANS_X), gravityMatrix.Get(Drawing::Matrix::TRANS_Y)};
}

std::shared_ptr<Drawing::Image> RSSurfaceRenderNodeDrawable::GetCompletedImage(
    RSPaintFilterCanvas& canvas, uint32_t threadIndex, bool isUIFirst)
{
    if (isUIFirst) {
#if defined(RS_ENABLE_GL) || defined(RS_ENABLE_VK)
        std::scoped_lock<std::recursive_mutex> lock(completeResourceMutex_);
        if (!UIFirstCompletedCache_->cacheBackendTexture_.IsValid()) {
            RS_LOGE("RSSurfaceRenderNodeDrawable::GetCompletedImage invalid grBackendTexture_");
            return nullptr;
        }
#ifdef RS_ENABLE_VK
        if (OHOS::Rosen::RSSystemProperties::GetGpuApiType() == OHOS::Rosen::GpuApiType::VULKAN ||
            OHOS::Rosen::RSSystemProperties::GetGpuApiType() == OHOS::Rosen::GpuApiType::DDGR) {
            if (!UIFirstCompletedCache_->cacheSurface_ || !UIFirstCompletedCache_->cacheCleanupHelper_) {
                RS_LOGE("RSSurfaceRenderNodeDrawable::GetCompletedImage surface %p cleanupHelper %p",
                    UIFirstCompletedCache_->cacheSurface_.get(), UIFirstCompletedCache_->cacheSurface_.get());
                return nullptr;
            }
        }
#endif
        auto& image = UIFirstCompletedCache_->image_;
        Drawing::TextureOrigin origin = Drawing::TextureOrigin::BOTTOM_LEFT;
        Drawing::BitmapFormat info = Drawing::BitmapFormat{ Drawing::COLORTYPE_RGBA_8888,
            Drawing::ALPHATYPE_PREMUL };
#ifdef RS_ENABLE_GL
        if (OHOS::Rosen::RSSystemProperties::GetGpuApiType() != OHOS::Rosen::GpuApiType::VULKAN &&
            OHOS::Rosen::RSSystemProperties::GetGpuApiType() != OHOS::Rosen::GpuApiType::DDGR) {
            image->BuildFromTexture(*canvas.GetGPUContext(), UIFirstCompletedCache_->cacheBackendTexture_.GetTextureInfo(),
                origin, info, nullptr);
        }
#endif

#ifdef RS_ENABLE_VK
        if (OHOS::Rosen::RSSystemProperties::GetGpuApiType() == OHOS::Rosen::GpuApiType::VULKAN ||
            OHOS::Rosen::RSSystemProperties::GetGpuApiType() == OHOS::Rosen::GpuApiType::DDGR) {
            image->BuildFromTexture(*canvas.GetGPUContext(), UIFirstCompletedCache_->cacheBackendTexture_.GetTextureInfo(),
                origin, info, nullptr,
                NativeBufferUtils::DeleteVkImage, UIFirstCompletedCache_->cacheCleanupHelper_->Ref());
        }
#endif
        return UIFirstCompletedCache_->cacheSurface_ ? image : nullptr;
#endif
    }

    if (!UIFirstCompletedCache_->cacheSurface_) {
        RS_LOGE("RSSurfaceRenderNodeDrawable::GetCompletedImage DrawCacheSurface invalid cacheCompletedSurface");
        return nullptr;
    }
    auto& completeImage = UIFirstCompletedCache_->image_;
    if (!completeImage) {
        RS_LOGE("RSSurfaceRenderNodeDrawable::GetCompletedImage DrawCacheSurface Get complete image failed");
        return nullptr;
    }
    if (threadIndex == completedSurfaceThreadIndex_) {
        return completeImage;
    }
#if defined(RS_ENABLE_GL) || defined(RS_ENABLE_VK)
    Drawing::TextureOrigin origin = Drawing::TextureOrigin::BOTTOM_LEFT;
    auto backendTexture = completeImage->GetBackendTexture(false, &origin);
    if (!backendTexture.IsValid()) {
        RS_LOGE("RSSurfaceRenderNodeDrawable::GetCompletedImage DrawCacheSurface get backendTexture failed");
        return nullptr;
    }
    SharedSurfaceContext* sharedContext = new SharedSurfaceContext(UIFirstCompletedCache_->cacheSurface_);
    auto cacheImage = std::make_shared<Drawing::Image>();
    Drawing::BitmapFormat info =
        Drawing::BitmapFormat{ completeImage->GetColorType(), completeImage->GetAlphaType() };
    bool ret = cacheImage->BuildFromTexture(*canvas.GetGPUContext(), backendTexture.GetTextureInfo(),
        origin, info, nullptr, SKResourceManager::DeleteSharedTextureContext, sharedContext);
    if (!ret) {
        RS_LOGE("RSSurfaceRenderNodeDrawable::GetCompletedImage image BuildFromTexture failed");
        return nullptr;
    }
    UIFirstCompletedCache_->image_ = cacheImage;
    return UIFirstCompletedCache_->cacheSurface_ ? cacheImage : nullptr;
#else
    return UIFirstCompletedCache_->cacheSurface_ ? completeImage : nullptr;
#endif
}

bool RSSurfaceRenderNodeDrawable::DrawCacheSurface(RSPaintFilterCanvas& canvas, const Vector2f& boundSize,
    uint32_t threadIndex, bool isUIFirst)
{
    if (ROSEN_EQ(boundsWidth_, 0.f) || ROSEN_EQ(boundsHeight_, 0.f)) {
        RS_LOGE("RSSurfaceRenderNodeDrawable::DrawCacheSurface return %d", __LINE__);
        return false;
    }

    auto cacheImage = GetCompletedImage(canvas, threadIndex, isUIFirst);
    RSBaseRenderUtil::WriteCacheImageRenderNodeToPng(cacheImage, "cacheImage");
    if (cacheImage == nullptr) {
        RS_LOGE("RSSurfaceRenderNodeDrawable::DrawCacheSurface return %d", __LINE__);
        return false;
    }
    float scaleX = boundSize.x_ / static_cast<float>(cacheImage->GetWidth());
    float scaleY = boundSize.y_ / static_cast<float>(cacheImage->GetHeight());
    canvas.Save();
    canvas.Scale(scaleX, scaleY);
    if (RSSystemProperties::GetRecordingEnabled()) {
        if (cacheImage->IsTextureBacked()) {
            RS_LOGI("RSSurfaceRenderNodeDrawable::DrawCacheSurface convert cacheImage from texture to raster image");
            cacheImage = cacheImage->MakeRasterImage();
        }
    }
    Drawing::Brush brush;
    if (GetHDRPresent()) {
        brush.SetForceBrightnessDisable(true);
    }
    canvas.AttachBrush(brush);
    auto samplingOptions = Drawing::SamplingOptions(Drawing::FilterMode::LINEAR, Drawing::MipmapMode::NONE);
    auto gravityTranslate = GetGravityTranslate(cacheImage->GetWidth(), cacheImage->GetHeight());
    canvas.DrawImage(*cacheImage, gravityTranslate.x_, gravityTranslate.y_, samplingOptions);
    canvas.DetachBrush();
    canvas.Restore();
    return true;
}

void RSSurfaceRenderNodeDrawable::InitCacheSurface(Drawing::GPUContext* gpuContext, ClearCacheSurfaceFunc func,
    uint32_t threadIndex)
{
    if (func) {
        cacheSurfaceThreadIndex_ = threadIndex;
        if (!clearCacheSurfaceFunc_) {
            clearCacheSurfaceFunc_ = func;
        }
        if (UIFirstCache_->cacheSurface_) {
            func(std::move(UIFirstCache_->cacheSurface_), nullptr,
                cacheSurfaceThreadIndex_, completedSurfaceThreadIndex_);
            UIFirstCache_->cacheSurface_ = nullptr;
        }
    } else {
        UIFirstCache_->cacheSurface_ = nullptr;
    }

    float width = 0.0f;
    float height = 0.0f;
    if (const auto& params = GetRenderParams()) {
        auto size = params->GetCacheSize();
        boundsWidth_ = size.x_;
        boundsHeight_ = size.y_;
    } else {
        RS_LOGE("uifirst cannot get cachesize");
    }

    width = boundsWidth_;
    height = boundsHeight_;

#if (defined (RS_ENABLE_GL) || defined (RS_ENABLE_VK)) && (defined RS_ENABLE_EGLIMAGE)
    if (gpuContext == nullptr) {
        if (func) {
            std::scoped_lock<std::recursive_mutex> lock(completeResourceMutex_);
            func(std::move(UIFirstCache_->cacheSurface_), std::move(UIFirstCompletedCache_->cacheSurface_),
                cacheSurfaceThreadIndex_, completedSurfaceThreadIndex_);
            ClearCacheSurface();
        }
        RS_LOGE("RSSurfaceRenderNodeDrawable::InitCacheSurface gpuContext == nullptr");
        return;
    }
#ifdef RS_ENABLE_GL
    if (OHOS::Rosen::RSSystemProperties::GetGpuApiType() != OHOS::Rosen::GpuApiType::VULKAN &&
        OHOS::Rosen::RSSystemProperties::GetGpuApiType() != OHOS::Rosen::GpuApiType::DDGR) {
        Drawing::ImageInfo info = Drawing::ImageInfo::MakeN32Premul(width, height);
        UIFirstCache_->cacheSurface_ = Drawing::Surface::MakeRenderTarget(gpuContext, true, info);
    }
#endif
#ifdef RS_ENABLE_VK
    if (OHOS::Rosen::RSSystemProperties::GetGpuApiType() == OHOS::Rosen::GpuApiType::VULKAN ||
        OHOS::Rosen::RSSystemProperties::GetGpuApiType() == OHOS::Rosen::GpuApiType::DDGR) {
        UIFirstCache_->cacheBackendTexture_ = MakeBackendTexture(width, height);
        auto vkTextureInfo = UIFirstCache_->cacheBackendTexture_.GetTextureInfo().GetVKTextureInfo();
        if (!UIFirstCache_->cacheBackendTexture_.IsValid() || !vkTextureInfo) {
            if (func) {
                std::scoped_lock<std::recursive_mutex> lock(completeResourceMutex_);
                func(std::move(UIFirstCache_->cacheSurface_), std::move(UIFirstCompletedCache_->cacheSurface_),
                    cacheSurfaceThreadIndex_, completedSurfaceThreadIndex_);
                ClearCacheSurface();
            }
            RS_LOGE("RSSurfaceRenderNodeDrawable::InitCacheSurface !UIFirstCache_->cacheBackendTexture_.IsValid() || !vkTextureInfo");
            return;
        }
        UIFirstCache_->cacheCleanupHelper_ = new NativeBufferUtils::VulkanCleanupHelper(RsVulkanContext::GetSingleton(),
            vkTextureInfo->vkImage, vkTextureInfo->vkAlloc.memory);
        UIFirstCache_->cacheSurface_ = Drawing::Surface::MakeFromBackendTexture(
            gpuContext, UIFirstCache_->cacheBackendTexture_.GetTextureInfo(), Drawing::TextureOrigin::BOTTOM_LEFT,
            1, Drawing::ColorType::COLORTYPE_RGBA_8888, nullptr,
            NativeBufferUtils::DeleteVkImage, UIFirstCache_->cacheCleanupHelper_);
    }
#endif
#else
    UIFirstCache_->cacheSurface_ = Drawing::Surface::MakeRasterN32Premul(width, height);
#endif
}
bool RSSurfaceRenderNodeDrawable::HasCachedTexture() const
{
#if (defined(RS_ENABLE_GL) || defined(RS_ENABLE_VK))
    return isTextureValid_.load() || GetBuffer() != nullptr;
#else
    return true;
#endif
}

bool RSSurfaceRenderNodeDrawable::NeedInitCacheSurface()
{
    int width = 0;
    int height = 0;

    if (const auto& params = GetRenderParams()) {
        auto size = params->GetCacheSize();
        width =  size.x_;
        height = size.y_;
    }

    if (UIFirstCache_->cacheSurface_ == nullptr) {
        return true;
    }
    auto cacheCanvas = UIFirstCache_->cacheSurface_->GetCanvas();
    if (cacheCanvas == nullptr) {
        return true;
    }
    return cacheCanvas->GetWidth() != width || cacheCanvas->GetHeight() != height;
}

#if defined(RS_ENABLE_GL) || defined(RS_ENABLE_VK)
void RSSurfaceRenderNodeDrawable::UpdateBackendTexture()
{
    RS_TRACE_NAME("RSRenderNodeDrawable::UpdateBackendTexture()");
    if (UIFirstCache_->cacheSurface_ == nullptr) {
        return;
    }
    UIFirstCache_->cacheBackendTexture_ = UIFirstCache_->cacheSurface_->GetBackendTexture();
}
#endif

void RSSurfaceRenderNodeDrawable::UpdateCompletedCacheSurface()
{
    RS_TRACE_NAME("RSRenderNodeDrawable::UpdateCompletedCacheSurface()");
    // renderthread not use, subthread done not use
    std::swap(UIFirstCache_, UIFirstCompletedCache_);
    UIFirstCompletedCache_->image_ = UIFirstCompletedCache_->cacheSurface_->GetImageSnapshot();
    std::swap(cacheSurfaceThreadIndex_, completedSurfaceThreadIndex_);
#if (defined(RS_ENABLE_GL) || defined(RS_ENABLE_VK))
    SetTextureValidFlag(true);
    SetCacheSurfaceNeedUpdated(false);
#endif
    RSBaseRenderUtil::WriteCacheImageRenderNodeToPng(UIFirstCache_->cacheSurface_, "UIFirstCache_->cacheSurface_");
    RSBaseRenderUtil::WriteCacheImageRenderNodeToPng(UIFirstCompletedCache_->cacheSurface_, "UIFirstCompletedCache_->cacheSurface_");
}
void RSSurfaceRenderNodeDrawable::SetTextureValidFlag(bool isValid)
{
#if (defined(RS_ENABLE_GL) || defined(RS_ENABLE_VK))
    isTextureValid_.store(isValid);
#endif
}
void RSSurfaceRenderNodeDrawable::ClearCacheSurface(bool isClearCompletedCacheSurface)
{
    UIFirstCache_->cacheSurface_ = nullptr;
#ifdef RS_ENABLE_VK
    if (RSSystemProperties::GetGpuApiType() == GpuApiType::VULKAN ||
        RSSystemProperties::GetGpuApiType() == GpuApiType::DDGR) {
        UIFirstCache_->cacheCleanupHelper_ = nullptr;
    }
#endif
    if (isClearCompletedCacheSurface) {
        std::scoped_lock<std::recursive_mutex> lock(completeResourceMutex_);
        UIFirstCompletedCache_->cacheSurface_ = nullptr;
#ifdef RS_ENABLE_VK
        if (RSSystemProperties::GetGpuApiType() == GpuApiType::VULKAN ||
            RSSystemProperties::GetGpuApiType() == GpuApiType::DDGR) {
            UIFirstCompletedCache_->cacheCleanupHelper_ = nullptr;
        }
#endif
#if defined(NEW_SKIA) && (defined(RS_ENABLE_GL) || defined(RS_ENABLE_VK))
        isTextureValid_.store(false);
#endif
    }
}

bool RSSurfaceRenderNodeDrawable::IsCurFrameStatic(DeviceType deviceType)
{
    auto surfaceParams = static_cast<RSSurfaceRenderParams*>(GetRenderParams().get());
    if (!surfaceParams) {
        RS_LOGE("RSSurfaceRenderNodeDrawable::OnDraw params is nullptr");
        return false;
    }
    RS_TRACE_NAME_FMT("RSSurfaceRenderNodeDrawable::GetSurfaceCacheContentStatic: [%d] name [%s] Id:%" PRIu64 "",
        surfaceParams->GetSurfaceCacheContentStatic(), surfaceParams->GetName().c_str(), surfaceParams->GetId());
    return surfaceParams->GetSurfaceCacheContentStatic();
}

void RSSurfaceRenderNodeDrawable::SetTaskFrameCount(uint64_t frameCount)
{
    frameCount_ = frameCount;
}

uint64_t RSSurfaceRenderNodeDrawable::GetTaskFrameCount() const
{
    return frameCount_;
}

void RSSurfaceRenderNodeDrawable::SubDraw(Drawing::Canvas& canvas)
{
    const auto& uifirstParams = GetUifirstRenderParams();
    auto debugSize = uifirstParams ? uifirstParams->GetCacheSize() : Vector2f(0.f, 0.f);
    RS_TRACE_NAME_FMT("RSSurfaceRenderNodeDrawable::SubDraw[%s] w%.1f h%.1f",
        name_.c_str(), debugSize.x_, debugSize.y_);

    auto rscanvas = reinterpret_cast<RSPaintFilterCanvas*>(&canvas);
    if (!rscanvas) {
        RS_LOGE("RSSurfaceRenderNodeDrawable::SubDraw, rscanvas us nullptr");
        return;
    }
    Drawing::Rect bounds = uifirstParams ? uifirstParams->GetBounds() : Drawing::Rect(0, 0, 0, 0);

    auto parentSurfaceMatrix = RSRenderParams::GetParentSurfaceMatrix();
    RSRenderParams::SetParentSurfaceMatrix(rscanvas->GetTotalMatrix());

    RSRenderNodeDrawable::DrawUifirstContentChildren(*rscanvas, bounds);
    RSRenderParams::SetParentSurfaceMatrix(parentSurfaceMatrix);
}

bool RSSurfaceRenderNodeDrawable::DrawUIFirstCache(RSPaintFilterCanvas& rscanvas, bool canSkipWait)
{
    RS_TRACE_NAME_FMT("DrawUIFirstCache_NOSTARTING");
    const auto& params = GetRenderParams();
    if (!params) {
        RS_LOGE("RSUniRenderUtil::HandleSubThreadNodeDrawable params is nullptr");
        return false;
    }

    static constexpr int REQUEST_SET_FRAME_LOAD_ID = 100006;
    static constexpr int REQUEST_FRAME_AWARE_LOAD = 90;
    static constexpr int REQUEST_FRAME_STANDARD_LOAD = 50;
    if (!HasCachedTexture()) {
        RS_TRACE_NAME_FMT("HandleSubThreadNode wait %d %lld", canSkipWait, nodeId_);
        if (canSkipWait) {
            return false; // draw nothing
        }
#if defined(RS_ENABLE_GL) || defined(RS_ENABLE_VK)
        bool frameParamEnable = RsFrameReport::GetInstance().GetEnable();
        if (frameParamEnable) {
            RsFrameReport::GetInstance().SetFrameParam(
                REQUEST_SET_FRAME_LOAD_ID, REQUEST_FRAME_AWARE_LOAD, 0, GetLastFrameUsedThreadIndex());
        }
        RSSubThreadManager::Instance()->WaitNodeTask(nodeId_);
        if (frameParamEnable) {
            RsFrameReport::GetInstance().SetFrameParam(
                REQUEST_SET_FRAME_LOAD_ID, REQUEST_FRAME_STANDARD_LOAD, 0, GetLastFrameUsedThreadIndex());
        }
        UpdateCompletedCacheSurface();
#endif
    }
    return DrawCacheSurface(rscanvas, params->GetCacheSize(), UNI_MAIN_THREAD_INDEX, true);
}

bool RSSurfaceRenderNodeDrawable::DrawUIFirstCacheWithStarting(RSPaintFilterCanvas& rscanvas, NodeId id)
{
    RS_TRACE_NAME_FMT("DrawUIFirstCacheWithStarting %d, nodeID:%lld", HasCachedTexture(), id);
    const auto& params = GetRenderParams();
    if (!params) {
        RS_LOGE("RSUniRenderUtil::HandleSubThreadNodeDrawable params is nullptr");
        return false;
    }
    bool ret = true;
    // draw surface content&&childrensss
    if (HasCachedTexture()) {
        ret = DrawCacheSurface(rscanvas, params->GetCacheSize(), UNI_MAIN_THREAD_INDEX, true);
    }
    // draw starting window
    {
        auto drawable = RSRenderNodeDrawableAdapter::GetDrawableById(id);
        if (!drawable) {
            return false;
        }
        RS_TRACE_NAME_FMT("drawStarting");
        drawable->Draw(rscanvas);
    }
    return ret;
}
} // namespace OHOS::Rosen
