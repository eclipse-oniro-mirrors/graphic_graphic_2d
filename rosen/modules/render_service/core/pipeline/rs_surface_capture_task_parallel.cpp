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

#include "pipeline/rs_surface_capture_task_parallel.h"

#include <memory>
#include <sys/mman.h>

#include "draw/surface.h"
#include "draw/color.h"
#include "rs_trace.h"

#include "common/rs_background_thread.h"
#include "common/rs_obj_abs_geometry.h"
#include "memory/rs_tag_tracker.h"
#include "params/rs_surface_render_params.h"
#include "pipeline/rs_base_render_node.h"
#include "pipeline/rs_display_render_node.h"
#include "pipeline/rs_main_thread.h"
#include "pipeline/rs_paint_filter_canvas.h"
#include "pipeline/rs_render_service_connection.h"
#include "pipeline/rs_surface_render_node.h"
#include "pipeline/rs_uifirst_manager.h"
#include "pipeline/rs_uni_render_judgement.h"
#include "pipeline/rs_uni_render_util.h"
#include "platform/common/rs_log.h"
#include "platform/drawing/rs_surface.h"
#include "render/rs_drawing_filter.h"
#include "render/rs_skia_filter.h"
#include "screen_manager/rs_screen_manager.h"
#include "screen_manager/rs_screen_mode_info.h"

namespace OHOS {
namespace Rosen {

static inline void DrawCapturedImg(Drawing::Image& image,
    Drawing::Surface& surface, const Drawing::BackendTexture& backendTexture,
    Drawing::TextureOrigin& textureOrigin, Drawing::BitmapFormat& bitmapFormat)
{
    RSPaintFilterCanvas canvas(&surface);
    auto gpuContext = canvas.GetGPUContext();
    if (gpuContext == nullptr) {
        RS_LOGE("DrawCapturedImg failed: gpuContext is nullptr");
        return;
    }
    image.BuildFromTexture(*gpuContext, backendTexture.GetTextureInfo(),
        textureOrigin, bitmapFormat, nullptr);
    canvas.DrawImage(image, 0.f, 0.f, Drawing::SamplingOptions());
    surface.FlushAndSubmit(true);
}

void RSSurfaceCaptureTaskParallel::CheckModifiers(NodeId id)
{
    RS_TRACE_NAME("RSSurfaceCaptureTaskParallel::CheckModifiers");
    bool needSync = RSMainThread::Instance()->IsOcclusionNodesNeedSync(id) ||
        RSMainThread::Instance()->IsHardwareEnabledNodesNeedSync();
    if (!needSync) {
        return;
    }
    std::function<void()> syncTask = []() -> void {
        RS_TRACE_NAME("RSSurfaceCaptureTaskParallel::SyncModifiers");
        auto& pendingSyncNodes = RSMainThread::Instance()->GetContext().pendingSyncNodes_;
        for (auto& [id, weakPtr] : pendingSyncNodes) {
            if (auto node = weakPtr.lock()) {
                if (!RSUifirstManager::Instance().CollectSkipSyncNode(node)) {
                    node->Sync();
                } else {
                    node->SkipSync();
                }
            }
        }
        pendingSyncNodes.clear();
    };
    RSUniRenderThread::Instance().PostSyncTask(syncTask);
}

void RSSurfaceCaptureTaskParallel::Capture(NodeId id,
    sptr<RSISurfaceCaptureCallback> callback, const RSSurfaceCaptureConfig& captureConfig)
{
    std::shared_ptr<RSSurfaceCaptureTaskParallel> captureHandle =
        std::make_shared<RSSurfaceCaptureTaskParallel>(id, captureConfig);
    if (captureHandle == nullptr) {
        RS_LOGD("RSSurfaceCaptureTaskParallel::Capture captureHandle is nullptr!");
        callback->OnSurfaceCapture(id, nullptr);
        return;
    }
    if (!captureHandle->CreateResources()) {
        callback->OnSurfaceCapture(id, nullptr);
    }

    std::function<void()> captureTask = [captureHandle, id, callback]() -> void {
        RS_TRACE_NAME("RSSurfaceCaptureTaskParallel::TakeSurfaceCapture");
        if (!captureHandle->Run(callback)) {
            callback->OnSurfaceCapture(id, nullptr);
        }
    };
    RSUniRenderThread::Instance().PostSyncTask(captureTask);
}

bool RSSurfaceCaptureTaskParallel::CreateResources()
{
    RS_LOGD("RSSurfaceCaptureTaskParallel capture nodeId:[%{public}" PRIu64 "]", nodeId_);
    if (ROSEN_EQ(captureConfig_.scaleX, 0.f) || ROSEN_EQ(captureConfig_.scaleY, 0.f) ||
        captureConfig_.scaleX < 0.f || captureConfig_.scaleY < 0.f) {
        RS_LOGE("RSSurfaceCaptureTaskParallel::CreateResources: SurfaceCapture scale is invalid.");
        return false;
    }
    auto node = RSMainThread::Instance()->GetContext().GetNodeMap().GetRenderNode(nodeId_);
    if (node == nullptr) {
        RS_LOGE("RSSurfaceCaptureTaskParallel::CreateResources: Invalid nodeId:[%{public}" PRIu64 "]",
            nodeId_);
        return false;
    }

    if (auto surfaceNode = node->ReinterpretCastTo<RSSurfaceRenderNode>()) {
        auto curNode = surfaceNode;
        if (!captureConfig_.useCurWindow) {
            auto parentNode = RSBaseRenderNode::ReinterpretCast<RSSurfaceRenderNode>(surfaceNode->GetParent().lock());
            if (parentNode && parentNode->IsLeashWindow() && parentNode->ShouldPaint()) {
                curNode = parentNode;
            }
        }
        if (!curNode->ShouldPaint()) {
            RS_LOGE("RSSurfaceCaptureTaskParallel::CreateResources: Node should not paint!");
            return false;
        }

        surfaceNodeDrawable_ = std::static_pointer_cast<DrawableV2::RSRenderNodeDrawable>(
            DrawableV2::RSRenderNodeDrawableAdapter::OnGenerate(curNode));
        pixelMap_ = CreatePixelMapBySurfaceNode(curNode);
    } else if (auto displayNode = node->ReinterpretCastTo<RSDisplayRenderNode>()) {
        displayNodeDrawable_ = std::static_pointer_cast<DrawableV2::RSRenderNodeDrawable>(
            DrawableV2::RSRenderNodeDrawableAdapter::OnGenerate(displayNode));
        pixelMap_ = CreatePixelMapByDisplayNode(displayNode);
    } else {
        RS_LOGE("RSSurfaceCaptureTaskParallel::CreateResources: Invalid RSRenderNodeType!");
        return false;
    }
    if (pixelMap_ == nullptr) {
        RS_LOGE("RSSurfaceCaptureTaskParallel::CreateResources: pixelMap_ is nullptr!");
        return false;
    }
    return true;
}

bool RSSurfaceCaptureTaskParallel::Run(sptr<RSISurfaceCaptureCallback> callback)
{
#if defined(RS_ENABLE_GL) || defined(RS_ENABLE_VK)
    SetupGpuContext();
    RSTagTracker tagTracker(gpuContext_.get(), nodeId_, RSTagTracker::TAGTYPE::TAG_CAPTURE);
#endif
    auto surface = CreateSurface(pixelMap_);
    if (surface == nullptr) {
        RS_LOGE("RSSurfaceCaptureTaskParallel::Run: surface is nullptr!");
        return false;
    }

    RSPaintFilterCanvas canvas(surface.get());
    canvas.Scale(captureConfig_.scaleX, captureConfig_.scaleY);
    canvas.SetDisableFilterCache(true);
    RSSurfaceRenderParams* curNodeParams = nullptr;
    if (surfaceNodeDrawable_) {
        curNodeParams = static_cast<RSSurfaceRenderParams*>(surfaceNodeDrawable_->GetRenderParams().get());
        RSUniRenderThread::SetCaptureParam(
            CaptureParam(true, true, false, captureConfig_.scaleX, captureConfig_.scaleY, true));
        surfaceNodeDrawable_->OnCapture(canvas);
    } else if (displayNodeDrawable_) {
        RSUniRenderThread::SetCaptureParam(
            CaptureParam(true, false, false, captureConfig_.scaleX, captureConfig_.scaleY));
        displayNodeDrawable_->OnCapture(canvas);
    } else {
        RS_LOGE("RSSurfaceCaptureTaskParallel::Run: Invalid RSRenderNodeDrawable!");
        return false;
    }
    RSUniRenderThread::ResetCaptureParam();

#if (defined (RS_ENABLE_GL) || defined (RS_ENABLE_VK)) && (defined RS_ENABLE_EGLIMAGE)
#ifdef RS_ENABLE_UNI_RENDER
    RSUniRenderUtil::OptimizedFlushAndSubmit(surface, gpuContext_.get(), !RSSystemProperties::IsPcType());
    if (curNodeParams && curNodeParams->IsNodeToBeCaptured()) {
        RSUifirstManager::Instance().AddCapturedNodes(curNodeParams->GetId());
    }
    if (RSSystemProperties::GetSnapshotWithDMAEnabled()) {
        auto copytask = CreateSurfaceSyncCopyTask(surface, std::move(pixelMap_),
            nodeId_, callback, finalRotationAngle_, captureConfig_.useDma);
        if (!copytask) {
            RS_LOGE("RSSurfaceCaptureTaskParallel::Run: create capture task failed!");
            return false;
        }
        RSBackgroundThread::Instance().PostTask(copytask);
        return true;
    } else {
        std::shared_ptr<Drawing::Image> img(surface.get()->GetImageSnapshot());
        if (!img) {
            RS_LOGE("RSSurfaceCaptureTaskParallel::Run: img is nullptr");
            return false;
        }
        if (!CopyDataToPixelMap(img, pixelMap_)) {
            RS_LOGE("RSSurfaceCaptureTaskParallel::Run: CopyDataToPixelMap failed");
            return false;
        }
    }
#endif
#endif
    if (finalRotationAngle_) {
        pixelMap_->rotate(finalRotationAngle_);
    }
    // To get dump image
    // execute "param set rosen.dumpsurfacetype.enabled 3 && setenforce 0"
    RSBaseRenderUtil::WritePixelMapToPng(*pixelMap_);
    callback->OnSurfaceCapture(nodeId_, pixelMap_.get());
    return true;
}

std::unique_ptr<Media::PixelMap> RSSurfaceCaptureTaskParallel::CreatePixelMapBySurfaceNode(
    std::shared_ptr<RSSurfaceRenderNode> node)
{
    if (node == nullptr) {
        RS_LOGE("RSSurfaceCaptureTaskParallel::CreatePixelMapBySurfaceNode: node == nullptr");
        return nullptr;
    }
    int pixmapWidth = node->GetRenderProperties().GetBoundsWidth();
    int pixmapHeight = node->GetRenderProperties().GetBoundsHeight();

    Media::InitializationOptions opts;
    opts.size.width = ceil(pixmapWidth * captureConfig_.scaleX);
    opts.size.height = ceil(pixmapHeight * captureConfig_.scaleY);
    RS_LOGD("RSSurfaceCaptureTaskParallel::CreatePixelMapBySurfaceNode: NodeId:[%{public}" PRIu64 "],"
        " origin pixelmap size: [%{public}u, %{public}u],"
        " created pixelmap size: [%{public}u, %{public}u],"
        " scale: [%{public}f, %{public}f],"
        " useDma: [%{public}d], useCurWindow: [%{public}d]",
        node->GetId(), pixmapWidth, pixmapHeight, opts.size.width, opts.size.height,
        captureConfig_.scaleX, captureConfig_.scaleY, captureConfig_.useDma, captureConfig_.useCurWindow);
    return Media::PixelMap::Create(opts);
}

std::unique_ptr<Media::PixelMap> RSSurfaceCaptureTaskParallel::CreatePixelMapByDisplayNode(
    std::shared_ptr<RSDisplayRenderNode> node)
{
    if (node == nullptr) {
        RS_LOGE("RSSurfaceCaptureTaskParallel::CreatePixelMapByDisplayNode: node is nullptr");
        return nullptr;
    }
    uint64_t screenId = node->GetScreenId();
    RSScreenModeInfo screenModeInfo;
    sptr<RSScreenManager> screenManager = CreateOrGetScreenManager();
    if (!screenManager) {
        RS_LOGE("RSSurfaceCaptureTaskParallel::CreatePixelMapByDisplayNode: screenManager is nullptr!");
        return nullptr;
    }
    auto screenInfo = screenManager->QueryScreenInfo(screenId);
    screenCorrection_ = screenManager->GetScreenCorrection(screenId);
    screenRotation_ = node->GetScreenRotation();
    finalRotationAngle_ = CalPixelMapRotation();
    uint32_t pixmapWidth = screenInfo.width;
    uint32_t pixmapHeight = screenInfo.height;

    Media::InitializationOptions opts;
    opts.size.width = ceil(pixmapWidth * captureConfig_.scaleX);
    opts.size.height = ceil(pixmapHeight * captureConfig_.scaleY);
    RS_LOGI("RSSurfaceCaptureTaskParallel::CreatePixelMapByDisplayNode: NodeId:[%{public}" PRIu64 "],"
        " origin pixelmap size: [%{public}u, %{public}u],"
        " created pixelmap size: [%{public}u, %{public}u],"
        " scale: [%{public}f, %{public}f],"
        " useDma: [%{public}d]",
        node->GetId(), pixmapWidth, pixmapHeight, opts.size.width, opts.size.height,
        captureConfig_.scaleX, captureConfig_.scaleY, captureConfig_.useDma);
    return Media::PixelMap::Create(opts);
}

std::shared_ptr<Drawing::Surface> RSSurfaceCaptureTaskParallel::CreateSurface(
    const std::unique_ptr<Media::PixelMap>& pixelmap)
{
    if (pixelmap == nullptr) {
        RS_LOGE("RSSurfaceCaptureTaskParallel::CreateSurface: pixelmap == nullptr");
        return nullptr;
    }
    auto address = const_cast<uint32_t*>(pixelmap->GetPixel32(0, 0));
    if (address == nullptr) {
        RS_LOGE("RSSurfaceCaptureTaskParallel::CreateSurface: address == nullptr");
        return nullptr;
    }
    Drawing::ImageInfo info = Drawing::ImageInfo{pixelmap->GetWidth(), pixelmap->GetHeight(),
        Drawing::ColorType::COLORTYPE_RGBA_8888, Drawing::AlphaType::ALPHATYPE_PREMUL};

#if (defined RS_ENABLE_GL) && (defined RS_ENABLE_EGLIMAGE)
    if (RSSystemProperties::GetGpuApiType() == GpuApiType::OPENGL) {
        auto renderContext = RSUniRenderThread::Instance().GetRenderEngine()->GetRenderContext();
        if (renderContext == nullptr) {
            RS_LOGE("RSSurfaceCaptureTaskParallel::CreateSurface: renderContext is nullptr");
            return nullptr;
        }
        renderContext->SetUpGpuContext(nullptr);
        return Drawing::Surface::MakeRenderTarget(renderContext->GetDrGPUContext(), false, info);
    }
#endif
#ifdef RS_ENABLE_VK
    if (RSSystemProperties::GetGpuApiType() == GpuApiType::VULKAN ||
        RSSystemProperties::GetGpuApiType() == GpuApiType::DDGR) {
        return Drawing::Surface::MakeRenderTarget(gpuContext_.get(), false, info);
    }
#endif

    return Drawing::Surface::MakeRasterDirect(info, address, pixelmap->GetRowBytes());
}

void RSSurfaceCaptureTaskParallel::SetupGpuContext()
{
    auto renderContext = RSUniRenderThread::Instance().GetRenderEngine()->GetRenderContext();
    gpuContext_ = renderContext != nullptr ? renderContext->GetSharedDrGPUContext() : nullptr;
    if (gpuContext_ == nullptr) {
        RS_LOGW("RSSurfaceCaptureTaskParallel::SetupGpuContext gpuContext_ is nullptr");
    }
}

int32_t RSSurfaceCaptureTaskParallel::CalPixelMapRotation()
{
    auto screenRotation = ScreenRotationMapping(screenRotation_);
    auto screenCorrection = ScreenRotationMapping(screenCorrection_);
    int32_t rotation = screenRotation - screenCorrection;
    RS_LOGI("RSSurfaceCaptureTaskParallel::CalPixelMapRotation: screenRotation:%{public}d"
        " screenCorrection:%{public}d", screenRotation, screenCorrection);
    return rotation;
}

#ifdef RS_ENABLE_UNI_RENDER
std::function<void()> RSSurfaceCaptureTaskParallel::CreateSurfaceSyncCopyTask(
    std::shared_ptr<Drawing::Surface> surface, std::unique_ptr<Media::PixelMap> pixelMap,
    NodeId id, sptr<RSISurfaceCaptureCallback> callback, int32_t rotation, bool useDma)
{
    Drawing::BackendTexture backendTexture = surface->GetBackendTexture();
    if (!backendTexture.IsValid()) {
        RS_LOGE("RSSurfaceCaptureTaskParallel: SkiaSurface bind Image failed: BackendTexture is invalid");
        return {};
    }
    auto wrapper = std::make_shared<std::tuple<std::unique_ptr<Media::PixelMap>>>();
    std::get<0>(*wrapper) = std::move(pixelMap);
    auto wrapperSf = std::make_shared<std::tuple<std::shared_ptr<Drawing::Surface>>>();
    std::get<0>(*wrapperSf) = std::move(surface);
    std::function<void()> copytask = [wrapper, callback, backendTexture, wrapperSf, id, rotation, useDma]() -> void {
        RS_TRACE_NAME_FMT("copy and send capture useDma:%d", useDma);
        if (!backendTexture.IsValid()) {
            RS_LOGE("RSSurfaceCaptureTaskParallel: Surface bind Image failed: BackendTexture is invalid");
            callback->OnSurfaceCapture(id, nullptr);
            RSUniRenderUtil::ClearNodeCacheSurface(
                std::move(std::get<0>(*wrapperSf)), nullptr, UNI_MAIN_THREAD_INDEX, 0);
            return;
        }
        auto pixelmap = std::move(std::get<0>(*wrapper));
        if (pixelmap == nullptr) {
            RS_LOGE("RSSurfaceCaptureTaskParallel: pixelmap == nullptr");
            callback->OnSurfaceCapture(id, nullptr);
            RSUniRenderUtil::ClearNodeCacheSurface(
                std::move(std::get<0>(*wrapperSf)), nullptr, UNI_MAIN_THREAD_INDEX, 0);
            return;
        }

        Drawing::ImageInfo info = Drawing::ImageInfo{ pixelmap->GetWidth(), pixelmap->GetHeight(),
            Drawing::COLORTYPE_RGBA_8888, Drawing::ALPHATYPE_PREMUL };
        Drawing::TextureOrigin textureOrigin = Drawing::TextureOrigin::BOTTOM_LEFT;
        Drawing::BitmapFormat bitmapFormat =
            Drawing::BitmapFormat{ Drawing::COLORTYPE_RGBA_8888, Drawing::ALPHATYPE_PREMUL };
        std::shared_ptr<Drawing::Surface> surface;
        auto grContext = RSBackgroundThread::Instance().GetShareGPUContext();
#if defined(ROSEN_OHOS) && defined(RS_ENABLE_VK)
        DmaMem dmaMem;
        if (useDma && RSMainThread::Instance()->GetDeviceType() == DeviceType::PHONE &&
            (RSSystemProperties::GetGpuApiType() == GpuApiType::VULKAN ||
            RSSystemProperties::GetGpuApiType() == GpuApiType::DDGR)) {
            sptr<SurfaceBuffer> surfaceBuffer = dmaMem.DmaMemAlloc(info, pixelmap);
            surface = dmaMem.GetSurfaceFromSurfaceBuffer(surfaceBuffer, grContext);
            if (surface == nullptr) {
                RS_LOGE("RSSurfaceCaptureTaskParallel: GetSurfaceFromSurfaceBuffer fail.");
                callback->OnSurfaceCapture(id, nullptr);
                RSUniRenderUtil::ClearNodeCacheSurface(
                    std::move(std::get<0>(*wrapperSf)), nullptr, UNI_MAIN_THREAD_INDEX, 0);
                return;
            }
            auto tmpImg = std::make_shared<Drawing::Image>();
            DrawCapturedImg(*tmpImg, *surface, backendTexture, textureOrigin, bitmapFormat);
        } else {
#else
        {
#endif
            auto tmpImg = std::make_shared<Drawing::Image>();
            tmpImg->BuildFromTexture(*grContext, backendTexture.GetTextureInfo(),
                textureOrigin, bitmapFormat, nullptr);
            if (!CopyDataToPixelMap(tmpImg, pixelmap)) {
                RS_LOGE("RSSurfaceCaptureTaskParallel: CopyDataToPixelMap failed");
                callback->OnSurfaceCapture(id, nullptr);
                RSUniRenderUtil::ClearNodeCacheSurface(
                    std::move(std::get<0>(*wrapperSf)), nullptr, UNI_MAIN_THREAD_INDEX, 0);
                return;
            }
        }
        if (rotation) {
            pixelmap->rotate(rotation);
        }
        // To get dump image
        // execute "param set rosen.dumpsurfacetype.enabled 3 && setenforce 0"
        RSBaseRenderUtil::WritePixelMapToPng(*pixelmap);
        callback->OnSurfaceCapture(id, pixelmap.get());
        RSBackgroundThread::Instance().CleanGrResource();
        RSUniRenderUtil::ClearNodeCacheSurface(
            std::move(std::get<0>(*wrapperSf)), nullptr, UNI_MAIN_THREAD_INDEX, 0);
    };
    return copytask;
}
#endif

#if defined(ROSEN_OHOS) && defined(RS_ENABLE_VK)
DmaMem::~DmaMem()
{
    ReleaseDmaMemory();
}

void DmaMem::ReleaseDmaMemory()
{
    if (nativeWindowBuffer_ != nullptr) {
        DestroyNativeWindowBuffer(nativeWindowBuffer_);
        nativeWindowBuffer_ = nullptr;
    }
}

sptr<SurfaceBuffer> DmaMem::DmaMemAlloc(Drawing::ImageInfo &dstInfo, const std::unique_ptr<Media::PixelMap>& pixelmap)
{
#if defined(_WIN32) || defined(_APPLE) || defined(A_PLATFORM) || defined(IOS_PLATFORM)
    RS_LOGE("Unsupport dma mem alloc");
    return nullptr;
#else
    sptr<SurfaceBuffer> surfaceBuffer = SurfaceBuffer::Create();
    if (!surfaceBuffer) {
        RS_LOGE("DmaMem::DmaMemAlloc: surfaceBuffer create failed");
        return nullptr;
    }
    BufferRequestConfig requestConfig = {
        .width = dstInfo.GetWidth(),
        .height = dstInfo.GetHeight(),
        .strideAlignment = 0x8, // set 0x8 as default value to alloc SurfaceBufferImpl
        .format = GRAPHIC_PIXEL_FMT_RGBA_8888, // PixelFormat
        .usage = BUFFER_USAGE_CPU_READ | BUFFER_USAGE_HW_RENDER | BUFFER_USAGE_HW_TEXTURE | BUFFER_USAGE_MEM_DMA,
        .timeout = 0,
        .colorGamut = GraphicColorGamut::GRAPHIC_COLOR_GAMUT_SRGB,
        .transform = GraphicTransformType::GRAPHIC_ROTATE_NONE,
    };
    GSError ret = surfaceBuffer->Alloc(requestConfig);
    if (ret != GSERROR_OK) {
        RS_LOGE("DmaMem::DmaMemAlloc: surfaceBuffer alloc failed, %{public}s", GSErrorStr(ret).c_str());
        return nullptr;
    }
    void* nativeBuffer = surfaceBuffer.GetRefPtr();
    OHOS::RefBase *ref = reinterpret_cast<OHOS::RefBase *>(nativeBuffer);
    ref->IncStrongRef(ref);
    int32_t bufferSize = pixelmap->GetByteCount();
    pixelmap->SetPixelsAddr(surfaceBuffer->GetVirAddr(), nativeBuffer, bufferSize,
        Media::AllocatorType::DMA_ALLOC, nullptr);
    return surfaceBuffer;
#endif
}

static inline void DeleteVkImage(void *context)
{
    NativeBufferUtils::VulkanCleanupHelper *cleanupHelper =
        static_cast<NativeBufferUtils::VulkanCleanupHelper *> (context);
    if (cleanupHelper != nullptr) {
        cleanupHelper->UnRef();
    }
}

std::shared_ptr<Drawing::Surface> DmaMem::GetSurfaceFromSurfaceBuffer(
    sptr<SurfaceBuffer> surfaceBuffer, std::shared_ptr<Drawing::GPUContext> gpuContext)
{
    if (surfaceBuffer == nullptr || gpuContext == nullptr) {
        RS_LOGE("GetSurfaceFromSurfaceBuffer surfaceBuffer or gpuContext is nullptr");
        return nullptr;
    }
    if (nativeWindowBuffer_ == nullptr) {
        nativeWindowBuffer_ = CreateNativeWindowBufferFromSurfaceBuffer(&surfaceBuffer);
        if (!nativeWindowBuffer_) {
            RS_LOGE("DmaMem::GetSurfaceFromSurfaceBuffer: nativeWindowBuffer_ is nullptr");
            return nullptr;
        }
    }

    Drawing::BackendTexture backendTextureTmp =
        NativeBufferUtils::MakeBackendTextureFromNativeBuffer(nativeWindowBuffer_,
            surfaceBuffer->GetWidth(), surfaceBuffer->GetHeight());
    if (!backendTextureTmp.IsValid()) {
        return nullptr;
    }

    auto vkTextureInfo = backendTextureTmp.GetTextureInfo().GetVKTextureInfo();
    vkTextureInfo->imageUsageFlags = vkTextureInfo->imageUsageFlags | VK_IMAGE_USAGE_COLOR_ATTACHMENT_BIT;
    auto cleanUpHelper = new NativeBufferUtils::VulkanCleanupHelper(RsVulkanContext::GetSingleton(),
        vkTextureInfo->vkImage, vkTextureInfo->vkAlloc.memory);
    if (cleanUpHelper == nullptr) {
        return nullptr;
    }

    auto drawingSurface = Drawing::Surface::MakeFromBackendTexture(
        gpuContext.get(),
        backendTextureTmp.GetTextureInfo(),
        Drawing::TextureOrigin::TOP_LEFT,
        1, Drawing::ColorType::COLORTYPE_RGBA_8888, nullptr,
        NativeBufferUtils::DeleteVkImage, cleanUpHelper);
    return drawingSurface;
}
#endif
} // namespace Rosen
} // namespace OHOS
