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

#include "pipeline/rs_ui_capture_task_parallel.h"

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
#include "pipeline/rs_surface_capture_task_parallel.h"
#include "pipeline/rs_uifirst_manager.h"
#include "pipeline/rs_uni_render_judgement.h"
#include "pipeline/rs_uni_render_util.h"
#include "platform/common/rs_log.h"
#include "platform/drawing/rs_surface.h"
#include "render/rs_drawing_filter.h"
#include "render/rs_skia_filter.h"
#include "screen_manager/rs_screen_manager.h"
#include "screen_manager/rs_screen_mode_info.h"
#include "drawable/rs_canvas_render_node_drawable.h"
#include "pipeline/rs_canvas_render_node.h"

#ifdef RS_ENABLE_VK
#include "platform/ohos/backend/native_buffer_utils.h"
#endif

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

void RSUiCaptureTaskParallel::Capture(NodeId id, sptr<RSISurfaceCaptureCallback> callback,
    const RSSurfaceCaptureConfig& captureConfig)
{
    if (callback == nullptr) {
        RS_LOGE("RSUiCaptureTaskParallel::Capture nodeId:[%{public}" PRIu64 "], callback is nullptr", id);
        return;
    }
    RS_LOGI("RSUiCaptureTaskParallel::Capture nodeId:[%{public}" PRIu64 "]", id);
    captureCount_++;
    std::shared_ptr<RSUiCaptureTaskParallel> captureHandle =
        std::make_shared<RSUiCaptureTaskParallel>(id, captureConfig);
    if (captureHandle == nullptr) {
        RS_LOGE("RSUiCaptureTaskParallel::Capture captureHandle is nullptr!");
        ProcessUiCaptureCallback(callback, id, nullptr);
        return;
    }
    if (!captureHandle->CreateResources()) {
        RS_LOGE("RSUiCaptureTaskParallel::Capture CreateResources failed");
        ProcessUiCaptureCallback(callback, id, nullptr);
        return;
    }

    std::function<void()> captureTask = [captureHandle, id, callback]() -> void {
        RSSystemProperties::SetForceHpsBlurDisabled(true);
        if (!captureHandle->Run(callback)) {
            ProcessUiCaptureCallback(callback, id, nullptr);
        }
        RSSystemProperties::SetForceHpsBlurDisabled(false);
    };
    RSUniRenderThread::Instance().PostTask(captureTask);
}

bool RSUiCaptureTaskParallel::CreateResources()
{
    if (ROSEN_EQ(captureConfig_.scaleX, 0.f) || ROSEN_EQ(captureConfig_.scaleY, 0.f) ||
        captureConfig_.scaleX < 0.f || captureConfig_.scaleY < 0.f) {
        RS_LOGE("RSUiCaptureTaskParallel::CreateResources: SurfaceCapture scale is invalid.");
        return false;
    }
    auto node = RSMainThread::Instance()->GetContext().GetNodeMap().GetRenderNode(nodeId_);
    if (node == nullptr) {
        RS_LOGE("RSUiCaptureTaskParallel::CreateResources: Invalid nodeId:[%{public}" PRIu64 "]",
            nodeId_);
        return false;
    }

    if (node->GetType() != RSRenderNodeType::ROOT_NODE &&
        node->GetType() != RSRenderNodeType::CANVAS_NODE &&
        node->GetType() != RSRenderNodeType::CANVAS_DRAWING_NODE &&
        node->GetType() != RSRenderNodeType::SURFACE_NODE) {
        RS_LOGE("RSUiCaptureTaskParallel::CreateResources: Invalid RSRenderNodeType!");
        return false;
    }
#ifdef RS_ENABLE_VK
    float nodeBoundsWidth = node->GetRenderProperties().GetBoundsWidth();
    float nodeBoundsHeight = node->GetRenderProperties().GetBoundsHeight();
    int32_t width = ceil(nodeBoundsWidth * captureConfig_.scaleX);
    int32_t height = ceil(nodeBoundsHeight * captureConfig_.scaleY);
    if (width * height > static_cast<int32_t>(OHOS::Rosen::NativeBufferUtils::VKIMAGE_LIMIT_SIZE)) {
        RS_LOGE("RSUiCaptureTaskParallel::CreateResources: image is too large, width:%{public}d, height::%{public}d",
            width, height);
        return false;
    }
#endif
    if (auto surfaceNode = node->ReinterpretCastTo<RSSurfaceRenderNode>()) {
        // Determine whether cache can be used
        auto curNode = surfaceNode;
        auto parentNode = RSBaseRenderNode::ReinterpretCast<RSSurfaceRenderNode>(surfaceNode->GetParent().lock());
        if (parentNode && parentNode->IsLeashWindow() && parentNode->ShouldPaint() &&
            (parentNode->GetLastFrameUifirstFlag() == MultiThreadCacheType::LEASH_WINDOW ||
            parentNode->GetLastFrameUifirstFlag() == MultiThreadCacheType::NONFOCUS_WINDOW)) {
            curNode = parentNode;
        }

        nodeDrawable_ = std::static_pointer_cast<DrawableV2::RSRenderNodeDrawable>(
            DrawableV2::RSRenderNodeDrawableAdapter::OnGenerate(curNode));
        pixelMap_ = CreatePixelMapByNode(curNode);
    } else if (auto canvasNode = node->ReinterpretCastTo<RSCanvasRenderNode>()) {
        nodeDrawable_ = std::static_pointer_cast<DrawableV2::RSRenderNodeDrawable>(
            DrawableV2::RSRenderNodeDrawableAdapter::OnGenerate(canvasNode));
        pixelMap_ = CreatePixelMapByNode(canvasNode);
    } else {
        RS_LOGE("RSUiCaptureTaskParallel::CreateResources: Invalid RSRenderNode!");
        return false;
    }
    if (pixelMap_ == nullptr) {
        RS_LOGE("RSUiCaptureTaskParallel::CreateResources: pixelMap_ is nullptr!");
        return false;
    }
    return true;
}

bool RSUiCaptureTaskParallel::Run(sptr<RSISurfaceCaptureCallback> callback)
{
    RS_TRACE_NAME("RSUiCaptureTaskParallel::TakeSurfaceCapture");

#if defined(RS_ENABLE_GL) || defined(RS_ENABLE_VK)
    auto renderContext = RSUniRenderThread::Instance().GetRenderEngine()->GetRenderContext();
    auto grContext = renderContext != nullptr ? renderContext->GetDrGPUContext() : nullptr;
    std::string nodeName("RSUiCaptureTaskParallel");
    RSTagTracker tagTracker(grContext, nodeId_, RSTagTracker::TAGTYPE::TAG_CAPTURE, nodeName);
#endif
    auto surface = CreateSurface(pixelMap_);
    if (surface == nullptr) {
        RS_LOGE("RSUiCaptureTaskParallel::Run: surface is nullptr!");
        return false;
    }
    if (!nodeDrawable_) {
        RS_LOGE("RSUiCaptureTaskParallel::Run: Invalid RSRenderNodeDrawable!");
        return false;
    }

    RSPaintFilterCanvas canvas(surface.get());
    canvas.Scale(captureConfig_.scaleX, captureConfig_.scaleY);
    canvas.SetDisableFilterCache(true);
    canvas.SetUICapture(true);
    const auto& nodeParams = nodeDrawable_->GetRenderParams();
    if (nodeParams) {
        Drawing::Matrix relativeMatrix = Drawing::Matrix();
        relativeMatrix.Set(Drawing::Matrix::Index::SCALE_X, captureConfig_.scaleX);
        relativeMatrix.Set(Drawing::Matrix::Index::SCALE_Y, captureConfig_.scaleY);
        Drawing::Matrix invertMatrix;
        if (nodeParams->GetMatrix().Invert(invertMatrix)) {
            relativeMatrix.PreConcat(invertMatrix);
        }
        canvas.SetMatrix(relativeMatrix);
    } else {
        RS_LOGD("RSUiCaptureTaskParallel::Run: RenderParams is nullptr!");
    }

    //make sure the previous uifirst task is completed
    if (!RSUiFirstProcessStateCheckerHelper::CheckMatchAndWaitNotify(*nodeParams, false)) {
        RS_LOGE("RSUiCaptureTaskParallel::Run: CheckMatchAndWaitNotify fail");
        return false;
    }
    RSUiFirstProcessStateCheckerHelper stateCheckerHelper(
        nodeParams->GetFirstLevelNodeId(), nodeParams->GetUifirstRootNodeId());
    RSUniRenderThread::SetCaptureParam(
        CaptureParam(true, true, false, captureConfig_.scaleX, captureConfig_.scaleY));
    nodeDrawable_->OnCapture(canvas);
    RSUniRenderThread::ResetCaptureParam();

#if (defined (RS_ENABLE_GL) || defined (RS_ENABLE_VK)) && (defined RS_ENABLE_EGLIMAGE)
#ifdef RS_ENABLE_UNI_RENDER
    if (RSSystemProperties::GetSnapshotWithDMAEnabled()) {
        RSUniRenderUtil::OptimizedFlushAndSubmit(surface, grContext, !RSSystemProperties::IsPcType());
        auto copytask =
            RSUiCaptureTaskParallel::CreateSurfaceSyncCopyTask(surface, std::move(pixelMap_), nodeId_, callback);
        if (!copytask) {
            RS_LOGE("RSUiCaptureTaskParallel::Run: create capture task failed!");
            return false;
        }
        RSBackgroundThread::Instance().PostTask(copytask);
        return true;
    } else {
        std::shared_ptr<Drawing::Image> img(surface.get()->GetImageSnapshot());
        if (!img) {
            RS_LOGE("RSUiCaptureTaskParallel::Run: img is nullptr");
            return false;
        }
        if (!CopyDataToPixelMap(img, pixelMap_)) {
            RS_LOGE("RSUiCaptureTaskParallel::Run: CopyDataToPixelMap failed");
            return false;
        }
    }
#endif
#endif
    // To get dump image
    // execute "param set rosen.dumpsurfacetype.enabled 3 && setenforce 0"
    RSBaseRenderUtil::WritePixelMapToPng(*pixelMap_);
    RS_LOGI("RSUiCaptureTaskParallel::Capture DMADisable capture success nodeId:[%{public}" PRIu64
            "], pixelMap width: %{public}d, height: %{public}d",
        nodeId_, pixelMap_->GetWidth(), pixelMap_->GetHeight());
    ProcessUiCaptureCallback(callback, nodeId_, pixelMap_.get());
    return true;
}

std::unique_ptr<Media::PixelMap> RSUiCaptureTaskParallel::CreatePixelMapByNode(
    std::shared_ptr<RSRenderNode> node) const
{
    float pixmapWidth = node->GetRenderProperties().GetBoundsWidth();
    float pixmapHeight = node->GetRenderProperties().GetBoundsHeight();
    Media::InitializationOptions opts;
    opts.size.width = ceil(pixmapWidth * captureConfig_.scaleX);
    opts.size.height = ceil(pixmapHeight * captureConfig_.scaleY);
    RS_LOGD("RSUiCaptureTaskParallel::CreatePixelMapByNode: NodeId:[%{public}" PRIu64 "],"
        " origin pixelmap width is [%{public}f], height is [%{public}f],"
        " created pixelmap width is [%{public}u], height is [%{public}u],"
        " the scale is scaleY:[%{public}f], scaleY:[%{public}f]",
        node->GetId(), pixmapWidth, pixmapHeight, opts.size.width, opts.size.height,
        captureConfig_.scaleX, captureConfig_.scaleY);
    return Media::PixelMap::Create(opts);
}

std::shared_ptr<Drawing::Surface> RSUiCaptureTaskParallel::CreateSurface(
    const std::unique_ptr<Media::PixelMap>& pixelmap) const
{
    if (pixelmap == nullptr) {
        RS_LOGE("RSUiCaptureTaskParallel::CreateSurface: pixelmap == nullptr");
        return nullptr;
    }
    auto address = const_cast<uint32_t*>(pixelmap->GetPixel32(0, 0));
    if (address == nullptr) {
        RS_LOGE("RSUiCaptureTaskParallel::CreateSurface: address == nullptr");
        return nullptr;
    }
    Drawing::ImageInfo info = Drawing::ImageInfo{pixelmap->GetWidth(), pixelmap->GetHeight(),
        Drawing::ColorType::COLORTYPE_RGBA_8888, Drawing::AlphaType::ALPHATYPE_PREMUL};

#if (defined RS_ENABLE_GL) && (defined RS_ENABLE_EGLIMAGE)
    if (RSSystemProperties::GetGpuApiType() == GpuApiType::OPENGL) {
        auto renderContext = RSUniRenderThread::Instance().GetRenderEngine()->GetRenderContext();
        if (renderContext == nullptr) {
            RS_LOGE("RSUiCaptureTaskParallel::CreateSurface: renderContext is nullptr");
            return nullptr;
        }
        renderContext->SetUpGpuContext(nullptr);
        return Drawing::Surface::MakeRenderTarget(renderContext->GetDrGPUContext(), false, info);
    }
#endif
#ifdef RS_ENABLE_VK
    if (RSSystemProperties::GetGpuApiType() == GpuApiType::VULKAN ||
        RSSystemProperties::GetGpuApiType() == GpuApiType::DDGR) {
        return Drawing::Surface::MakeRenderTarget(
            RSUniRenderThread::Instance().GetRenderEngine()->GetSkContext().get(), false, info);
    }
#endif

    return Drawing::Surface::MakeRasterDirect(info, address, pixelmap->GetRowBytes());
}

#ifdef RS_ENABLE_UNI_RENDER
std::function<void()> RSUiCaptureTaskParallel::CreateSurfaceSyncCopyTask(
    std::shared_ptr<Drawing::Surface> surface, std::unique_ptr<Media::PixelMap> pixelMap,
    NodeId id, sptr<RSISurfaceCaptureCallback> callback, int32_t rotation, bool useDma)
{
    Drawing::BackendTexture backendTexture = surface->GetBackendTexture();
    if (!backendTexture.IsValid()) {
        RS_LOGE("RSUiCaptureTaskParallel: SkiaSurface bind Image failed: BackendTexture is invalid");
        return {};
    }
    auto wrapper = std::make_shared<std::tuple<std::unique_ptr<Media::PixelMap>>>();
    std::get<0>(*wrapper) = std::move(pixelMap);
    auto wrapperSf = std::make_shared<std::tuple<std::shared_ptr<Drawing::Surface>>>();
    std::get<0>(*wrapperSf) = std::move(surface);
    std::function<void()> copytask = [wrapper, callback, backendTexture, wrapperSf, id, rotation, useDma]() -> void {
        RS_TRACE_NAME_FMT("copy and send capture useDma:%d", useDma);
        if (!backendTexture.IsValid()) {
            RS_LOGE("RSUiCaptureTaskParallel: Surface bind Image failed: BackendTexture is invalid");
            ProcessUiCaptureCallback(callback, id, nullptr);
            RSUniRenderUtil::ClearNodeCacheSurface(
                std::move(std::get<0>(*wrapperSf)), nullptr, UNI_MAIN_THREAD_INDEX, 0);
            return;
        }
        auto pixelmap = std::move(std::get<0>(*wrapper));
        if (pixelmap == nullptr) {
            RS_LOGE("RSUiCaptureTaskParallel: pixelmap == nullptr");
            ProcessUiCaptureCallback(callback, id, nullptr);
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
        if (!grContext) {
            RS_LOGE("RSUiCaptureTaskParallel: SharedGPUContext get failed");
            ProcessUiCaptureCallback(callback, id, nullptr);
            return;
        }
#if defined(ROSEN_OHOS) && defined(RS_ENABLE_VK)
        DmaMem dmaMem;
        if (useDma && RSMainThread::Instance()->GetDeviceType() == DeviceType::PHONE &&
            (RSSystemProperties::GetGpuApiType() == GpuApiType::VULKAN ||
            RSSystemProperties::GetGpuApiType() == GpuApiType::DDGR)) {
            sptr<SurfaceBuffer> surfaceBuffer = dmaMem.DmaMemAlloc(info, pixelmap);
            surface = dmaMem.GetSurfaceFromSurfaceBuffer(surfaceBuffer, grContext);
            if (surface == nullptr) {
                RS_LOGE("RSUiCaptureTaskParallel: GetSurfaceFromSurfaceBuffer fail.");
                ProcessUiCaptureCallback(callback, id, nullptr);
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
                RS_LOGE("RSUiCaptureTaskParallel: CopyDataToPixelMap failed");
                ProcessUiCaptureCallback(callback, id, nullptr);
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
        RS_LOGI("RSUiCaptureTaskParallel::Capture capture success nodeId:[%{public}" PRIu64
                "], pixelMap width: %{public}d, height: %{public}d",
            id, pixelmap->GetWidth(), pixelmap->GetHeight());
        ProcessUiCaptureCallback(callback, id, pixelmap.get());
        RSBackgroundThread::Instance().CleanGrResource();
        RSUniRenderUtil::ClearNodeCacheSurface(
            std::move(std::get<0>(*wrapperSf)), nullptr, UNI_MAIN_THREAD_INDEX, 0);
    };
    return copytask;
}
#endif

void RSUiCaptureTaskParallel::ProcessUiCaptureCallback(
    sptr<RSISurfaceCaptureCallback> callback, NodeId id, Media::PixelMap* pixelmap)
{
    callback->OnSurfaceCapture(id, pixelmap);
    RSUiCaptureTaskParallel::captureCount_--;
    RSMainThread::Instance()->RequestNextVSync();
}
} // namespace Rosen
} // namespace OHOS
