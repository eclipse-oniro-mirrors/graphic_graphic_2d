/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "feature/hpae/rs_hpae_buffer.h"

#if defined(ROSEN_OHOS)

#include "feature/hpae/rs_hpae_render_listener.h"
#include "hpae_base/rs_hpae_log.h"

#include "common/rs_optional_trace.h"
#include "pipeline/main_thread/rs_main_thread.h"
#include "pipeline/render_thread/rs_base_render_engine.h"
#include "pipeline/render_thread/rs_uni_render_thread.h"
#include "pipeline/render_thread/rs_uni_render_util.h"
#include "pipeline/rs_surface_handler.h"
#include "platform/common/rs_log.h"
#ifdef RS_ENABLE_VK
#include "platform/ohos/backend/rs_surface_ohos_vulkan.h"
#endif
#include "rs_trace.h"

namespace OHOS::Rosen {
namespace DrawableV2 {

const std::string HPAE_BUFFER_NAME = "hpae_memory_blur";

RSHpaeBuffer::RSHpaeBuffer(const std::string& name, const int layerId)
{
    layerName_ = name;
    surfaceHandler_ = std::make_shared<RSSurfaceHandler>(layerId);

    bufferConfig_ = {
        .width = 0,
        .height = 0,
        .strideAlignment = 0x8, // default stride is 8 Bytes.
        .format = GRAPHIC_PIXEL_FMT_RGBA_8888,
        .usage = 0,
        .timeout = 0,
        .colorGamut = GraphicColorGamut::GRAPHIC_COLOR_GAMUT_SRGB,
        .transform = GraphicTransformType::GRAPHIC_ROTATE_NONE,
    };
}

RSHpaeBuffer::~RSHpaeBuffer()
{
}

void RSHpaeBuffer::Init(const BufferRequestConfig& config, bool isHebc)
{
    RS_OPTIONAL_TRACE_NAME("Init");
    bufferConfig_ = config;
    std::shared_ptr<RSBaseRenderEngine> uniRenderEngine = RSUniRenderThread::Instance().GetRenderEngine();
    if (UNLIKELY(!uniRenderEngine)) {
        RS_LOGE("Init RenderEngine is null!");
        return;
    }

    if (grContext_ == nullptr) {
        if (uniRenderEngine->GetRenderContext()) {
            grContext_ = uniRenderEngine->GetRenderContext()->GetSharedDrGPUContext();
        } else {
            HPAE_LOGE("Exception: context is nullptr");
            return;
        }
    }

    if (!surfaceCreated_) {
        sptr<IBufferConsumerListener> listener = new RSHpaeRenderListener(surfaceHandler_);
        RS_OPTIONAL_TRACE_NAME("create layer surface");
        if (!CreateSurface(listener)) {
            RS_LOGE("Init CreateSurface failed");
            return;
        }
    }

    if (rsSurface_ == nullptr) {
        RS_LOGE("surface is null!");
        return;
    }

#ifdef RS_ENABLE_VK
    if ((RSSystemProperties::GetGpuApiType() == GpuApiType::VULKAN ||
        RSSystemProperties::GetGpuApiType() == GpuApiType::DDGR) && grContext_ != nullptr) {
        auto vulkanSurface = std::static_pointer_cast<RSSurfaceOhosVulkan>(rsSurface_);
        vulkanSurface->SetSkContext(grContext_);
        vulkanSurface->MarkAsHpaeSurface();
    }
#endif
    rsSurface_->SetColorSpace(config.colorGamut);
    rsSurface_->SetSurfacePixelFormat(config.format);
    rsSurface_->SetSurfaceBufferUsage(config.usage);
}

void RSHpaeBuffer::PreAllocateBuffer(int32_t width, int32_t height, bool isHebc)
{
#ifdef RS_ENABLE_VK
    auto vulkanSurface = std::static_pointer_cast<RSSurfaceOhosVulkan>(rsSurface_);
    if (vulkanSurface == nullptr) {
        RS_LOGE("PreAllocateBuffer: surface is null!");
        return;
    }

    vulkanSurface->PreAllocateHpaeBuffer(width, height, HPAE_BUFFER_SIZE, isHebc);
#endif
}

std::unique_ptr<RSRenderFrame> RSHpaeBuffer::RequestFrame(int32_t width, int32_t height, bool isHebc)
{
    if (rsSurface_ == nullptr) {
        RS_LOGE("RequestFrame: surface is null!");
        return nullptr;
    }

    constexpr uint64_t uiTimestamp = 0;
    auto surfaceFrame = rsSurface_ ->RequestFrame(width, height, uiTimestamp, isHebc);
    if (!surfaceFrame) {
        // buffer not ready
        return nullptr;
    }

    return std::make_unique<RSRenderFrame>(rsSurface_, std::move(surfaceFrame));
}

// reference to RSDisplayRenderNodeDrawable::RequestFrame
std::unique_ptr<RSRenderFrame> RSHpaeBuffer::RequestFrame(const BufferRequestConfig& config, bool isHebc)
{
    RS_OPTIONAL_TRACE_NAME("RSHpaeBuffer:RequestFrame");
    bufferConfig_ = config;
    std::shared_ptr<RSBaseRenderEngine> uniRenderEngine = RSUniRenderThread::Instance().GetRenderEngine();
    if (UNLIKELY(!uniRenderEngine)) {
        RS_LOGE("RSHpaeBuffer::RequestFrame RenderEngine is null!");
        return nullptr;
    }

    if (grContext_ == nullptr) {
        if (uniRenderEngine->GetRenderContext()) {
            grContext_ = uniRenderEngine->GetRenderContext()->GetSharedDrGPUContext();
        } else {
            HPAE_LOGE("Exception: context is nullptr");
            return nullptr;
        }
    }

    if (!surfaceCreated_) {
        sptr<IBufferConsumerListener> listener = sptr<RSHpaeRenderListener>::MakeSptr(surfaceHandler_);
        RS_OPTIONAL_TRACE_NAME("create layer surface");
        if (!CreateSurface(listener)) {
            RS_LOGE("RSHpaeBuffer::RequestFrame CreateSurface failed");
            return nullptr;
        }
    }

    if (rsSurface_ == nullptr) {
        RS_LOGE("RSHpaeBuffer::RequestFrame: surface is null!");
        return nullptr;
    }

    auto renderFrame = uniRenderEngine->RequestFrame(std::static_pointer_cast<RSSurfaceOhos>(rsSurface_),
        config, false, isHebc);
    if (!renderFrame) {
        RS_LOGE("RSHpaeBuffer::RequestFrame renderEngine requestFrame is null");
        return nullptr;
    }

    return renderFrame;
}

bool RSHpaeBuffer::FlushFrame()
{
    if (!producerSurface_ || !surfaceHandler_ || !rsSurface_) {
        RS_LOGE("RSHpaeBuffer::FlushFrame producerSurface_ or surfaceHandler_ is nullptr");
        return false;
    }
    BufferFlushConfig flushConfig_ = {
        .damage = {
            .x = 0,
            .y = 0,
            .w = bufferConfig_.width,
            .h = bufferConfig_.height,
        },
    };
    RS_OPTIONAL_TRACE_NAME("RSHpaeBuffer::FlushFrame");

    auto fbBuffer = rsSurface_->GetCurrentBuffer();

    SurfaceError err = producerSurface_->FlushBuffer(fbBuffer, -1, flushConfig_);
    if (err != SURFACE_ERROR_OK) {
        int errval = err;
        RS_LOGE("RSHpaeBuffer::Flushframe Failed, error is : %{public}s, errval:%{public}d",
            SurfaceErrorStr(err).c_str(), errval);
        return false;
    }
    return true;
}

GSError RSHpaeBuffer::ForceDropFrame(uint64_t presentWhen)
{
    if (!surfaceHandler_) {
        RS_LOGE("RSHpaeBuffer::ForceDropFrame surfaceHandler_ is nullptr");
        return OHOS::GSERROR_NOT_INIT;
    }
    const auto surfaceConsumer = surfaceHandler_->GetConsumer();
    if (surfaceConsumer == nullptr) {
        RS_LOGE("RsDebug RSHpaeBuffer::DropFrame (node: %{public}" PRIu64 "): surfaceConsumer is null!",
            surfaceHandler_->GetNodeId());
        return OHOS::GSERROR_NO_CONSUMER;
    }

    IConsumerSurface::AcquireBufferReturnValue returnValue;
    returnValue.fence = SyncFence::InvalidFence();
    int32_t ret = surfaceConsumer->AcquireBuffer(returnValue, static_cast<int64_t>(presentWhen), false);
    if (ret != OHOS::SURFACE_ERROR_OK) {
        RS_LOGE("RSHpaeBuffer::DropFrameProcess(node: %{public}" PRIu64 "): AcquireBuffer failed("
            " ret: %{public}d), do nothing ", surfaceHandler_->GetNodeId(), ret);
        return OHOS::GSERROR_NO_BUFFER;
    }

    RS_OPTIONAL_TRACE_NAME("Force drop: DropFrame");
    ret = surfaceConsumer->ReleaseBuffer(returnValue.buffer, returnValue.fence);
    if (ret != OHOS::SURFACE_ERROR_OK) {
        RS_LOGE("RSHpaeBuffer::DropFrameProcess(node: %{public}" PRIu64
            "): ReleaseBuffer failed(ret: %{public}d), Acquire done ",
            surfaceHandler_->GetNodeId(), ret);
    }
    surfaceHandler_->SetAvailableBufferCount(static_cast<int32_t>(surfaceConsumer->GetAvailableBufferCount()));
    RS_LOGD("RsDebug RSHpaeBuffer::DropFrameProcess (node: %{public}" PRIu64 "), drop one frame",
        surfaceHandler_->GetNodeId());

    return OHOS::GSERROR_OK;
}

// reference to RSDisplayRenderNodeDrawable::CreateSurface
bool RSHpaeBuffer::CreateSurface(sptr<IBufferConsumerListener> listener)
{
    auto consumer = surfaceHandler_->GetConsumer();
    if (consumer != nullptr && rsSurface_ != nullptr) {
        RS_LOGI("RSHpaeBuffer::CreateSurface already created, return");
        return true;
    }
    consumer = IConsumerSurface::Create(layerName_);
    if (consumer == nullptr) {
        RS_LOGE("RSHpaeBuffer::CreateSurface get consumer surface fail");
        return false;
    }
    SurfaceError ret = consumer->RegisterConsumerListener(listener);
    if (ret != SURFACE_ERROR_OK) {
        RS_LOGE("RSHpaeBuffer::CreateSurface RegisterConsumerListener fail");
        return false;
    }
    auto producer = consumer->GetProducer();
    producerSurface_ = Surface::CreateSurfaceAsProducer(producer);
    if (!producerSurface_) {
        RS_LOGE("RSHpaeBuffer::CreateSurface CreateSurfaceAsProducer fail");
        return false;
    }
    producerSurface_->SetQueueSize(HPAE_BUFFER_SIZE);
    producerSurface_->SetBufferName(HPAE_BUFFER_NAME);

    auto client = std::static_pointer_cast<RSRenderServiceClient>(RSIRenderClient::CreateRenderServiceClient());
    auto surface = client->CreateRSSurface(producerSurface_);
    rsSurface_ = std::static_pointer_cast<RSSurfaceOhos>(surface);
    RS_LOGI("RSHpaeBuffer::CreateSurface end");
    surfaceCreated_ = true;
    surfaceHandler_->SetConsumer(consumer);

    return true;
}

void* RSHpaeBuffer::GetBufferHandle()
{
    if (UNLIKELY(!rsSurface_)) {
        HPAE_LOGE("surface not exist");
        return nullptr;
    }

    auto buffer = rsSurface_->GetCurrentBuffer();
    if (buffer) {
        bufferHandle_ = buffer->GetBufferHandle();
        return bufferHandle_;
    }

    return nullptr;
}

} // DrawableV2
} // OHOS::Rosen

#endif // (ROSEN_OHOS)