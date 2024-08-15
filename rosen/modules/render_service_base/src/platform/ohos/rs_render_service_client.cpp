/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "transaction/rs_render_service_client.h"
#include "surface_type.h"
#include "surface_utils.h"

#include "backend/rs_surface_ohos_gl.h"
#include "backend/rs_surface_ohos_raster.h"
#ifdef RS_ENABLE_VK
#include "backend/rs_surface_ohos_vulkan.h"
#endif

#include "command/rs_command.h"
#include "command/rs_node_showing_command.h"
#include "ipc_callbacks/pointer_render/pointer_luminance_callback_stub.h"
#include "ipc_callbacks/rs_surface_occlusion_change_callback_stub.h"
#include "ipc_callbacks/screen_change_callback_stub.h"
#include "ipc_callbacks/surface_capture_callback_stub.h"
#include "ipc_callbacks/buffer_available_callback_stub.h"
#include "ipc_callbacks/buffer_clear_callback_stub.h"
#include "ipc_callbacks/hgm_config_change_callback_stub.h"
#include "ipc_callbacks/rs_occlusion_change_callback_stub.h"
#include "ipc_callbacks/rs_uiextension_callback_stub.h"
#include "platform/common/rs_log.h"
#include "platform/common/rs_system_properties.h"
#ifdef NEW_RENDER_CONTEXT
#include "render_backend/rs_surface_factory.h"
#endif
#include "render/rs_typeface_cache.h"
#include "rs_render_service_connect_hub.h"
#include "rs_surface_ohos.h"
#include "vsync_iconnection_token.h"

namespace OHOS {
namespace Rosen {
std::shared_ptr<RSIRenderClient> RSIRenderClient::CreateRenderServiceClient()
{
    static std::shared_ptr<RSIRenderClient> client = std::make_shared<RSRenderServiceClient>();
    return client;
}

void RSRenderServiceClient::CommitTransaction(std::unique_ptr<RSTransactionData>& transactionData)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService != nullptr) {
        renderService->CommitTransaction(transactionData);
    }
}

void RSRenderServiceClient::ExecuteSynchronousTask(const std::shared_ptr<RSSyncTask>& task)
{
    if (task == nullptr) {
        return;
    }

    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService != nullptr) {
        renderService->ExecuteSynchronousTask(task);
    }
}

bool RSRenderServiceClient::GetUniRenderEnabled()
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        return false;
    }
    return renderService->GetUniRenderEnabled();
}

MemoryGraphic RSRenderServiceClient::GetMemoryGraphic(int pid)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        return MemoryGraphic {};
    }
    return renderService->GetMemoryGraphic(pid);
}

std::vector<MemoryGraphic> RSRenderServiceClient::GetMemoryGraphics()
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        return {};
    }
    return renderService->GetMemoryGraphics();
}

bool RSRenderServiceClient::GetTotalAppMemSize(float& cpuMemSize, float& gpuMemSize)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        return false;
    }
    return renderService->GetTotalAppMemSize(cpuMemSize, gpuMemSize);
}

bool RSRenderServiceClient::CreateNode(const RSSurfaceRenderNodeConfig& config)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        return false;
    }
    return renderService->CreateNode(config);
}

#ifdef NEW_RENDER_CONTEXT
std::shared_ptr<RSRenderSurface> RSRenderServiceClient::CreateNodeAndSurface(const RSSurfaceRenderNodeConfig& config)
#else
std::shared_ptr<RSSurface> RSRenderServiceClient::CreateNodeAndSurface(const RSSurfaceRenderNodeConfig& config)
#endif
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        return nullptr;
    }
    sptr<Surface> surface = renderService->CreateNodeAndSurface(config);
    return CreateRSSurface(surface);
}

#if defined(NEW_RENDER_CONTEXT)
std::shared_ptr<RSRenderSurface> RSRenderServiceClient::CreateRSSurface(const sptr<Surface> &surface)
{
    std::shared_ptr<RSRenderSurface> producer = RSSurfaceFactory::CreateRSSurface(PlatformName::OHOS, surface);
    return producer;
}
#else
std::shared_ptr<RSSurface> RSRenderServiceClient::CreateRSSurface(const sptr<Surface> &surface)
{
#if defined (ACE_ENABLE_VK)
    if (RSSystemProperties::IsUseVulkan()) {
        return std::make_shared<RSSurfaceOhosVulkan>(surface); // GPU render
    }
#endif

#if defined (ACE_ENABLE_GL)
    if (RSSystemProperties::GetGpuApiType() == Rosen::GpuApiType::OPENGL) {
        return std::make_shared<RSSurfaceOhosGl>(surface); // GPU render
    }
#endif
    return std::make_shared<RSSurfaceOhosRaster>(surface); // CPU render
}
#endif

std::shared_ptr<VSyncReceiver> RSRenderServiceClient::CreateVSyncReceiver(
    const std::string& name,
    const std::shared_ptr<OHOS::AppExecFwk::EventHandler> &looper,
    uint64_t id,
    NodeId windowNodeId)
{
    ROSEN_LOGD("RSRenderServiceClient::CreateVSyncReceiver Start");
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        return nullptr;
    }
    sptr<VSyncIConnectionToken> token = new IRemoteStub<VSyncIConnectionToken>();
    sptr<IVSyncConnection> conn = renderService->CreateVSyncConnection(name, token, id, windowNodeId);
    if (conn == nullptr) {
        ROSEN_LOGE("RSRenderServiceClient::CreateVSyncReceiver Failed");
        return nullptr;
    }
    return std::make_shared<VSyncReceiver>(conn, token->AsObject(), looper, name);
}

std::shared_ptr<Media::PixelMap> RSRenderServiceClient::CreatePixelMapFromSurfaceId(uint64_t surfaceId,
    const Rect &srcRect)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        return nullptr;
    }
    sptr<Surface> surface = SurfaceUtils::GetInstance()->GetSurface(surfaceId);
    if (surface == nullptr) {
        return nullptr;
    }

    return renderService->CreatePixelMapFromSurface(surface, srcRect);
}

void RSRenderServiceClient::TriggerSurfaceCaptureCallback(NodeId id, Media::PixelMap* pixelmap)
{
    ROSEN_LOGD("RSRenderServiceClient::Into TriggerSurfaceCaptureCallback nodeId:[%{public}" PRIu64 "]", id);
    std::vector<std::shared_ptr<SurfaceCaptureCallback>> callbackVector;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto iter = surfaceCaptureCbMap_.find(id);
        if (iter != surfaceCaptureCbMap_.end()) {
            callbackVector = iter->second;
            surfaceCaptureCbMap_.erase(iter);
        }
    }
    if (callbackVector.empty()) {
        ROSEN_LOGE("RSRenderServiceClient::TriggerSurfaceCaptureCallback: callbackVector is empty!");
        return;
    }
    for (decltype(callbackVector.size()) i = 0; i < callbackVector.size(); ++i) {
        if (callbackVector[i] == nullptr) {
            ROSEN_LOGE("RSRenderServiceClient::TriggerSurfaceCaptureCallback: callback is nullptr!");
            continue;
        }
        Media::PixelMap* pixelmapCopyRelease = nullptr;
        if (i != callbackVector.size() - 1) {
            if (pixelmap != nullptr) {
                Media::InitializationOptions options;
                std::unique_ptr<Media::PixelMap> pixelmapCopy = Media::PixelMap::Create(*pixelmap, options);
                pixelmapCopyRelease = pixelmapCopy.release();
            }
        } else {
            pixelmapCopyRelease = pixelmap;
        }
        std::shared_ptr<Media::PixelMap> surfaceCapture(pixelmapCopyRelease);
        callbackVector[i]->OnSurfaceCapture(surfaceCapture);
    }
}

class SurfaceCaptureCallbackDirector : public RSSurfaceCaptureCallbackStub
{
public:
    explicit SurfaceCaptureCallbackDirector(RSRenderServiceClient* client) : client_(client) {}
    ~SurfaceCaptureCallbackDirector() override {};
    void OnSurfaceCapture(NodeId id, Media::PixelMap* pixelmap) override
    {
        client_->TriggerSurfaceCaptureCallback(id, pixelmap);
    };

private:
    RSRenderServiceClient* client_;
};

bool RSRenderServiceClient::TakeSurfaceCapture(NodeId id, std::shared_ptr<SurfaceCaptureCallback> callback,
    const RSSurfaceCaptureConfig& captureConfig)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        ROSEN_LOGE("RSRenderServiceClient::TakeSurfaceCapture renderService == nullptr!");
        return false;
    }
    if (callback == nullptr) {
        ROSEN_LOGE("RSRenderServiceClient::TakeSurfaceCapture callback == nullptr!");
        return false;
    }
    {
        std::lock_guard<std::mutex> lock(mutex_);
        auto iter = surfaceCaptureCbMap_.find(id);
        if (iter != surfaceCaptureCbMap_.end()) {
            ROSEN_LOGW("RSRenderServiceClient::TakeSurfaceCapture surfaceCaptureCbMap_.count(id) != 0");
            iter->second.emplace_back(callback);
            return true;
        }
        std::vector<std::shared_ptr<SurfaceCaptureCallback>> callbackVector = {callback};
        surfaceCaptureCbMap_.emplace(id, callbackVector);
    }

    if (surfaceCaptureCbDirector_ == nullptr) {
        surfaceCaptureCbDirector_ = new SurfaceCaptureCallbackDirector(this);
    }
    renderService->TakeSurfaceCapture(id, surfaceCaptureCbDirector_, captureConfig);
    return true;
}

int32_t RSRenderServiceClient::SetFocusAppInfo(
    int32_t pid, int32_t uid, const std::string &bundleName, const std::string &abilityName, uint64_t focusNodeId)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        return RENDER_SERVICE_NULL;
    }

    return renderService->SetFocusAppInfo(pid, uid, bundleName, abilityName, focusNodeId);
}

ScreenId RSRenderServiceClient::GetDefaultScreenId()
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        return INVALID_SCREEN_ID;
    }

    return renderService->GetDefaultScreenId();
}

ScreenId RSRenderServiceClient::GetActiveScreenId()
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        return INVALID_SCREEN_ID;
    }

    return renderService->GetActiveScreenId();
}

std::vector<ScreenId> RSRenderServiceClient::GetAllScreenIds()
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        return std::vector<ScreenId>();
    }

    return renderService->GetAllScreenIds();
}

ScreenId RSRenderServiceClient::CreateVirtualScreen(
    const std::string &name,
    uint32_t width,
    uint32_t height,
    sptr<Surface> surface,
    ScreenId mirrorId,
    int32_t flags,
    std::vector<NodeId> whiteList)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        return INVALID_SCREEN_ID;
    }

    return renderService->CreateVirtualScreen(name, width, height, surface, mirrorId, flags, whiteList);
}

int32_t RSRenderServiceClient::SetVirtualScreenBlackList(ScreenId id, std::vector<NodeId>& blackListVector)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        return RENDER_SERVICE_NULL;
    }

    return renderService->SetVirtualScreenBlackList(id, blackListVector);
}

int32_t RSRenderServiceClient::SetCastScreenEnableSkipWindow(ScreenId id, bool enable)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        return RENDER_SERVICE_NULL;
    }

    return renderService->SetCastScreenEnableSkipWindow(id, enable);
}

int32_t RSRenderServiceClient::SetVirtualScreenSurface(ScreenId id, sptr<Surface> surface)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        return RENDER_SERVICE_NULL;
    }

    return renderService->SetVirtualScreenSurface(id, surface);
}

#ifdef RS_ENABLE_VK
bool RSRenderServiceClient::Set2DRenderCtrl(bool enable)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        return false;
    }

    return renderService->Set2DRenderCtrl(enable);
}
#endif

void RSRenderServiceClient::RemoveVirtualScreen(ScreenId id)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        return;
    }

    renderService->RemoveVirtualScreen(id);
}

#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
int32_t RSRenderServiceClient::SetPointerColorInversionConfig(float darkBuffer, float brightBuffer,
    int64_t interval, int32_t rangeSize)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        return RENDER_SERVICE_NULL;
    }
 
    return renderService->SetPointerColorInversionConfig(darkBuffer, brightBuffer, interval, rangeSize);
}
 
int32_t RSRenderServiceClient::SetPointerColorInversionEnabled(bool enable)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        return RENDER_SERVICE_NULL;
    }
 
    return renderService->SetPointerColorInversionEnabled(enable);
}
 
class CustomPointerLuminanceChangeCallback : public RSPointerLuminanceChangeCallbackStub
{
public:
    explicit CustomPointerLuminanceChangeCallback(const PointerLuminanceChangeCallback &callback) : cb_(callback) {}
    ~CustomPointerLuminanceChangeCallback() override {};
 
    void OnPointerLuminanceChanged(int32_t brightness) override
    {
        if (cb_ != nullptr) {
            cb_(brightness);
        }
    }
 
private:
    PointerLuminanceChangeCallback cb_;
};
 
int32_t RSRenderServiceClient::RegisterPointerLuminanceChangeCallback(const PointerLuminanceChangeCallback &callback)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        return RENDER_SERVICE_NULL;
    }
 
    sptr<RSIPointerLuminanceChangeCallback> cb = new CustomPointerLuminanceChangeCallback(callback);
    return renderService->RegisterPointerLuminanceChangeCallback(cb);
}
 
int32_t RSRenderServiceClient::UnRegisterPointerLuminanceChangeCallback()
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        return RENDER_SERVICE_NULL;
    }
    return renderService->UnRegisterPointerLuminanceChangeCallback();
}
#endif

class CustomScreenChangeCallback : public RSScreenChangeCallbackStub
{
public:
    explicit CustomScreenChangeCallback(const ScreenChangeCallback &callback) : cb_(callback) {}
    ~CustomScreenChangeCallback() override {};

    void OnScreenChanged(ScreenId id, ScreenEvent event) override
    {
        if (cb_ != nullptr) {
            cb_(id, event);
        }
    }

private:
    ScreenChangeCallback cb_;
};

int32_t RSRenderServiceClient::SetScreenChangeCallback(const ScreenChangeCallback &callback)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        return RENDER_SERVICE_NULL;
    }

    screenChangeCb_ = new CustomScreenChangeCallback(callback);
    return renderService->SetScreenChangeCallback(screenChangeCb_);
}

void RSRenderServiceClient::SetScreenActiveMode(ScreenId id, uint32_t modeId)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        return;
    }

    renderService->SetScreenActiveMode(id, modeId);
}

void RSRenderServiceClient::SetScreenRefreshRate(ScreenId id, int32_t sceneId, int32_t rate)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        ROSEN_LOGW("RSRenderServiceClient renderService == nullptr!");
        return;
    }

    renderService->SetScreenRefreshRate(id, sceneId, rate);
}

void RSRenderServiceClient::SetRefreshRateMode(int32_t refreshRateMode)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        ROSEN_LOGW("RSRenderServiceClient renderService == nullptr!");
        return;
    }

    renderService->SetRefreshRateMode(refreshRateMode);
}

void RSRenderServiceClient::SyncFrameRateRange(FrameRateLinkerId id,
    const FrameRateRange& range, int32_t animatorExpectedFrameRate)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        ROSEN_LOGW("RSRenderServiceClient renderService == nullptr!");
        return;
    }

    return renderService->SyncFrameRateRange(id, range, animatorExpectedFrameRate);
}

uint32_t RSRenderServiceClient::GetScreenCurrentRefreshRate(ScreenId id)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        ROSEN_LOGW("RSRenderServiceClient renderService == nullptr!");
        return RENDER_SERVICE_NULL;
    }

    return renderService->GetScreenCurrentRefreshRate(id);
}

int32_t RSRenderServiceClient::GetCurrentRefreshRateMode()
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        ROSEN_LOGW("RSRenderServiceClient renderService == nullptr!");
        return RENDER_SERVICE_NULL;
    }

    return renderService->GetCurrentRefreshRateMode();
}

std::vector<int32_t> RSRenderServiceClient::GetScreenSupportedRefreshRates(ScreenId id)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        ROSEN_LOGW("RSRenderServiceClient renderService == nullptr!");
        return {};
    }

    return renderService->GetScreenSupportedRefreshRates(id);
}

bool RSRenderServiceClient::GetShowRefreshRateEnabled()
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        ROSEN_LOGW("RSRenderServiceClient renderService == nullptr!");
        return false;
    }

    return renderService->GetShowRefreshRateEnabled();
}

std::string RSRenderServiceClient::GetRefreshInfo(pid_t pid)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        ROSEN_LOGW("RSRenderServiceClient renderService == nullptr!");
        return "";
    }
    return renderService->GetRefreshInfo(pid);
}

void RSRenderServiceClient::SetShowRefreshRateEnabled(bool enable)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        ROSEN_LOGW("RSRenderServiceClient renderService == nullptr!");
        return;
    }

    return renderService->SetShowRefreshRateEnabled(enable);
}

int32_t RSRenderServiceClient::SetVirtualScreenResolution(ScreenId id, uint32_t width, uint32_t height)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        ROSEN_LOGE("RSRenderServiceClient::SetVirtualScreenResolution renderService == nullptr!");
        return RENDER_SERVICE_NULL;
    }

    return renderService->SetVirtualScreenResolution(id, width, height);
}

RSVirtualScreenResolution RSRenderServiceClient::GetVirtualScreenResolution(ScreenId id)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        return RSVirtualScreenResolution {}; // return empty RSVirtualScreenResolution.
    }

    return renderService->GetVirtualScreenResolution(id);
}

void RSRenderServiceClient::MarkPowerOffNeedProcessOneFrame()
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        return;
    }

    renderService->MarkPowerOffNeedProcessOneFrame();
}

void RSRenderServiceClient::DisablePowerOffRenderControl(ScreenId id)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        return;
    }

    renderService->DisablePowerOffRenderControl(id);
}

void RSRenderServiceClient::SetScreenPowerStatus(ScreenId id, ScreenPowerStatus status)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        return;
    }

    renderService->SetScreenPowerStatus(id, status);
}

RSScreenModeInfo RSRenderServiceClient::GetScreenActiveMode(ScreenId id)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        return RSScreenModeInfo {}; // return empty RSScreenModeInfo.
    }

    return renderService->GetScreenActiveMode(id);
}

std::vector<RSScreenModeInfo> RSRenderServiceClient::GetScreenSupportedModes(ScreenId id)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        return {};
    }

    return renderService->GetScreenSupportedModes(id);
}

RSScreenCapability RSRenderServiceClient::GetScreenCapability(ScreenId id)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        return RSScreenCapability {};
    }

    return renderService->GetScreenCapability(id);
}

ScreenPowerStatus RSRenderServiceClient::GetScreenPowerStatus(ScreenId id)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        return ScreenPowerStatus::INVALID_POWER_STATUS;
    }

    return renderService->GetScreenPowerStatus(id);
}

RSScreenData RSRenderServiceClient::GetScreenData(ScreenId id)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        return RSScreenData {};
    }

    return renderService->GetScreenData(id);
}

int32_t RSRenderServiceClient::GetScreenBacklight(ScreenId id)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        return INVALID_BACKLIGHT_VALUE;
    }

    return renderService->GetScreenBacklight(id);
}

void RSRenderServiceClient::SetScreenBacklight(ScreenId id, uint32_t level)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        return;
    }

    renderService->SetScreenBacklight(id, level);
}

class CustomBufferAvailableCallback : public RSBufferAvailableCallbackStub
{
public:
    explicit CustomBufferAvailableCallback(const BufferAvailableCallback &callback) : cb_(callback) {}
    ~CustomBufferAvailableCallback() override {};

    void OnBufferAvailable() override
    {
        if (cb_ != nullptr) {
            cb_();
        }
    }

private:
    BufferAvailableCallback cb_;
};

class CustomBufferClearCallback : public RSBufferClearCallbackStub
{
public:
    explicit CustomBufferClearCallback(const BufferClearCallback &callback) : cb_(callback) {}
    ~CustomBufferClearCallback() override {};

    void OnBufferClear() override
    {
        if (cb_ != nullptr) {
            cb_();
        }
    }

private:
    BufferClearCallback cb_;
};

bool RSRenderServiceClient::RegisterBufferAvailableListener(
    NodeId id, const BufferAvailableCallback &callback, bool isFromRenderThread)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        return false;
    }

    auto iter = isFromRenderThread ? bufferAvailableCbRTMap_.find(id) : bufferAvailableCbUIMap_.find(id);
    if (isFromRenderThread && iter != bufferAvailableCbRTMap_.end()) {
        ROSEN_LOGW("RSRenderServiceClient::RegisterBufferAvailableListener "
                   "Node %{public}" PRIu64 " already, bufferAvailableCbRTMap_", iter->first);
    }

    if (!isFromRenderThread && iter != bufferAvailableCbUIMap_.end()) {
        ROSEN_LOGW("RSRenderServiceClient::RegisterBufferAvailableListener "
                   "Node %{public}" PRIu64 " already, bufferAvailableCbUIMap_", iter->first);
        bufferAvailableCbUIMap_.erase(iter);
    }

    sptr<RSIBufferAvailableCallback> bufferAvailableCb = new CustomBufferAvailableCallback(callback);
    renderService->RegisterBufferAvailableListener(id, bufferAvailableCb, isFromRenderThread);
    if (isFromRenderThread) {
        bufferAvailableCbRTMap_.emplace(id, bufferAvailableCb);
    } else {
        std::lock_guard<std::mutex> lock(mapMutex_);
        bufferAvailableCbUIMap_.emplace(id, bufferAvailableCb);
    }
    return true;
}

bool RSRenderServiceClient::RegisterBufferClearListener(NodeId id, const BufferClearCallback& callback)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        return false;
    }
    sptr<RSIBufferClearCallback> bufferClearCb = new CustomBufferClearCallback(callback);
    renderService->RegisterBufferClearListener(id, bufferClearCb);
    return true;
}


bool RSRenderServiceClient::UnregisterBufferAvailableListener(NodeId id)
{
    auto iter = bufferAvailableCbRTMap_.find(id);
    if (iter != bufferAvailableCbRTMap_.end()) {
        bufferAvailableCbRTMap_.erase(iter);
    } else {
        ROSEN_LOGD("RSRenderServiceClient::UnregisterBufferAvailableListener "
                   "Node %{public}" PRIu64 " has not registered RT callback", id);
    }
    std::lock_guard<std::mutex> lock(mapMutex_);
    iter = bufferAvailableCbUIMap_.find(id);
    if (iter != bufferAvailableCbUIMap_.end()) {
        bufferAvailableCbUIMap_.erase(iter);
    } else {
        ROSEN_LOGD("RSRenderServiceClient::UnregisterBufferAvailableListener "
                   "Node %{public}" PRIu64 " has not registered UI callback", id);
    }
    return true;
}

int32_t RSRenderServiceClient::GetScreenSupportedColorGamuts(ScreenId id, std::vector<ScreenColorGamut>& mode)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        return RENDER_SERVICE_NULL;
    }
    return renderService->GetScreenSupportedColorGamuts(id, mode);
}

int32_t RSRenderServiceClient::GetScreenSupportedMetaDataKeys(ScreenId id, std::vector<ScreenHDRMetadataKey>& keys)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        ROSEN_LOGE("RSRenderServiceClient::RequestRotation renderService == nullptr!");
        return RENDER_SERVICE_NULL;
    }
    return renderService->GetScreenSupportedMetaDataKeys(id, keys);
}

int32_t RSRenderServiceClient::GetScreenColorGamut(ScreenId id, ScreenColorGamut& mode)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        return RENDER_SERVICE_NULL;
    }
    return renderService->GetScreenColorGamut(id, mode);
}

int32_t RSRenderServiceClient::SetScreenColorGamut(ScreenId id, int32_t modeIdx)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        return RENDER_SERVICE_NULL;
    }
    return renderService->SetScreenColorGamut(id, modeIdx);
}

int32_t RSRenderServiceClient::SetScreenGamutMap(ScreenId id, ScreenGamutMap mode)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        return RENDER_SERVICE_NULL;
    }
    return renderService->SetScreenGamutMap(id, mode);
}

int32_t RSRenderServiceClient::SetScreenCorrection(ScreenId id, ScreenRotation screenRotation)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        return RENDER_SERVICE_NULL;
    }
    return renderService->SetScreenCorrection(id, screenRotation);
}

bool RSRenderServiceClient::SetVirtualMirrorScreenCanvasRotation(ScreenId id, bool canvasRotation)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        ROSEN_LOGE("RSRenderServiceClient::SetVirtualMirrorScreenCanvasRotation: renderService is nullptr");
        return false;
    }
    return renderService->SetVirtualMirrorScreenCanvasRotation(id, canvasRotation);
}

bool RSRenderServiceClient::SetVirtualMirrorScreenScaleMode(ScreenId id, ScreenScaleMode scaleMode)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        ROSEN_LOGE("RSRenderServiceClient::SetVirtualMirrorScreenScaleMode: renderService is nullptr");
        return false;
    }
    return renderService->SetVirtualMirrorScreenScaleMode(id, scaleMode);
}

int32_t RSRenderServiceClient::GetScreenGamutMap(ScreenId id, ScreenGamutMap& mode)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        return RENDER_SERVICE_NULL;
    }
    return renderService->GetScreenGamutMap(id, mode);
}

int32_t RSRenderServiceClient::GetScreenHDRCapability(ScreenId id, RSScreenHDRCapability& screenHdrCapability)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        ROSEN_LOGE("RSRenderServiceClient::GetScreenHDRCapability renderService == nullptr!");
        return RENDER_SERVICE_NULL;
    }
    return renderService->GetScreenHDRCapability(id, screenHdrCapability);
}

int32_t RSRenderServiceClient::GetPixelFormat(ScreenId id, GraphicPixelFormat& pixelFormat)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        ROSEN_LOGE("RSRenderServiceClient::GetPixelFormat renderService == nullptr!");
        return RENDER_SERVICE_NULL;
    }
    return renderService->GetPixelFormat(id, pixelFormat);
}

int32_t RSRenderServiceClient::SetPixelFormat(ScreenId id, GraphicPixelFormat pixelFormat)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        ROSEN_LOGE("RSRenderServiceClient::SetPixelFormat renderService == nullptr!");
        return RENDER_SERVICE_NULL;
    }
    return renderService->SetPixelFormat(id, pixelFormat);
}

int32_t RSRenderServiceClient::GetScreenSupportedHDRFormats(ScreenId id, std::vector<ScreenHDRFormat>& hdrFormats)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        return RENDER_SERVICE_NULL;
    }
    return renderService->GetScreenSupportedHDRFormats(id, hdrFormats);
}

int32_t RSRenderServiceClient::GetScreenHDRFormat(ScreenId id, ScreenHDRFormat& hdrFormat)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        return RENDER_SERVICE_NULL;
    }
    return renderService->GetScreenHDRFormat(id, hdrFormat);
}

int32_t RSRenderServiceClient::SetScreenHDRFormat(ScreenId id, int32_t modeIdx)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        return RENDER_SERVICE_NULL;
    }
    return renderService->SetScreenHDRFormat(id, modeIdx);
}

int32_t RSRenderServiceClient::GetScreenSupportedColorSpaces(
    ScreenId id, std::vector<GraphicCM_ColorSpaceType>& colorSpaces)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        return RENDER_SERVICE_NULL;
    }
    return renderService->GetScreenSupportedColorSpaces(id, colorSpaces);
}

int32_t RSRenderServiceClient::GetScreenColorSpace(ScreenId id, GraphicCM_ColorSpaceType& colorSpace)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        return RENDER_SERVICE_NULL;
    }
    return renderService->GetScreenColorSpace(id, colorSpace);
}

int32_t RSRenderServiceClient::SetScreenColorSpace(ScreenId id, GraphicCM_ColorSpaceType colorSpace)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        return RENDER_SERVICE_NULL;
    }
    return renderService->SetScreenColorSpace(id, colorSpace);
}

int32_t RSRenderServiceClient::GetScreenType(ScreenId id, RSScreenType& screenType)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        ROSEN_LOGE("RSRenderServiceClient::GetScreenType renderService == nullptr!");
        return RENDER_SERVICE_NULL;
    }
    return renderService->GetScreenType(id, screenType);
}

bool RSRenderServiceClient::GetBitmap(NodeId id, Drawing::Bitmap& bitmap)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        ROSEN_LOGE("RSRenderServiceClient::GetBitmap renderService == nullptr!");
        return false;
    }
    return renderService->GetBitmap(id, bitmap);
}

bool RSRenderServiceClient::GetPixelmap(NodeId id, std::shared_ptr<Media::PixelMap> pixelmap,
    const Drawing::Rect* rect, std::shared_ptr<Drawing::DrawCmdList> drawCmdList)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        ROSEN_LOGE("RSRenderServiceClient::GetPixelmap: renderService is nullptr");
        return false;
    }
    return renderService->GetPixelmap(id, pixelmap, rect, drawCmdList);
}

bool RSRenderServiceClient::RegisterTypeface(std::shared_ptr<Drawing::Typeface>& typeface)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        ROSEN_LOGE("RSRenderServiceClient::RegisterTypeface: renderService is nullptr");
        return false;
    }
    uint64_t globalUniqueId = RSTypefaceCache::GenGlobalUniqueId(typeface->GetUniqueID());
    ROSEN_LOGD("RSRenderServiceClient::RegisterTypeface: pid[%{public}d] register typface[%{public}u]",
        RSTypefaceCache::GetTypefacePid(globalUniqueId), RSTypefaceCache::GetTypefaceId(globalUniqueId));
    return renderService->RegisterTypeface(globalUniqueId, typeface);
}

bool RSRenderServiceClient::UnRegisterTypeface(std::shared_ptr<Drawing::Typeface>& typeface)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        ROSEN_LOGE("RSRenderServiceClient::UnRegisterTypeface: renderService is nullptr");
        return false;
    }
    uint64_t globalUniqueId = RSTypefaceCache::GenGlobalUniqueId(typeface->GetUniqueID());
    ROSEN_LOGD("RSRenderServiceClient::UnRegisterTypeface: pid[%{public}d] unregister typface[%{public}u]",
        RSTypefaceCache::GetTypefacePid(globalUniqueId), RSTypefaceCache::GetTypefaceId(globalUniqueId));
    return renderService->UnRegisterTypeface(globalUniqueId);
}

int32_t RSRenderServiceClient::SetScreenSkipFrameInterval(ScreenId id, uint32_t skipFrameInterval)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        return RENDER_SERVICE_NULL;
    }
    return renderService->SetScreenSkipFrameInterval(id, skipFrameInterval);
}

class CustomOcclusionChangeCallback : public RSOcclusionChangeCallbackStub
{
public:
    explicit CustomOcclusionChangeCallback(const OcclusionChangeCallback &callback) : cb_(callback) {}
    ~CustomOcclusionChangeCallback() override {};

    void OnOcclusionVisibleChanged(std::shared_ptr<RSOcclusionData> occlusionData) override
    {
        if (cb_ != nullptr) {
            cb_(occlusionData);
        }
    }

private:
    OcclusionChangeCallback cb_;
};

int32_t RSRenderServiceClient::RegisterOcclusionChangeCallback(const OcclusionChangeCallback& callback)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        ROSEN_LOGE("RSRenderServiceClient::RegisterOcclusionChangeCallback renderService == nullptr!");
        return RENDER_SERVICE_NULL;
    }
    sptr<CustomOcclusionChangeCallback> cb = new CustomOcclusionChangeCallback(callback);
    return renderService->RegisterOcclusionChangeCallback(cb);
}

class CustomSurfaceOcclusionChangeCallback : public RSSurfaceOcclusionChangeCallbackStub
{
public:
    explicit CustomSurfaceOcclusionChangeCallback(const SurfaceOcclusionChangeCallback &callback) : cb_(callback) {}
    ~CustomSurfaceOcclusionChangeCallback() override {};

    void OnSurfaceOcclusionVisibleChanged(float visibleAreaRatio) override
    {
        if (cb_ != nullptr) {
            cb_(visibleAreaRatio);
        }
    }

private:
    SurfaceOcclusionChangeCallback cb_;
};

int32_t RSRenderServiceClient::RegisterSurfaceOcclusionChangeCallback(
    NodeId id, const SurfaceOcclusionChangeCallback& callback, std::vector<float>& partitionPoints)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        ROSEN_LOGE("RSRenderServiceClient::RegisterSurfaceOcclusionChangeCallback renderService == nullptr!");
        return RENDER_SERVICE_NULL;
    }
    sptr<CustomSurfaceOcclusionChangeCallback> cb = new CustomSurfaceOcclusionChangeCallback(callback);
    return renderService->RegisterSurfaceOcclusionChangeCallback(id, cb, partitionPoints);
}

int32_t RSRenderServiceClient::UnRegisterSurfaceOcclusionChangeCallback(NodeId id)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        ROSEN_LOGE("RSRenderServiceClient::UnRegisterSurfaceOcclusionChangeCallback renderService == nullptr!");
        return RENDER_SERVICE_NULL;
    }
    return renderService->UnRegisterSurfaceOcclusionChangeCallback(id);
}

class CustomHgmConfigChangeCallback : public RSHgmConfigChangeCallbackStub
{
public:
    explicit CustomHgmConfigChangeCallback(const HgmConfigChangeCallback& callback) : cb_(callback) {}
    ~CustomHgmConfigChangeCallback() override {};

    void OnHgmConfigChanged(std::shared_ptr<RSHgmConfigData> configData) override
    {
        if (cb_ != nullptr) {
            cb_(configData);
        }
    }

    void OnHgmRefreshRateModeChanged(int32_t refreshRateMode) override
    {
    }

    void OnHgmRefreshRateUpdate(int32_t refreshRate) override
    {
    }
private:
    HgmConfigChangeCallback cb_;
};

int32_t RSRenderServiceClient::RegisterHgmConfigChangeCallback(const HgmConfigChangeCallback& callback)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        ROSEN_LOGE("RSRenderServiceClient::RegisterHgmConfigChangeCallback renderService == nullptr!");
        return RENDER_SERVICE_NULL;
    }
    sptr<CustomHgmConfigChangeCallback> cb = new CustomHgmConfigChangeCallback(callback);
    return renderService->RegisterHgmConfigChangeCallback(cb);
}

class CustomHgmRefreshRateModeChangeCallback : public RSHgmConfigChangeCallbackStub
{
public:
    explicit CustomHgmRefreshRateModeChangeCallback(const HgmRefreshRateModeChangeCallback& callback) : cb_(callback) {}
    ~CustomHgmRefreshRateModeChangeCallback() override {};

    void OnHgmRefreshRateModeChanged(int32_t refreshRateMode) override
    {
        if (cb_ != nullptr) {
            cb_(refreshRateMode);
        }
    }

    void OnHgmConfigChanged(std::shared_ptr<RSHgmConfigData> configData) override
    {
    }

    void OnHgmRefreshRateUpdate(int32_t refreshRate) override
    {
    }
private:
    HgmRefreshRateModeChangeCallback cb_;
};

int32_t RSRenderServiceClient::RegisterHgmRefreshRateModeChangeCallback(
    const HgmRefreshRateModeChangeCallback& callback)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        ROSEN_LOGE("RSRenderServiceClient::RegisterHgmRefreshRateModeChangeCallback renderService == nullptr!");
        return RENDER_SERVICE_NULL;
    }
    sptr<CustomHgmRefreshRateModeChangeCallback> cb = new CustomHgmRefreshRateModeChangeCallback(callback);
    return renderService->RegisterHgmRefreshRateModeChangeCallback(cb);
}

class CustomHgmRefreshRateUpdateCallback : public RSHgmConfigChangeCallbackStub
{
public:
    explicit CustomHgmRefreshRateUpdateCallback(const HgmRefreshRateModeChangeCallback& callback) : cb_(callback) {}
    ~CustomHgmRefreshRateUpdateCallback() override {};

    void OnHgmRefreshRateModeChanged(int32_t refreshRateMode) override
    {
    }

    void OnHgmConfigChanged(std::shared_ptr<RSHgmConfigData> configData) override
    {
    }

    void OnHgmRefreshRateUpdate(int32_t refreshRate) override
    {
        ROSEN_LOGD("CustomHgmRefreshRateUpdateCallback::OnHgmRefreshRateUpdate called");
        if (cb_ != nullptr) {
            cb_(refreshRate);
        }
    }

private:
    HgmRefreshRateUpdateCallback cb_;
};

int32_t RSRenderServiceClient::RegisterHgmRefreshRateUpdateCallback(
    const HgmRefreshRateUpdateCallback& callback)
{
    sptr<CustomHgmRefreshRateUpdateCallback> cb = nullptr;
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        ROSEN_LOGE("RSRenderServiceClient::RegisterHgmRefreshRateUpdateCallback renderService == nullptr!");
        return RENDER_SERVICE_NULL;
    }

    if (callback) {
        cb = new CustomHgmRefreshRateUpdateCallback(callback);
    }

    ROSEN_LOGD("RSRenderServiceClient::RegisterHgmRefreshRateUpdateCallback called");
    return renderService->RegisterHgmRefreshRateUpdateCallback(cb);
}

void RSRenderServiceClient::SetAppWindowNum(uint32_t num)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService != nullptr) {
        renderService->SetAppWindowNum(num);
    }
}

bool RSRenderServiceClient::SetSystemAnimatedScenes(SystemAnimatedScenes systemAnimatedScenes)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        ROSEN_LOGE("RSRenderServiceClient::SetSystemAnimatedScenes renderService == nullptr!");
        return false;
    }
    return renderService->SetSystemAnimatedScenes(systemAnimatedScenes);
}

void RSRenderServiceClient::ShowWatermark(const std::shared_ptr<Media::PixelMap> &watermarkImg, bool isShow)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService != nullptr) {
        renderService->ShowWatermark(watermarkImg, isShow);
    }
}

int32_t RSRenderServiceClient::ResizeVirtualScreen(ScreenId id, uint32_t width, uint32_t height)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        ROSEN_LOGE("RSRenderServiceClient::ResizeVirtualScreen renderService == nullptr!");
        return RENDER_SERVICE_NULL;
    }

    ROSEN_LOGI("RSRenderServiceClient::ResizeVirtualScreen, width:%{public}u, height:%{public}u", width, height);
    return renderService->ResizeVirtualScreen(id, width, height);
}

void RSRenderServiceClient::ReportJankStats()
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService != nullptr) {
        renderService->ReportJankStats();
    }
}

void RSRenderServiceClient::ReportEventResponse(DataBaseRs info)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService != nullptr) {
        renderService->ReportEventResponse(info);
    }
}

void RSRenderServiceClient::ReportEventComplete(DataBaseRs info)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService != nullptr) {
        renderService->ReportEventComplete(info);
    }
}

void RSRenderServiceClient::ReportEventJankFrame(DataBaseRs info)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService != nullptr) {
        renderService->ReportEventJankFrame(info);
    }
}

void RSRenderServiceClient::ReportGameStateData(GameStateData info)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService != nullptr) {
        renderService->ReportGameStateData(info);
    }
}

void RSRenderServiceClient::SetHardwareEnabled(NodeId id, bool isEnabled, SelfDrawingNodeType selfDrawingType)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService != nullptr) {
        renderService->SetHardwareEnabled(id, isEnabled, selfDrawingType);
    }
}

void RSRenderServiceClient::NotifyLightFactorStatus(bool isSafe)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService != nullptr) {
        renderService->NotifyLightFactorStatus(isSafe);
    }
}

void RSRenderServiceClient::NotifyPackageEvent(uint32_t listSize, const std::vector<std::string>& packageList)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService != nullptr) {
        renderService->NotifyPackageEvent(listSize, packageList);
    }
}

void RSRenderServiceClient::NotifyRefreshRateEvent(const EventInfo& eventInfo)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService != nullptr) {
        renderService->NotifyRefreshRateEvent(eventInfo);
    }
}

void RSRenderServiceClient::NotifyTouchEvent(int32_t touchStatus, int32_t touchCnt)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService != nullptr) {
        renderService->NotifyTouchEvent(touchStatus, touchCnt);
    }
}

void RSRenderServiceClient::NotifyDynamicModeEvent(bool enableDynamicMode)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService != nullptr) {
        renderService->NotifyDynamicModeEvent(enableDynamicMode);
    }
}

void RSRenderServiceClient::SetCacheEnabledForRotation(bool isEnabled)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService != nullptr) {
        renderService->SetCacheEnabledForRotation(isEnabled);
    }
}

void RSRenderServiceClient::SetOnRemoteDiedCallback(const OnRemoteDiedCallback& callback)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService != nullptr) {
        renderService->SetOnRemoteDiedCallback(callback);
    }
}

std::vector<ActiveDirtyRegionInfo> RSRenderServiceClient::GetActiveDirtyRegionInfo()
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        return {};
    }
    return renderService->GetActiveDirtyRegionInfo();
}

GlobalDirtyRegionInfo RSRenderServiceClient::GetGlobalDirtyRegionInfo()
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        return GlobalDirtyRegionInfo {};
    }
    return renderService->GetGlobalDirtyRegionInfo();
}

LayerComposeInfo RSRenderServiceClient::GetLayerComposeInfo()
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        return LayerComposeInfo {};
    }
    return renderService->GetLayerComposeInfo();
}

HwcDisabledReasonInfos RSRenderServiceClient::GetHwcDisabledReasonInfo()
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        return {};
    }
    return renderService->GetHwcDisabledReasonInfo();
}

#ifdef TP_FEATURE_ENABLE
void RSRenderServiceClient::SetTpFeatureConfig(int32_t feature, const char* config)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        return;
    }
    renderService->SetTpFeatureConfig(feature, config);
}
#endif

void RSRenderServiceClient::SetVirtualScreenUsingStatus(bool isVirtualScreenUsingStatus)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService != nullptr) {
        renderService->SetVirtualScreenUsingStatus(isVirtualScreenUsingStatus);
    }
}

void RSRenderServiceClient::SetCurtainScreenUsingStatus(bool isCurtainScreenOn)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService != nullptr) {
        renderService->SetCurtainScreenUsingStatus(isCurtainScreenOn);
    }
}

class CustomUIExtensionCallback : public RSUIExtensionCallbackStub
{
public:
    explicit CustomUIExtensionCallback(const UIExtensionCallback &callback) : cb_(callback) {}
    ~CustomUIExtensionCallback() override {};

    void OnUIExtension(std::shared_ptr<RSUIExtensionData> uiExtensionData, uint64_t userId) override
    {
        if (cb_ != nullptr) {
            cb_(uiExtensionData, userId);
        }
    }

private:
    UIExtensionCallback cb_;
};

int32_t RSRenderServiceClient::RegisterUIExtensionCallback(uint64_t userId, const UIExtensionCallback& callback)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService == nullptr) {
        ROSEN_LOGE("RSRenderServiceClient::RegisterUIExtensionCallback renderService == nullptr!");
        return RENDER_SERVICE_NULL;
    }
    sptr<CustomUIExtensionCallback> cb = new CustomUIExtensionCallback(callback);
    return renderService->RegisterUIExtensionCallback(userId, cb);
}

bool RSRenderServiceClient::SetVirtualScreenStatus(ScreenId id, VirtualScreenStatus screenStatus)
{
    auto renderService = RSRenderServiceConnectHub::GetRenderService();
    if (renderService != nullptr) {
        return renderService->SetVirtualScreenStatus(id, screenStatus);
    }
    return false;
}
} // namespace Rosen
} // namespace OHOS
