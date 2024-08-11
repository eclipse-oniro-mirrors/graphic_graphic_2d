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

#include "rs_render_service_connection.h"
#include <string>

#include "frame_report.h"
#include "hgm_command.h"
#include "hgm_core.h"
#include "hgm_frame_rate_manager.h"
#include "luminance/rs_luminance_control.h"
#include "offscreen_render/rs_offscreen_render_thread.h"
#include "rs_main_thread.h"
#include "rs_trace.h"
#include "system/rs_system_parameters.h"

#include "command/rs_surface_node_command.h"
#include "common/rs_background_thread.h"
#include "drawable/rs_canvas_drawing_render_node_drawable.h"
#include "include/gpu/GrDirectContext.h"
#include "pipeline/parallel_render/rs_sub_thread_manager.h"
#include "pipeline/rs_canvas_drawing_render_node.h"
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
#include "pipeline/pointer_render/rs_pointer_render_manager.h"
#endif
#include "pipeline/rs_realtime_refresh_rate_manager.h"
#include "pipeline/rs_render_frame_rate_linker_map.h"
#include "pipeline/rs_render_node_gc.h"
#include "pipeline/rs_render_node_map.h"
#include "pipeline/rs_render_service_listener.h"
#include "pipeline/rs_surface_capture_task.h"
#include "pipeline/rs_surface_capture_task_parallel.h"
#include "pipeline/rs_ui_capture_task_parallel.h"
#include "pipeline/rs_surface_render_node.h"
#include "pipeline/rs_task_dispatcher.h"
#include "pipeline/rs_uifirst_manager.h"
#include "pipeline/rs_uni_render_judgement.h"
#include "pipeline/rs_uni_ui_capture.h"
#include "pixel_map_from_surface.h"
#include "platform/common/rs_log.h"
#include "platform/common/rs_system_properties.h"
#include "platform/ohos/rs_jank_stats.h"
#include "render/rs_typeface_cache.h"

#ifdef TP_FEATURE_ENABLE
#include "touch_screen/touch_screen.h"
#endif

#ifdef RS_ENABLE_VK
#include "platform/ohos/backend/rs_vulkan_context.h"
#endif

namespace OHOS {
namespace Rosen {
constexpr int SLEEP_TIME_US = 1000;
constexpr int TASK_DELAY_TIME_MS = 1000;
const std::string REGISTER_NODE = "RegisterNode";
// we guarantee that when constructing this object,
// all these pointers are valid, so will not check them.
RSRenderServiceConnection::RSRenderServiceConnection(
    pid_t remotePid,
    wptr<RSRenderService> renderService,
    RSMainThread* mainThread,
    sptr<RSScreenManager> screenManager,
    sptr<IRemoteObject> token,
    sptr<VSyncDistributor> distributor)
    : remotePid_(remotePid),
      renderService_(renderService),
      mainThread_(mainThread),
      renderThread_(RSUniRenderThread::Instance()),
      screenManager_(screenManager),
      token_(token),
      connDeathRecipient_(new RSConnectionDeathRecipient(this)),
      ApplicationDeathRecipient_(new RSApplicationRenderThreadDeathRecipient(this)),
      appVSyncDistributor_(distributor)
{
    if (!token_->AddDeathRecipient(connDeathRecipient_)) {
        RS_LOGW("RSRenderServiceConnection: Failed to set death recipient.");
    }
}

RSRenderServiceConnection::~RSRenderServiceConnection() noexcept
{
    if (token_ && connDeathRecipient_) {
        token_->RemoveDeathRecipient(connDeathRecipient_);
    }
    CleanAll();
}

void RSRenderServiceConnection::CleanVirtualScreens() noexcept
{
    std::lock_guard<std::mutex> lock(mutex_);

    for (const auto id : virtualScreenIds_) {
        screenManager_->RemoveVirtualScreen(id);
    }
    virtualScreenIds_.clear();

    if (screenChangeCallback_ != nullptr) {
        screenManager_->RemoveScreenChangeCallback(screenChangeCallback_);
        screenChangeCallback_ = nullptr;
    }
}

void RSRenderServiceConnection::CleanRenderNodes() noexcept
{
    auto& context = mainThread_->GetContext();
    auto& nodeMap = context.GetMutableNodeMap();

    nodeMap.FilterNodeByPid(remotePid_);
}

void RSRenderServiceConnection::CleanFrameRateLinkers() noexcept
{
    auto& context = mainThread_->GetContext();
    auto& frameRateLinkerMap = context.GetMutableFrameRateLinkerMap();

    frameRateLinkerMap.FilterFrameRateLinkerByPid(remotePid_);
}

void RSRenderServiceConnection::CleanAll(bool toDelete) noexcept
{
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (cleanDone_) {
            return;
        }
    }
    if (!mainThread_) {
        return;
    }
    RS_LOGD("RSRenderServiceConnection::CleanAll() start.");
    mainThread_->ScheduleTask(
        [this]() {
            RS_TRACE_NAME_FMT("CleanVirtualScreens %d", remotePid_);
            CleanVirtualScreens();
        }).wait();
    mainThread_->ScheduleTask(
        [this]() {
            RS_TRACE_NAME_FMT("CleanRenderNodes %d", remotePid_);
            CleanRenderNodes();
            CleanFrameRateLinkers();
        }).wait();
    mainThread_->ScheduleTask(
        [this]() {
            RS_TRACE_NAME_FMT("ClearTransactionDataPidInfo %d", remotePid_);
            mainThread_->ClearTransactionDataPidInfo(remotePid_);
        }).wait();
    mainThread_->ScheduleTask(
        [this]() {
            RS_TRACE_NAME_FMT("CleanHgmEvent %d", remotePid_);
            mainThread_->GetFrameRateMgr()->CleanVote(remotePid_);
        }).wait();
    mainThread_->ScheduleTask(
        [this]() {
            RS_TRACE_NAME_FMT("UnRegisterCallback %d", remotePid_);
            HgmConfigCallbackManager::GetInstance()->UnRegisterHgmConfigChangeCallback(remotePid_);
            mainThread_->UnRegisterOcclusionChangeCallback(remotePid_);
            mainThread_->ClearSurfaceOcclusionChangeCallback(remotePid_);
            mainThread_->UnRegisterUIExtensionCallback(remotePid_);
        }).wait();
    RSTypefaceCache::Instance().RemoveDrawingTypefacesByPid(remotePid_);
    {
        std::lock_guard<std::mutex> lock(mutex_);
        cleanDone_ = true;
    }

    if (toDelete) {
        auto renderService = renderService_.promote();
        if (renderService == nullptr) {
            RS_LOGW("RSRenderServiceConnection::CleanAll() RenderService is dead.");
        } else {
            renderService->RemoveConnection(GetToken());
        }
    }

    RS_LOGD("RSRenderServiceConnection::CleanAll() end.");
}

RSRenderServiceConnection::RSConnectionDeathRecipient::RSConnectionDeathRecipient(
    wptr<RSRenderServiceConnection> conn) : conn_(conn)
{
}

void RSRenderServiceConnection::RSConnectionDeathRecipient::OnRemoteDied(const wptr<IRemoteObject>& token)
{
    auto tokenSptr = token.promote();
    if (tokenSptr == nullptr) {
        RS_LOGW("RSConnectionDeathRecipient::OnRemoteDied: can't promote remote object.");
        return;
    }

    auto rsConn = conn_.promote();
    if (rsConn == nullptr) {
        RS_LOGW("RSConnectionDeathRecipient::OnRemoteDied: RSRenderServiceConnection was dead, do nothing.");
        return;
    }

    if (rsConn->GetToken() != tokenSptr) {
        RS_LOGI("RSConnectionDeathRecipient::OnRemoteDied: token doesn't match, ignore it.");
        return;
    }

    rsConn->CleanAll(true);
}

RSRenderServiceConnection::RSApplicationRenderThreadDeathRecipient::RSApplicationRenderThreadDeathRecipient(
    wptr<RSRenderServiceConnection> conn) : conn_(conn)
{}

void RSRenderServiceConnection::RSApplicationRenderThreadDeathRecipient::OnRemoteDied(const wptr<IRemoteObject>& token)
{
    auto tokenSptr = token.promote();
    if (tokenSptr == nullptr) {
        RS_LOGW("RSApplicationRenderThreadDeathRecipient::OnRemoteDied: can't promote remote object.");
        return;
    }

    auto rsConn = conn_.promote();
    if (rsConn == nullptr) {
        RS_LOGW("RSApplicationRenderThreadDeathRecipient::OnRemoteDied: "
            "RSRenderServiceConnection was dead, do nothing.");
        return;
    }

    RS_LOGD("RSApplicationRenderThreadDeathRecipient::OnRemoteDied: Unregister.");
    auto app = iface_cast<IApplicationAgent>(tokenSptr);
    rsConn->UnRegisterApplicationAgent(app);
}

void RSRenderServiceConnection::CommitTransaction(std::unique_ptr<RSTransactionData>& transactionData)
{
    if (!mainThread_) {
        return;
    }
    bool isProcessBySingleFrame = mainThread_->IsNeedProcessBySingleFrameComposer(transactionData);
    if (isProcessBySingleFrame) {
        mainThread_->ProcessDataBySingleFrameComposer(transactionData);
    } else {
        mainThread_->RecvRSTransactionData(transactionData);
    }
}

void RSRenderServiceConnection::ExecuteSynchronousTask(const std::shared_ptr<RSSyncTask>& task)
{
    std::mutex mutex;
    std::unique_lock<std::mutex> lock(mutex);
    auto cv = std::make_shared<std::condition_variable>();
    auto& mainThread = mainThread_;
    if (!task || !mainThread_) {
        return;
    }
    mainThread->PostTask([task, cv, &mainThread]() {
        if (task == nullptr || cv == nullptr) {
            return;
        }
        task->Process(mainThread->GetContext());
        cv->notify_all();
    });
    cv->wait_for(lock, std::chrono::nanoseconds(task->GetTimeout()));
}

bool RSRenderServiceConnection::GetUniRenderEnabled()
{
    return RSUniRenderJudgement::IsUniRender();
}

bool RSRenderServiceConnection::CreateNode(const RSSurfaceRenderNodeConfig& config)
{
    if (!mainThread_) {
        return false;
    }
    std::shared_ptr<RSSurfaceRenderNode> node =
        SurfaceNodeCommandHelper::CreateWithConfigInRS(config, mainThread_->GetContext());
    if (node == nullptr) {
        RS_LOGE("RSRenderService::CreateNode fail");
        return false;
    }
    std::function<void()> registerNode = [node, weakThis = wptr<RSRenderServiceConnection>(this)]() -> void {
        sptr<RSRenderServiceConnection> connection = weakThis.promote();
        if (!connection) {
            return;
        }
        connection->mainThread_->GetContext().GetMutableNodeMap().RegisterRenderNode(node);
    };
    mainThread_->PostTask(registerNode);
    return true;
}

sptr<Surface> RSRenderServiceConnection::CreateNodeAndSurface(const RSSurfaceRenderNodeConfig& config)
{
    if (!mainThread_) {
        return nullptr;
    }
    std::shared_ptr<RSSurfaceRenderNode> node =
        SurfaceNodeCommandHelper::CreateWithConfigInRS(config, mainThread_->GetContext());
    if (node == nullptr) {
        RS_LOGE("RSRenderService::CreateNodeAndSurface CreateNode fail");
        return nullptr;
    }
    sptr<IConsumerSurface> surface = IConsumerSurface::Create(config.name);
    if (surface == nullptr) {
        RS_LOGE("RSRenderService::CreateNodeAndSurface get consumer surface fail");
        return nullptr;
    }
    const std::string& surfaceName = surface->GetName();
    RS_LOGI("RsDebug RSRenderService::CreateNodeAndSurface node" \
        "id:%{public}" PRIu64 " name:%{public}s bundleName:%{public}s surface id:%{public}" PRIu64 " name:%{public}s",
        node->GetId(), node->GetName().c_str(), node->GetBundleName().c_str(),
        surface->GetUniqueId(), surfaceName.c_str());
    auto defaultUsage = surface->GetDefaultUsage();
    surface->SetDefaultUsage(defaultUsage | BUFFER_USAGE_MEM_DMA | BUFFER_USAGE_HW_COMPOSER);
    node->GetRSSurfaceHandler()->SetConsumer(surface);
    RSMainThread* mainThread = mainThread_;
    std::function<void()> registerNode = [node, mainThread]() -> void {
        if (auto preNode = mainThread->GetContext().GetNodeMap().GetRenderNode(node->GetId())) {
            RS_LOGE("CreateNodeAndSurface same id node:%{public}" PRIu64 ", type:%d",
                node->GetId(), preNode->GetType());
            usleep(SLEEP_TIME_US);
        }
        mainThread->GetContext().GetMutableNodeMap().RegisterRenderNode(node);
    };
    if (config.isSync) {
        mainThread_->PostSyncTask(registerNode);
    } else {
        mainThread_->PostTask(registerNode, REGISTER_NODE, 0, AppExecFwk::EventQueue::Priority::VIP);
    }
    std::weak_ptr<RSSurfaceRenderNode> surfaceRenderNode(node);
    sptr<IBufferConsumerListener> listener = new RSRenderServiceListener(surfaceRenderNode);
    SurfaceError ret = surface->RegisterConsumerListener(listener);
    if (ret != SURFACE_ERROR_OK) {
        RS_LOGE("RSRenderService::CreateNodeAndSurface Register Consumer Listener fail");
        return nullptr;
    }
    sptr<IBufferProducer> producer = surface->GetProducer();
    sptr<Surface> pSurface = Surface::CreateSurfaceAsProducer(producer);
    return pSurface;
}


sptr<IVSyncConnection> RSRenderServiceConnection::CreateVSyncConnection(const std::string& name,
                                                                        const sptr<VSyncIConnectionToken>& token,
                                                                        uint64_t id,
                                                                        NodeId windowNodeId)
{
    if (!mainThread_) {
        return nullptr;
    }
    sptr<VSyncConnection> conn = new VSyncConnection(appVSyncDistributor_, name, token->AsObject(), 0, windowNodeId);
    if (ExtractPid(id) == remotePid_) {
        auto linker = std::make_shared<RSRenderFrameRateLinker>(id);
        auto& context = mainThread_->GetContext();
        auto& frameRateLinkerMap = context.GetMutableFrameRateLinkerMap();
        frameRateLinkerMap.RegisterFrameRateLinker(linker);
        conn->id_ = id;
    }
    auto ret = appVSyncDistributor_->AddConnection(conn, windowNodeId);
    if (ret != VSYNC_ERROR_OK) {
        return nullptr;
    }
    return conn;
}

std::shared_ptr<Media::PixelMap> RSRenderServiceConnection::CreatePixelMapFromSurface(sptr<Surface> surface,
    const Rect &srcRect)
{
    OHOS::Media::Rect rect = {
        .left = srcRect.x,
        .top = srcRect.y,
        .width = srcRect.w,
        .height = srcRect.h,
    };
    std::shared_ptr<Media::PixelMap> pixelmap = nullptr;
    RSBackgroundThread::Instance().PostSyncTask([surface, rect, &pixelmap]() {
        pixelmap = OHOS::Rosen::CreatePixelMapFromSurface(surface, rect);
    });
    return pixelmap;
}

int32_t RSRenderServiceConnection::SetFocusAppInfo(
    int32_t pid, int32_t uid, const std::string &bundleName, const std::string &abilityName, uint64_t focusNodeId)
{
    if (!mainThread_) {
        return INVALID_ARGUMENTS;
    }
    mainThread_->SetFocusAppInfo(pid, uid, bundleName, abilityName, focusNodeId);
    return SUCCESS;
}

ScreenId RSRenderServiceConnection::GetDefaultScreenId()
{
    if (!screenManager_) {
        return StatusCode::SCREEN_NOT_FOUND;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    return screenManager_->GetDefaultScreenId();
}

ScreenId RSRenderServiceConnection::GetActiveScreenId()
{
    if (!screenManager_) {
        return StatusCode::SCREEN_NOT_FOUND;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    return screenManager_->GetActiveScreenId();
}

std::vector<ScreenId> RSRenderServiceConnection::GetAllScreenIds()
{
    std::vector<ScreenId> ids;
    if (!screenManager_) {
        return ids;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    return screenManager_->GetAllScreenIds();
}

ScreenId RSRenderServiceConnection::CreateVirtualScreen(
    const std::string &name,
    uint32_t width,
    uint32_t height,
    sptr<Surface> surface,
    ScreenId mirrorId,
    int32_t flags,
    std::vector<NodeId> whiteList)
{
    if (!screenManager_) {
        return StatusCode::SCREEN_NOT_FOUND;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    auto newVirtualScreenId = screenManager_->CreateVirtualScreen(
        name, width, height, surface, mirrorId, flags, whiteList);
    virtualScreenIds_.insert(newVirtualScreenId);
    if (surface != nullptr) {
        EventInfo event = { "VOTER_VIRTUALDISPLAY", ADD_VOTE, OLED_60_HZ, OLED_60_HZ, name };
        NotifyRefreshRateEvent(event);
    }
    return newVirtualScreenId;
}

int32_t RSRenderServiceConnection::SetVirtualScreenBlackList(ScreenId id, std::vector<NodeId>& blackListVector)
{
    if (!screenManager_) {
        return StatusCode::SCREEN_NOT_FOUND;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    if (blackListVector.empty()) {
        RS_LOGW("SetVirtualScreenBlackList blackList is empty.");
    }
    return screenManager_->SetVirtualScreenBlackList(id, blackListVector);
}

int32_t RSRenderServiceConnection::SetCastScreenEnableSkipWindow(ScreenId id, bool enable)
{
    if (!screenManager_) {
        return StatusCode::SCREEN_NOT_FOUND;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    return screenManager_->SetCastScreenEnableSkipWindow(id, enable);
}

int32_t RSRenderServiceConnection::SetVirtualScreenSurface(ScreenId id, sptr<Surface> surface)
{
    if (!screenManager_) {
        return StatusCode::SCREEN_NOT_FOUND;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    return screenManager_->SetVirtualScreenSurface(id, surface);
}

#ifdef RS_ENABLE_VK
bool RSRenderServiceConnection::Set2DRenderCtrl(bool enable)
{
    if (RsVulkanContext::GetSingleton().GetRsVulkanInterface().vkSetFreqAdjustEnable != nullptr) {
        RsVulkanContext::GetSingleton().GetRsVulkanInterface().vkSetFreqAdjustEnable(enable);
    }
    return true;
}
#endif

#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
int32_t RSRenderServiceConnection::SetPointerColorInversionConfig(float darkBuffer,
    float brightBuffer, int64_t interval, int32_t rangeSize)
{
    RSPointerRenderManager::GetInstance().SetPointerColorInversionConfig(darkBuffer, brightBuffer,
        interval, rangeSize);
    return StatusCode::SUCCESS;
}
 
int32_t RSRenderServiceConnection::SetPointerColorInversionEnabled(bool enable)
{
    RSPointerRenderManager::GetInstance().SetPointerColorInversionEnabled(enable);
    return StatusCode::SUCCESS;
}
 
int32_t RSRenderServiceConnection::RegisterPointerLuminanceChangeCallback(
    sptr<RSIPointerLuminanceChangeCallback> callback)
{
    if (!callback) {
        RS_LOGE("RSRenderServiceConnection::RegisterPointerLuminanceChangeCallback: callback is nullptr");
        return StatusCode::INVALID_ARGUMENTS;
    }
    RSPointerRenderManager::GetInstance().RegisterPointerLuminanceChangeCallback(remotePid_, callback);
    return StatusCode::SUCCESS;
}
 
int32_t RSRenderServiceConnection::UnRegisterPointerLuminanceChangeCallback()
{
    RSPointerRenderManager::GetInstance().UnRegisterPointerLuminanceChangeCallback(remotePid_);
    return StatusCode::SUCCESS;
}
#endif

void RSRenderServiceConnection::RemoveVirtualScreen(ScreenId id)
{
    if (!screenManager_) {
        return;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    screenManager_->RemoveVirtualScreen(id);
    virtualScreenIds_.erase(id);
    EventInfo event = { "VOTER_VIRTUALDISPLAY", REMOVE_VOTE };
    NotifyRefreshRateEvent(event);
}

int32_t RSRenderServiceConnection::SetScreenChangeCallback(sptr<RSIScreenChangeCallback> callback)
{
    if (!callback) {
        return INVALID_ARGUMENTS;
    }
    std::unique_lock<std::mutex> lock(mutex_);
    if (screenChangeCallback_ == callback) {
        return INVALID_ARGUMENTS;
    }

    if (screenChangeCallback_ != nullptr) {
        // remove the old callback
        screenManager_->RemoveScreenChangeCallback(screenChangeCallback_);
    }

    // update
    int32_t status = screenManager_->AddScreenChangeCallback(callback);
    auto tmp = screenChangeCallback_;
    screenChangeCallback_ = callback;
    lock.unlock();
    return status;
}

void RSRenderServiceConnection::SetScreenActiveMode(ScreenId id, uint32_t modeId)
{
    if (!screenManager_) {
        return;
    }
    auto renderType = RSUniRenderJudgement::GetUniRenderEnabledType();
    if (renderType == UniRenderEnabledType::UNI_RENDER_ENABLED_FOR_ALL) {
        return RSHardwareThread::Instance().ScheduleTask(
            [=]() { screenManager_->SetScreenActiveMode(id, modeId); }).wait();
    } else {
        return mainThread_->ScheduleTask(
            [=]() { screenManager_->SetScreenActiveMode(id, modeId); }).wait();
    }
}

void RSRenderServiceConnection::SetScreenRefreshRate(ScreenId id, int32_t sceneId, int32_t rate)
{
    ROSEN_TRACE_BEGIN(HITRACE_TAG_GRAPHIC_AGP, "RSRenderService::SetScreenRefreshRate");
    auto &hgmCore = OHOS::Rosen::HgmCore::Instance();
    int32_t setResult = hgmCore.SetScreenRefreshRate(id, sceneId, rate);
    if (setResult != 0) {
        RS_LOGW("SetScreenRefreshRate request of screen %{public}" PRIu64 " of rate %{public}d is refused",
            id, rate);
        return;
    }
    ROSEN_TRACE_END(HITRACE_TAG_GRAPHIC_AGP);
}

void RSRenderServiceConnection::SetRefreshRateMode(int32_t refreshRateMode)
{
    if (!mainThread_) {
        return;
    }
    ROSEN_TRACE_BEGIN(HITRACE_TAG_GRAPHIC_AGP, "RSRenderService::SetRefreshRateMode");
    auto &hgmCore = OHOS::Rosen::HgmCore::Instance();
    int32_t setResult = hgmCore.SetRefreshRateMode(refreshRateMode);
    RSSystemProperties::SetHgmRefreshRateModesEnabled(std::to_string(refreshRateMode));
    if (setResult != 0) {
        RS_LOGW("SetRefreshRateMode mode %{public}d is not supported", refreshRateMode);
    }
    ROSEN_TRACE_END(HITRACE_TAG_GRAPHIC_AGP);
}

void RSRenderServiceConnection::SyncFrameRateRange(FrameRateLinkerId id,
    const FrameRateRange& range, int32_t animatorExpectedFrameRate)
{
    if (!mainThread_) {
        return;
    }
    mainThread_->ScheduleTask([=]() {
        auto& context = mainThread_->GetContext();
        auto& linkerMap = context.GetMutableFrameRateLinkerMap();
        auto linker = linkerMap.GetFrameRateLinker(id);
        if (linker == nullptr) {
            RS_LOGW("SyncFrameRateRange there is no frameRateLinker for id %{public}" PRIu64, id);
            return;
        }
        linker->SetExpectedRange(range);
        linker->SetAnimatorExpectedFrameRate(animatorExpectedFrameRate);
    }).wait();
}

uint32_t RSRenderServiceConnection::GetScreenCurrentRefreshRate(ScreenId id)
{
    auto &hgmCore = OHOS::Rosen::HgmCore::Instance();
    uint32_t rate = hgmCore.GetScreenCurrentRefreshRate(id);
    if (rate == 0) {
        RS_LOGW("GetScreenCurrentRefreshRate failed to get current refreshrate of"
            " screen : %{public}" PRIu64 "", id);
    }
    return rate;
}

std::vector<int32_t> RSRenderServiceConnection::GetScreenSupportedRefreshRates(ScreenId id)
{
    auto &hgmCore = OHOS::Rosen::HgmCore::Instance();
    std::vector<int32_t> rates = hgmCore.GetScreenComponentRefreshRates(id);
    return rates;
}

bool RSRenderServiceConnection::GetShowRefreshRateEnabled()
{
    return RSRealtimeRefreshRateManager::Instance().GetShowRefreshRateEnabled();
}

void RSRenderServiceConnection::SetShowRefreshRateEnabled(bool enable)
{
    return RSRealtimeRefreshRateManager::Instance().SetShowRefreshRateEnabled(enable);
}

std::string RSRenderServiceConnection::GetRefreshInfo(pid_t pid)
{
    if (!mainThread_) {
        return "";
    }
    auto& context = mainThread_->GetContext();
    auto& nodeMap = context.GetMutableNodeMap();
    std::string surfaceName = nodeMap.GetSelfDrawSurfaceNameByPid(pid);
    if (surfaceName.empty()) {
        return "";
    }
    std::string dumpString;
    auto renderType = RSUniRenderJudgement::GetUniRenderEnabledType();
    if (renderType == UniRenderEnabledType::UNI_RENDER_ENABLED_FOR_ALL) {
        RSHardwareThread::Instance().ScheduleTask(
            [this, &dumpString, &surfaceName]() { return screenManager_->FpsDump(dumpString, surfaceName); }).wait();
    } else {
        mainThread_->ScheduleTask(
            [this, &dumpString, &surfaceName]() { return screenManager_->FpsDump(dumpString, surfaceName); }).wait();
    }
    return dumpString;
}

int32_t RSRenderServiceConnection::GetCurrentRefreshRateMode()
{
    auto &hgmCore = OHOS::Rosen::HgmCore::Instance();
    int32_t refreshRateMode = hgmCore.GetCurrentRefreshRateMode();
    return refreshRateMode;
}

int32_t RSRenderServiceConnection::SetVirtualScreenResolution(ScreenId id, uint32_t width, uint32_t height)
{
    if (!screenManager_) {
        return StatusCode::SCREEN_NOT_FOUND;
    }
    auto renderType = RSUniRenderJudgement::GetUniRenderEnabledType();
    if (renderType == UniRenderEnabledType::UNI_RENDER_ENABLED_FOR_ALL) {
        return RSHardwareThread::Instance().ScheduleTask(
            [=]() { return screenManager_->SetVirtualScreenResolution(id, width, height); }).get();
    } else {
        return mainThread_->ScheduleTask(
            [=]() { return screenManager_->SetVirtualScreenResolution(id, width, height); }).get();
    }
}

void RSRenderServiceConnection::MarkPowerOffNeedProcessOneFrame()
{
    auto renderType = RSUniRenderJudgement::GetUniRenderEnabledType();
    if (renderType == UniRenderEnabledType::UNI_RENDER_ENABLED_FOR_ALL) {
        renderThread_.PostTask([=]() { screenManager_->MarkPowerOffNeedProcessOneFrame(); });
    }
}

void RSRenderServiceConnection::DisablePowerOffRenderControl(ScreenId id)
{
    auto renderType = RSUniRenderJudgement::GetUniRenderEnabledType();
    if (renderType == UniRenderEnabledType::UNI_RENDER_ENABLED_FOR_ALL) {
        renderThread_.PostTask([=]() { screenManager_->DisablePowerOffRenderControl(id); });
    }
}

void RSRenderServiceConnection::SetScreenPowerStatus(ScreenId id, ScreenPowerStatus status)
{
    if (!screenManager_) {
        return;
    }
    auto renderType = RSUniRenderJudgement::GetUniRenderEnabledType();
    if (renderType == UniRenderEnabledType::UNI_RENDER_ENABLED_FOR_ALL) {
        RSHardwareThread::Instance().ScheduleTask(
            [=]() { screenManager_->SetScreenPowerStatus(id, status); }).wait();
        mainThread_->SetDiscardJankFrames(true);
        renderThread_.SetDiscardJankFrames(true);
        OHOS::Rosen::HgmCore::Instance().NotifyScreenPowerStatus(id, status);
    } else {
        mainThread_->ScheduleTask(
            [=]() { screenManager_->SetScreenPowerStatus(id, status); }).wait();
    }
}

namespace {
void TakeSurfaceCaptureForUiParallel(
    NodeId id, sptr<RSISurfaceCaptureCallback> callback, const RSSurfaceCaptureConfig& captureConfig)
{
    std::function<void()> captureTask = [id, callback, captureConfig]() {
        RSUiCaptureTaskParallel::Capture(id, callback, captureConfig);
    };

    if (captureConfig.isSync) {
        RSMainThread::Instance()->AddUiCaptureTask(id, captureTask);
        return;
    }

    auto node = RSMainThread::Instance()->GetContext().GetNodeMap().GetRenderNode<RSRenderNode>(id);
    if (!node) {
        RS_LOGE("RSRenderServiceConnection::TakeSurfaceCaptureForUiParallel node is nullptr");
        callback->OnSurfaceCapture(id, nullptr);
        return;
    }

    if (node->IsOnTheTree() && !node->IsDirty()) {
        RSMainThread::Instance()->PostTask(captureTask);
    } else {
        RSMainThread::Instance()->AddUiCaptureTask(id, captureTask);
    }
}

void TakeSurfaceCaptureForUIWithUni(NodeId id, sptr<RSISurfaceCaptureCallback> callback,
    const RSSurfaceCaptureConfig& captureConfig)
{
    std::function<void()> offscreenRenderTask = [id, callback, captureConfig]() -> void {
        RS_LOGD("RSRenderService::TakeSurfaceCaptureForUIWithUni callback->OnOffscreenRender"
            " nodeId:[%{public}" PRIu64 "]", id);
        ROSEN_TRACE_BEGIN(HITRACE_TAG_GRAPHIC_AGP, "RSRenderService::TakeSurfaceCaptureForUIWithUni");
        std::shared_ptr<RSUniUICapture> rsUniUICapture = std::make_shared<RSUniUICapture>(id, captureConfig);
        std::shared_ptr<Media::PixelMap> pixelmap = rsUniUICapture->TakeLocalCapture();
        callback->OnSurfaceCapture(id, pixelmap.get());
        ROSEN_TRACE_END(HITRACE_TAG_GRAPHIC_AGP);
    };
    if (!captureConfig.isSync) {
        RSOffscreenRenderThread::Instance().PostTask(offscreenRenderTask);
    } else {
        auto node = RSMainThread::Instance()->GetContext().GetNodeMap().GetRenderNode<RSRenderNode>(id);
        if (node == nullptr || !node->GetCommandExecuted()) {
            RSOffscreenRenderThread::Instance().InSertCaptureTask(id, offscreenRenderTask);
            return;
        }
        RSOffscreenRenderThread::Instance().PostTask(offscreenRenderTask);
        node->SetCommandExecuted(false);
    }
}
}

void RSRenderServiceConnection::TakeSurfaceCapture(NodeId id, sptr<RSISurfaceCaptureCallback> callback,
    const RSSurfaceCaptureConfig& captureConfig, bool accessible)
{
    if (!mainThread_) {
        return;
    }
    std::function<void()> captureTask = [id, callback, captureConfig, accessible]() -> void {
        auto node = RSMainThread::Instance()->GetContext().GetNodeMap().GetRenderNode(id);
        if (node != nullptr && node->GetType() == RSRenderNodeType::DISPLAY_NODE && !accessible) {
            RS_LOGE("RSRenderServiceConnection::TakeSurfaceCapture no permission");
            return;
        }
        auto renderType = RSUniRenderJudgement::GetUniRenderEnabledType();
        if (captureConfig.captureType == SurfaceCaptureType::DEFAULT_CAPTURE) {
            if (RSSystemParameters::GetRsSurfaceCaptureType() ==
                RsSurfaceCaptureType::RS_SURFACE_CAPTURE_TYPE_MAIN_THREAD ||
                renderType == UniRenderEnabledType::UNI_RENDER_DISABLED) {
                if (node == nullptr) {
                    RS_LOGE("RSRenderServiceConnection::TakeSurfaceCapture node == nullptr");
                    return;
                }
                auto isProcOnBgThread = (renderType == UniRenderEnabledType::UNI_RENDER_ENABLED_FOR_ALL) ?
                    !node->IsOnTheTree() : false;
                std::function<void()> captureTaskInner = [id, callback, captureConfig, isProcOnBgThread]() -> void {
                    RS_LOGD("RSRenderService::TakeSurfaceCapture captureTaskInner nodeId:[%{public}" PRIu64 "]",
                        id);
                    ROSEN_TRACE_BEGIN(HITRACE_TAG_GRAPHIC_AGP, "RSRenderService::TakeSurfaceCapture");
                    RSSurfaceCaptureTask task(id, captureConfig, isProcOnBgThread);
                    if (!task.Run(callback)) {
                        callback->OnSurfaceCapture(id, nullptr);
                    }
                    ROSEN_TRACE_END(HITRACE_TAG_GRAPHIC_AGP);
                };
                if (isProcOnBgThread) {
                    RSBackgroundThread::Instance().PostTask(captureTaskInner);
                } else {
                    captureTaskInner();
                }
            } else {
                RSSurfaceCaptureTaskParallel::CheckModifiers(id);
                RSSurfaceCaptureTaskParallel::Capture(id, callback, captureConfig);
            }
        } else {
            if (RSUniRenderJudgement::IsUniRender()) {
                TakeSurfaceCaptureForUiParallel(id, callback, captureConfig);
            } else {
                TakeSurfaceCaptureForUIWithUni(id, callback, captureConfig);
            }
        }
    };
    mainThread_->PostTask(captureTask);
}

void RSRenderServiceConnection::RegisterApplicationAgent(uint32_t pid, sptr<IApplicationAgent> app)
{
    if (!mainThread_) {
        return;
    }
    auto captureTask = [=]() -> void {
        mainThread_->RegisterApplicationAgent(pid, app);
    };
    mainThread_->PostTask(captureTask);

    app->AsObject()->AddDeathRecipient(ApplicationDeathRecipient_);
}

void RSRenderServiceConnection::UnRegisterApplicationAgent(sptr<IApplicationAgent> app)
{
    auto captureTask = [=]() -> void {
        RSMainThread::Instance()->UnRegisterApplicationAgent(app);
    };
    RSMainThread::Instance()->ScheduleTask(captureTask).wait();
}

RSVirtualScreenResolution RSRenderServiceConnection::GetVirtualScreenResolution(ScreenId id)
{
    RSVirtualScreenResolution virtualScreenResolution;
    if (!screenManager_) {
        return virtualScreenResolution;
    }
    screenManager_->GetVirtualScreenResolution(id, virtualScreenResolution);
    return virtualScreenResolution;
}

RSScreenModeInfo RSRenderServiceConnection::GetScreenActiveMode(ScreenId id)
{
    RSScreenModeInfo screenModeInfo;
    if (!screenManager_) {
        return screenModeInfo;
    }
    auto renderType = RSUniRenderJudgement::GetUniRenderEnabledType();
    if (renderType == UniRenderEnabledType::UNI_RENDER_ENABLED_FOR_ALL) {
        RSHardwareThread::Instance().ScheduleTask(
            [=, &screenModeInfo]() { return screenManager_->GetScreenActiveMode(id, screenModeInfo); }).wait();
    } else {
        mainThread_->ScheduleTask(
            [=, &screenModeInfo]() { return screenManager_->GetScreenActiveMode(id, screenModeInfo); }).wait();
    }
    return screenModeInfo;
}

bool RSRenderServiceConnection::GetTotalAppMemSize(float& cpuMemSize, float& gpuMemSize)
{
    RSMainThread::Instance()->GetAppMemoryInMB(cpuMemSize, gpuMemSize);
    gpuMemSize += RSSubThreadManager::Instance()->GetAppGpuMemoryInMB();
    return true;
}

MemoryGraphic RSRenderServiceConnection::GetMemoryGraphic(int pid)
{
    MemoryGraphic memoryGraphic;
    if (!mainThread_) {
        return memoryGraphic;
    }
    if (GetUniRenderEnabled()) {
        RSMainThread* mainThread = mainThread_;
        mainThread_->ScheduleTask([mainThread, &pid, &memoryGraphic]() {
            if (RSMainThread::Instance()->GetContext().GetNodeMap().ContainPid(pid)) {
                mainThread->CountMem(pid, memoryGraphic);
            }
        }).wait();
        return memoryGraphic;
    } else {
        return memoryGraphic;
    }
}

std::vector<MemoryGraphic> RSRenderServiceConnection::GetMemoryGraphics()
{
    std::vector<MemoryGraphic> memoryGraphics;
    if (!mainThread_) {
        return memoryGraphics;
    }
    if (GetUniRenderEnabled()) {
        mainThread_->ScheduleTask(
            [weakThis = wptr<RSRenderServiceConnection>(this), &memoryGraphics]() {
                sptr<RSRenderServiceConnection> connection = weakThis.promote();
                if (!connection) {
                    return;
                }
                return connection->mainThread_->CountMem(memoryGraphics);
            }).wait();
        return memoryGraphics;
    } else {
        return memoryGraphics;
    }
}

std::vector<RSScreenModeInfo> RSRenderServiceConnection::GetScreenSupportedModes(ScreenId id)
{
    std::vector<RSScreenModeInfo> screenSupportedModes;
    if (!screenManager_) {
        return screenSupportedModes;
    }
    auto renderType = RSUniRenderJudgement::GetUniRenderEnabledType();
    if (renderType == UniRenderEnabledType::UNI_RENDER_ENABLED_FOR_ALL) {
        return RSHardwareThread::Instance().ScheduleTask(
            [=]() { return screenManager_->GetScreenSupportedModes(id); }).get();
    } else {
        return mainThread_->ScheduleTask(
            [=]() { return screenManager_->GetScreenSupportedModes(id); }).get();
    }
}

RSScreenCapability RSRenderServiceConnection::GetScreenCapability(ScreenId id)
{
    RSScreenCapability screenCapability;
    if (!screenManager_) {
        return screenCapability;
    }
    auto renderType = RSUniRenderJudgement::GetUniRenderEnabledType();
    if (renderType == UniRenderEnabledType::UNI_RENDER_ENABLED_FOR_ALL) {
        return RSHardwareThread::Instance().ScheduleTask(
            [=]() { return screenManager_->GetScreenCapability(id); }).get();
    } else {
        return mainThread_->ScheduleTask(
            [=]() { return screenManager_->GetScreenCapability(id); }).get();
    }
}

ScreenPowerStatus RSRenderServiceConnection::GetScreenPowerStatus(ScreenId id)
{
    if (!screenManager_) {
        return ScreenPowerStatus::INVALID_POWER_STATUS;
    }
    auto renderType = RSUniRenderJudgement::GetUniRenderEnabledType();
    if (renderType == UniRenderEnabledType::UNI_RENDER_ENABLED_FOR_ALL) {
        return RSHardwareThread::Instance().ScheduleTask(
            [=]() { return screenManager_->GetScreenPowerStatus(id); }).get();
    } else {
        return mainThread_->ScheduleTask(
            [=]() { return screenManager_->GetScreenPowerStatus(id); }).get();
    }
}

RSScreenData RSRenderServiceConnection::GetScreenData(ScreenId id)
{
    RSScreenData screenData;
    if (!screenManager_) {
        return screenData;
    }
    auto renderType = RSUniRenderJudgement::GetUniRenderEnabledType();
    if (renderType == UniRenderEnabledType::UNI_RENDER_ENABLED_FOR_ALL) {
        return RSHardwareThread::Instance().ScheduleTask(
            [=]() { return screenManager_->GetScreenData(id); }).get();
    } else {
        return mainThread_->ScheduleTask(
            [=]() { return screenManager_->GetScreenData(id); }).get();
    }
}

int32_t RSRenderServiceConnection::GetScreenBacklight(ScreenId id)
{
    if (!screenManager_) {
        return INVALID_BACKLIGHT_VALUE;
    }
    auto renderType = RSUniRenderJudgement::GetUniRenderEnabledType();
    if (renderType == UniRenderEnabledType::UNI_RENDER_ENABLED_FOR_ALL) {
        return RSHardwareThread::Instance().ScheduleTask(
            [=]() { return screenManager_->GetScreenBacklight(id); }).get();
    } else {
        return mainThread_->ScheduleTask(
            [=]() { return screenManager_->GetScreenBacklight(id); }).get();
    }
}

void RSRenderServiceConnection::SetScreenBacklight(ScreenId id, uint32_t level)
{
    if (!screenManager_) {
        return;
    }
    RSLuminanceControl::Get().SetSdrLuminance(id, level);
    if (RSLuminanceControl::Get().IsHdrOn(id) && level > 0) {
        return;
    }

    auto renderType = RSUniRenderJudgement::GetUniRenderEnabledType();
    if (renderType == UniRenderEnabledType::UNI_RENDER_ENABLED_FOR_ALL) {
        screenManager_->SetScreenBacklight(id, level);
    } else {
        mainThread_->ScheduleTask(
            [=]() { screenManager_->SetScreenBacklight(id, level); }).wait();
    }
}

void RSRenderServiceConnection::RegisterBufferClearListener(
    NodeId id, sptr<RSIBufferClearCallback> callback)
{
    if (!mainThread_) {
        return;
    }
    auto registerBufferClearListener = 
        [id, callback, weakThis = wptr<RSRenderServiceConnection>(this)]() -> bool {
            sptr<RSRenderServiceConnection> connection = weakThis.promote();
            if (!connection) {
                return false;
            }
            if (auto node = connection->mainThread_->GetContext().GetNodeMap().GetRenderNode<RSSurfaceRenderNode>(id)) {
                node->RegisterBufferClearListener(callback);
                return true;
            }
            return false;
    };
    if (!registerBufferClearListener()) {
        mainThread_->PostTask(registerBufferClearListener);
    }
}

void RSRenderServiceConnection::RegisterBufferAvailableListener(
    NodeId id, sptr<RSIBufferAvailableCallback> callback, bool isFromRenderThread)
{
    if (!mainThread_) {
        return;
    }
    auto registerBufferAvailableListener =
        [id, callback, isFromRenderThread, weakThis = wptr<RSRenderServiceConnection>(this)]() -> bool {
            sptr<RSRenderServiceConnection> connection = weakThis.promote();
            if (!connection) {
                return false;
            }
            if (auto node = connection->mainThread_->GetContext().GetNodeMap().GetRenderNode<RSSurfaceRenderNode>(id)) {
                node->RegisterBufferAvailableListener(callback, isFromRenderThread);
                return true;
            }
            return false;
    };
    if (!registerBufferAvailableListener()) {
        RS_LOGD("RegisterBufferAvailableListener: node not found, post task to retry");
        mainThread_->PostTask(registerBufferAvailableListener);
    }
}

int32_t RSRenderServiceConnection::GetScreenSupportedColorGamuts(ScreenId id, std::vector<ScreenColorGamut>& mode)
{
    if (!screenManager_) {
        return StatusCode::SCREEN_NOT_FOUND;
    }
    auto renderType = RSUniRenderJudgement::GetUniRenderEnabledType();
    if (renderType == UniRenderEnabledType::UNI_RENDER_ENABLED_FOR_ALL) {
        return RSHardwareThread::Instance().ScheduleTask(
            [=, &mode]() { return screenManager_->GetScreenSupportedColorGamuts(id, mode); }).get();
    } else {
        return mainThread_->ScheduleTask(
            [=, &mode]() { return screenManager_->GetScreenSupportedColorGamuts(id, mode); }).get();
    }
}

int32_t RSRenderServiceConnection::GetScreenSupportedMetaDataKeys(ScreenId id, std::vector<ScreenHDRMetadataKey>& keys)
{
    if (!screenManager_) {
        return StatusCode::SCREEN_NOT_FOUND;
    }
    auto renderType = RSUniRenderJudgement::GetUniRenderEnabledType();
    if (renderType == UniRenderEnabledType::UNI_RENDER_ENABLED_FOR_ALL) {
        return RSHardwareThread::Instance().ScheduleTask(
            [=, &keys]() { return screenManager_->GetScreenSupportedMetaDataKeys(id, keys); }).get();
    } else {
        return mainThread_->ScheduleTask(
            [=, &keys]() { return screenManager_->GetScreenSupportedMetaDataKeys(id, keys); }).get();
    }
}

int32_t RSRenderServiceConnection::GetScreenColorGamut(ScreenId id, ScreenColorGamut& mode)
{
    if (!screenManager_) {
        return StatusCode::SCREEN_NOT_FOUND;
    }
    auto renderType = RSUniRenderJudgement::GetUniRenderEnabledType();
    if (renderType == UniRenderEnabledType::UNI_RENDER_ENABLED_FOR_ALL) {
        return RSHardwareThread::Instance().ScheduleTask(
            [=, &mode]() { return screenManager_->GetScreenColorGamut(id, mode); }).get();
    } else {
        return mainThread_->ScheduleTask(
            [=, &mode]() { return screenManager_->GetScreenColorGamut(id, mode); }).get();
    }
}

int32_t RSRenderServiceConnection::SetScreenColorGamut(ScreenId id, int32_t modeIdx)
{
    if (!screenManager_) {
        return StatusCode::SCREEN_NOT_FOUND;
    }
    auto renderType = RSUniRenderJudgement::GetUniRenderEnabledType();
    if (renderType == UniRenderEnabledType::UNI_RENDER_ENABLED_FOR_ALL) {
        return RSHardwareThread::Instance().ScheduleTask(
            [=]() { return screenManager_->SetScreenColorGamut(id, modeIdx); }).get();
    } else {
        return mainThread_->ScheduleTask(
            [=]() { return screenManager_->SetScreenColorGamut(id, modeIdx); }).get();
    }
}

int32_t RSRenderServiceConnection::SetScreenGamutMap(ScreenId id, ScreenGamutMap mode)
{
    if (!screenManager_) {
        return StatusCode::SCREEN_NOT_FOUND;
    }
    auto renderType = RSUniRenderJudgement::GetUniRenderEnabledType();
    if (renderType == UniRenderEnabledType::UNI_RENDER_ENABLED_FOR_ALL) {
        return RSHardwareThread::Instance().ScheduleTask(
            [=]() { return screenManager_->SetScreenGamutMap(id, mode); }).get();
    } else {
        return mainThread_->ScheduleTask(
            [=]() { return screenManager_->SetScreenGamutMap(id, mode); }).get();
    }
}

int32_t RSRenderServiceConnection::SetScreenCorrection(ScreenId id, ScreenRotation screenRotation)
{
    if (!screenManager_) {
        return StatusCode::SCREEN_NOT_FOUND;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    return screenManager_->SetScreenCorrection(id, screenRotation);
}

bool RSRenderServiceConnection::SetVirtualMirrorScreenCanvasRotation(ScreenId id, bool canvasRotation)
{
    if (!screenManager_) {
        return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    return screenManager_->SetVirtualMirrorScreenCanvasRotation(id, canvasRotation);
}

bool RSRenderServiceConnection::SetVirtualMirrorScreenScaleMode(ScreenId id, ScreenScaleMode scaleMode)
{
    if (!screenManager_) {
        return false;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    return screenManager_->SetVirtualMirrorScreenScaleMode(id, scaleMode);
}

int32_t RSRenderServiceConnection::GetScreenGamutMap(ScreenId id, ScreenGamutMap& mode)
{
    if (!screenManager_) {
        return StatusCode::SCREEN_NOT_FOUND;
    }
    auto renderType = RSUniRenderJudgement::GetUniRenderEnabledType();
    if (renderType == UniRenderEnabledType::UNI_RENDER_ENABLED_FOR_ALL) {
        return RSHardwareThread::Instance().ScheduleTask(
            [=, &mode]() { return screenManager_->GetScreenGamutMap(id, mode); }).get();
    } else {
        return mainThread_->ScheduleTask(
            [=, &mode]() { return screenManager_->GetScreenGamutMap(id, mode); }).get();
    }
}

int32_t RSRenderServiceConnection::GetScreenHDRCapability(ScreenId id, RSScreenHDRCapability& screenHdrCapability)
{
    if (!screenManager_) {
        return StatusCode::SCREEN_NOT_FOUND;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    return screenManager_->GetScreenHDRCapability(id, screenHdrCapability);
}

int32_t RSRenderServiceConnection::GetPixelFormat(ScreenId id, GraphicPixelFormat& pixelFormat)
{
    if (!screenManager_) {
        return StatusCode::SCREEN_NOT_FOUND;
    }
    auto renderType = RSUniRenderJudgement::GetUniRenderEnabledType();
    if (renderType == UniRenderEnabledType::UNI_RENDER_ENABLED_FOR_ALL) {
        return RSHardwareThread::Instance().ScheduleTask(
            [=, &pixelFormat]() { return screenManager_->GetPixelFormat(id, pixelFormat); }).get();
    } else {
        return mainThread_->ScheduleTask(
            [=, &pixelFormat]() { return screenManager_->GetPixelFormat(id, pixelFormat); }).get();
    }
}

int32_t RSRenderServiceConnection::SetPixelFormat(ScreenId id, GraphicPixelFormat pixelFormat)
{
    if (!screenManager_) {
        return StatusCode::SCREEN_NOT_FOUND;
    }
    auto renderType = RSUniRenderJudgement::GetUniRenderEnabledType();
    if (renderType == UniRenderEnabledType::UNI_RENDER_ENABLED_FOR_ALL) {
        return RSHardwareThread::Instance().ScheduleTask(
            [=]() { return screenManager_->SetPixelFormat(id, pixelFormat); }).get();
    } else {
        return mainThread_->ScheduleTask(
            [=]() { return screenManager_->SetPixelFormat(id, pixelFormat); }).get();
    }
}

int32_t RSRenderServiceConnection::GetScreenSupportedHDRFormats(ScreenId id, std::vector<ScreenHDRFormat>& hdrFormats)
{
    if (!screenManager_) {
        return StatusCode::SCREEN_NOT_FOUND;
    }
    auto renderType = RSUniRenderJudgement::GetUniRenderEnabledType();
    if (renderType == UniRenderEnabledType::UNI_RENDER_ENABLED_FOR_ALL) {
        return RSHardwareThread::Instance().ScheduleTask(
            [=, &hdrFormats]() { return screenManager_->GetScreenSupportedHDRFormats(id, hdrFormats); }).get();
    } else {
        return mainThread_->ScheduleTask(
            [=, &hdrFormats]() { return screenManager_->GetScreenSupportedHDRFormats(id, hdrFormats); }).get();
    }
}

int32_t RSRenderServiceConnection::GetScreenHDRFormat(ScreenId id, ScreenHDRFormat& hdrFormat)
{
    if (!screenManager_) {
        return StatusCode::SCREEN_NOT_FOUND;
    }
    auto renderType = RSUniRenderJudgement::GetUniRenderEnabledType();
    if (renderType == UniRenderEnabledType::UNI_RENDER_ENABLED_FOR_ALL) {
        return RSHardwareThread::Instance().ScheduleTask(
            [=, &hdrFormat]() { return screenManager_->GetScreenHDRFormat(id, hdrFormat); }).get();
    } else {
        return mainThread_->ScheduleTask(
            [=, &hdrFormat]() { return screenManager_->GetScreenHDRFormat(id, hdrFormat); }).get();
    }
}

int32_t RSRenderServiceConnection::SetScreenHDRFormat(ScreenId id, int32_t modeIdx)
{
    if (!screenManager_) {
        return StatusCode::SCREEN_NOT_FOUND;
    }
    auto renderType = RSUniRenderJudgement::GetUniRenderEnabledType();
    if (renderType == UniRenderEnabledType::UNI_RENDER_ENABLED_FOR_ALL) {
        return RSHardwareThread::Instance().ScheduleTask(
            [=]() { return screenManager_->SetScreenHDRFormat(id, modeIdx); }).get();
    } else {
        return mainThread_->ScheduleTask(
            [=]() { return screenManager_->SetScreenHDRFormat(id, modeIdx); }).get();
    }
}

int32_t RSRenderServiceConnection::GetScreenSupportedColorSpaces(
    ScreenId id, std::vector<GraphicCM_ColorSpaceType>& colorSpaces)
{
    if (!screenManager_) {
        return StatusCode::SCREEN_NOT_FOUND;
    }
    auto renderType = RSUniRenderJudgement::GetUniRenderEnabledType();
    if (renderType == UniRenderEnabledType::UNI_RENDER_ENABLED_FOR_ALL) {
        return RSHardwareThread::Instance().ScheduleTask(
            [=, &colorSpaces]() { return screenManager_->GetScreenSupportedColorSpaces(id, colorSpaces); }).get();
    } else {
        return mainThread_->ScheduleTask(
            [=, &colorSpaces]() { return screenManager_->GetScreenSupportedColorSpaces(id, colorSpaces); }).get();
    }
}

int32_t RSRenderServiceConnection::GetScreenColorSpace(ScreenId id, GraphicCM_ColorSpaceType& colorSpace)
{
    if (!screenManager_) {
        return StatusCode::SCREEN_NOT_FOUND;
    }
    auto renderType = RSUniRenderJudgement::GetUniRenderEnabledType();
    if (renderType == UniRenderEnabledType::UNI_RENDER_ENABLED_FOR_ALL) {
        return RSHardwareThread::Instance().ScheduleTask(
            [=, &colorSpace]() { return screenManager_->GetScreenColorSpace(id, colorSpace); }).get();
    } else {
        return mainThread_->ScheduleTask(
            [=, &colorSpace]() { return screenManager_->GetScreenColorSpace(id, colorSpace); }).get();
    }
}

int32_t RSRenderServiceConnection::SetScreenColorSpace(ScreenId id, GraphicCM_ColorSpaceType colorSpace)
{
    if (!screenManager_) {
        return StatusCode::SCREEN_NOT_FOUND;
    }
    auto renderType = RSUniRenderJudgement::GetUniRenderEnabledType();
    if (renderType == UniRenderEnabledType::UNI_RENDER_ENABLED_FOR_ALL) {
        return RSHardwareThread::Instance().ScheduleTask(
            [=]() { return screenManager_->SetScreenColorSpace(id, colorSpace); }).get();
    } else {
        return mainThread_->ScheduleTask(
            [=]() { return screenManager_->SetScreenColorSpace(id, colorSpace); }).get();
    }
}

int32_t RSRenderServiceConnection::GetScreenType(ScreenId id, RSScreenType& screenType)
{
    if (!screenManager_) {
        return StatusCode::SCREEN_NOT_FOUND;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    return screenManager_->GetScreenType(id, screenType);
}

bool RSRenderServiceConnection::GetBitmap(NodeId id, Drawing::Bitmap& bitmap)
{
    if (!mainThread_) {
        return false;
    }
    std::promise<bool> result;
    std::future<bool> future = result.get_future();
    RSMainThread* mainThread = mainThread_;
    RSUniRenderThread* renderThread = &renderThread_;
    auto getBitmapTask = [id, &bitmap, mainThread, renderThread, &result]() {
        auto node = mainThread->GetContext().GetNodeMap().GetRenderNode<RSCanvasDrawingRenderNode>(id);
        if (node == nullptr) {
            RS_LOGE("RSRenderServiceConnection::GetBitmap cannot find NodeId: [%{public}" PRIu64 "]", id);
            result.set_value(false);
            return;
        }
        if (node->GetType() != RSRenderNodeType::CANVAS_DRAWING_NODE) {
            RS_LOGE("RSRenderServiceConnection::GetBitmap RenderNodeType != RSRenderNodeType::CANVAS_DRAWING_NODE");
            result.set_value(false);
            return;
        }
        auto grContext = renderThread->GetRenderEngine()->GetRenderContext()->GetDrGPUContext();
        auto drawableNode = DrawableV2::RSRenderNodeDrawableAdapter::OnGenerate(node);
        auto getDrawableBitmapTask = [drawableNode, &bitmap, grContext, &result]() {
            bitmap = std::static_pointer_cast<DrawableV2::RSCanvasDrawingRenderNodeDrawable>(drawableNode)
                ->GetBitmap(grContext);
            result.set_value(!bitmap.IsEmpty());
        };
        renderThread->PostTask(getDrawableBitmapTask);
    };
    mainThread_->PostTask(getBitmapTask);
    return future.get();
}

bool RSRenderServiceConnection::GetPixelmap(NodeId id, const std::shared_ptr<Media::PixelMap> pixelmap,
    const Drawing::Rect* rect, std::shared_ptr<Drawing::DrawCmdList> drawCmdList)
{
    if (!mainThread_) {
        return false;
    }
    std::promise<bool> result;
    std::future<bool> future = result.get_future();
    RSMainThread* mainThread = mainThread_;
    RSUniRenderThread* renderThread = &renderThread_;
    auto getPixelMapTask = [id, &pixelmap, rect, drawCmdList, mainThread, renderThread, &result]() {
        auto node = mainThread->GetContext().GetNodeMap().GetRenderNode<RSCanvasDrawingRenderNode>(id);
        if (node == nullptr) {
            RS_LOGD("RSRenderServiceConnection::GetPixelmap: cannot find NodeId: [%{public}" PRIu64 "]", id);
            result.set_value(false);
            return;
        }
        if (node->GetType() != RSRenderNodeType::CANVAS_DRAWING_NODE) {
            RS_LOGE("RSRenderServiceConnection::GetPixelmap: RenderNodeType != RSRenderNodeType::CANVAS_DRAWING_NODE");
            result.set_value(false);
            return;
        }

        auto tid = node->GetTid(); // planning: id may change in subthread
        auto drawableNode = DrawableV2::RSRenderNodeDrawableAdapter::OnGenerate(node);
        if (drawableNode) {
            tid = std::static_pointer_cast<DrawableV2::RSCanvasDrawingRenderNodeDrawable>(drawableNode)->GetTid();
        }
        auto getDrawablePixelmapTask = [drawableNode, &pixelmap, rect, &result, tid, drawCmdList]() {
            result.set_value(std::static_pointer_cast<DrawableV2::RSCanvasDrawingRenderNodeDrawable>(drawableNode)->
                GetPixelmap(pixelmap, rect, tid, drawCmdList));
        };
        if (!node->IsOnTheTree()) {
            node->ClearOp();
        }
        if (tid == UNI_MAIN_THREAD_INDEX) {
            if (!mainThread->IsIdle() && mainThread->GetContext().HasActiveNode(node)) {
                result.set_value(false);
                return;
            }
            result.set_value(node->GetPixelmap(pixelmap, rect, tid, drawCmdList));
        } else if (tid == UNI_RENDER_THREAD_INDEX) {
            renderThread->PostTask(getDrawablePixelmapTask);
        } else {
            RSTaskDispatcher::GetInstance().PostTask(
                RSSubThreadManager::Instance()->GetReThreadIndexMap()[tid], getDrawablePixelmapTask, false);
        }
    };
    mainThread_->PostTask(getPixelMapTask);
    return future.get();
}

bool RSRenderServiceConnection::RegisterTypeface(uint64_t globalUniqueId,
    std::shared_ptr<Drawing::Typeface>& typeface)
{
    RS_LOGD("RSRenderServiceConnection::RegisterTypeface: pid[%{public}d] register typeface[%{public}u]",
        RSTypefaceCache::GetTypefacePid(globalUniqueId), RSTypefaceCache::GetTypefaceId(globalUniqueId));
    RSTypefaceCache::Instance().CacheDrawingTypeface(globalUniqueId, typeface);
    return true;
}

bool RSRenderServiceConnection::UnRegisterTypeface(uint64_t globalUniqueId)
{
    RS_LOGD("RSRenderServiceConnection::UnRegisterTypeface: pid[%{public}d] unregister typeface[%{public}u]",
        RSTypefaceCache::GetTypefacePid(globalUniqueId), RSTypefaceCache::GetTypefaceId(globalUniqueId));
    RSTypefaceCache::Instance().AddDelayDestroyQueue(globalUniqueId);
    return true;
}

int32_t RSRenderServiceConnection::SetScreenSkipFrameInterval(ScreenId id, uint32_t skipFrameInterval)
{
    if (!screenManager_) {
        return StatusCode::SCREEN_NOT_FOUND;
    }
    auto renderType = RSUniRenderJudgement::GetUniRenderEnabledType();
    if (renderType == UniRenderEnabledType::UNI_RENDER_ENABLED_FOR_ALL) {
        return RSHardwareThread::Instance().ScheduleTask(
            [=]() { return screenManager_->SetScreenSkipFrameInterval(id, skipFrameInterval); }).get();
    } else {
        return mainThread_->ScheduleTask(
            [=]() { return screenManager_->SetScreenSkipFrameInterval(id, skipFrameInterval); }).get();
    }
}

int32_t RSRenderServiceConnection::RegisterOcclusionChangeCallback(sptr<RSIOcclusionChangeCallback> callback)
{
    if (!mainThread_) {
        return StatusCode::INVALID_ARGUMENTS;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    if (!callback) {
        RS_LOGD("RSRenderServiceConnection::RegisterOcclusionChangeCallback: callback is nullptr");
        return StatusCode::INVALID_ARGUMENTS;
    }
    mainThread_->RegisterOcclusionChangeCallback(remotePid_, callback);
    return StatusCode::SUCCESS;
}

int32_t RSRenderServiceConnection::RegisterSurfaceOcclusionChangeCallback(
    NodeId id, sptr<RSISurfaceOcclusionChangeCallback> callback, std::vector<float>& partitionPoints)
{
    if (!mainThread_) {
        return StatusCode::INVALID_ARGUMENTS;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    if (!callback) {
        RS_LOGD("RSRenderServiceConnection::RegisterSurfaceOcclusionChangeCallback: callback is nullptr");
        return StatusCode::INVALID_ARGUMENTS;
    }
    mainThread_->RegisterSurfaceOcclusionChangeCallback(id, remotePid_, callback, partitionPoints);
    return StatusCode::SUCCESS;
}

int32_t RSRenderServiceConnection::UnRegisterSurfaceOcclusionChangeCallback(NodeId id)
{
    if (!mainThread_) {
        return StatusCode::INVALID_ARGUMENTS;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    mainThread_->UnRegisterSurfaceOcclusionChangeCallback(id);
    return StatusCode::SUCCESS;
}

int32_t RSRenderServiceConnection::RegisterHgmConfigChangeCallback(sptr<RSIHgmConfigChangeCallback> callback)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!callback) {
        RS_LOGD("RSRenderServiceConnection::RegisterHgmConfigChangeCallback: callback is nullptr");
        return StatusCode::INVALID_ARGUMENTS;
    }

    HgmConfigCallbackManager::GetInstance()->RegisterHgmConfigChangeCallback(remotePid_, callback);
    return StatusCode::SUCCESS;
}

int32_t RSRenderServiceConnection::RegisterHgmRefreshRateModeChangeCallback(
    sptr<RSIHgmConfigChangeCallback> callback)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!callback) {
        RS_LOGD("RSRenderServiceConnection::RegisterHgmRefreshRateModeChangeCallback: callback is nullptr");
        return StatusCode::INVALID_ARGUMENTS;
    }

    HgmConfigCallbackManager::GetInstance()->RegisterHgmRefreshRateModeChangeCallback(remotePid_, callback);
    return StatusCode::SUCCESS;
}

int32_t RSRenderServiceConnection::RegisterHgmRefreshRateUpdateCallback(
    sptr<RSIHgmConfigChangeCallback> callback)
{
    std::lock_guard<std::mutex> lock(mutex_);

    HgmConfigCallbackManager::GetInstance()->RegisterHgmRefreshRateUpdateCallback(remotePid_, callback);
    return StatusCode::SUCCESS;
}

void RSRenderServiceConnection::SetAppWindowNum(uint32_t num)
{
    if (!mainThread_) {
        return;
    }
    auto task = [this, num]() -> void {
        mainThread_->SetAppWindowNum(num);
    };
    mainThread_->PostTask(task);
}

bool RSRenderServiceConnection::SetSystemAnimatedScenes(SystemAnimatedScenes systemAnimatedScenes)
{
    if (!mainThread_) {
        return false;
    }
    RSUifirstManager::Instance().OnProcessAnimateScene(systemAnimatedScenes);
    std::lock_guard<std::mutex> lock(mutex_);
    return mainThread_->SetSystemAnimatedScenes(systemAnimatedScenes);
}

void RSRenderServiceConnection::ShowWatermark(const std::shared_ptr<Media::PixelMap> &watermarkImg, bool isShow)
{
    if (!mainThread_) {
        return;
    }
    auto task = [this, watermarkImg, isShow]() -> void {
        mainThread_->ShowWatermark(watermarkImg, isShow);
    };
    mainThread_->PostTask(task);
}

int32_t RSRenderServiceConnection::ResizeVirtualScreen(ScreenId id, uint32_t width, uint32_t height)
{
    if (!screenManager_) {
        return StatusCode::SCREEN_NOT_FOUND;
    }
    auto renderType = RSUniRenderJudgement::GetUniRenderEnabledType();
    if (renderType == UniRenderEnabledType::UNI_RENDER_ENABLED_FOR_ALL) {
        return RSHardwareThread::Instance().ScheduleTask(
            [=]() { return screenManager_->ResizeVirtualScreen(id, width, height); }).get();
    } else {
        return mainThread_->ScheduleTask(
            [=]() { return screenManager_->ResizeVirtualScreen(id, width, height); }).get();
    }
}

void RSRenderServiceConnection::ReportJankStats()
{
    auto task = []() -> void { RSJankStats::GetInstance().ReportJankStats(); };
    renderThread_.PostTask(task);
}

void RSRenderServiceConnection::NotifyLightFactorStatus(bool isSafe)
{
    if (!mainThread_) {
        return;
    }
    mainThread_->GetFrameRateMgr()->HandleLightFactorStatus(remotePid_, isSafe);
}

void RSRenderServiceConnection::NotifyPackageEvent(uint32_t listSize, const std::vector<std::string>& packageList)
{
    if (!mainThread_) {
        return;
    }
    if (mainThread_->GetFrameRateMgr() == nullptr) {
        RS_LOGW("RSRenderServiceConnection::NotifyPackageEvent: frameRateMgr is nullptr.");
        return;
    }
    mainThread_->GetFrameRateMgr()->HandlePackageEvent(remotePid_, listSize, packageList);
}

void RSRenderServiceConnection::NotifyRefreshRateEvent(const EventInfo& eventInfo)
{
    if (!mainThread_) {
        return;
    }
    if (mainThread_->GetFrameRateMgr() == nullptr) {
        RS_LOGW("RSRenderServiceConnection::NotifyRefreshRateEvent: frameRateMgr is nullptr.");
        return;
    }
    mainThread_->GetFrameRateMgr()->HandleRefreshRateEvent(remotePid_, eventInfo);
}

void RSRenderServiceConnection::NotifyTouchEvent(int32_t touchStatus, int32_t touchCnt)
{
    if (!mainThread_) {
        return;
    }
    if (mainThread_->GetFrameRateMgr() == nullptr) {
        RS_LOGW("RSRenderServiceConnection::NotifyTouchEvent: frameRateMgr is nullptr.");
        return;
    }
    mainThread_->GetFrameRateMgr()->HandleTouchEvent(remotePid_, touchStatus, touchCnt);
    if (touchStatus == TouchStatus::TOUCH_DOWN) {
        GrDirectContext::setLastTouchDownTime();
    }
}

void RSRenderServiceConnection::NotifyDynamicModeEvent(bool enableDynamicModeEvent)
{
    HgmTaskHandleThread::Instance().PostTask([enableDynamicModeEvent] () {
        auto frameRateMgr = HgmCore::Instance().GetFrameRateMgr();
        if (frameRateMgr == nullptr) {
            RS_LOGW("RSRenderServiceConnection::NotifyDynamicModeEvent: frameRateMgr is nullptr.");
            return;
        }
        frameRateMgr->HandleDynamicModeEvent(enableDynamicModeEvent);
    });
}

void RSRenderServiceConnection::ReportEventResponse(DataBaseRs info)
{
    auto task = [info]() -> void {
        RSJankStats::GetInstance().SetReportEventResponse(info);
    };
    renderThread_.PostTask(task);
    RSUifirstManager::Instance().OnProcessEventResponse(info);
}

void RSRenderServiceConnection::ReportEventComplete(DataBaseRs info)
{
    auto task = [info]() -> void {
        RSJankStats::GetInstance().SetReportEventComplete(info);
    };
    renderThread_.PostTask(task);
    RSUifirstManager::Instance().OnProcessEventComplete(info);
}

void RSRenderServiceConnection::ReportEventJankFrame(DataBaseRs info)
{
    bool isReportTaskDelayed = renderThread_.IsMainLooping();
    auto task = [info, isReportTaskDelayed]() -> void {
        RSJankStats::GetInstance().SetReportEventJankFrame(info, isReportTaskDelayed);
    };
    renderThread_.PostTask(task);
}

void RSRenderServiceConnection::ReportGameStateData(GameStateData info)
{
    RS_LOGD("RSRenderServiceConnection::ReportGameStateData = %{public}s, uid = %{public}d, state = %{public}d, "
            "pid = %{public}d renderTid = %{public}d ",
        info.bundleName.c_str(), info.uid, info.state, info.pid, info.renderTid);

    FrameReport::GetInstance().SetGameScene(info.pid, info.state);
}

void RSRenderServiceConnection::SetHardwareEnabled(NodeId id, bool isEnabled, SelfDrawingNodeType selfDrawingType)
{
    if (!mainThread_) {
        return;
    }
    auto task = [weakThis = wptr<RSRenderServiceConnection>(this), id, isEnabled, selfDrawingType]() -> void {
        sptr<RSRenderServiceConnection> connection = weakThis.promote();
        if (!connection) {
            return;
        }
        auto& context = connection->mainThread_->GetContext();
        auto node = context.GetNodeMap().GetRenderNode<RSSurfaceRenderNode>(id);
        if (node) {
            node->SetHardwareEnabled(isEnabled, selfDrawingType);
        }
    };
    mainThread_->PostTask(task);
}

void RSRenderServiceConnection::SetCacheEnabledForRotation(bool isEnabled)
{
    RSSystemProperties::SetCacheEnabledForRotation(isEnabled);
}

std::vector<ActiveDirtyRegionInfo> RSRenderServiceConnection::GetActiveDirtyRegionInfo()
{
    const auto& activeDirtyRegionInfos = GpuDirtyRegionCollection::GetInstance().GetActiveDirtyRegionInfo();
    GpuDirtyRegionCollection::GetInstance().ResetActiveDirtyRegionInfo();
    return activeDirtyRegionInfos;
}

GlobalDirtyRegionInfo RSRenderServiceConnection::GetGlobalDirtyRegionInfo()
{
    const auto& globalDirtyRegionInfo = GpuDirtyRegionCollection::GetInstance().GetGlobalDirtyRegionInfo();
    GpuDirtyRegionCollection::GetInstance().ResetGlobalDirtyRegionInfo();
    return globalDirtyRegionInfo;
}

LayerComposeInfo RSRenderServiceConnection::GetLayerComposeInfo()
{
    const auto& layerComposeInfo = LayerComposeCollection::GetInstance().GetLayerComposeInfo();
    LayerComposeCollection::GetInstance().ResetLayerComposeInfo();
    return layerComposeInfo;
}

HwcDisabledReasonInfos RSRenderServiceConnection::GetHwcDisabledReasonInfo()
{
    return HwcDisabledReasonCollection::GetInstance().GetHwcDisabledReasonInfo();
}

#ifdef TP_FEATURE_ENABLE
void RSRenderServiceConnection::SetTpFeatureConfig(int32_t feature, const char* config)
{
    if (TOUCH_SCREEN->tsSetFeatureConfig_ == nullptr) {
        RS_LOGW("RSRenderServiceConnection::SetTpFeatureConfig: touch screen function symbol is nullptr.");
        return;
    }
    if (TOUCH_SCREEN->tsSetFeatureConfig_(feature, config) < 0) {
        RS_LOGW("RSRenderServiceConnection::SetTpFeatureConfig: tsSetFeatureConfig_ failed.");
        return;
    }
}
#endif

void RSRenderServiceConnection::SetVirtualScreenUsingStatus(bool isVirtualScreenUsingStatus)
{
    if (isVirtualScreenUsingStatus) {
        EventInfo event = { "VOTER_VIRTUALDISPLAY", ADD_VOTE, OLED_60_HZ, OLED_60_HZ };
        NotifyRefreshRateEvent(event);
    } else {
        EventInfo event = { "VOTER_VIRTUALDISPLAY", REMOVE_VOTE };
        NotifyRefreshRateEvent(event);
    }
    return;
}

void RSRenderServiceConnection::SetCurtainScreenUsingStatus(bool isCurtainScreenOn)
{
    if (!mainThread_) {
        return;
    }
    auto task = [this, isCurtainScreenOn]() -> void {
        mainThread_->SetCurtainScreenUsingStatus(isCurtainScreenOn);
    };
    mainThread_->PostTask(task);
}

int32_t RSRenderServiceConnection::RegisterUIExtensionCallback(uint64_t userId, sptr<RSIUIExtensionCallback> callback)
{
    if (!mainThread_) {
        return StatusCode::INVALID_ARGUMENTS;
    }
    std::lock_guard<std::mutex> lock(mutex_);
    if (!callback) {
        RS_LOGE("RSRenderServiceConnection::RegisterUIExtensionCallback register null callback, failed.");
        return StatusCode::INVALID_ARGUMENTS;
    }
    mainThread_->RegisterUIExtensionCallback(remotePid_, userId, callback);
    return StatusCode::SUCCESS;
}

bool RSRenderServiceConnection::SetVirtualScreenStatus(ScreenId id, VirtualScreenStatus screenStatus)
{
    RS_LOGD("RSRenderServiceConnection::SetVirtualScreenStatus ScreenId:%{public}" PRIu64 " screenStatus:%{public}d",
        id, screenStatus);
    return screenManager_->SetVirtualScreenStatus(id, screenStatus);
}
} // namespace Rosen
} // namespace OHOS
