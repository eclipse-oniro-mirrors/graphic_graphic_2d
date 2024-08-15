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
#include "pipeline/rs_uni_render_thread.h"
#include <memory>

#include <malloc.h>
#include <parameters.h>
#include "graphic_common_c.h"
#include "rs_trace.h"
#include "hgm_core.h"

#include "common/rs_common_def.h"
#include "common/rs_optional_trace.h"
#include "drawable/rs_property_drawable_utils.h"
#include "include/core/SkGraphics.h"
#include "include/gpu/GrDirectContext.h"
#include "surface.h"
#include "sync_fence.h"
#include "drawable/rs_display_render_node_drawable.h"
#include "drawable/rs_surface_render_node_drawable.h"
#include "memory/rs_memory_manager.h"
#include "params/rs_display_render_params.h"
#include "params/rs_surface_render_params.h"
#include "pipeline/rs_hardware_thread.h"
#include "pipeline/rs_main_thread.h"
#include "pipeline/rs_render_node_gc.h"
#include "pipeline/rs_surface_handler.h"
#include "pipeline/rs_task_dispatcher.h"
#include "pipeline/rs_uni_render_engine.h"
#include "pipeline/rs_uni_render_util.h"
#include "pipeline/sk_resource_manager.h"
#include "platform/common/rs_log.h"
#include "platform/ohos/rs_jank_stats.h"
#include "platform/ohos/rs_node_stats.h"
#ifdef RES_SCHED_ENABLE
#include "system_ability_definition.h"
#include "if_system_ability_manager.h"
#include <iservice_registry.h>
#endif
#include "common/rs_singleton.h"
#include "pipeline/parallel_render/rs_sub_thread_manager.h"
#include "pipeline/round_corner_display/rs_round_corner_display.h"
#include "pipeline/rs_uifirst_manager.h"
#include "system/rs_system_parameters.h"

#ifdef SOC_PERF_ENABLE
#include "socperf_client.h"
#endif

namespace OHOS {
namespace Rosen {
namespace {
constexpr const char* CLEAR_GPU_CACHE = "ClearGpuCache";
constexpr const char* DEFAULT_CLEAR_GPU_CACHE = "DefaultClearGpuCache";
constexpr const char* PURGE_CACHE_BETWEEN_FRAMES = "PurgeCacheBetweenFrames";
constexpr const char* PRE_ALLOCATE_TEXTURE_BETWEEN_FRAMES = "PreAllocateTextureBetweenFrames";
constexpr const char* ASYNC_FREE_VMAMEMORY_BETWEEN_FRAMES = "AsyncFreeVMAMemoryBetweenFrames";
const std::string PERF_FOR_BLUR_IF_NEEDED_TASK_NAME = "PerfForBlurIfNeeded";
constexpr uint32_t TIME_OF_EIGHT_FRAMES = 8000;
constexpr uint32_t TIME_OF_THE_FRAMES = 1000;
constexpr uint32_t TIME_OF_DEFAULT_CLEAR_GPU_CACHE = 5000;
constexpr uint32_t WAIT_FOR_RELEASED_BUFFER_TIMEOUT = 3000;
constexpr uint32_t RELEASE_IN_HARDWARE_THREAD_TASK_NUM = 4;
constexpr uint64_t PERF_PERIOD_BLUR = 480000000;
constexpr uint64_t PERF_PERIOD_BLUR_TIMEOUT = 80000000;

const std::map<int, int32_t> BLUR_CNT_TO_BLUR_CODE {
    { 1, 10021 },
    { 2, 10022 },
    { 3, 10023 },
};

void PerfRequest(int32_t perfRequestCode, bool onOffTag)
{
#ifdef SOC_PERF_ENABLE
    OHOS::SOCPERF::SocPerfClient::GetInstance().PerfRequestEx(perfRequestCode, onOffTag, "");
    RS_LOGD("RSUniRenderThread::soc perf info [%{public}d %{public}d]", perfRequestCode, onOffTag);
#endif
}
};

thread_local CaptureParam RSUniRenderThread::captureParam_ = {};

void RSUniRenderThread::SetCaptureParam(const CaptureParam& param)
{
    captureParam_ = param;
}

CaptureParam& RSUniRenderThread::GetCaptureParam()
{
    return captureParam_;
}

void RSUniRenderThread::ResetCaptureParam()
{
    captureParam_ = {};
}

bool RSUniRenderThread::IsInCaptureProcess()
{
    return captureParam_.isSnapshot_ || captureParam_.isMirror_;
}

RSUniRenderThread& RSUniRenderThread::Instance()
{
    static RSUniRenderThread instance;
    return instance;
}

RSUniRenderThread::RSUniRenderThread()
    :postImageReleaseTaskFlag_(Rosen::RSSystemProperties::GetImageReleaseUsingPostTask())
{}

RSUniRenderThread::~RSUniRenderThread() noexcept {}

void RSUniRenderThread::InitGrContext()
{
    // uniRenderEngine must be inited on the same thread with requestFrame
    uniRenderEngine_ = std::make_shared<RSUniRenderEngine>();
    if (!uniRenderEngine_) {
        RS_LOGE("uniRenderEngine_ is nullptr");
        return;
    }
    uniRenderEngine_->Init();
#ifdef RS_ENABLE_VK
    if (Drawing::SystemProperties::GetGpuApiType() == GpuApiType::VULKAN ||
        Drawing::SystemProperties::GetGpuApiType() == GpuApiType::DDGR) {
        uniRenderEngine_->GetSkContext()->RegisterPostFunc([](const std::function<void()>& task) {
            RSUniRenderThread::Instance().PostImageReleaseTask(task);
        });
    }
#endif
}

void RSUniRenderThread::Inittcache()
{
    if (RSSystemParameters::GetTcacheEnabled()) {
        // enable cache
        mallopt(M_SET_THREAD_CACHE, M_THREAD_CACHE_ENABLE);
    }
}

void RSUniRenderThread::Start()
{
    runner_ = AppExecFwk::EventRunner::Create("RSUniRenderThread");
    if (!runner_) {
        RS_LOGE("RSUniRenderThread Start runner null");
        return;
    }
    handler_ = std::make_shared<AppExecFwk::EventHandler>(runner_);
    runner_->Run();
    auto PostTaskProxy = [](RSTaskMessage::RSTask task, const std::string& name, int64_t delayTime,
        AppExecFwk::EventQueue::Priority priority) {
        RSUniRenderThread::Instance().PostTask(task, name, delayTime, priority);
    };
    RSRenderNodeGC::Instance().SetRenderTask(PostTaskProxy);
    PostSyncTask([this] {
        RS_LOGE("RSUniRenderThread Started ...");
        Inittcache();
        InitGrContext();
        tid_ = gettid();
#ifdef RES_SCHED_ENABLE
        SubScribeSystemAbility();
#endif
    });

    auto taskDispatchFunc = [this](const RSTaskDispatcher::RSTask& task, bool isSyncTask = false) {
        if (isSyncTask) {
            PostSyncTask(task);
        } else {
            PostTask(task);
        }
    };
    RSTaskDispatcher::GetInstance().RegisterTaskDispatchFunc(tid_, taskDispatchFunc);

    if (!rootNodeDrawable_) {
        const std::shared_ptr<RSBaseRenderNode> rootNode =
            RSMainThread::Instance()->GetContext().GetGlobalRootRenderNode();
        if (!rootNode) {
            RS_LOGE("rootNode is nullptr");
            return;
        }
        auto ptr = DrawableV2::RSRenderNodeDrawableAdapter::OnGenerate(rootNode);
        rootNodeDrawable_ = std::static_pointer_cast<DrawableV2::RSRenderNodeDrawable>(ptr);
    }
}

std::shared_ptr<RSBaseRenderEngine> RSUniRenderThread::GetRenderEngine() const
{
    return uniRenderEngine_;
}

void RSUniRenderThread::PostTask(const std::function<void()>& task)
{
    if (!handler_) {
        return;
    }
    handler_->PostTask(task, AppExecFwk::EventQueue::Priority::IMMEDIATE);
}

void RSUniRenderThread::PostRTTask(const std::function<void()>& task)
{
    auto tid = gettid();
    if (tid == tid_) {
        task();
    } else {
        PostTask(task);
    }
}

void RSUniRenderThread::PostImageReleaseTask(const std::function<void()>& task)
{
    imageReleaseCount_++;
    if (postImageReleaseTaskFlag_) {
        PostRTTask(task);
        return;
    }
    if (tid_ == gettid()) {
        task();
        return;
    }
    std::unique_lock<std::mutex> releaseLock(imageReleaseMutex_);
    imageReleaseTasks_.push_back(task);
}

void RSUniRenderThread::RunImageReleaseTask()
{
    if (postImageReleaseTaskFlag_) { // release using post task
        RS_TRACE_NAME_FMT("RunImageReleaseTask using PostTask: count %d", imageReleaseCount_);
        imageReleaseCount_ = 0;
        return;
    }
    std::vector<Callback> tasks;
    {
        std::unique_lock<std::mutex> releaseLock(imageReleaseMutex_);
        std::swap(imageReleaseTasks_, tasks);
    }
    if (tasks.empty()) {
        return;
    }
    RS_TRACE_NAME_FMT("RunImageReleaseTask: count %d", imageReleaseCount_);
    imageReleaseCount_ = 0;
    for (auto task : tasks) {
        task();
    }
}

void RSUniRenderThread::PostTask(RSTaskMessage::RSTask task, const std::string& name, int64_t delayTime,
    AppExecFwk::EventQueue::Priority priority)
{
    if (handler_) {
        handler_->PostTask(task, name, delayTime, priority);
    }
}

void RSUniRenderThread::RemoveTask(const std::string& name)
{
    if (handler_) {
        handler_->RemoveTask(name);
    }
}

void RSUniRenderThread::PostSyncTask(const std::function<void()>& task)
{
    if (!handler_) {
        return;
    }
    handler_->PostSyncTask(task, AppExecFwk::EventQueue::Priority::IMMEDIATE);
}

bool RSUniRenderThread::IsIdle() const
{
    return handler_ ? handler_->IsIdle() : false;
}

void RSUniRenderThread::Sync(std::unique_ptr<RSRenderThreadParams>& stagingRenderThreadParams)
{
    renderThreadParams_ = std::move(stagingRenderThreadParams);
}

void RSUniRenderThread::Render()
{
    if (!rootNodeDrawable_) {
        RS_LOGE("rootNodeDrawable is nullptr");
    }
    Drawing::Canvas canvas;
    RSNodeStats::GetInstance().ClearNodeStats();
    rootNodeDrawable_->OnDraw(canvas);
    RSNodeStats::GetInstance().ReportRSNodeLimitExceeded();
    PerfForBlurIfNeeded();
}

void RSUniRenderThread::ReleaseSkipSyncBuffer(std::vector<std::function<void()>>& tasks)
{
#ifndef ROSEN_CROSS_PLATFORM
    auto& bufferToRelease = RSMainThread::Instance()->GetContext().GetMutableSkipSyncBuffer();
    if (bufferToRelease.empty()) {
        return;
    }
    for (const auto& item : bufferToRelease) {
        if (!item.buffer || !item.consumer) {
            continue;
        }
        auto releaseTask = [buffer = item.buffer, consumer = item.consumer,
            useReleaseFence = item.useFence, acquireFence = acquireFence_]() mutable {
            auto ret = consumer->ReleaseBuffer(buffer, useReleaseFence ?
                RSHardwareThread::Instance().releaseFence_ : acquireFence);
            if (ret != OHOS::SURFACE_ERROR_OK) {
                RS_LOGD("ReleaseSelfDrawingNodeBuffer failed ret:%{public}d", ret);
            }
        };
        tasks.emplace_back(releaseTask);
    }
    bufferToRelease.clear();
#endif
}

void RSUniRenderThread::ReleaseSelfDrawingNodeBuffer()
{
    std::vector<std::function<void()>> releaseTasks;
    for (const auto& surfaceNode : renderThreadParams_->GetSelfDrawingNodes()) {
        auto drawable = surfaceNode->GetRenderDrawable();
        if (UNLIKELY(!drawable)) {
            continue;
        }
        auto surfaceDrawable = std::static_pointer_cast<DrawableV2::RSSurfaceRenderNodeDrawable>(drawable);
        auto& params = surfaceDrawable->GetRenderParams();
        if (UNLIKELY(!params)) {
            continue;
        }
        auto surfaceParams = static_cast<RSSurfaceRenderParams*>(params.get());
        bool needRelease = !surfaceParams->GetHardwareEnabled() || !surfaceParams->GetLayerCreated();
        if (needRelease && surfaceParams->GetLastFrameHardwareEnabled()) {
            surfaceParams->releaseInHardwareThreadTaskNum_ = RELEASE_IN_HARDWARE_THREAD_TASK_NUM;
        }
        if (needRelease) {
            auto preBuffer = params->GetPreBuffer();
            if (preBuffer == nullptr) {
                if (surfaceParams->releaseInHardwareThreadTaskNum_ > 0) {
                    surfaceParams->releaseInHardwareThreadTaskNum_--;
                }
                continue;
            }
            auto surfaceDrawable = std::static_pointer_cast<DrawableV2::RSSurfaceRenderNodeDrawable>(drawable);
            auto releaseTask = [buffer = preBuffer, consumer = surfaceDrawable->GetConsumerOnDraw(),
                                   useReleaseFence = surfaceParams->GetLastFrameHardwareEnabled(),
                                   acquireFence = acquireFence_]() mutable {
                auto ret = consumer->ReleaseBuffer(buffer, useReleaseFence ?
                    RSHardwareThread::Instance().releaseFence_ : acquireFence);
                if (ret != OHOS::SURFACE_ERROR_OK) {
                    RS_LOGD("ReleaseSelfDrawingNodeBuffer failed ret:%{public}d", ret);
                }
            };
            params->SetPreBuffer(nullptr);
            if (surfaceParams->releaseInHardwareThreadTaskNum_ > 0) {
                releaseTasks.emplace_back(releaseTask);
                surfaceParams->releaseInHardwareThreadTaskNum_--;
            } else {
                releaseTask();
            }
        }
    }
    ReleaseSkipSyncBuffer(releaseTasks);
    if (releaseTasks.empty()) {
        return;
    }
    auto releaseBufferTask = [releaseTasks]() {
        for (const auto& task : releaseTasks) {
            task();
        }
    };
    auto delayTime = RSHardwareThread::Instance().delayTime_;
    if (delayTime > 0) {
        RSHardwareThread::Instance().PostDelayTask(releaseBufferTask, delayTime);
    } else {
        RSHardwareThread::Instance().PostTask(releaseBufferTask);
    }
}

void RSUniRenderThread::ReleaseSurface()
{
    std::lock_guard<std::mutex> lock(mutex_);
    while (tmpSurfaces_.size() > 0) {
        auto tmp = tmpSurfaces_.front();
        tmpSurfaces_.pop();
        tmp = nullptr;
    }
}

void RSUniRenderThread::AddToReleaseQueue(std::shared_ptr<Drawing::Surface>&& surface)
{
    std::lock_guard<std::mutex> lock(mutex_);
    tmpSurfaces_.push(std::move(surface));
}

uint64_t RSUniRenderThread::GetCurrentTimestamp() const
{
    return renderThreadParams_->GetCurrentTimestamp();
}

uint32_t RSUniRenderThread::GetPendingScreenRefreshRate() const
{
    return renderThreadParams_->GetPendingScreenRefreshRate();
}

uint64_t RSUniRenderThread::GetPendingConstraintRelativeTime() const
{
    return renderThreadParams_->GetPendingConstraintRelativeTime();
}

#ifdef RES_SCHED_ENABLE
void RSUniRenderThread::SubScribeSystemAbility()
{
    RS_LOGD("%{public}s", __func__);
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (!systemAbilityManager) {
        RS_LOGE("%{public}s failed to get system ability manager client", __func__);
        return;
    }
    std::string threadName = "RSHardwareThread";
    std::string strUid = std::to_string(getuid());
    std::string strPid = std::to_string(getpid());
    std::string strTid = std::to_string(gettid());

    saStatusChangeListener_ = new (std::nothrow)VSyncSystemAbilityListener(threadName, strUid, strPid, strTid);
    int32_t ret = systemAbilityManager->SubscribeSystemAbility(RES_SCHED_SYS_ABILITY_ID, saStatusChangeListener_);
    if (ret != ERR_OK) {
        RS_LOGE("%{public}s subscribe system ability %{public}d failed.", __func__, RES_SCHED_SYS_ABILITY_ID);
        saStatusChangeListener_ = nullptr;
    }
}
#endif
bool RSUniRenderThread::WaitUntilDisplayNodeBufferReleased(
    DrawableV2::RSDisplayRenderNodeDrawable& displayNodeDrawable)
{
    std::unique_lock<std::mutex> lock(displayNodeBufferReleasedMutex_);
    displayNodeBufferReleased_ = false; // prevent spurious wakeup of condition variable
    if (!displayNodeDrawable.IsSurfaceCreated()) {
        return true;
    }
    auto consumer = displayNodeDrawable.GetRSSurfaceHandlerOnDraw()->GetConsumer();
    if (consumer && consumer->QueryIfBufferAvailable()) {
        return true;
    }
    return displayNodeBufferReleasedCond_.wait_until(lock, std::chrono::system_clock::now() +
        std::chrono::milliseconds(WAIT_FOR_RELEASED_BUFFER_TIMEOUT), [this]() { return displayNodeBufferReleased_; });
}

void RSUniRenderThread::NotifyDisplayNodeBufferReleased()
{
    RS_TRACE_NAME("RSUniRenderThread::NotifyDisplayNodeBufferReleased");
    std::lock_guard<std::mutex> lock(displayNodeBufferReleasedMutex_);
    displayNodeBufferReleased_ = true;
    displayNodeBufferReleasedCond_.notify_one();
}

void RSUniRenderThread::PerfForBlurIfNeeded()
{
    if (!handler_) {
        return;
    }
    handler_->RemoveTask(PERF_FOR_BLUR_IF_NEEDED_TASK_NAME);
    static uint64_t prePerfTimestamp = 0;
    static int preBlurCnt = 0;
    static int cnt = 0;
    auto params = GetRSRenderThreadParams().get();
    if (!params) {
        return;
    }
    auto threadTimestamp = params->GetCurrentTimestamp();

    auto task = [this]() {
        if (preBlurCnt == 0) {
            return;
        }
        auto now = std::chrono::steady_clock::now().time_since_epoch();
        auto timestamp = std::chrono::duration_cast<std::chrono::nanoseconds>(now).count();
        RS_OPTIONAL_TRACE_NAME_FMT("PerfForBlurIfNeeded now[%ld] timestamp[%ld] preBlurCnt[%d]",
            now, timestamp, preBlurCnt);
        if (static_cast<uint64_t>(timestamp) - prePerfTimestamp > PERF_PERIOD_BLUR_TIMEOUT) {
            PerfRequest(BLUR_CNT_TO_BLUR_CODE.at(preBlurCnt), false);
            prePerfTimestamp = 0;
            preBlurCnt = 0;
        }
    };

    // delay 100ms
    handler_->PostTask(task, PERF_FOR_BLUR_IF_NEEDED_TASK_NAME, 100);
    int blurCnt = RSPropertyDrawableUtils::GetAndResetBlurCnt();
    // clamp blurCnt to 0~3.
    blurCnt = std::clamp<int>(blurCnt, 0, 3);
    cnt = (blurCnt < preBlurCnt) ? (cnt + 1) : 0;

    // if blurCnt > preBlurCnt, than change perf code;
    // if blurCnt < preBlurCnt 10 times continuously, than change perf code.
    bool cntIsMatch = blurCnt > preBlurCnt || cnt > 10;
    if (cntIsMatch && preBlurCnt != 0) {
        RS_OPTIONAL_TRACE_NAME_FMT("PerfForBlurIfNeeded Perf close, preBlurCnt[%d] blurCnt[%ld]", preBlurCnt, blurCnt);
        PerfRequest(BLUR_CNT_TO_BLUR_CODE.at(preBlurCnt), false);
        preBlurCnt = blurCnt == 0 ? 0 : preBlurCnt;
    }
    if (blurCnt == 0) {
        return;
    }
    if (threadTimestamp - prePerfTimestamp > PERF_PERIOD_BLUR || cntIsMatch) {
        RS_OPTIONAL_TRACE_NAME_FMT("PerfForBlurIfNeeded PerfRequest, preBlurCnt[%d] blurCnt[%ld]", preBlurCnt, blurCnt);
        PerfRequest(BLUR_CNT_TO_BLUR_CODE.at(blurCnt), true);
        prePerfTimestamp = threadTimestamp;
        preBlurCnt = blurCnt;
    }
}

bool RSUniRenderThread::GetClearMemoryFinished() const
{
    std::lock_guard<std::mutex> lock(clearMemoryMutex_);
    return clearMemoryFinished_;
}

bool RSUniRenderThread::GetClearMemDeeply() const
{
    std::lock_guard<std::mutex> lock(clearMemoryMutex_);
    return clearMemDeeply_;
}

void RSUniRenderThread::SetClearMoment(ClearMemoryMoment moment)
{
    clearMoment_ = moment;
}

ClearMemoryMoment RSUniRenderThread::GetClearMoment() const
{
    std::lock_guard<std::mutex> lock(clearMemoryMutex_);
    return clearMoment_;
}

uint32_t RSUniRenderThread::GetRefreshRate() const
{
    auto screenManager = CreateOrGetScreenManager();
    if (!screenManager) {
        RS_LOGE("RSUniRenderThread::GetRefreshRate screenManager is nullptr");
        return 60; // The default refreshrate is 60
    }
    return HgmCore::Instance().GetScreenCurrentRefreshRate(screenManager->GetDefaultScreenId());
}

std::shared_ptr<Drawing::Image> RSUniRenderThread::GetWatermarkImg()
{
    auto& renderThreadParams = GetRSRenderThreadParams();
    return renderThreadParams->GetWatermarkImg();
}

bool RSUniRenderThread::GetWatermarkFlag()
{
    auto& renderThreadParams = GetRSRenderThreadParams();
    return renderThreadParams->GetWatermarkFlag();
}

bool RSUniRenderThread::IsCurtainScreenOn() const
{
    return renderThreadParams_->IsCurtainScreenOn();
}

void RSUniRenderThread::TrimMem(std::string& dumpString, std::string& type)
{
    auto task = [this, &dumpString, &type] {
        auto gpuContext = GetRenderEngine()->GetRenderContext()->GetDrGPUContext();
        if (type.empty()) {
            gpuContext->Flush();
            SkGraphics::PurgeAllCaches();
            gpuContext->FreeGpuResources();
            gpuContext->PurgeUnlockedResources(true);
#ifdef NEW_RENDER_CONTEXT
            MemoryHandler::ClearShader();
#else
            std::shared_ptr<RenderContext> rendercontext = std::make_shared<RenderContext>();
            rendercontext->CleanAllShaderCache();
#endif
            gpuContext->FlushAndSubmit(true);
        } else if (type == "cpu") {
            gpuContext->Flush();
            SkGraphics::PurgeAllCaches();
            gpuContext->FlushAndSubmit(true);
        } else if (type == "gpu") {
            gpuContext->Flush();
            gpuContext->FreeGpuResources();
            gpuContext->FlushAndSubmit(true);
        } else if (type == "uihidden") {
            gpuContext->Flush();
            gpuContext->PurgeUnlockAndSafeCacheGpuResources();
            gpuContext->FlushAndSubmit(true);
        } else if (type == "unlock") {
            gpuContext->Flush();
            gpuContext->PurgeUnlockedResources(false);
            gpuContext->FlushAndSubmit(true);
        } else if (type == "shader") {
#ifdef NEW_RENDER_CONTEXT
            MemoryHandler::ClearShader();
#else
            std::shared_ptr<RenderContext> rendercontext = std::make_shared<RenderContext>();
            rendercontext->CleanAllShaderCache();
#endif
        } else if (type == "flushcache") {
            int ret = mallopt(M_FLUSH_THREAD_CACHE, 0);
            dumpString.append("flushcache " + std::to_string(ret) + "\n");
        } else {
            uint32_t pid = static_cast<uint32_t>(std::stoll(type));
            Drawing::GPUResourceTag tag(pid, 0, 0, 0);
            MemoryManager::ReleaseAllGpuResource(gpuContext, tag);
        }
        dumpString.append("trimMem: " + type + "\n");
    };
    PostSyncTask(task);
}

void RSUniRenderThread::DumpMem(DfxString& log)
{
    std::vector<std::pair<NodeId, std::string>> nodeTags;
    const auto& nodeMap = RSMainThread::Instance()->GetContext().GetNodeMap();
    nodeMap.TraverseSurfaceNodes([&nodeTags](const std::shared_ptr<RSSurfaceRenderNode> node) {
        std::string name = node->GetName() + " " + std::to_string(node->GetId());
        nodeTags.push_back({node->GetId(), name});
    });
    PostSyncTask([&log, &nodeTags, this]() {
        MemoryManager::DumpDrawingGpuMemory(log, GetRenderEngine()->GetRenderContext()->GetDrGPUContext(), nodeTags);
    });
}

void RSUniRenderThread::ClearMemoryCache(ClearMemoryMoment moment, bool deeply, pid_t pid)
{
    if (!RSSystemProperties::GetReleaseResourceEnabled()) {
        return;
    }
    {
        std::lock_guard<std::mutex> lock(clearMemoryMutex_);
        clearMemDeeply_ = clearMemDeeply_ || deeply;
        SetClearMoment(moment);
        clearMemoryFinished_ = false;
        exitedPidSet_.emplace(pid);
    }
    PostClearMemoryTask(moment, deeply, false);
}

void RSUniRenderThread::DefaultClearMemoryCache()
{
    // To clean memory when no render in 5s
    if (!RSSystemProperties::GetReleaseResourceEnabled()) {
        return;
    }
    PostClearMemoryTask(ClearMemoryMoment::DEFAULT_CLEAN, false, true);
}

void RSUniRenderThread::PostClearMemoryTask(ClearMemoryMoment moment, bool deeply, bool isDefaultClean)
{
    auto task = [this, moment, deeply, isDefaultClean]() {
        auto grContext = GetRenderEngine()->GetRenderContext()->GetDrGPUContext();
        if (UNLIKELY(!grContext)) {
            return;
        }
        RS_LOGD("Clear memory cache %{public}d", this->GetClearMoment());
        RS_TRACE_NAME_FMT("Clear memory cache, cause the moment [%d] happen", this->GetClearMoment());
        std::lock_guard<std::mutex> lock(clearMemoryMutex_);
        SKResourceManager::Instance().ReleaseResource();
        grContext->Flush();
        SkGraphics::PurgeAllCaches(); // clear cpu cache
        auto pid = *(this->exitedPidSet_.begin());
        if (this->exitedPidSet_.size() == 1 && pid == -1) { // no exited app, just clear scratch resource
            if (deeply || this->deviceType_ != DeviceType::PHONE) {
                MemoryManager::ReleaseUnlockAndSafeCacheGpuResource(grContext);
            } else {
                MemoryManager::ReleaseUnlockGpuResource(grContext);
            }
        } else {
            MemoryManager::ReleaseUnlockGpuResource(grContext, this->exitedPidSet_);
        }
        auto screenManager_ = CreateOrGetScreenManager();
        screenManager_->ClearFrameBufferIfNeed();
        grContext->FlushAndSubmit(true);
        if (!isDefaultClean) {
            this->clearMemoryFinished_ = true;
        }
        RSUifirstManager::Instance().TryReleaseTextureForIdleThread();
        this->exitedPidSet_.clear();
        this->clearMemDeeply_ = false;
        this->SetClearMoment(ClearMemoryMoment::NO_CLEAR);
    };
    if (!isDefaultClean) {
        PostTask(task, CLEAR_GPU_CACHE,
            (this->deviceType_ == DeviceType::PHONE ? TIME_OF_EIGHT_FRAMES : TIME_OF_THE_FRAMES) / GetRefreshRate());
    } else {
        PostTask(task, DEFAULT_CLEAR_GPU_CACHE, TIME_OF_DEFAULT_CLEAR_GPU_CACHE);
    }
}

void RSUniRenderThread::ResetClearMemoryTask()
{
    if (!GetClearMemoryFinished()) {
        RemoveTask(CLEAR_GPU_CACHE);
        ClearMemoryCache(clearMoment_, clearMemDeeply_);
    }
    RemoveTask(DEFAULT_CLEAR_GPU_CACHE);
    DefaultClearMemoryCache();
}

void RSUniRenderThread::PurgeCacheBetweenFrames()
{
    if (!RSSystemProperties::GetReleaseResourceEnabled()) {
        return;
    }
    RS_TRACE_NAME_FMT("MEM PurgeCacheBetweenFrames add task");
    PostTask(
        [this]() {
            auto grContext = GetRenderEngine()->GetRenderContext()->GetDrGPUContext();
            if (!grContext) {
                return;
            }
            RS_TRACE_NAME_FMT("PurgeCacheBetweenFrames");
            std::set<int> protectedPidSet = { RSMainThread::Instance()->GetDesktopPidForRotationScene() };
            MemoryManager::PurgeCacheBetweenFrames(grContext, true, this->exitedPidSet_, protectedPidSet);
            RemoveTask(PURGE_CACHE_BETWEEN_FRAMES);
        },
        PURGE_CACHE_BETWEEN_FRAMES, 0, AppExecFwk::EventQueue::Priority::LOW);
}

void RSUniRenderThread::PreAllocateTextureBetweenFrames()
{
    if (!RSSystemProperties::IsPhoneType()) {
        return;
    }
    RemoveTask(PRE_ALLOCATE_TEXTURE_BETWEEN_FRAMES);
    PostTask(
        [this]() {
            RS_TRACE_NAME_FMT("PreAllocateTextureBetweenFrames");
            GrDirectContext::preAllocateTextureBetweenFrames();
        },
        PRE_ALLOCATE_TEXTURE_BETWEEN_FRAMES,
        0,
        AppExecFwk::EventQueue::Priority::LOW);
}

void RSUniRenderThread::AsyncFreeVMAMemoryBetweenFrames()
{
    RemoveTask(ASYNC_FREE_VMAMEMORY_BETWEEN_FRAMES);
    PostTask(
        [this]() {
            RS_TRACE_NAME_FMT("AsyncFreeVMAMemoryBetweenFrames");
            GrDirectContext::asyncFreeVMAMemoryBetweenFrames([this]() -> bool {
                return this->handler_->HasPreferEvent(static_cast<int>(AppExecFwk::EventQueue::Priority::HIGH));
            });
        },
        ASYNC_FREE_VMAMEMORY_BETWEEN_FRAMES, 0, AppExecFwk::EventQueue::Priority::LOW);
}

void RSUniRenderThread::MemoryManagementBetweenFrames()
{
    if (RSSystemProperties::GetPreAllocateTextureBetweenFramesEnabled()) {
        PreAllocateTextureBetweenFrames();
    }
    if (RSSystemProperties::GetAsyncFreeVMAMemoryBetweenFramesEnabled()) {
        AsyncFreeVMAMemoryBetweenFrames();
    }
}

void RSUniRenderThread::RenderServiceTreeDump(std::string& dumpString) const
{
    const std::shared_ptr<RSBaseRenderNode> rootNode =
        RSMainThread::Instance()->GetContext().GetGlobalRootRenderNode();
    if (!rootNode) {
        dumpString += "rootNode is nullptr";
        return;
    }
    rootNode->DumpDrawableTree(0, dumpString);
}

void RSUniRenderThread::UpdateDisplayNodeScreenId()
{
    const std::shared_ptr<RSBaseRenderNode> rootNode =
        RSMainThread::Instance()->GetContext().GetGlobalRootRenderNode();
    if (!rootNode) {
        RS_LOGE("RSUniRenderThread::UpdateDisplayNodeScreenId rootNode is nullptr");
        return;
    }
    auto child = rootNode->GetFirstChild();
    if (child != nullptr && child->IsInstanceOf<RSDisplayRenderNode>()) {
        auto displayNode = child->ReinterpretCastTo<RSDisplayRenderNode>();
        if (displayNode) {
            displayNodeScreenId_ = displayNode->GetScreenId();
        }
    }
}

uint32_t RSUniRenderThread::GetDynamicRefreshRate() const
{
    uint32_t refreshRate = OHOS::Rosen::HgmCore::Instance().GetScreenCurrentRefreshRate(displayNodeScreenId_);
    if (refreshRate == 0) {
        RS_LOGE("RSUniRenderThread::GetDynamicRefreshRate refreshRate is invalid");
        return STANDARD_REFRESH_RATE;
    }
    return refreshRate;
}

void RSUniRenderThread::SetAcquireFence(sptr<SyncFence> acquireFence)
{
    acquireFence_ = acquireFence;
}
} // namespace Rosen
} // namespace OHOS
