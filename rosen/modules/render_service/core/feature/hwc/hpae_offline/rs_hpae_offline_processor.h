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

#ifndef RS_CORE_PIPELINE_HPAE_OFFLINE_PROCESSOR_H
#define RS_CORE_PIPELINE_HPAE_OFFLINE_PROCESSOR_H
#include "feature/hwc/hpae_offline/rs_hpae_offline_layer.h"
#include "feature/hwc/hpae_offline/rs_hpae_offline_thread_manager.h"
#include "feature/hwc/hpae_offline/rs_hpae_offline_process_syncer.h"
#include "feature/hwc/hpae_offline/rs_hpae_offline_result.h"
#include "feature/hwc/rs_uni_hwc_prevalidate_common.h"

#include <cstdint>
#include <atomic>
#include <buffer_handle.h>

namespace OHOS {
namespace Rosen {
struct OfflineProcessInputInfo {
    uint64_t id;
    BufferHandle* srcHandle = nullptr;
    BufferHandle* dstHandle = nullptr;
    RequestRect srcRect;
    RequestRect dstRect;
    uint32_t transform = 0;
    int32_t acquireFence = 0;
    bool timeout = false;
};

struct OfflineBufferConfig {
    int32_t width = 0;
    int32_t height = 0;
    int32_t strideAlignment = 0;
    int32_t format = 0;
    uint64_t usage = 0;
    int32_t timeout = 0;
    int32_t colorGamut = 0;
    int32_t transform = 0;
};

struct OfflineProcessOutputInfo {
    OfflineBufferConfig bufferConfig;
    RequestRect outRect;
};

using ProcessOfflineFunc = int32_t (*)(const OfflineProcessInputInfo &);
using GetOfflineConfigFunc = int32_t (*)(OfflineProcessOutputInfo &);
using InitOfflineResourceFunc = int32_t (*)();
using DeInitOfflineResourceFunc = void (*)();

class RSHpaeOfflineProcessor : public std::enable_shared_from_this<RSHpaeOfflineProcessor> {
public:
    static RSHpaeOfflineProcessor& GetOfflineProcessor();
    ~RSHpaeOfflineProcessor();

    bool PostProcessOfflineTask(std::shared_ptr<DrawableV2::RSSurfaceRenderNodeDrawable>& surfaceDrawable,
        uint64_t taskId);
    bool PostProcessOfflineTask(std::shared_ptr<RSSurfaceRenderNode>& node, uint64_t taskId);
    bool IsRSHpaeOfflineProcessorReady();
    void CheckAndPostClearOfflineResourceTask();
    bool WaitForProcessOfflineResult(uint64_t taskId, std::chrono::milliseconds timeout,
        ProcessOfflineResult& processOfflineResult);

private:
    RSHpaeOfflineProcessor();
    RSHpaeOfflineProcessor(const RSHpaeOfflineProcessor&) = delete;
    RSHpaeOfflineProcessor(const RSHpaeOfflineProcessor&&) = delete;
    RSHpaeOfflineProcessor& operator=(const RSHpaeOfflineProcessor&) = delete;
    RSHpaeOfflineProcessor& operator=(const RSHpaeOfflineProcessor&&) = delete;
    void CloseOfflineHandle(const std::string& errSymbol, const char* errNo);
    bool LoadPreProcessHandle();
    bool InitForOfflineProcess();
    void CheckAndPostPreAllocBuffersTask();
    bool GetOfflineProcessInput(RSSurfaceRenderParams& params, OfflineProcessInputInfo& inputInfo,
        sptr<SurfaceBuffer>& dstSurfaceBuffer, int32_t& releaseFence);
    void FlushAndReleaseOfflineLayer(sptr<SurfaceBuffer>& dstSurfaceBuffer);
    void OfflineTaskFunc(RSRenderParams* paramsPtr, std::shared_ptr<ProcessOfflineFuture>& futurePtr);
    bool DoProcessOffline(RSSurfaceRenderParams& params, ProcessOfflineResult& processOfflineResult);
    void CheckAndHandleTimeoutEvent(std::shared_ptr<ProcessOfflineFuture>& futurePtr);

    // so handler
    bool loadSuccess_ = false;
    void* preProcessHandle_ = nullptr;
    ProcessOfflineFunc preProcessFunc_ = nullptr;
    GetOfflineConfigFunc getConfigFunc_ = nullptr;
    InitOfflineResourceFunc initOfflineFunc_ = nullptr;
    DeInitOfflineResourceFunc deInitOfflineFunc_ = nullptr;
    RSHpaeOfflineProcessSyncer offlineResultSync_;
    RSHpaeOfflineThreadManager offlineThreadManager_;

    // surface
    RSHpaeOfflineLayer offlineLayer_{"DeviceOfflineLayer", INVALID_NODEID};
    BufferFlushConfig flushConfig_{
        .damage = {.x = 0, .y = 0, .w = 0, .h = 0},
        .timestamp = 0,
        .desiredPresentTimestamp = 0,
    };
    std::atomic<bool> preAllocBufferSucc_ = false;
    // offline config
    std::mutex offlineConfigMutex_;
    BufferRequestConfig layerConfig_{
        .width = 0,
        .height = 0,
        .strideAlignment = 0,
        .format = 0,
        .usage = 0,
        .timeout = 0,
    };
    RequestRect offlineRect_;
    // status
    std::atomic<size_t> invalidFrames_ = 0;
    std::atomic<bool> isBusy_ = false;
    std::atomic<bool> timeout_ = false;
};
} // Rosen
} // OHOS
#endif // RS_CORE_PIPELINE_HPAE_OFFLINE_PROCESSOR_H