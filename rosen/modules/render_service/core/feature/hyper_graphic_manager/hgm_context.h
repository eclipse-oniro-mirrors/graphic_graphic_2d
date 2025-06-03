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
#ifndef HGM_CONTEXT_H
#define HGM_CONTEXT_H

#include "feature/hyper_graphic_manager/rs_vblank_idle_corrector.h"
#include "hdi_backend.h"
#include "hgm_frame_rate_manager.h"
#include "vsync_distributor.h"

namespace OHOS {
namespace Rosen {

struct RefreshRateParam {
    uint32_t rate = 0;
    uint64_t frameTimestamp = 0;
    int64_t actualTimestamp = 0;
    uint64_t vsyncId = 0;
    uint64_t constraintRelativeTime = 0;
    bool isForceRefresh = false;
    uint64_t fastComposeTimeStampDiff = 0;
};

class HgmContext {
public:
    HgmContext();
    ~HgmContext() noexcept = default;

    // called by RSMainThread start
    void InitHgmTaskHandleThread(
        sptr<VSyncController> rsVSyncController, sptr<VSyncController> appVSyncController,
        sptr<VSyncGenerator> vsyncGenerator, sptr<VSyncDistributor> appVSyncDistributor) const;
    static int32_t FrameRateGetFunc(const RSPropertyUnit unit, float velocity, int32_t area, int32_t length);
    void ProcessHgmFrameRate(uint64_t timestamp, sptr<VSyncDistributor> rsVSyncDistributor, uint64_t vsyncId);
    FrameRateRange& GetRSCurrRangeRef()
    {
        return rsCurrRange_;
    }

    std::shared_ptr<RSRenderFrameRateLinker> GetRSFrameRateLinker() const
    {
        return rsFrameRateLinker_;
    }
    // called by RSMainThread end

    // called by RSHardwareThread start
    void RegisterChangeDssRefreshRateCb();
    void ExecuteSwitchRefreshRate(const std::shared_ptr<HdiOutput> output, uint32_t refreshRate);
    void PerformSetActiveMode(std::shared_ptr<HdiOutput> output, uint64_t timestamp, uint64_t constraintRelativeTime);
    void ChangeDssRefreshRate(ScreenId screenId, uint32_t refreshRate, bool followPipline);
    void InitRefreshRateParam();
    void SetScreenVBlankIdle(ScreenId screenId)
    {
        vblankIdleCorrector_.SetScreenVBlankIdle(screenId);
    }

    RefreshRateParam GetRefreshRateParam() const
    {
        return refreshRateParam_;
    }
    // called by RSHardwareThread end
private:
    FrameRateRange rsCurrRange_;
    std::shared_ptr<RSRenderFrameRateLinker> rsFrameRateLinker_ = nullptr;
    bool needRetrySetRate_ = false;
    HgmRefreshRates hgmRefreshRates_ = HgmRefreshRates::SET_RATE_NULL;
    RefreshRateParam refreshRateParam_;
    std::unordered_map<ScreenId, std::weak_ptr<HdiOutput>> outputMap_;
    RSVBlankIdleCorrector vblankIdleCorrector_;
};
} // namespace OHOS
} // namespace Rosen
#endif // HGM_CONTEXT_H