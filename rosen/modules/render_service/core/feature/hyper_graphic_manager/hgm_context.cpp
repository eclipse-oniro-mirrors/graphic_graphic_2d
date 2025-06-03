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

#include "common/rs_optional_trace.h"
#include "feature/hyper_graphic_manager/hgm_context.h"
#include "parameters.h"
#include "pipeline/hardware_thread/rs_hardware_thread.h"
#include "pipeline/hardware_thread/rs_realtime_refresh_rate_manager.h"
#include "pipeline/main_thread/rs_main_thread.h"
#include "screen_manager/rs_screen_manager.h"

namespace OHOS {
namespace Rosen {

HgmContext::HgmContext()
{
    rsFrameRateLinker_ = std::make_shared<RSRenderFrameRateLinker>(
        [] (const RSRenderFrameRateLinker& linker) { HgmCore::Instance().SetHgmTaskFlag(true); }
    );
}

void HgmContext::InitHgmTaskHandleThread(
    sptr<VSyncController> rsVSyncController, sptr<VSyncController> appVSyncController,
    sptr<VSyncGenerator> vsyncGenerator, sptr<VSyncDistributor> appVSyncDistributor) const
{
    RS_LOGI("HgmTaskHandleThread init");
    auto mainThread = RSMainThread::Instance();
    if (mainThread == nullptr) {
        return;
    }
    auto forceUpdateTask = [this](bool idleTimerExpired, bool forceUpdate) {
        RSMainThread::Instance()->PostTask([this, idleTimerExpired, forceUpdate]() {
            RS_TRACE_NAME_FMT("HgmContext::TimerExpiredCallback Run idleTimerExpiredFlag: %s forceUpdateFlag: %s",
                idleTimerExpired ? "True" : "False", forceUpdate ? "True" : "False");
            RSMainThread::Instance()->SetForceUpdateUniRenderFlag(forceUpdate);
            RSMainThread::Instance()->RequestNextVSync("ltpoForceUpdate");
        });
    };
    HgmTaskHandleThread::Instance().PostSyncTask([
        forceUpdateTask, rsVSyncController,
        appVSyncController, vsyncGenerator, appVSyncDistributor] () {
            auto frameRateMgr = OHOS::Rosen::HgmCore::Instance().GetFrameRateMgr();
            if (frameRateMgr == nullptr) {
                return;
            }
            frameRateMgr->SetForceUpdateCallback(forceUpdateTask);
            frameRateMgr->Init(rsVSyncController, appVSyncController, vsyncGenerator, appVSyncDistributor);
        }
    );
}

int32_t HgmContext::FrameRateGetFunc(
    const RSPropertyUnit unit, float velocity, int32_t area, int32_t length)
{
    auto frameRateMgr = HgmCore::Instance().GetFrameRateMgr();
    if (frameRateMgr != nullptr) {
        return frameRateMgr->GetExpectedFrameRate(unit, velocity, area, length);
    }
    return 0;
}

void HgmContext::ProcessHgmFrameRate(
    uint64_t timestamp, sptr<VSyncDistributor> rsVSyncDistributor, uint64_t vsyncId)
{
    int changed = 0;
    if (bool enable = RSSystemParameters::GetShowRefreshRateEnabled(&changed); changed != 0) {
        RSRealtimeRefreshRateManager::Instance().SetShowRefreshRateEnabled(enable, 1);
    }
    bool isUiDvsyncOn = rsVSyncDistributor != nullptr ? rsVSyncDistributor->IsUiDvsyncOn() : false;
    auto frameRateMgr = HgmCore::Instance().GetFrameRateMgr();
    if (frameRateMgr == nullptr || rsVSyncDistributor == nullptr) {
        return;
    }

    static std::once_flag initUIFwkTableFlag;
    std::call_once(initUIFwkTableFlag, [this]() {
        if (auto config = HgmCore::Instance().GetPolicyConfigData(); config != nullptr) {
            RSMainThread::Instance()->GetContext().SetUiFrameworkTypeTable(config->appBufferList_);
        }
    });

    // Check and processing refresh rate task.
    frameRateMgr->ProcessPendingRefreshRate(
        timestamp, vsyncId, rsVSyncDistributor->GetRefreshRate(), isUiDvsyncOn);
    if (rsFrameRateLinker_ != nullptr) {
        auto rsCurrRange = rsCurrRange_;
        rsCurrRange.type_ = RS_ANIMATION_FRAME_RATE_TYPE;
        HgmEnergyConsumptionPolicy::Instance().GetAnimationIdleFps(rsCurrRange);
        rsFrameRateLinker_->SetExpectedRange(rsCurrRange);
        RS_TRACE_NAME_FMT("rsCurrRange = (%d, %d, %d)", rsCurrRange.min_, rsCurrRange.max_, rsCurrRange.preferred_);
    }
    rsCurrRange_.IsValid() ? frameRateMgr->GetRsFrameRateTimer().Start() : frameRateMgr->GetRsFrameRateTimer().Stop();
    
    bool needRefresh = frameRateMgr->UpdateUIFrameworkDirtyNodes(
        RSMainThread::Instance()->GetContext().GetUiFrameworkDirtyNodes(), timestamp);
    bool setHgmTaskFlag = HgmCore::Instance().SetHgmTaskFlag(false);
    auto& rsVsyncRateReduceManager = RSMainThread::Instance()->GetRSVsyncRateReduceManager();
    bool vrateStatusChange = rsVsyncRateReduceManager.SetVSyncRatesChangeStatus(false);
    bool isVideoCallVsyncChange = HgmEnergyConsumptionPolicy::Instance().GetVideoCallVsyncChange();
    if (!vrateStatusChange && !setHgmTaskFlag && !needRefresh && !isVideoCallVsyncChange &&
        HgmCore::Instance().GetPendingScreenRefreshRate() == frameRateMgr->GetCurrRefreshRate()) {
        return;
    }
    HgmTaskHandleThread::Instance().PostTask([timestamp, rsFrameRateLinker = rsFrameRateLinker_,
        appFrameRateLinkers = RSMainThread::Instance()->GetContext().GetFrameRateLinkerMap().Get(),
        linkers = rsVsyncRateReduceManager.GetVrateMap() ]() mutable {
            RS_TRACE_NAME("ProcessHgmFrameRate");
            if (auto frameRateMgr = HgmCore::Instance().GetFrameRateMgr(); frameRateMgr != nullptr) {
                frameRateMgr->UniProcessDataForLtpo(timestamp, rsFrameRateLinker, appFrameRateLinkers, linkers);
            }
        }
    );
}

void HgmContext::RegisterChangeDssRefreshRateCb()
{
    auto changeDssRefreshRateCb = [this] (ScreenId screenId, uint32_t refreshRate, bool followPipline) {
        RSHardwareThread::Instance().PostTask([this, screenId, refreshRate, followPipline] () {
            ChangeDssRefreshRate(screenId, refreshRate, followPipline);
        });
    };
    HgmTaskHandleThread::Instance().PostTask([changeDssRefreshRateCb] () {
        if (auto frameRateMgr = HgmCore::Instance().GetFrameRateMgr(); frameRateMgr != nullptr) {
            frameRateMgr->SetChangeDssRefreshRateCb(changeDssRefreshRateCb);
        }
    });
}

void HgmContext::ExecuteSwitchRefreshRate(
    const std::shared_ptr<HdiOutput> output, uint32_t refreshRate)
{
    static bool refreshRateSwitch = system::GetBoolParameter("persist.hgm.refreshrate.enabled", true);
    if (!refreshRateSwitch) {
        RS_LOGD("refreshRateSwitch is off, currRefreshRate is %{public}d", refreshRate);
        return;
    }

    auto& hgmCore = OHOS::Rosen::HgmCore::Instance();
    if (hgmCore.GetFrameRateMgr() == nullptr) {
        RS_LOGD("FrameRateMgr is null");
        return;
    }
    ScreenId id = output->GetScreenId();
    auto& hardwareThread = RSHardwareThread::Instance();
    outputMap_[id] = output;
    auto screen = hgmCore.GetScreen(id);
    if (!screen || !screen->GetSelfOwnedScreenFlag()) {
        return;
    }
    auto screenRefreshRateImme = hgmCore.GetScreenRefreshRateImme();
    if (screenRefreshRateImme > 0) {
        RS_LOGD("ExecuteSwitchRefreshRate:rate change: %{public}u -> %{public}u", refreshRate, screenRefreshRateImme);
        refreshRate = screenRefreshRateImme;
    }
    ScreenId curScreenId = hgmCore.GetFrameRateMgr()->GetCurScreenId();
    ScreenId lastCurScreenId = hgmCore.GetFrameRateMgr()->GetLastCurScreenId();
    hgmCore.SetScreenSwitchDssEnable(id, true);
    if (refreshRate != hgmCore.GetScreenCurrentRefreshRate(id) || lastCurScreenId != curScreenId ||
        needRetrySetRate_) {
        RS_LOGD("CommitAndReleaseLayers screenId %{public}d refreshRate %{public}d \
            needRetrySetRate %{public}d", static_cast<int>(id), refreshRate, needRetrySetRate_);
        int32_t sceneId = (lastCurScreenId != curScreenId || needRetrySetRate_) ? SWITCH_SCREEN_SCENE : 0;
        hgmCore.GetFrameRateMgr()->SetLastCurScreenId(curScreenId);
        int32_t status = hgmCore.SetScreenRefreshRate(id, sceneId, refreshRate);
        needRetrySetRate_ = false;
        if (status < EXEC_SUCCESS) {
            RS_LOGD("HgmContext: failed to set refreshRate %{public}d, screenId %{public}" PRIu64 "",
                refreshRate, id);
        }
    }
}

void HgmContext::PerformSetActiveMode(
    std::shared_ptr<HdiOutput> output, uint64_t timestamp, uint64_t constraintRelativeTime)
{
    auto &hgmCore = OHOS::Rosen::HgmCore::Instance();
    auto screenManager = CreateOrGetScreenManager();
    if (screenManager == nullptr) {
        return;
    }
    vblankIdleCorrector_.ProcessScreenConstraint(timestamp, constraintRelativeTime);
    HgmRefreshRates newRate = RSSystemProperties::GetHgmRefreshRatesEnabled();
    if (hgmRefreshRates_ != newRate) {
        hgmRefreshRates_ = newRate;
        hgmCore.SetScreenRefreshRate(screenManager->GetDefaultScreenId(), 0, static_cast<int32_t>(hgmRefreshRates_));
    }

    std::unique_ptr<std::unordered_map<ScreenId, int32_t>> modeMap(hgmCore.GetModesToApply());
    if (modeMap == nullptr) {
        return;
    }

    RS_TRACE_NAME_FMT("HgmContext::PerformSetActiveMode setting active mode. rate: %d",
        HgmCore::Instance().GetScreenCurrentRefreshRate(HgmCore::Instance().GetActiveScreenId()));
    for (auto mapIter = modeMap->begin(); mapIter != modeMap->end(); ++mapIter) {
        ScreenId id = mapIter->first;
        int32_t modeId = mapIter->second;

        auto supportedModes = screenManager->GetScreenSupportedModes(id);
        for (auto mode : supportedModes) {
            RS_OPTIONAL_TRACE_NAME_FMT(
                "HgmContext check modes w:%" PRId32", h:%" PRId32", rate:%" PRId32", id:%" PRId32"",
                mode.GetScreenWidth(), mode.GetScreenHeight(), mode.GetScreenRefreshRate(), mode.GetScreenModeId());
        }

        uint32_t ret = screenManager->SetScreenActiveMode(id, modeId);
        needRetrySetRate_ = (ret == StatusCode::SET_RATE_ERROR);
        RS_LOGD_IF(needRetrySetRate_, "HgmContext: need retry set modeId %{public}d", modeId);

        auto pendingPeriod = hgmCore.GetIdealPeriod(hgmCore.GetScreenCurrentRefreshRate(id));
        int64_t pendingTimestamp = static_cast<int64_t>(timestamp);
        if (auto hdiBackend = HdiBackend::GetInstance(); hdiBackend != nullptr) {
            hdiBackend->SetPendingMode(output, pendingPeriod, pendingTimestamp);
            hdiBackend->StartSample(output);
        }
    }
}

void HgmContext::InitRefreshRateParam()
{
    // need to sync the hgm data from main thread.
    // Temporary sync the timestamp to fix the duplicate time stamp issue.
    auto& hgmCore = OHOS::Rosen::HgmCore::Instance();
    bool directComposition = hgmCore.GetDirectCompositionFlag();
    RS_LOGI_IF(DEBUG_COMPOSER, "GetRefreshRateData period is %{public}d", directComposition);
    if (directComposition) {
        hgmCore.SetDirectCompositionFlag(false);
    }
    if (directComposition) {
        refreshRateParam_ = {
            .rate = hgmCore.GetPendingScreenRefreshRate(),
            .frameTimestamp = hgmCore.GetCurrentTimestamp(),
            .actualTimestamp = hgmCore.GetActualTimestamp(),
            .vsyncId = hgmCore.GetVsyncId(),
            .constraintRelativeTime = hgmCore.GetPendingConstraintRelativeTime(),
            .isForceRefresh = hgmCore.GetForceRefreshFlag(),
            .fastComposeTimeStampDiff = hgmCore.GetFastComposeTimeStampDiff()
        };
    } else {
        refreshRateParam_ = {
            .rate = RSUniRenderThread::Instance().GetPendingScreenRefreshRate(),
            .frameTimestamp = RSUniRenderThread::Instance().GetCurrentTimestamp(),
            .actualTimestamp = RSUniRenderThread::Instance().GetActualTimestamp(),
            .vsyncId = RSUniRenderThread::Instance().GetVsyncId(),
            .constraintRelativeTime = RSUniRenderThread::Instance().GetPendingConstraintRelativeTime(),
            .isForceRefresh = RSUniRenderThread::Instance().GetForceRefreshFlag(),
            .fastComposeTimeStampDiff = RSUniRenderThread::Instance().GetFastComposeTimeStampDiff()
        };
    }
}

void HgmContext::ChangeDssRefreshRate(ScreenId screenId, uint32_t refreshRate, bool followPipline)
{
    if (followPipline) {
        auto& hgmCore = OHOS::Rosen::HgmCore::Instance();
        auto task = [this, screenId, refreshRate, vsyncId = refreshRateParam_.vsyncId] () {
            if (vsyncId != refreshRateParam_.vsyncId || !HgmCore::Instance().IsSwitchDssEnable(screenId)) {
                return;
            }
            // switch hardware vsync
            ChangeDssRefreshRate(screenId, refreshRate, false);
        };
        int64_t period = hgmCore.GetIdealPeriod(hgmCore.GetScreenCurrentRefreshRate(screenId));
        auto& hardwareThread = RSHardwareThread::Instance();
        hardwareThread.PostDelayTask(
            task, period / NS_MS_UNIT_CONVERSION + hardwareThread.GetDelayTime() + DELAY_TIME_OFFSET);
    } else {
        auto outputIter = outputMap_.find(screenId);
        if (outputIter == outputMap_.end()) {
            return;
        }
        auto output = outputIter->second.lock();
        if (output == nullptr) {
            outputMap_.erase(screenId);
            return;
        }
        if (HgmCore::Instance().GetActiveScreenId() != screenId) {
            return;
        }
        ExecuteSwitchRefreshRate(output, refreshRate);
        PerformSetActiveMode(
            output, refreshRateParam_.frameTimestamp, refreshRateParam_.constraintRelativeTime);
        auto hdiBackend = HdiBackend::GetInstance();
        if (hdiBackend != nullptr && output->IsDeviceValid()) {
            hdiBackend->Repaint(output);
        }
    }
}
} // namespace Rosen
} // namespace OHOS