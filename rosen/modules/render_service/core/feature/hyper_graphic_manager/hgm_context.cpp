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

#include "feature/hyper_graphic_manager/hgm_context.h"

#include "common/rs_optional_trace.h"
#include "rp_hgm_xml_parser.h"
#include "parameters.h"
#include "pipeline/hardware_thread/rs_realtime_refresh_rate_manager.h"
#include "pipeline/main_thread/rs_main_thread.h"

namespace OHOS {
namespace Rosen {
namespace {
constexpr const char* HGM_CONFIG_PATH = "/sys_prod/etc/graphic/hgm_policy_config.xml";
}

HgmContext::HgmContext()
{
    rsFrameRateLinker_ = std::make_shared<RSRenderFrameRateLinker>(
        [](const RSRenderFrameRateLinker& linker) { HgmCore::Instance().SetHgmTaskFlag(true); });
    convertFrameRateFunc_ = [this](const RSPropertyUnit unit, float velocity, int32_t area, int32_t length) -> int32_t {
        return rpFrameRatePolicy_.GetExpectedFrameRate(unit, velocity, area, length);
    };
}

int32_t HgmContext::InitHgmConfig(std::unordered_map<std::string, std::string>& sourceTuningConfig,
    std::unordered_map<std::string, std::string>& solidLayerConfig, std::vector<std::string>& appBufferList)
{
    auto parser = std::make_unique<RPHgmXMLParser>();
    if (parser->LoadConfiguration(HGM_CONFIG_PATH) != EXEC_SUCCESS) {
        HGM_LOGW("HgmRPContext failed to load hgm xml configuration file");
        return XML_FILE_LOAD_FAIL;
    }
    sourceTuningConfig = parser->GetSourceTuningConfig();
    solidLayerConfig = parser->GetSolidLayerConfig();
    appBufferList = parser->GetAppBufferList();

    return EXEC_SUCCESS;
}

void HgmContext::InitHgmTaskHandleThread(
    sptr<VSyncController> rsVSyncController, sptr<VSyncController> appVSyncController,
    sptr<VSyncGenerator> vsyncGenerator, sptr<VSyncDistributor> appVSyncDistributor)
{
    RS_LOGI("HgmTaskHandleThread init");
    auto forceUpdateTask = [this](bool idleTimerExpired, bool forceUpdate) {
        RSMainThread::Instance()->PostTask([this, idleTimerExpired, forceUpdate]() {
            RS_TRACE_NAME_FMT("HgmContext::TimerExpiredCallback Run idleTimerExpiredFlag: %s forceUpdateFlag: %s",
                idleTimerExpired ? "True" : "False", forceUpdate ? "True" : "False");
            if (lastForceUpdateVsyncId_ != currVsyncId_) {
                lastForceUpdateVsyncId_ = currVsyncId_;
                RSMainThread::Instance()->SetForceUpdateUniRenderFlag(forceUpdate);
                RSMainThread::Instance()->RequestNextVSync("ltpoForceUpdate");
            }
        });
    };
    HgmTaskHandleThread::Instance().PostSyncTask([
        forceUpdateTask, rsVSyncController,
        appVSyncController, vsyncGenerator, appVSyncDistributor]() {
            auto frameRateMgr = OHOS::Rosen::HgmCore::Instance().GetFrameRateMgr();
            if (frameRateMgr == nullptr) {
                return;
            }
            frameRateMgr->SetForceUpdateCallback(forceUpdateTask);
            frameRateMgr->Init(rsVSyncController, appVSyncController, vsyncGenerator, appVSyncDistributor);
        });

    InitHgmUpdateCallback();
}

void HgmContext::InitHgmUpdateCallback()
{
    auto hgmConfigUpdateCallbackTask = [this](std::shared_ptr<RPHgmConfigData> configData,
        bool ltpoEnabled, bool isDelayMode, int32_t pipelineOffsetPulseNum) {
        RSMainThread::Instance()->PostTask([this, configData, ltpoEnabled, isDelayMode, pipelineOffsetPulseNum]() {
            rpHgmConfigDataChange_ = true;
            rpHgmConfigData_ = std::move(configData);
            ltpoEnabled_ = ltpoEnabled;
            isDelayMode_ = isDelayMode;
            pipelineOffsetPulseNum_ = pipelineOffsetPulseNum;
        });
    };

    HgmTaskHandleThread::Instance().PostTask([
        hgmConfigUpdateCallbackTask]() {
        auto frameRateMgr = HgmCore::Instance().GetFrameRateMgr();
        if (frameRateMgr == nullptr) {
            return;
        }
        frameRateMgr->SetHgmConfigUpdateCallback(hgmConfigUpdateCallbackTask);
    });
}

void HgmContext::ProcessHgmFrameRate(
    uint64_t timestamp, sptr<VSyncDistributor> rsVSyncDistributor, uint64_t vsyncId)
{
    currVsyncId_ = vsyncId;
    int changed = 0;
    if (bool enable = RSSystemParameters::GetShowRefreshRateEnabled(&changed); changed != 0) {
        RSRealtimeRefreshRateManager::Instance().SetShowRefreshRateEnabled(enable, 1);
    }

    if (rpHgmConfigDataChange_) {
        rpHgmConfigDataChange_ = false;
        rpFrameRatePolicy_.HgmConfigUpdateCallback(rpHgmConfigData_);
    }

    bool isUiDvsyncOn = rsVSyncDistributor != nullptr ? rsVSyncDistributor->IsUiDvsyncOn() : false;
    auto frameRateMgr = HgmCore::Instance().GetFrameRateMgr();
    if (frameRateMgr == nullptr || rsVSyncDistributor == nullptr) {
        return;
    }

    if (frameRateMgr->AdaptiveStatus() == SupportASStatus::SUPPORT_AS) {
        frameRateMgr->HandleGameNode(RSMainThread::Instance()->GetContext().GetNodeMap());
    }

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
        linkers = rsVsyncRateReduceManager.GetVrateMap()]() mutable {
            RS_TRACE_NAME("ProcessHgmFrameRate");
            if (auto frameRateMgr = HgmCore::Instance().GetFrameRateMgr(); frameRateMgr != nullptr) {
                frameRateMgr->UniProcessDataForLtpo(timestamp, rsFrameRateLinker, appFrameRateLinkers, linkers);
            }
        });
}
} // namespace Rosen
} // namespace OHOS