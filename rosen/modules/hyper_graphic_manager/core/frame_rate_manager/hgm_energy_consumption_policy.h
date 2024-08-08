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

#ifndef HGM_ENERGY_CONSUMPTION_POLICY_H
#define HGM_ENERGY_CONSUMPTION_POLICY_H

#include <mutex>
#include <string>
#include <unordered_map>

#include "animation/rs_frame_rate_range.h"

namespace OHOS::Rosen {
class HgmEnergyConsumptionPolicy {
public:
    static HgmEnergyConsumptionPolicy& Instance();
    void SetEnergyConsumptionConfig(std::unordered_map<std::string, std::string> animationPowerConfig);
    void SetUiEnergyConsumptionConfig(std::unordered_map<std::string, std::string> uiPowerConfig);
    void SetAnimationEnergyConsumptionAssuranceMode(bool isEnergyConsumptionAssuranceMode);
    void SetUiEnergyConsumptionAssuranceMode(bool isEnergyConsumptionAssuranceMode);
    void StatisticAnimationTime(uint64_t timestamp);
    void StartNewAnimation();
    void GetAnimationIdleFps(FrameRateRange& rsRange);
    void GetUiIdleFps(FrameRateRange& rsRange);

private:
    std::recursive_mutex mutex_;
    // <rateType, <isEnable, idleFps>>
    std::unordered_map<int32_t, std::pair<bool, int>> uiEnergyAssuranceMap_;
    bool isAnimationEnergyAssuranceEnable_ = false;
    bool isAnimationEnergyConsumptionAssuranceMode_ = false;
    bool isUiEnergyConsumptionAssuranceMode_ = false;
    uint64_t firstAnimationTimestamp_ = 0;
    uint64_t lastAnimationTimestamp_ = 0;
    // Unit: ms
    int animationIdleDuration_ = 2000;
    int animationIdleFps_ = 60;
    std::unordered_map<int32_t, bool> energyAssuranceState_;

    HgmEnergyConsumptionPolicy();
    ~HgmEnergyConsumptionPolicy() = default;
    HgmEnergyConsumptionPolicy(const HgmEnergyConsumptionPolicy&) = delete;
    HgmEnergyConsumptionPolicy(const HgmEnergyConsumptionPolicy&&) = delete;
    HgmEnergyConsumptionPolicy& operator=(const HgmEnergyConsumptionPolicy&) = delete;
    HgmEnergyConsumptionPolicy& operator=(const HgmEnergyConsumptionPolicy&&) = delete;
    static void ConverStrToInt(int& targetNum, std::string sourceStr, int defaultValue);
    void SetEnergyConsumptionRateRange(FrameRateRange& rsRange, int idleFps);
    void PrintLog(FrameRateRange &rsRange, bool state, int idleFps);
};
} // namespace OHOS::Rosen

#endif