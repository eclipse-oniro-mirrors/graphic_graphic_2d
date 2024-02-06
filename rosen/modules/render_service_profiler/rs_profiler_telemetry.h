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

#ifndef RS_PROFILER_TELEMETRY_H
#define RS_PROFILER_TELEMETRY_H

#include <string>

namespace OHOS::Rosen {

struct GPUInfo {
    float frequency_ = 0.0F;
    float load_ = 0.0F;
};

struct CPUInfo {
    static constexpr uint32_t MAX_CORE_COUNT = 16U;

    float coreFrequency_[MAX_CORE_COUNT] = {};
    float coreLoad_[MAX_CORE_COUNT] = {};
    uint32_t cores_ = 0U;
    float temperature_ = 0.0F;
    float current_ = 0.0F;
    float voltage_ = 0.0F;
    uint64_t ramTotal_ = 0U;
    uint64_t ramFree_ = 0U;
};

struct DeviceInfo {
    CPUInfo cpu_;
    GPUInfo gpu_;
};

class Telemetry final {
public:
    static const DeviceInfo& GetDeviceInfo();
    static std::string GetDeviceInfoString();
};

} // namespace OHOS::Rosen

#endif // RS_PROFILER_TELEMETRY_H