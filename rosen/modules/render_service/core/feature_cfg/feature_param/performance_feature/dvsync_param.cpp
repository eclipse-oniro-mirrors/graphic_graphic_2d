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

#include "dvsync_param.h"

namespace OHOS::Rosen {

bool DVSyncParam::IsDVSyncEnable() const
{
    return isRsDVSyncEnabled_;
}
bool DVSyncParam::IsUiDVSyncEnable() const
{
    return isUiDVSyncEnabled_;
}

bool DVSyncParam::IsNativeDVSyncEnable() const
{
    return isNativeDVSyncEnabled_;
}

bool DVSyncParam::IsAdaptiveDVSyncEnable() const
{
    return isAdaptiveDVSyncEnabled_;
}

uint32_t DVSyncParam::GetRsBufferCount() const
{
    return rsBufferCount_;
}

uint32_t DVSyncParam::GetUiBufferCount() const
{
    return uiBufferCount_;
}

uint32_t DVSyncParam::GetNativeBufferCount() const
{
    return nativeBufferCount_;
}

uint32_t DVSyncParam::GetWebBufferCount() const
{
    return webBufferCount_;
}

std::unordered_map<std::string, std::string> DVSyncParam::GetAdaptiveConfig() const
{
    return adaptiveConfig_;
}

void DVSyncParam::SetDVSyncEnable(bool isEnable)
{
    isRsDVSyncEnabled_ = isEnable;
}

void DVSyncParam::SetUiDVSyncEnable(bool isEnable)
{
    isUiDVSyncEnabled_ = isEnable;
}

void DVSyncParam::SetNativeDVSyncEnable(bool isEnable)
{
    isNativeDVSyncEnabled_ = isEnable;
}

void DVSyncParam::SetAdaptiveDVSyncEnable(bool isEnable)
{
    isAdaptiveDVSyncEnabled_ = isEnable;
}

void DVSyncParam::SetRsBufferCount(int32_t cnt)
{
    rsBufferCount_ = static_cast<uint32_t>(cnt);
}

void DVSyncParam::SetUiBufferCount(int32_t cnt)
{
    uiBufferCount_ = static_cast<uint32_t>(cnt);
}

void DVSyncParam::SetNativeBufferCount(int32_t cnt)
{
    nativeBufferCount_ = static_cast<uint32_t>(cnt);
}

void DVSyncParam::SetWebBufferCount(int32_t cnt)
{
    webBufferCount_ = static_cast<uint32_t>(cnt);
}

void DVSyncParam::SetAdaptiveConfig(const std::string &name, const std::string &val)
{
    adaptiveConfig_[name] = val;
}
} // namespace OHOS::Rosen