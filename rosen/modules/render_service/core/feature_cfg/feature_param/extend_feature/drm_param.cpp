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

#include "drm_param.h"

namespace OHOS::Rosen {

bool DRMParam::IsDrmEnable()
{
    return isDrmEnable_;
}

void DRMParam::SetDrmEnable(bool isEnable)
{
    isDrmEnable_ = isEnable;
}

bool DRMParam::IsDrmMarkAllParentBlurEnable()
{
    return isDrmMarkAllParentBlurEnable_;
}

void DRMParam::SetDrmMarkAllParentBlurEnable(bool isEnable)
{
    isDrmMarkAllParentBlurEnable_ = isEnable;
}

void DRMParam::AddWhiteList(const std::string& name)
{
    whiteMarkBlurList_.push_back(name);
}

void DRMParam::AddBlackList(const std::string& name)
{
    blackMarkBlurList_.push_back(name);
}

const std::vector<std::string>& DRMParam::GetWhiteList()
{
    return whiteMarkBlurList_;
}

const std::vector<std::string>& DRMParam::GetBlackList()
{
    return blackMarkBlurList_;
}
} // namespace OHOS::Rosen