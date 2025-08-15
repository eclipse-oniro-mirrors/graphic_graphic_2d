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
#ifndef UIEFFECT_FILTER_HDR_BRIGHTNESS_RATIO_PARA_H
#define UIEFFECT_FILTER_HDR_BRIGHTNESS_RATIO_PARA_H

#include "filter_para.h"


namespace OHOS {
namespace Rosen {
class HDRBrightnessRatioPara : public FilterPara {
public:
    HDRBrightnessRatioPara()
    {
        this->type_ = FilterPara::ParaType::HDR_BRIGHTNESS_RATIO;
    }
    ~HDRBrightnessRatioPara() override = default;

    void SetBrightnessRatio(const float& ratio)
    {
        brightnessRatio_ = ratio;
    }

    float GetBrightnessRatio() const
    {
        return brightnessRatio_;
    }

private:
    float brightnessRatio_ = 1.0f;
};
} // namespace Rosen
} // namespace OHOS
#endif // UIEFFECT_FILTER_HDR_BRIGHTNESS_RATIO_PARA_H
