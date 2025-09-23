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
#ifndef ROSEN_RENDER_SERVICE_CLIENT_CORE_UI_EFFECT_BLUR_UI_FILTER_H
#define ROSEN_RENDER_SERVICE_CLIENT_CORE_UI_EFFECT_BLUR_UI_FILTER_H

#include "ui_effect/filter/include/filter_blur_para.h"
#include "ui_effect/property/include/rs_ui_filter_para_base.h"

namespace OHOS {
namespace Rosen {

class RSUIBlurFilterPara : public RSUIFilterParaBase {
public:
    RSUIBlurFilterPara() : RSUIFilterParaBase(RSUIFilterType::BLUR) {}
    ~RSUIBlurFilterPara() override = default;

    bool Equals(const std::shared_ptr<RSUIFilterParaBase>& other) override;

    void SetProperty(const std::shared_ptr<RSUIFilterParaBase>& other) override;

    void SetBlurPara(std::shared_ptr<FilterBlurPara>& blurPara);

    void SetRadiusX(float radiusX);

    void SetRadiusY(float radiusY);

    std::shared_ptr<RSRenderFilterParaBase> CreateRSRenderFilter() override;

    std::vector<std::shared_ptr<RSPropertyBase>> GetLeafProperties() override;
};
} // namespace Rosen
} // namespace OHOS
#endif // ROSEN_RENDER_SERVICE_CLIENT_CORE_UI_EFFECT_BLUR_UI_FILTER_H