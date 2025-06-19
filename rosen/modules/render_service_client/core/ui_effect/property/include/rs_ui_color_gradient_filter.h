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

#ifndef ROSEN_RENDER_SERVICE_CLIENT_CORE_UI_EFFECT_COLOR_GRADIENT_FILTER_H
#define ROSEN_RENDER_SERVICE_CLIENT_CORE_UI_EFFECT_COLOR_GRADIENT_FILTER_H

#include <memory>
#include <vector>

#include "ui_effect/filter/include/filter_color_gradient_para.h"
#include "ui_effect/property/include/rs_ui_filter_base.h"
#include "ui_effect/property/include/rs_ui_filter_para_base.h"
#include "ui_effect/property/include/rs_ui_mask_para.h"

#include "modifier/rs_property.h"

namespace OHOS {
namespace Rosen {

class RSB_EXPORT RSNGColorGradientFilter : public RSNGFilterTemplate<RSUIFilterType::COLOR_GRADIENT> {
public:
    RSNGColorGradientFilter() = default;
    ~RSNGColorGradientFilter() = default;
    using Base = RSNGFilterTemplate<RSUIFilterType::COLOR_GRADIENT>;

    std::shared_ptr<RSNGRenderFilterBase> GetRenderEffect() override;

    bool SetValue(const std::shared_ptr<RSNGFilterBase>& other, std::shared_ptr<RSNode> node) override;

    void Attach(const std::shared_ptr<RSNode>& node) override;

    void Detach() override;

private:
    bool SetColors(std::vector<ColorGradientColorTag> colors);
    bool SetPositions(std::vector<ColorGradientPositionTag> positions);
    bool SetStrengths(std::vector<ColorGradientStrengthTag> strengths);

    std::vector<ColorGradientColorTag> colors_;
    std::vector<ColorGradientPositionTag> positions_;
    std::vector<ColorGradientStrengthTag> strengths_;
};

class RSUIColorGradientFilterPara : public RSUIFilterParaBase {
public:
    RSUIColorGradientFilterPara() : RSUIFilterParaBase(RSUIFilterType::COLOR_GRADIENT) {}
    virtual ~RSUIColorGradientFilterPara() = default;

    bool Equals(const std::shared_ptr<RSUIFilterParaBase>& other) override;

    void Dump(std::string& out) const override;

    virtual void SetProperty(const std::shared_ptr<RSUIFilterParaBase>& other) override;

    void SetColorGradient(const std::shared_ptr<ColorGradientPara>& colorGradientPara);

    void SetColors(std::vector<float> colors);
    void SetPositions(std::vector<float> positions);
    void SetStrengths(std::vector<float> strengths);
    void SetMask(std::shared_ptr<RSUIMaskPara> mask);

    virtual std::shared_ptr<RSRenderFilterParaBase> CreateRSRenderFilter() override;

    virtual std::vector<std::shared_ptr<RSPropertyBase>> GetLeafProperties() override;

private:
    static std::shared_ptr<RSUIMaskPara> CreateMask(RSUIFilterType type);
};

} // namespace Rosen
} // namespace OHOS

#endif // ROSEN_RENDER_SERVICE_CLIENT_CORE_UI_EFFECT_COLOR_GRADIENT_FILTER_H