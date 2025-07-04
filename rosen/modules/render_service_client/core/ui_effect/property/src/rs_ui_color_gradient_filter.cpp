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

#include "ui_effect/property/include/rs_ui_color_gradient_filter.h"

#include "platform/common/rs_log.h"
#include "render/rs_render_color_gradient_filter.h"
#include "ui_effect/property/include/rs_ui_radial_gradient_mask.h"
#include "ui_effect/property/include/rs_ui_ripple_mask.h"

namespace OHOS {
namespace Rosen {

#undef LOG_TAG
#define LOG_TAG "RSNGColorGradientFilter"

namespace {
    constexpr uint32_t COLOR_PROPS_NUM = 4;
}

std::shared_ptr<RSNGRenderFilterBase> RSNGColorGradientFilter::GetRenderEffect()
{
    return nullptr;
}

bool RSNGColorGradientFilter::SetValue(
    const std::shared_ptr<RSNGFilterBase>& other, RSNode& node, const std::weak_ptr<ModifierNG::RSModifier>& modifier)
{
    if (other == nullptr || GetType() != other->GetType()) {
        return false;
    }

    auto otherDown = std::static_pointer_cast<RSNGColorGradientFilter>(other);
    bool updateFlag = SetColors(otherDown->colors_) &&
        SetPositions(otherDown->positions_) &&
        SetStrengths(otherDown->strengths_);
    if (!updateFlag) {
        return false;
    }

    return Base::SetValue(other, node, modifier);
}

void RSNGColorGradientFilter::Attach(RSNode& node, const std::weak_ptr<ModifierNG::RSModifier>& modifier)
{
    std::for_each(colors_.begin(), colors_.end(), [&node, &modifier](const auto& propTag) {
        (RSNGEffectUtils::Attach(propTag.value_, node, modifier));
    });
    std::for_each(positions_.begin(), positions_.end(), [&node, &modifier](const auto& propTag) {
        (RSNGEffectUtils::Attach(propTag.value_, node, modifier));
    });
    std::for_each(strengths_.begin(), strengths_.end(), [&node, &modifier](const auto& propTag) {
        (RSNGEffectUtils::Attach(propTag.value_, node, modifier));
    });
    Base::Attach(node, modifier);
}

void RSNGColorGradientFilter::Detach()
{
    std::for_each(colors_.begin(), colors_.end(), [](const auto& propTag) {
        (RSNGEffectUtils::Detach(propTag.value_));
    });
    std::for_each(positions_.begin(), positions_.end(), [](const auto& propTag) {
        (RSNGEffectUtils::Detach(propTag.value_));
    });
    std::for_each(strengths_.begin(), strengths_.end(), [](const auto& propTag) {
        (RSNGEffectUtils::Detach(propTag.value_));
    });
    Base::Detach();
}

bool RSNGColorGradientFilter::SetColors(std::vector<ColorGradientColorTag> colors)
{
    size_t colorSize = colors.size();
    if (colorSize != colors_.size()) {
        return false;
    }

    for (size_t index = 0; index < colorSize; ++index) {
        colors_[index].value_->Set(colors[index].value_->Get());
    }
    return true;
}

bool RSNGColorGradientFilter::SetPositions(std::vector<ColorGradientPositionTag> positions)
{
    size_t positionSize = positions.size();
    if (positionSize != positions_.size()) {
        return false;
    }

    for (size_t index = 0; index < positionSize; ++index) {
        positions_[index].value_->Set(positions[index].value_->Get());
    }
    return true;
}

bool RSNGColorGradientFilter::SetStrengths(std::vector<ColorGradientStrengthTag> strengths)
{
    size_t strengthSize = strengths.size();
    if (strengthSize != strengths_.size()) {
        return false;
    }

    for (size_t index = 0; index < strengthSize; ++index) {
        strengths_[index].value_->Set(strengths[index].value_->Get());
    }
    return true;
}

bool RSUIColorGradientFilterPara::Equals(const std::shared_ptr<RSUIFilterParaBase>& other)
{
    if (other == nullptr || other->GetType() != RSUIFilterType::COLOR_GRADIENT) {
        ROSEN_LOGW("RSUIColorGradientFilterPara::Equals type NG %{public}d!",
            other == nullptr ? -1 : static_cast<int>(other->GetType()));
        return false;
    }

    if (other->GetMaskType() != maskType_) {
        return false;
    }

    auto mask = other->GetRSProperty(maskType_);
    auto oldMask = GetRSProperty(maskType_);
    if ((oldMask == nullptr) != (mask == nullptr)) {
        return false;
    }

    auto colorGradientProperty = std::static_pointer_cast<RSUIColorGradientFilterPara>(other);
    if (colorGradientProperty == nullptr) { return false; }
    auto strengths = colorGradientProperty->GetRSProperty(RSUIFilterType::COLOR_GRADIENT_STRENGTH);
    if (strengths == nullptr) { return false; }
    auto strengthProperty = std::static_pointer_cast<RSAnimatableProperty<std::vector<float>>>(strengths);
    if (strengthProperty == nullptr) { return false; }

    auto oldStrengthsProperty = std::static_pointer_cast<RSAnimatableProperty<std::vector<float>>>(
        GetRSProperty(RSUIFilterType::COLOR_GRADIENT_STRENGTH));
    if (oldStrengthsProperty == nullptr) { return false; }
    if (strengthProperty->Get().size() != oldStrengthsProperty->Get().size()) {
        return false;
    }

    return true;
}

void RSUIColorGradientFilterPara::Dump(std::string& out) const
{
    out += "RSUIColorGradientFilterPara: [";
    char buffer[UINT8_MAX] = { 0 };
    auto iter = properties_.find(RSUIFilterType::COLOR_GRADIENT_STRENGTH);
    if (iter != properties_.end()) {
        auto strength = std::static_pointer_cast<RSProperty<std::vector<float>>>(iter->second);
        if (strength) {
            sprintf_s(buffer, UINT8_MAX, "[strength: %f]", strength->Get()[0]);
            out.append(buffer);
        } else {
            out += "nullptr";
        }
    }
}

void RSUIColorGradientFilterPara::SetProperty(const std::shared_ptr<RSUIFilterParaBase>& other)
{
    if (other == nullptr || other->GetType() != RSUIFilterType::COLOR_GRADIENT) {
        ROSEN_LOGW("RSUIColorGradientFilterPara::SetProperty type NG %{public}d!",
            other == nullptr ? -1 : static_cast<int>(other->GetType()));
        return;
    }

    auto colorGradientProperty = std::static_pointer_cast<RSUIColorGradientFilterPara>(other);
    if (colorGradientProperty == nullptr) {
        ROSEN_LOGW("RSUIColorGradientFilterPara::SetProperty colorGradientProperty NG!");
        return;
    }

    auto colors = colorGradientProperty->GetRSProperty(RSUIFilterType::COLOR_GRADIENT_COLOR);
    auto positions = colorGradientProperty->GetRSProperty(RSUIFilterType::COLOR_GRADIENT_POSITION);
    auto strengths = colorGradientProperty->GetRSProperty(RSUIFilterType::COLOR_GRADIENT_STRENGTH);
    if (colors == nullptr || positions == nullptr || strengths == nullptr) {
        ROSEN_LOGW("RSUIColorGradientFilterPara::SetProperty colors or positions, strengths null NG!");
        return;
    }
    auto colorProperty = std::static_pointer_cast<RSAnimatableProperty<std::vector<float>>>(colors);
    auto positionProperty = std::static_pointer_cast<RSAnimatableProperty<std::vector<float>>>(positions);
    auto strengthProperty = std::static_pointer_cast<RSAnimatableProperty<std::vector<float>>>(strengths);
    if (colorProperty == nullptr || positionProperty == nullptr || strengthProperty == nullptr) {
        ROSEN_LOGW("RSUIColorGradientFilterPara::SetProperty property null NG!");
        return;
    }
    SetColors(colorProperty->Get());
    SetPositions(positionProperty->Get());
    SetStrengths(strengthProperty->Get());

    if (maskType_ != RSUIFilterType::NONE) {
        auto mask = colorGradientProperty->GetRSProperty(maskType_);
        auto oldMask = GetRSProperty(maskType_);
        if (mask == nullptr || oldMask == nullptr) {
            ROSEN_LOGW("RSUIColorGradientFilterPara::SetProperty mask or oldMask null NG!");
            return;
        }

        auto m = std::static_pointer_cast<RSUIMaskPara>(mask);
        auto oldM = std::static_pointer_cast<RSUIMaskPara>(oldMask);
        if (m == nullptr || oldM == nullptr) {
            ROSEN_LOGW("RSUIColorGradientFilterPara::SetProperty mask null NG!");
            return;
        }
        oldM->SetProperty(m);
    }
}

void RSUIColorGradientFilterPara::SetColorGradient(
    const std::shared_ptr<ColorGradientPara>& colorGradientPara)
{
    if (colorGradientPara == nullptr) {
        return;
    }

    SetColors(colorGradientPara->GetColors());

    SetPositions(colorGradientPara->GetPositions());

    SetStrengths(colorGradientPara->GetStrengths());

    auto maskPara = colorGradientPara->GetMask();
    if (maskPara) {
        maskType_ = RSUIMaskPara::ConvertMaskType(maskPara->GetMaskParaType());
        std::shared_ptr<RSUIMaskPara> uiMaskPara = CreateMask(maskType_);
        if (uiMaskPara == nullptr) {
            ROSEN_LOGW("RSUIColorGradientFilterPara::SetColorGradient uiMaskPara nullptr");
            return;
        }

        uiMaskPara->SetPara(maskPara);
        SetMask(uiMaskPara);
    }
}

void RSUIColorGradientFilterPara::SetColors(std::vector<float> colors)
{
    Setter<RSAnimatableProperty<std::vector<float>>>(RSUIFilterType::COLOR_GRADIENT_COLOR, colors);
}

void RSUIColorGradientFilterPara::SetPositions(std::vector<float> positions)
{
    Setter<RSAnimatableProperty<std::vector<float>>>(RSUIFilterType::COLOR_GRADIENT_POSITION, positions);
}

void RSUIColorGradientFilterPara::SetStrengths(std::vector<float> strengths)
{
    Setter<RSAnimatableProperty<std::vector<float>>>(RSUIFilterType::COLOR_GRADIENT_STRENGTH, strengths);
}

void RSUIColorGradientFilterPara::SetMask(std::shared_ptr<RSUIMaskPara> mask)
{
    if (mask == nullptr) {
        ROSEN_LOGW("RSUIColorGradientFilterPara::SetMask mask nullptr");
        return;
    }
    properties_[mask->GetType()] = mask;
}

std::shared_ptr<RSRenderFilterParaBase> RSUIColorGradientFilterPara::CreateRSRenderFilter()
{
    auto frProperty = std::make_shared<RSRenderColorGradientFilterPara>(id_, maskType_);

    auto colors = std::static_pointer_cast<RSAnimatableProperty<std::vector<float>>>(
        GetRSProperty(RSUIFilterType::COLOR_GRADIENT_COLOR));
    if (colors == nullptr) {
        ROSEN_LOGE("RSUIColorGradientFilterPara::CreateRSRenderFilter not found colors");
        return nullptr;
    }
    auto colorsProperty = std::make_shared<RSRenderAnimatableProperty<std::vector<float>>>(
        colors->Get(), colors->GetId());
    frProperty->Setter(RSUIFilterType::COLOR_GRADIENT_COLOR, colorsProperty);

    auto positions = std::static_pointer_cast<RSAnimatableProperty<std::vector<float>>>(
        GetRSProperty(RSUIFilterType::COLOR_GRADIENT_POSITION));
    if (positions == nullptr) {
        ROSEN_LOGE("RSUIColorGradientFilterPara::CreateRSRenderFilter not found positions");
        return nullptr;
    }
    auto positionsProperty = std::make_shared<RSRenderAnimatableProperty<std::vector<float>>>(
        positions->Get(), positions->GetId());
    frProperty->Setter(RSUIFilterType::COLOR_GRADIENT_POSITION, positionsProperty);

    auto strengths = std::static_pointer_cast<RSAnimatableProperty<std::vector<float>>>(
        GetRSProperty(RSUIFilterType::COLOR_GRADIENT_STRENGTH));
    if (strengths == nullptr) {
        ROSEN_LOGE("RSUIColorGradientFilterPara::CreateRSRenderFilter not found strengths");
        return nullptr;
    }
    auto strengthsProperty = std::make_shared<RSRenderAnimatableProperty<std::vector<float>>>(
        strengths->Get(), strengths->GetId());
    frProperty->Setter(RSUIFilterType::COLOR_GRADIENT_STRENGTH, strengthsProperty);

    if (maskType_ != RSUIFilterType::NONE) {
        auto mask = std::static_pointer_cast<RSUIMaskPara>(GetRSProperty(maskType_));
        if (mask == nullptr) {
            ROSEN_LOGE("RSUIColorGradientFilterPara::CreateRSRenderFilter not found mask");
            return nullptr;
        }

        auto maskProperty = mask->CreateRSRenderFilter();
        if (maskProperty == nullptr) {
            ROSEN_LOGE("RSUIColorGradientFilterPara::CreateRSRenderFilter not found maskProperty");
            return nullptr;
        }
        frProperty->Setter(maskType_, maskProperty);
    }

    return frProperty;
}

std::vector<std::shared_ptr<RSPropertyBase>> RSUIColorGradientFilterPara::GetLeafProperties()
{
    auto colors = std::static_pointer_cast<RSAnimatableProperty<std::vector<float>>>(
        GetRSProperty(RSUIFilterType::COLOR_GRADIENT_COLOR));
    if (colors == nullptr) {
        ROSEN_LOGE("RSUIColorGradientFilterPara::GetLeafProperties not found colors");
        return {};
    }

    auto positions = std::static_pointer_cast<RSAnimatableProperty<std::vector<float>>>(
        GetRSProperty(RSUIFilterType::COLOR_GRADIENT_POSITION));
    if (positions == nullptr) {
        ROSEN_LOGE("RSUIColorGradientFilterPara::GetLeafProperties not found positions");
        return {};
    }

    auto strengths = std::static_pointer_cast<RSAnimatableProperty<std::vector<float>>>(
        GetRSProperty(RSUIFilterType::COLOR_GRADIENT_STRENGTH));
    if (strengths == nullptr) {
        ROSEN_LOGE("RSUIColorGradientFilterPara::GetLeafProperties not found strengths");
        return {};
    }

    std::vector<std::shared_ptr<RSPropertyBase>> out;
    out.emplace_back(colors);
    out.emplace_back(positions);
    out.emplace_back(strengths);

    if (maskType_ != RSUIFilterType::NONE) {
        auto mask = std::static_pointer_cast<RSUIMaskPara>(GetRSProperty(maskType_));
        if (mask == nullptr) {
            ROSEN_LOGE("RSUIColorGradientFilterPara::GetLeafProperties not found mask");
            return {};
        }
        std::vector<std::shared_ptr<RSPropertyBase>> maskProperty = mask->GetLeafProperties();
        out.insert(out.end(), maskProperty.begin(), maskProperty.end());
    }

    return out;
}

bool RSUIColorGradientFilterPara::CheckEnableHdrEffect()
{
    auto colors = std::static_pointer_cast<RSAnimatableProperty<std::vector<float>>>(
        GetRSProperty(RSUIFilterType::COLOR_GRADIENT_COLOR));
    if (colors == nullptr) {
        return false;
    }

    auto c = colors->Get();
    for (size_t i = 0; i < c.size(); i++) {
        if ((i + 1) % COLOR_PROPS_NUM == 0) {
            continue;
        }
        if (ROSEN_GNE(c[i], 1.0f)) {
            enableHdrEffect_ = true;
            break;
        }
    }
    return enableHdrEffect_ || stagingEnableHdrEffect_;
}

std::shared_ptr<RSUIMaskPara> RSUIColorGradientFilterPara::CreateMask(RSUIFilterType type)
{
    switch (type) {
        case RSUIFilterType::RIPPLE_MASK: {
            return std::make_shared<RSUIRippleMaskPara>();
        }
        case RSUIFilterType::RADIAL_GRADIENT_MASK: {
            return std::make_shared<RSUIRadialGradientMaskPara>();
        }
        default:
            return nullptr;
    }
}

} // namespace Rosen
} // namespace OHOS