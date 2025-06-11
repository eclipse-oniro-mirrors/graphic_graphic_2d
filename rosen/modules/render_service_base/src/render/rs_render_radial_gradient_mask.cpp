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

#include "platform/common/rs_log.h"
#include "render/rs_render_radial_gradient_mask.h"
namespace OHOS {
namespace Rosen {
std::shared_ptr<RSRenderPropertyBase> RSRenderRadialGradientMaskPara::CreateRenderProperty(RSUIFilterType type)
{
    switch (type) {
        case RSUIFilterType::RADIAL_GRADIENT_MASK_RADIUSX: {
            return std::make_shared<RSRenderAnimatableProperty<float>>(
                0.f, 0, RSPropertyType::FLOAT);
        }
        case RSUIFilterType::RADIAL_GRADIENT_MASK_RADIUSY: {
            return std::make_shared<RSRenderAnimatableProperty<float>>(
                0.f, 0, RSPropertyType::FLOAT);
        }
        case RSUIFilterType::RADIAL_GRADIENT_MASK_CENTER: {
            Vector2f value = {0.f, 0.f};
            return std::make_shared<RSRenderAnimatableProperty<Vector2f>>(
                value, 0, RSPropertyType::VECTOR2F);
        }
        case RSUIFilterType::RADIAL_GRADIENT_MASK_COLORS: {
            std::vector<float> value = {};
            return std::make_shared<RSRenderAnimatableProperty<std::vector<float>>>(
                value, 0, RSPropertyType::SHADER_PARAM);
        }
        case RSUIFilterType::RADIAL_GRADIENT_MASK_POSITIONS: {
            std::vector<float> value = {};
            return std::make_shared<RSRenderAnimatableProperty<std::vector<float>>>(
                value, 0, RSPropertyType::SHADER_PARAM);
        }
        default:
            ROSEN_LOGE("RSRenderRadialGradientMaskPara::CreateRenderProperty mask nullptr");
            return nullptr;
    }
    return nullptr;
}

void RSRenderRadialGradientMaskPara::GetDescription(std::string& out) const
{
    out += "RSRenderRadialGradientMaskPara";
}

bool RSRenderRadialGradientMaskPara::WriteToParcel(Parcel& parcel)
{
    if (!RSMarshallingHelper::Marshalling(parcel, id_) ||
        !RSMarshallingHelper::Marshalling(parcel, static_cast<int16_t>(type_)) ||
        !RSMarshallingHelper::Marshalling(parcel, static_cast<int16_t>(modifierType_))) {
        ROSEN_LOGE("RSRenderRadialGradientMaskPara::WriteToParcel type Error");
        return false;
    }
    if (!parcel.WriteUint32(properties_.size())) {
        ROSEN_LOGE("RSRenderRadialGradientMaskPara::WriteToParcel size Error");
        return false;
    }
    for (const auto& [key, value] : properties_) {
        if (!RSMarshallingHelper::Marshalling(parcel, key) ||
            !RSRenderPropertyBase::Marshalling(parcel, value)) {
            return false;
        }
        ROSEN_LOGD("RSRenderRadialGradientMaskPara::WriteToParcel type %{public}d", static_cast<int>(key));
    }
    return true;
}

bool RSRenderRadialGradientMaskPara::ReadFromParcel(Parcel& parcel)
{
    int16_t type = 0;
    int16_t modifierType = 0;
    if (!RSMarshallingHelper::Unmarshalling(parcel, id_) ||
        !RSMarshallingHelper::Unmarshalling(parcel, type) ||
        !RSMarshallingHelper::Unmarshalling(parcel, modifierType)) {
        ROSEN_LOGE("RSRenderRadialGradientMaskPara::ReadFromParcel type Error");
        return false;
    }
    type_ = static_cast<RSUIFilterType>(type);
    modifierType_ = static_cast<RSModifierType>(modifierType);

    uint32_t size = 0;
    if (!RSMarshallingHelper::Unmarshalling(parcel, size)) {
        ROSEN_LOGE("RSRenderRadialGradientMaskPara::ReadFromParcel size Error");
        return false;
    }
    if (size > static_cast<size_t>(RSMarshallingHelper::UNMARSHALLING_MAX_VECTOR_SIZE)) {
        ROSEN_LOGE("RSRenderRadialGradientMaskPara::ReadFromParcel size large Error");
        return false;
    }
    properties_.clear();
    for (uint32_t i = 0; i < size; ++i) {
        RSUIFilterType key;
        if (!RSMarshallingHelper::Unmarshalling(parcel, key)) {
            ROSEN_LOGE("RSRenderRadialGradientMaskPara::ReadFromParcel type %{public}d", static_cast<int>(key));
            return false;
        }
        std::shared_ptr<RSRenderPropertyBase> value = CreateRenderProperty(key);
        if (!RSRenderPropertyBase::Unmarshalling(parcel, value)) {
            ROSEN_LOGE("RSRenderRadialGradientMaskPara::ReadFromParcel value %{public}d", static_cast<int>(key));
            return false;
        }
        Setter(key, value);
    }
    return true;
}

std::vector<std::shared_ptr<RSRenderPropertyBase>> RSRenderRadialGradientMaskPara::GetLeafRenderProperties()
{
    std::vector<std::shared_ptr<RSRenderPropertyBase>> out;
    for (auto& [k, v] : properties_) {
        out.emplace_back(v);
    }
    return out;
}
} // namespace Rosen
} // namespace OHOS
