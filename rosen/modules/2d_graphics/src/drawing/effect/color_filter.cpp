/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include "effect/color_filter.h"

#include "impl_factory.h"

#include "impl_interface/color_filter_impl.h"

#ifdef ROSEN_OHOS
#include "utils/log.h"
#include "utils/object_helper.h"
#endif

namespace OHOS {
namespace Rosen {
namespace Drawing {
ColorFilter::ColorFilter(FilterType t, ColorQuad c, BlendMode mode) noexcept : ColorFilter()
{
    type_ = t;
    impl_->InitWithBlendMode(c, mode);
}

ColorFilter::ColorFilter(FilterType t, const ColorMatrix& m, Clamp clamp) noexcept : ColorFilter()
{
    type_ = t;
    impl_->InitWithColorMatrix(m, clamp);
}

ColorFilter::ColorFilter(FilterType t, const float f[20], Clamp clamp) noexcept : ColorFilter()
{
    type_ = t;
    impl_->InitWithColorFloat(f, clamp);
}

ColorFilter::ColorFilter(FilterType t, ColorFilter& f1, ColorFilter& f2) noexcept : ColorFilter()
{
    type_ = t;
    impl_->InitWithCompose(f1, f2);
}

ColorFilter::ColorFilter(FilterType t, const float f1[MATRIX_SIZE],
    const float f2[MATRIX_SIZE], Clamp clamp) noexcept : ColorFilter()
{
    type_ = t;
    impl_->InitWithCompose(f1, f2, clamp);
}

ColorFilter::ColorFilter(FilterType t,
    const ColorQuad colors[OVER_DRAW_COLOR_NUM]) noexcept : ColorFilter()
{
    type_ = t;
    impl_->InitWithOverDrawColor(colors);
}

ColorFilter::ColorFilter(FilterType t, ColorQuad mul, ColorQuad add) noexcept : ColorFilter()
{
    type_ = t;
    impl_->InitWithLighting(mul, add);
}

void ColorFilter::InitWithCompose(const float f1[MATRIX_SIZE], const float f2[MATRIX_SIZE], Clamp clamp)
{
    type_ = ColorFilter::FilterType::COMPOSE;
    impl_->InitWithCompose(f1, f2, clamp);
}

ColorFilter::ColorFilter(FilterType t) noexcept : ColorFilter()
{
    type_ = t;
    switch (type_) {
        case ColorFilter::FilterType::LINEAR_TO_SRGB_GAMMA:
            impl_->InitWithLinearToSrgbGamma();
            break;
        case ColorFilter::FilterType::SRGB_GAMMA_TO_LINEAR:
            impl_->InitWithSrgbGammaToLinear();
            break;
        case ColorFilter::FilterType::LUMA:
            impl_->InitWithLuma();
            break;
        default:
            break;
    }
}

ColorFilter::ColorFilter() noexcept
    : type_(ColorFilter::FilterType::NO_TYPE), impl_(ImplFactory::CreateColorFilterImpl())
{}

ColorFilter::FilterType ColorFilter::GetType() const
{
    return type_;
}

void ColorFilter::Compose(const ColorFilter& filter)
{
    if (impl_ == nullptr) {
        return;
    }
    impl_->Compose(filter);
}

std::shared_ptr<ColorFilter> ColorFilter::CreateBlendModeColorFilter(ColorQuad c, BlendMode mode)
{
    return std::make_shared<ColorFilter>(ColorFilter::FilterType::BLEND_MODE, c, mode);
}

std::shared_ptr<ColorFilter> ColorFilter::CreateComposeColorFilter(ColorFilter& f1, ColorFilter& f2)
{
    return std::make_shared<ColorFilter>(ColorFilter::FilterType::COMPOSE, f1, f2);
}

std::shared_ptr<ColorFilter> ColorFilter::CreateComposeColorFilter(
    const float (&f1)[MATRIX_SIZE], const float (&f2)[MATRIX_SIZE], Clamp clamp)
{
    return std::make_shared<ColorFilter>(ColorFilter::FilterType::COMPOSE, f1, f2, clamp);
}

std::shared_ptr<ColorFilter> ColorFilter::CreateMatrixColorFilter(const ColorMatrix& m, Clamp clamp)
{
    return std::make_shared<ColorFilter>(ColorFilter::FilterType::MATRIX, m, clamp);
}

std::shared_ptr<ColorFilter> ColorFilter::CreateFloatColorFilter(const float (&f)[MATRIX_SIZE], Clamp clamp)
{
    return std::make_shared<ColorFilter>(ColorFilter::FilterType::MATRIX, f, clamp);
}

std::shared_ptr<ColorFilter> ColorFilter::CreateLinearToSrgbGamma()
{
    return std::make_shared<ColorFilter>(ColorFilter::FilterType::LINEAR_TO_SRGB_GAMMA);
}

std::shared_ptr<ColorFilter> ColorFilter::CreateSrgbGammaToLinear()
{
    return std::make_shared<ColorFilter>(ColorFilter::FilterType::SRGB_GAMMA_TO_LINEAR);
}

std::shared_ptr<ColorFilter> ColorFilter::CreateLumaColorFilter()
{
    return std::make_shared<ColorFilter>(ColorFilter::FilterType::LUMA);
}

std::shared_ptr<ColorFilter> ColorFilter::CreateOverDrawColorFilter(
    const ColorQuad colors[OVER_DRAW_COLOR_NUM])
{
    return std::make_shared<ColorFilter>(ColorFilter::FilterType::OVER_DRAW, colors);
}

std::shared_ptr<ColorFilter> ColorFilter::CreateLightingColorFilter(ColorQuad mul, ColorQuad add)
{
    return std::make_shared<ColorFilter>(ColorFilter::FilterType::LIGHTING, mul, add);
}

std::shared_ptr<Data> ColorFilter::Serialize() const
{
    return impl_->Serialize();
}

bool ColorFilter::Deserialize(std::shared_ptr<Data> data)
{
    return impl_->Deserialize(data);
}

bool ColorFilter::AsAColorMatrix(scalar matrix[MATRIX_SIZE]) const
{
    return impl_->AsAColorMatrix(matrix);
}

#ifdef ROSEN_OHOS
bool ColorFilter::Marshalling(Parcel& parcel)
{
    // Write type first
    if (!parcel.WriteInt32(static_cast<int32_t>(type_))) {
        LOGE("ColorFilter::Marshalling, failed to write type");
        return false;
    }

    // Use Serialize to convert to Data then serialize
    auto data = Serialize();

    // Write flag indicating whether data is valid
    bool hasValidData = (data != nullptr && data->GetSize() > 0);
    if (!parcel.WriteBool(hasValidData)) {
        LOGE("ColorFilter::Marshalling, failed to write hasData flag");
        return false;
    }

    // If data is null or empty, just write the flag and return success
    if (!hasValidData) {
        LOGD("ColorFilter::Marshalling, Serialize returned null or empty data, continuing with empty marker");
        return true;
    }

    // Use registered callback for Data marshalling
    auto callback = ObjectHelper::Instance().GetDataMarshallingCallback();
    if (!callback) {
        LOGE("ColorFilter::Marshalling, DataMarshallingCallback is not registered");
        return false;
    }
    if (!callback(parcel, data)) {
        LOGE("ColorFilter::Marshalling, DataMarshallingCallback failed");
        return false;
    }
    return true;
}

std::shared_ptr<ColorFilter> ColorFilter::Unmarshalling(Parcel& parcel, bool& isValid)
{
    // Read type first
    int32_t typeValue;
    if (!parcel.ReadInt32(typeValue)) {
        LOGE("ColorFilter::Unmarshalling, failed to read type");
        return nullptr;
    }

    // Validate type range
    if (typeValue < static_cast<int32_t>(FilterType::NO_TYPE) ||
        typeValue > static_cast<int32_t>(FilterType::LIGHTING)) {
        LOGE("ColorFilter::Unmarshalling, invalid type value: %{public}d", typeValue);
        return nullptr;
    }

    // Read hasData flag
    bool hasData;
    if (!parcel.ReadBool(hasData)) {
        LOGE("ColorFilter::Unmarshalling, failed to read hasData flag");
        return nullptr;
    }

    // If no data, create an empty ColorFilter and return
    if (!hasData) {
        LOGD("ColorFilter::Unmarshalling, empty data marker detected, creating ColorFilter with type only");
        auto colorFilter = std::make_shared<ColorFilter>(static_cast<FilterType>(typeValue));
        return colorFilter;
    }

    // Use registered callback for Data unmarshalling
    auto callback = ObjectHelper::Instance().GetDataUnmarshallingCallback();
    if (!callback) {
        LOGE("ColorFilter::Unmarshalling, DataUnmarshallingCallback is not registered");
        return nullptr;
    }
    auto data = callback(parcel);
    if (!data) {
        LOGE("ColorFilter::Unmarshalling, DataUnmarshallingCallback failed");
        return nullptr;
    }

    // Create ColorFilter with correct type
    auto colorFilter = std::make_shared<ColorFilter>(static_cast<FilterType>(typeValue));
    if (!colorFilter->Deserialize(data)) {
        LOGE("ColorFilter::Unmarshalling, Deserialize failed");
        // For compatibility: mark as invalid but return object instead of nullptr
        isValid = false;
        return colorFilter;
    }
    return colorFilter;
}
#endif

} // namespace Drawing
} // namespace Rosen
} // namespace OHOS
