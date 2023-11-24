/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "skia_color_filter.h"

#include "include/effects/SkLumaColorFilter.h"
#include "include/effects/SkOverdrawColorFilter.h"
#include "src/core/SkReadBuffer.h"
#include "src/core/SkWriteBuffer.h"

#include "effect/color_filter.h"
#include "utils/data.h"
#include "utils/log.h"

namespace OHOS {
namespace Rosen {
namespace Drawing {
SkiaColorFilter::SkiaColorFilter() noexcept : filter_(nullptr) {}

void SkiaColorFilter::InitWithBlendMode(ColorQuad c, BlendMode mode)
{
    filter_ = SkColorFilters::Blend(static_cast<SkColor>(c), static_cast<SkBlendMode>(mode));
}

void SkiaColorFilter::InitWithColorMatrix(const ColorMatrix& m)
{
    scalar dst[ColorMatrix::MATRIX_SIZE];
    m.GetArray(dst);
    filter_ = SkColorFilters::Matrix(dst);
}

void SkiaColorFilter::InitWithLinearToSrgbGamma()
{
    filter_ = SkColorFilters::LinearToSRGBGamma();
}

void SkiaColorFilter::InitWithSrgbGammaToLinear()
{
    filter_ = SkColorFilters::SRGBToLinearGamma();
}

void SkiaColorFilter::InitWithCompose(const ColorFilter& f1, const ColorFilter& f2)
{
    auto outer = f1.GetImpl<SkiaColorFilter>();
    auto inner = f2.GetImpl<SkiaColorFilter>();
    if (outer != nullptr && inner != nullptr) {
        filter_ = SkColorFilters::Compose(outer->GetColorFilter(), inner->GetColorFilter());
    }
}

void SkiaColorFilter::Compose(const ColorFilter& f)
{
    auto skColorFilterImpl = f.GetImpl<SkiaColorFilter>();
    if (filter_ != nullptr && skColorFilterImpl != nullptr) {
        filter_ = filter_->makeComposed(skColorFilterImpl->GetColorFilter());
    }
}

void SkiaColorFilter::InitWithLuma()
{
    filter_ = SkLumaColorFilter::Make();
}

sk_sp<SkColorFilter> SkiaColorFilter::GetColorFilter() const
{
    return filter_;
}

void SkiaColorFilter::SetColorFilter(const sk_sp<SkColorFilter>& filter)
{
    filter_ = filter;
}

std::shared_ptr<Data> SkiaColorFilter::Serialize() const
{
#ifdef ROSEN_OHOS
    if (filter_ == nullptr) {
        LOGE("SkiaColorFilter::Serialize, filter_ is nullptr!");
        return nullptr;
    }

    SkBinaryWriteBuffer writer;
    writer.writeFlattenable(filter_.get());
    size_t length = writer.bytesWritten();
    std::shared_ptr<Data> data = std::make_shared<Data>();
    data->BuildUninitialized(length);
    writer.writeToMemory(data->WritableData());
    return data;
#else
    return nullptr;
#endif
}

bool SkiaColorFilter::Deserialize(std::shared_ptr<Data> data)
{
#ifdef ROSEN_OHOS
    if (data == nullptr) {
        LOGE("SkiaColorFilter::Deserialize, data is invalid!");
        return false;
    }

    SkReadBuffer reader(data->GetData(), data->GetSize());
    filter_ = reader.readColorFilter();
    return filter_ != nullptr;
#else
    return false;
#endif
}

bool SkiaColorFilter::AsAColorMatrix(scalar matrix[MATRIX_SIZE]) const
{
    if (filter_ == nullptr) {
        LOGE("SkiaColorFilter::AsAColorMatrix filter_ is nullptr!");
        return false;
    }
    return filter_->asAColorMatrix(matrix);
}

} // namespace Drawing
} // namespace Rosen
} // namespace OHOS