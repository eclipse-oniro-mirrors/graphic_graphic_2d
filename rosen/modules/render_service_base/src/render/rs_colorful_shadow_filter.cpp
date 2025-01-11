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
#include "render/rs_colorful_shadow_filter.h"

#include "common/rs_common_def.h"
#include "common/rs_optional_trace.h"
#include "platform/common/rs_log.h"
#include "src/core/SkOpts.h"

namespace OHOS {
namespace Rosen {
RSColorfulShadowFilter::RSColorfulShadowFilter(float blurRadius, float offsetX, float offsetY)
    : RSForegroundEffectFilter(blurRadius), blurRadius_(blurRadius), offsetX_(offsetX), offsetY_(offsetY)
{
    type_ = FilterType::COLORFUL_SHADOW;
    hash_ = SkOpts::hash(&type_, sizeof(type_), 0);
}

std::string RSColorfulShadowFilter::GetDescription()
{
    return "RSColorfulShadowFilter " + std::to_string(blurRadius_);
}

bool RSColorfulShadowFilter::IsValid() const
{
    constexpr float epsilon = 0.999f;  // if blur radius less than 1, do not need to draw
    return blurRadius_ > epsilon;
}

void RSColorfulShadowFilter::DrawImageRect(Drawing::Canvas &canvas, const std::shared_ptr<Drawing::Image> &image,
    const Drawing::Rect &src, const Drawing::Rect &dst) const
{
    if (image == nullptr) {
        ROSEN_LOGE("RSColorfulShadowFilter::DrawImageRect error");
        return;
    }

    // draw blur image
    canvas.Translate(offsetX_, offsetY_);
    RSForegroundEffectFilter::DrawImageRect(canvas, image, src, dst);
    canvas.Translate(-offsetX_, -offsetY_);

    // draw clear image
    auto samplingOptions = Drawing::SamplingOptions(Drawing::FilterMode::LINEAR, Drawing::MipmapMode::LINEAR);
    canvas.DrawImage(*image, 0.f, 0.f, samplingOptions);
}
}  // namespace Rosen
}  // namespace OHOS
