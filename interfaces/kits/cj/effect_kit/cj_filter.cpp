/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "cj_filter.h"

#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>

#include "effect_errors.h"
#include "effect_utils.h"
#include "filter_common.h"
#include "sk_image_chain.h"
#include "sk_image_filter_factory.h"

namespace OHOS {
namespace CJEffectKit {
using namespace OHOS::Rosen;
using namespace OHOS::Media;

int64_t CJFilter::CreateEffect(Media::PixelMapImpl* source, uint32_t& errorCode)
{
    std::shared_ptr<Media::PixelMap> pixmap = source->GetRealPixelMap();
    FilterCommon::CreateEffect(pixmap, errorCode);
    auto native = FFIData::Create<CJFilter>();
    return native->GetID();
}

void CJFilter::Blur(float radius)
{
    FilterCommon::Blur(radius);
}

void CJFilter::Invert()
{
    FilterCommon::Invert();
}

void CJFilter::Brightness(float bright)
{
    FilterCommon::Brightness(bright);
}

void CJFilter::Grayscale()
{
    FilterCommon::Grayscale();
}

void CJFilter::SetColorMatrix(std::vector<float> cjcolorMatrix, uint32_t& code)
{
    FilterCommon::SetColorMatrix(cjcolorMatrix, code);
}

std::shared_ptr<OHOS::Media::PixelMap> CJFilter::GetEffectPixelMap()
{
    return FilterCommon::GetEffectPixelMap();
}

} // namespace CJEffectKit
} // namespace OHOS