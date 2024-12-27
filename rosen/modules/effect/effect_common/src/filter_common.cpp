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
#include "filter_common.h"

#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <unordered_map>

#include "effect_errors.h"
#include "effect_utils.h"
#include "sk_image_chain.h"
#include "sk_image_filter_factory.h"

namespace OHOS {
namespace Rosen {
using namespace OHOS::Media;

namespace {
constexpr uint32_t MALLOC_FAILED = -1;
}

struct CMFilterContext {
    uint32_t status = SUCCESS;
    std::shared_ptr<FilterCommon> filter = nullptr;
    bool forceCPU = true;
    std::shared_ptr<Media::PixelMap> dstPixelMap_;
};

thread_local std::shared_ptr<FilterCommon> FilterCommon::sConstructor_ = nullptr;

void FilterCommon::AddNextFilter(sk_sp<SkImageFilter> filter)
{
    skFilters_.emplace_back(filter);
}

std::shared_ptr<FilterCommon> FilterCommon::CreateEffect(const std::shared_ptr<PixelMap>& pixmap, uint32_t& errorCode)
{
    if (pixmap == nullptr) {
        errorCode = ERR_INVALID_PARAM;
        return nullptr;
    }
    auto context = std::make_shared<FilterCommon>();
    if (context == nullptr) {
        EFFECT_LOG_E("[FilterCommon]failed to create ColorPickerCommon with null context.");
        errorCode = MALLOC_FAILED;
        return nullptr;
    }

    context->srcPixelMap_ = pixmap;
    sConstructor_ = context;
    return context;
}

bool FilterCommon::Blur(float radius)
{
    SkTileMode tileMode = SkTileMode::kDecal;
    auto blur = Rosen::SKImageFilterFactory::Blur(radius, tileMode);
    if (!blur) {
        EFFECT_LOG_E("[FilterCommon]blur is nullptr.");
        return false;
    }
    sConstructor_->AddNextFilter(blur);
    return true;
}

bool FilterCommon::Invert()
{
    auto invert = Rosen::SKImageFilterFactory::Invert();
    if (!invert) {
        EFFECT_LOG_E("[FilterCommon]invert is nullptr.");
        return false;
    }
    sConstructor_->AddNextFilter(invert);
    return true;
}

bool FilterCommon::Brightness(float bright)
{
    auto brightness = Rosen::SKImageFilterFactory::Brightness(bright);
    if (!brightness) {
        EFFECT_LOG_E("[FilterCommon]brightness is nullptr.");
        return false;
    }
    sConstructor_->AddNextFilter(brightness);
    return true;
}

bool FilterCommon::Grayscale()
{
    auto grayscale = Rosen::SKImageFilterFactory::Grayscale();
    if (!grayscale) {
        EFFECT_LOG_E("[FilterCommon]grayscale is nullptr.");
        return false;
    }
    sConstructor_->AddNextFilter(grayscale);
    return true;
}

static uint32_t ParseColorMatrix(std::vector<float> inputColorMatrix, PixelColorMatrix& colorMatrix)
{
    size_t len = inputColorMatrix.size();
    for (size_t i = 0; i < len; i++) {
        colorMatrix.val[i] = inputColorMatrix[i];
    }
    return SUCCESS;
}

bool FilterCommon::SetColorMatrix(std::vector<float> inputcolorMatrix, uint32_t& code)
{
    uint32_t res = 0;
    PixelColorMatrix colorMatrix;
    res = ParseColorMatrix(inputcolorMatrix, colorMatrix);
    if (res != SUCCESS) {
        EFFECT_LOG_E("[FilterCommon]Color matrix mismatch");
        code = ERR_INVALID_PARAM;
        return false;
    }

    auto applyColorMatrix = Rosen::SKImageFilterFactory::ApplyColorMatrix(colorMatrix);
    if (!applyColorMatrix) {
        EFFECT_LOG_E("[FilterCommon]applyColorMatrix is nullptr.");
        return false;
    }
    sConstructor_->AddNextFilter(applyColorMatrix);
    return true;
}

DrawError FilterCommon::Render(bool forceCPU)
{
    Rosen::SKImageChain skImage(srcPixelMap_);
    return skImage.Render(skFilters_, forceCPU, dstPixelMap_);
}

std::shared_ptr<Media::PixelMap> FilterCommon::GetDstPixelMap()
{
    return dstPixelMap_;
}

std::shared_ptr<OHOS::Media::PixelMap> FilterCommon::GetEffectPixelMap()
{
    std::unique_ptr<CMFilterContext> ctx = std::make_unique<CMFilterContext>();
    ctx->filter = sConstructor_;
    if (ctx->filter->Render(ctx->forceCPU) != DrawError::ERR_OK) {
        EFFECT_LOG_E("[FilterCommon]Render fail");
        return nullptr;
    }
    ctx->dstPixelMap_ = ctx->filter->GetDstPixelMap();

    return ctx->dstPixelMap_;
}

} // namespace Rosen
} // namespace OHOS