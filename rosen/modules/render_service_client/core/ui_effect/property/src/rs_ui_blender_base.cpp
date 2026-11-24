/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "ui_effect/property/include/rs_ui_blender_base.h"

#include "platform/common/rs_log.h"
#include "ui_effect/effect/include/brightness_blender.h"
#include "ui_effect/effect/include/colorful_brightness_blender.h"
#include "ui_effect/effect/include/hdr_darken_blender.h"

#undef LOG_TAG
#define LOG_TAG "RSNGBlenderBase"

namespace OHOS {
namespace Rosen {
using BlenderCreator = std::function<std::shared_ptr<RSNGBlenderBase>()>;
using BlenderConvertor = std::function<std::shared_ptr<RSNGBlenderBase>(const Blender*)>;

static thread_local std::unordered_map<RSNGEffectType, BlenderCreator> creatorLUT = {
    {RSNGEffectType::COLORFUL_BRIGHTNESS_BLENDER, [] {
            return std::make_shared<RSNGColorfulBrightnessBlender>();
        }
    },
    {RSNGEffectType::BRIGHTNESS_BLENDER, [] {
            return std::make_shared<RSNGBrightnessBlender>();
        }
    },
    {RSNGEffectType::HDR_DARKEN_BLENDER, [] {
            return std::make_shared<RSNGHdrDarkenBlender>();
        }
    },
};

namespace {
std::shared_ptr<RSNGBlenderBase> ConvertColorfulBrightnessBlender(const Blender* blender)
{
    auto ngBlender = RSNGBlenderBase::Create(RSNGEffectType::COLORFUL_BRIGHTNESS_BLENDER);
    if (ngBlender == nullptr) {
        ROSEN_LOGE("ConvertColorfulBrightnessBlender: Create ng blender failed");
        return nullptr;
    }
    auto colorfulBlender = std::static_pointer_cast<RSNGColorfulBrightnessBlender>(ngBlender);
    auto oldBlender = static_cast<const ColorfulBrightnessBlender*>(blender);
    colorfulBlender->Setter<ColorfulBrightnessBlenderDarkenWeightTag>(oldBlender->GetDarkenWeight());
    colorfulBlender->Setter<ColorfulBrightnessBlenderFractionTag>(oldBlender->GetFraction());
    colorfulBlender->Setter<ColorfulBrightnessBlenderCubicRateTag>(oldBlender->GetCubicRate());
    colorfulBlender->Setter<ColorfulBrightnessBlenderQuadRateTag>(oldBlender->GetQuadRate());
    colorfulBlender->Setter<ColorfulBrightnessBlenderLinearRateTag>(oldBlender->GetLinearRate());
    colorfulBlender->Setter<ColorfulBrightnessBlenderDegreeTag>(oldBlender->GetDegree());
    colorfulBlender->Setter<ColorfulBrightnessBlenderSaturationTag>(oldBlender->GetSaturation());
    colorfulBlender->Setter<ColorfulBrightnessBlenderPositiveCoeffTag>(oldBlender->GetPositiveCoeff());
    colorfulBlender->Setter<ColorfulBrightnessBlenderNegativeCoeffTag>(oldBlender->GetNegativeCoeff());
    colorfulBlender->Setter<ColorfulBrightnessBlenderVibrancyStrengthTag>(oldBlender->GetVibrancyStrength());
    colorfulBlender->Setter<ColorfulBrightnessBlenderLumaDiffTag>(oldBlender->GetLumaDiff());
    colorfulBlender->Setter<ColorfulBrightnessBlenderHdrEnabledTag>(oldBlender->GetHdrEnabled());
    colorfulBlender->Setter<ColorfulBrightnessBlenderTintedColorPercentTag>(oldBlender->GetTintedColorPercent());
    return colorfulBlender;
}

std::shared_ptr<RSNGBlenderBase> ConvertBrightnessBlender(const Blender* blender)
{
    auto ngBlender = RSNGBlenderBase::Create(RSNGEffectType::BRIGHTNESS_BLENDER);
    if (ngBlender == nullptr) {
        ROSEN_LOGE("ConvertBrightnessBlender: Create ng blender failed");
        return nullptr;
    }
    auto brightnessBlender = std::static_pointer_cast<RSNGBrightnessBlender>(ngBlender);
    auto oldBlender = static_cast<const BrightnessBlender*>(blender);
    brightnessBlender->Setter<BrightnessBlenderFractionTag>(oldBlender->GetFraction());
    brightnessBlender->Setter<BrightnessBlenderCubicRateTag>(oldBlender->GetCubicRate());
    brightnessBlender->Setter<BrightnessBlenderQuadRateTag>(oldBlender->GetQuadRate());
    brightnessBlender->Setter<BrightnessBlenderLinearRateTag>(oldBlender->GetLinearRate());
    brightnessBlender->Setter<BrightnessBlenderDegreeTag>(oldBlender->GetDegree());
    brightnessBlender->Setter<BrightnessBlenderSaturationTag>(oldBlender->GetSaturation());
    brightnessBlender->Setter<BrightnessBlenderPositiveCoeffTag>(oldBlender->GetPositiveCoeff());
    brightnessBlender->Setter<BrightnessBlenderNegativeCoeffTag>(oldBlender->GetNegativeCoeff());
    // EDR guard: enabled only when hdr is on and fraction != 1.0, same as the legacy flat path
    brightnessBlender->Setter<BrightnessBlenderHdrEnabledTag>(
        oldBlender->GetHdr() && oldBlender->GetFraction() != 1.0f);
    return brightnessBlender;
}

std::shared_ptr<RSNGBlenderBase> ConvertHdrDarkenBlender(const Blender* blender)
{
    auto ngBlender = RSNGBlenderBase::Create(RSNGEffectType::HDR_DARKEN_BLENDER);
    if (ngBlender == nullptr) {
        ROSEN_LOGE("ConvertHdrDarkenBlender: Create ng blender failed");
        return nullptr;
    }
    auto hdrDarkenBlender = std::static_pointer_cast<RSNGHdrDarkenBlender>(ngBlender);
    auto oldBlender = static_cast<const HdrDarkenBlender*>(blender);
    hdrDarkenBlender->Setter<HdrDarkenBlenderHdrBrightnessRatioTag>(oldBlender->GetHdrBrightnessRatio());
    hdrDarkenBlender->Setter<HdrDarkenBlenderGrayscaleFactorTag>(oldBlender->GetGrayscaleFactor());
    return hdrDarkenBlender;
}
}

static thread_local std::unordered_map<Blender::BlenderType, BlenderConvertor> convertorLUT = {
    {Blender::COLORFUL_BRIGHTNESS_BLENDER, ConvertColorfulBrightnessBlender},
    {Blender::BRIGHTNESS_BLENDER, ConvertBrightnessBlender},
    {Blender::HDR_DARKEN_BLENDER, ConvertHdrDarkenBlender},
};

std::shared_ptr<RSNGBlenderBase> RSNGBlenderBase::Create(RSNGEffectType type)
{
    auto it = creatorLUT.find(type);
    return it != creatorLUT.end() ? it->second() : nullptr;
}

std::shared_ptr<RSNGBlenderBase> RSNGBlenderBase::Create(const Blender* blender)
{
    if (blender == nullptr) {
        return nullptr;
    }
    auto it = convertorLUT.find(blender->GetBlenderType());
    if (it == convertorLUT.end()) {
        ROSEN_LOGE("RSNGBlenderBase::Create: convertor not found, blender type %{public}d convert failed",
            static_cast<int>(blender->GetBlenderType()));
        return nullptr;
    }
    return it->second(blender);
}
} // namespace Rosen
} // namespace OHOS
