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

#include "drawable/rs_blender_drawable_utils.h"

#include <algorithm>
#include <functional>
#include <unordered_map>

#include "common/rs_common_def.h"
#include "common/rs_optional_trace.h"
#include "effect/rs_render_blender_base.h"
#include "pipeline/rs_paint_filter_canvas.h"
#include "platform/common/rs_log.h"
#include "platform/common/rs_system_properties.h"
#include "property/rs_properties.h"
#include "render/rs_effect_luminance_manager.h"

namespace OHOS::Rosen {
namespace {
constexpr char COLORFUL_BRIGHTNESS_BLENDER_PROG[] = R"(
        uniform half darkenWeight;
        uniform half fraction;
        uniform half activeRatesX;
        uniform half activeRatesY;
        uniform half activeKBSx;
        uniform half activeKBSy;
        uniform half activeKBSz;
        uniform half activePosX;
        uniform half activePosY;
        uniform half activePosZ;
        uniform half activeNegX;
        uniform half activeNegY;
        uniform half activeNegZ;
        uniform half lumaDiff;
        uniform half colorLimit;
        uniform half tintedColorPercent;
        uniform half penetration;

        const half3 lumaWeight = half3(0.2126, 0.7152, 0.0722);
        const half3 baseVec = half3(0.2412016, 0.6922296, 0.0665688);
        const half eps = 1e-3;
        const half lumaMapK = 0.6628;
        const half lumaMapB = 0.3137;
        const half grayMapK = -0.15;
        const half grayMapB = 0.2;
        const half darkModeBrightness = 0.4;

        half3 Sat(half3 inColor, half n, half3 pos, half3 neg)
        {
            half3 r = (1.0 - n) * inColor;
            half base = dot(r, baseVec);
            half3 delta = base - r;
            half3 v = mix(neg, pos, step(0.0, delta));
            return inColor + delta * v;
        }

        half3 Vibrancy(half3 color)
        {
            half3 grayColor = ((activeRatesX * color + activeRatesY) * color + activeKBSx) * color + activeKBSy;
            return Sat(grayColor, activeKBSz, half3(activePosX, activePosY, activePosZ),
                half3(activeNegX, activeNegY, activeNegZ));
        }

        half GetMaxChannelValue(half luma, half ref, half colorMax, half colorMin)
        {
            half k1 = max(5.55 * colorMax - 4.37, 0.0);
            half k2 = max(0.28 * colorMax - 0.24, 0.0);
            half y1 = ref + k1 * colorMin;
            half y2 = ref + k2 * colorMin;
            return min(mix(y1, y2, luma), 1.0);
        }

        half GetMinChannelValue(half luma, half resMax, half s1, half colorMax)
        {
            half s0 = clamp(max(1.4 * colorMax, 1.75 * s1), 0.5, 1.0);
            s0 = mix(s0, 1.0, step(0.5, s1));
            half k = min(-0.46 * s1 + 1.46, 1.23);
            half newS = mix(s0, s1, luma) + 2.0 * (k - 1.0) * (s0 + s1) * luma * (1.0 - luma);
            return resMax*(1.0 - newS);
        }

        half GetMidChannelValue(half luma, half ref, half resMax, half resMin,
            half colorMax, half colorMin, half colorMid)
        {
            half anchor = mix(colorMin, colorMax, 0.39);
            half range = colorMax - anchor;
            half isRangeValid = step(0.0001, range);
            half t = (colorMid - anchor) / (range + 0.0001);
            half midMin = max(mix(resMin, resMax, t), resMin);
            half result = mix(midMin, ref, luma);
            return mix(resMin, result, isRangeValid);
        }

        half3 sdrColorFilter(half3 dst, half dstLuma, half3 src, half darkenWeight)
        {
            half srcMax = max(max(src.r, src.g), src.b);
            half srcMin = min(min(src.r, src.g), src.b);
            half saturation = srcMax > 0.0 ? (srcMax - srcMin) / srcMax : 0.0;
            half m = mix(grayMapK * srcMax + grayMapB, 0.0, smoothstep(0.0, 0.03, saturation));
            half lightModeNewLuma = dstLuma * lumaMapK + lumaMapB;
            half dstNewLuma = mix(1.0, lightModeNewLuma, darkenWeight);
            half n = mix(dstLuma * darkModeBrightness, 0.0, darkenWeight);
            half3 baseColor = src * (dstNewLuma + (dst - dstLuma) * penetration) + m * dst + n;
            if (darkenWeight == 0.0) {return baseColor;}

            half3 isMax = step(half3(srcMax), src);
            isMax.g *= (1.0 - isMax.r);
            isMax.b *= (1.0 - isMax.r) * (1.0 - isMax.g);
            half3 isMin = step(src, half3(srcMin));
            isMin *= (1.0 - isMax);
            isMin.g *= (1.0 - isMin.r);
            isMin.b *= (1.0 - isMin.r) * (1.0 - isMin.g);
            half3 isMid = 1.0 - isMax - isMin;

            half srcMid = dot(src, isMid);
            half resColorMax = dot(baseColor, isMax);
            half resColorMid = dot(baseColor, isMid);

            half resMax = GetMaxChannelValue(dstLuma, resColorMax, srcMax, srcMin);
            half resMin = GetMinChannelValue(dstLuma, resMax, saturation, srcMax);
            half resMid = GetMidChannelValue(dstLuma, resColorMid, resMax, resMin, srcMax, srcMin, srcMid);

            half midMappedAsMax = GetMaxChannelValue(dstLuma, resColorMid, srcMax, srcMin);
            half blendMax = smoothstep(0.0, 0.05, abs(srcMax - srcMid));
            resMid = mix(midMappedAsMax, resMid, blendMax);
            half blendMin = smoothstep(0.0, 0.05, abs(srcMid - srcMin));
            resMid = mix(resMin, resMid, blendMin);

            half3 reorderedColor = isMax * resMax + isMin * resMin + isMid * resMid;
            half t1 = smoothstep(0.0, 0.05, saturation);
            half t2 = 1.0 - smoothstep(0.95, 1.0, saturation);
            half3 finalLightModeColor = mix(baseColor, reorderedColor, t1 * t2);
            return mix(baseColor, finalLightModeColor, darkenWeight);
        }

        half3 keepLumaDiff(half3 inColor, half darkenWeight)
        {
            if (lumaDiff == 0.0) {return inColor;}
            return max(half3(0.0), inColor + lumaDiff * (1.0 - 2.0 * darkenWeight));
        }

        half4 main(half4 srcColor, half4 dstColor)
        {
            half factorSrc = 1.0 / (max(srcColor.a, eps));
            half3 fgRgb = saturate(srcColor.rgb * factorSrc);
            half fgA = srcColor.a;

            half factorDst = 1.0 / (max(dstColor.a, eps));
            half3 bgRgb = max(dstColor.rgb * factorDst, half3(0.0));
            half bgA = dstColor.a;

            half bgMaxChannelVal = max(max(bgRgb.r, bgRgb.g), bgRgb.b);
            half hdrExposure = max(bgMaxChannelVal, 1.0);
            half3 bgSdrColor = bgRgb / hdrExposure;
            half bgLuma = dot(bgSdrColor, lumaWeight);

            half3 resColor = bgSdrColor;
            if (tintedColorPercent > 0.0) {
                half3 filteredColor = sdrColorFilter(bgSdrColor, bgLuma, fgRgb, darkenWeight);
                resColor = mix(bgSdrColor, filteredColor, tintedColorPercent);
            }
            resColor = Vibrancy(resColor);
            resColor = keepLumaDiff(resColor, darkenWeight);
            resColor = clamp(resColor, 0.0, colorLimit);
            resColor = mix(bgSdrColor, resColor, fgA);

            half3 straightGlassRgb = resColor * hdrExposure;

            half3 pmaNormalBlend = srcColor.rgb * bgA + dstColor.rgb * (1.0 - fgA);
            half3 pmaGlassBlend = straightGlassRgb * bgA;
            half3 finalPmaRgb = mix(pmaGlassBlend, pmaNormalBlend, fraction);

            return half4(finalPmaRgb, bgA);
        }
    )";

__attribute__((noinline)) RSColorfulBrightnessBlenderPara GetColorfulBrightnessPara(
    const std::shared_ptr<RSNGRenderBlenderBase>& blender)
{
    auto colorfulBlender = std::static_pointer_cast<RSNGRenderColorfulBrightnessBlender>(blender);
    RSColorfulBrightnessBlenderPara params;
    params.darkenWeight_ = colorfulBlender->Getter<ColorfulBrightnessBlenderDarkenWeightRenderTag>()->Get();
    params.fraction_ = colorfulBlender->Getter<ColorfulBrightnessBlenderFractionRenderTag>()->Get();
    params.cubicRate_ = colorfulBlender->Getter<ColorfulBrightnessBlenderCubicRateRenderTag>()->Get();
    params.quadRate_ = colorfulBlender->Getter<ColorfulBrightnessBlenderQuadRateRenderTag>()->Get();
    params.linearRate_ = colorfulBlender->Getter<ColorfulBrightnessBlenderLinearRateRenderTag>()->Get();
    params.degree_ = colorfulBlender->Getter<ColorfulBrightnessBlenderDegreeRenderTag>()->Get();
    params.saturation_ = colorfulBlender->Getter<ColorfulBrightnessBlenderSaturationRenderTag>()->Get();
    params.positiveCoeff_ = colorfulBlender->Getter<ColorfulBrightnessBlenderPositiveCoeffRenderTag>()->Get();
    params.negativeCoeff_ = colorfulBlender->Getter<ColorfulBrightnessBlenderNegativeCoeffRenderTag>()->Get();
    params.vibrancyStrength_ =
        colorfulBlender->Getter<ColorfulBrightnessBlenderVibrancyStrengthRenderTag>()->Get();
    params.lumaDiff_ = colorfulBlender->Getter<ColorfulBrightnessBlenderLumaDiffRenderTag>()->Get();
    params.hdrEnabled_ = colorfulBlender->Getter<ColorfulBrightnessBlenderHdrEnabledRenderTag>()->Get();
    params.tintedColorPercent_ =
        colorfulBlender->Getter<ColorfulBrightnessBlenderTintedColorPercentRenderTag>()->Get();
    return params;
}

__attribute__((noinline)) RSColorfulBrightnessBlenderPara LerpColorfulBrightnessPara(
    const RSColorfulBrightnessBlenderPara& from, const RSColorfulBrightnessBlenderPara& to, float fraction)
{
    auto lerp = [](float src, float dst, float ratio) { return src + (dst - src) * ratio; };
    RSColorfulBrightnessBlenderPara result;
    const float t = std::clamp(fraction, 0.0f, 1.0f);
    result.darkenWeight_ = lerp(from.darkenWeight_, to.darkenWeight_, t);
    result.fraction_ = std::clamp(lerp(from.fraction_, to.fraction_, t), 0.0f, 1.0f);
    result.cubicRate_ = lerp(from.cubicRate_, to.cubicRate_, t);
    result.quadRate_ = lerp(from.quadRate_, to.quadRate_, t);
    result.linearRate_ = lerp(from.linearRate_, to.linearRate_, t);
    result.degree_ = lerp(from.degree_, to.degree_, t);
    result.saturation_ = lerp(from.saturation_, to.saturation_, t);
    result.positiveCoeff_ = Vector3f(lerp(from.positiveCoeff_.x_, to.positiveCoeff_.x_, t),
        lerp(from.positiveCoeff_.y_, to.positiveCoeff_.y_, t),
        lerp(from.positiveCoeff_.z_, to.positiveCoeff_.z_, t));
    result.negativeCoeff_ = Vector3f(lerp(from.negativeCoeff_.x_, to.negativeCoeff_.x_, t),
        lerp(from.negativeCoeff_.y_, to.negativeCoeff_.y_, t),
        lerp(from.negativeCoeff_.z_, to.negativeCoeff_.z_, t));
    result.vibrancyStrength_ = lerp(from.vibrancyStrength_, to.vibrancyStrength_, t);
    result.lumaDiff_ = lerp(from.lumaDiff_, to.lumaDiff_, t);
    result.hdrEnabled_ = from.hdrEnabled_ && to.hdrEnabled_;
    result.tintedColorPercent_ = lerp(from.tintedColorPercent_, to.tintedColorPercent_, t);
    return result;
}

std::shared_ptr<Drawing::Blender> MakeColorfulBrightnessFromNG(
    const std::shared_ptr<RSNGRenderBlenderBase>& blender)
{
    return RSBlenderDrawableUtils::MakeColorfulBrightnessBlender(GetColorfulBrightnessPara(blender));
}

std::shared_ptr<Drawing::Blender> MakeBrightnessFromNG(
    const std::shared_ptr<RSNGRenderBlenderBase>& blender)
{
    auto brightnessBlender = std::static_pointer_cast<RSNGRenderBrightnessBlender>(blender);
    // rates_/posCoeff_/negCoeff_ pack multiple tags into Vector4f; coeff w is unused padding
    RSDynamicBrightnessPara params;
    params.fraction_ = brightnessBlender->Getter<BrightnessBlenderFractionRenderTag>()->Get();
    params.rates_ = Vector4f(brightnessBlender->Getter<BrightnessBlenderCubicRateRenderTag>()->Get(),
        brightnessBlender->Getter<BrightnessBlenderQuadRateRenderTag>()->Get(),
        brightnessBlender->Getter<BrightnessBlenderLinearRateRenderTag>()->Get(),
        brightnessBlender->Getter<BrightnessBlenderDegreeRenderTag>()->Get());
    params.saturation_ = brightnessBlender->Getter<BrightnessBlenderSaturationRenderTag>()->Get();
    const auto posCoeff = brightnessBlender->Getter<BrightnessBlenderPositiveCoeffRenderTag>()->Get();
    params.posCoeff_ = Vector4f(posCoeff.x_, posCoeff.y_, posCoeff.z_, 0.0f);
    const auto negCoeff = brightnessBlender->Getter<BrightnessBlenderNegativeCoeffRenderTag>()->Get();
    params.negCoeff_ = Vector4f(negCoeff.x_, negCoeff.y_, negCoeff.z_, 0.0f);
    params.enableHdr_ = brightnessBlender->Getter<BrightnessBlenderHdrEnabledRenderTag>()->Get();
    // fraction == 1.0 means no fg brightness effect (legacy IsFgBrightnessValid gate)
    if (ROSEN_EQ(params.fraction_, 1.0f)) {
        return nullptr;
    }
    return RSBlenderDrawableUtils::MakeDynamicBrightnessBlender(params);
}

std::shared_ptr<Drawing::Blender> MakeHdrDarkenFromNG(
    const std::shared_ptr<RSNGRenderBlenderBase>& blender)
{
    auto hdrDarkenBlender = std::static_pointer_cast<RSNGRenderHdrDarkenBlender>(blender);
    RSHdrDarkenBlenderPara params(hdrDarkenBlender->Getter<HdrDarkenBlenderHdrBrightnessRatioRenderTag>()->Get(),
        hdrDarkenBlender->Getter<HdrDarkenBlenderGrayscaleFactorRenderTag>()->Get());
    return RSBlenderDrawableUtils::MakeHdrDarkenBlender(params);
}

using BlenderMaker = std::function<std::shared_ptr<Drawing::Blender>(
    const std::shared_ptr<RSNGRenderBlenderBase>&)>;
const std::unordered_map<RSNGEffectType, BlenderMaker> blenderMakerLUT = {
    {RSNGEffectType::COLORFUL_BRIGHTNESS_BLENDER, MakeColorfulBrightnessFromNG},
    {RSNGEffectType::BRIGHTNESS_BLENDER, MakeBrightnessFromNG},
    {RSNGEffectType::HDR_DARKEN_BLENDER, MakeHdrDarkenFromNG},
};
} // namespace

std::shared_ptr<Drawing::RuntimeEffect> RSBlenderDrawableUtils::dynamicBrightnessBlenderEffect_ = nullptr;
std::shared_ptr<Drawing::RuntimeEffect> RSBlenderDrawableUtils::dynamicBrightnessLinearBlenderEffect_ = nullptr;
std::shared_ptr<Drawing::RuntimeEffect> RSBlenderDrawableUtils::hdrDarkenBlenderEffect_ = nullptr;

std::shared_ptr<Drawing::Blender> RSBlenderDrawableUtils::MakeBlenderFromNG(
    const std::shared_ptr<RSNGRenderBlenderBase>& blender)
{
    if (blender == nullptr) {
        return nullptr;
    }
    auto it = blenderMakerLUT.find(blender->GetType());
    if (it == blenderMakerLUT.end()) {
        // unregistered type falls back to the caller's blendMode path
        ROSEN_LOGE("RSBlenderDrawableUtils::MakeBlenderFromNG: no maker for NG blender type %{public}d",
            static_cast<int>(blender->GetType()));
        return nullptr;
    }
    return it->second(blender);
}

std::shared_ptr<Drawing::Blender> RSBlenderDrawableUtils::MakeAdaptiveBlenderFromNG(
    const std::shared_ptr<RSNGRenderBlenderBase>& darkBlender,
    const std::shared_ptr<RSNGRenderBlenderBase>& lightBlender, const float fraction)
{
    if (darkBlender == nullptr || lightBlender == nullptr) {
        return nullptr;
    }
    auto darkParams = GetColorfulBrightnessPara(darkBlender);
    auto lightParams = GetColorfulBrightnessPara(lightBlender);
    auto interpolated = LerpColorfulBrightnessPara(darkParams, lightParams, fraction);
    RS_OPTIONAL_TRACE_FMT("RSBlenderDrawableUtils::MakeAdaptiveBlenderFromNG fraction[%f]", fraction);
    return RSBlenderDrawableUtils::MakeColorfulBrightnessBlender(interpolated);
}

bool RSBlenderDrawableUtils::GetNGBlenderEnableEDR(const RSProperties& properties)
{
    const auto& ngBlender = properties.GetNGBlender();
    if (ngBlender != nullptr) {
        if (ngBlender->GetType() == RSNGEffectType::COLORFUL_BRIGHTNESS_BLENDER) {
            auto colorfulBlender = std::static_pointer_cast<RSNGRenderColorfulBrightnessBlender>(ngBlender);
            if (colorfulBlender->Getter<ColorfulBrightnessBlenderHdrEnabledRenderTag>()->Get()) {
                return true;
            }
        } else if (ngBlender->GetType() == RSNGEffectType::BRIGHTNESS_BLENDER) {
            auto brightnessBlender = std::static_pointer_cast<RSNGRenderBrightnessBlender>(ngBlender);
            if (brightnessBlender->Getter<BrightnessBlenderHdrEnabledRenderTag>()->Get()) {
                return true;
            }
        }
    }
    return GetNGAdaptiveBlenderEnableEDR(properties);
}

bool RSBlenderDrawableUtils::GetNGAdaptiveBlenderEnableEDR(const RSProperties& properties)
{
    const auto darkBlender = properties.GetNGAdaptiveDarkBlender();
    const auto lightBlender = properties.GetNGAdaptiveLightBlender();
    if (darkBlender == nullptr || lightBlender == nullptr) {
        return false;
    }
    auto darkColorful = std::static_pointer_cast<RSNGRenderColorfulBrightnessBlender>(darkBlender);
    auto lightColorful = std::static_pointer_cast<RSNGRenderColorfulBrightnessBlender>(lightBlender);
    return darkColorful->Getter<ColorfulBrightnessBlenderHdrEnabledRenderTag>()->Get() &&
        lightColorful->Getter<ColorfulBrightnessBlenderHdrEnabledRenderTag>()->Get();
}

std::shared_ptr<Drawing::Blender> RSBlenderDrawableUtils::MakeDynamicBrightnessBlender(
    const RSDynamicBrightnessPara& params)
{
    if (!RSSystemProperties::GetDynamicBrightnessEnabled()) {
        return nullptr;
    }

    std::shared_ptr<Drawing::RuntimeBlenderBuilder> builder;
    if (ROSEN_EQ(params.rates_.x_, 0.f) && ROSEN_EQ(params.rates_.y_, 0.f) && ROSEN_EQ(params.fraction_, 0.f)) {
        builder = MakeDynamicBrightnessLinearBuilder();
        ROSEN_LOGD("RSBlenderDrawableUtils::MakeDynamicBrightnessBlender equivalent blender in the linear case");
        if (!builder) {
            ROSEN_LOGE("RSBlenderDrawableUtils::MakeDynamicBrightnessBlender make linear builder fail");
            return nullptr;
        }
        // pre-process for pos and neg params
        float minusSat = 1.f - params.saturation_;
        bool swap = ROSEN_LE(minusSat, 0.f);
        const auto& posCoeffTmp = swap ? params.negCoeff_ : params.posCoeff_;
        const auto& negCoeffTmp = swap ? params.posCoeff_ : params.negCoeff_;
        builder->SetUniform("ubo_posr", posCoeffTmp.x_ * minusSat);
        builder->SetUniform("ubo_posg", posCoeffTmp.y_ * minusSat);
        builder->SetUniform("ubo_posb", posCoeffTmp.z_ * minusSat);
        builder->SetUniform("ubo_negr", negCoeffTmp.x_ * minusSat);
        builder->SetUniform("ubo_negg", negCoeffTmp.y_ * minusSat);
        builder->SetUniform("ubo_negb", negCoeffTmp.z_ * minusSat);
    } else {
        builder = MakeDynamicBrightnessBuilder();
        if (!builder) {
            ROSEN_LOGE("RSBlenderDrawableUtils::MakeDynamicBrightnessBlender make builder fail");
            return nullptr;
        }
        builder->SetUniform("ubo_fract", std::clamp(params.fraction_, 0.0f, 1.0f));
        builder->SetUniform("ubo_cubic", params.rates_.x_);
        builder->SetUniform("ubo_quad", params.rates_.y_);
        builder->SetUniform("ubo_baseSat", params.saturation_);
        builder->SetUniform("ubo_posr", params.posCoeff_.x_);
        builder->SetUniform("ubo_posg", params.posCoeff_.y_);
        builder->SetUniform("ubo_posb", params.posCoeff_.z_);
        builder->SetUniform("ubo_negr", params.negCoeff_.x_);
        builder->SetUniform("ubo_negg", params.negCoeff_.y_);
        builder->SetUniform("ubo_negb", params.negCoeff_.z_);
    }

    RS_OPTIONAL_TRACE_NAME("RSBlenderDrawableUtils::MakeDynamicBrightnessBlender");
    builder->SetUniform("ubo_rate", params.rates_.z_);
    builder->SetUniform("ubo_degree", params.rates_.w_);
    builder->SetUniform("ubo_headroom", params.enableHdr_ ? EFFECT_MAX_LUMINANCE : 1.0f);
    return builder->MakeBlender();
}

std::shared_ptr<Drawing::RuntimeBlenderBuilder> RSBlenderDrawableUtils::MakeDynamicBrightnessLinearBuilder()
{
    RS_OPTIONAL_TRACE_NAME("RSBlenderDrawableUtils::MakeDynamicBrightnessLinearBuilder");
    static constexpr char prog[] = R"(
        uniform half ubo_rate;
        uniform half ubo_degree;
        uniform half ubo_posr;
        uniform half ubo_posg;
        uniform half ubo_posb;
        uniform half ubo_negr;
        uniform half ubo_negg;
        uniform half ubo_negb;
        uniform half ubo_headroom;

        const half3 baseVec = half3(0.2412016, 0.6922296, 0.0665688);
        half3 sat(half3 inColor, half3 pos, half3 neg) {
            half3 delta = dot(inColor, baseVec) - inColor;
            half3 v = mix(neg, pos, step(0, delta));
            return clamp(inColor + delta * v, half3(0.0), half3(ubo_headroom));
        }

        half4 main(half4 src, half4 dst) {
            half2 coeff = half2(ubo_rate, ubo_degree);
            half3 color = coeff.x * dst.rgb + coeff.y * dst.a;
            half3 pos = half3(ubo_posr, ubo_posg, ubo_posb);
            half3 neg = half3(ubo_negr, ubo_negg, ubo_negb);
            color = sat(color, pos, neg);
            return half4(mix(dst.rgb, color, src.a), dst.a);
        }
    )";
    if (dynamicBrightnessLinearBlenderEffect_ == nullptr) {
        dynamicBrightnessLinearBlenderEffect_ = Drawing::RuntimeEffect::CreateForBlender(prog);
        if (dynamicBrightnessLinearBlenderEffect_ == nullptr) { return nullptr; }
    }
    return std::make_shared<Drawing::RuntimeBlenderBuilder>(dynamicBrightnessLinearBlenderEffect_);
}

std::shared_ptr<Drawing::RuntimeBlenderBuilder> RSBlenderDrawableUtils::MakeDynamicBrightnessBuilder()
{
    RS_OPTIONAL_TRACE_NAME("RSBlenderDrawableUtils::MakeDynamicBrightnessBuilder");
    static constexpr char prog[] = R"(
        uniform half ubo_fract;
        uniform half ubo_rate;
        uniform half ubo_degree;
        uniform half ubo_cubic;
        uniform half ubo_quad;
        uniform half ubo_baseSat;
        uniform half ubo_posr;
        uniform half ubo_posg;
        uniform half ubo_posb;
        uniform half ubo_negr;
        uniform half ubo_negg;
        uniform half ubo_negb;
        uniform half ubo_headroom;

        const vec3 baseVec = vec3(0.2412016, 0.6922296, 0.0665688);
        const half eps = 1e-5;
        half3 getUnpremulRGB(half4 color) {
            half factor = 1.0 / (max(color.a, eps));
            return saturate(color.rgb * factor);
        }
        half3 gray(half3 x, half4 coeff) {
            return coeff.x * x * x * x + coeff.y * x * x + coeff.z * x + coeff.w;
        }
        half3 sat(half3 inColor, half n, half3 pos, half3 neg) {
            half3 r = (1.0 - n) * inColor;
            half base = dot(r, baseVec);
            half3 delta = base - r;
            half3 v = mix(neg, pos, step(0, delta));
            return clamp(inColor + delta * v, half3(0.0), half3(ubo_headroom));
        }

        half4 main(half4 src, half4 dst) {
            half4 coeff = half4(ubo_cubic, ubo_quad, ubo_rate, ubo_degree);
            half3 color = gray(getUnpremulRGB(dst), coeff);
            half3 pos = half3(ubo_posr, ubo_posg, ubo_posb);
            half3 neg = half3(ubo_negr, ubo_negg, ubo_negb);
            color = sat(color, ubo_baseSat, pos, neg);
            color = mix(color, getUnpremulRGB(src), ubo_fract);
            return half4(mix(dst.rgb, color * dst.a, src.a), dst.a);
        }
    )";
    if (dynamicBrightnessBlenderEffect_ == nullptr) {
        dynamicBrightnessBlenderEffect_ = Drawing::RuntimeEffect::CreateForBlender(prog);
        if (dynamicBrightnessBlenderEffect_ == nullptr) { return nullptr; }
    }
    return std::make_shared<Drawing::RuntimeBlenderBuilder>(dynamicBrightnessBlenderEffect_);
}

std::shared_ptr<Drawing::Blender> RSBlenderDrawableUtils::MakeHdrDarkenBlender(const RSHdrDarkenBlenderPara& params)
{
    static constexpr char prog[] = R"(
        uniform float hdrBrightnessRatio;
        uniform float grayscaleFactors_r;
        uniform float grayscaleFactors_g;
        uniform float grayscaleFactors_b;

        half4 main(half4 srcColor, half4 dstColor) {
            // 1. calc darken result (a=1), original Darken algorithm
            float3 darkenRGB = srcColor.rgb + dstColor.rgb - max(srcColor.rgb * dstColor.a, dstColor.rgb * srcColor.a);
            // 2. calc hdr_extra, extracting colors from HDR layers
            float uMaxVal = pow(1 / hdrBrightnessRatio, 1 / 2.2);
            vec3 hdrExtraRGB = max(srcColor.rgb - uMaxVal * srcColor.a, vec3(0.0));
            // 3. add darken_result and hdr_extra
            vec3 grayscaleFactors = vec3(grayscaleFactors_r, grayscaleFactors_g, grayscaleFactors_b);
            float s = dot(dstColor.rgb / uMaxVal, grayscaleFactors);

            hdrExtraRGB *= s;
            float alpha = srcColor.a + dstColor.a * (1 - srcColor.a);
            return half4(darkenRGB + hdrExtraRGB, alpha);
        }
    )";
    if (hdrDarkenBlenderEffect_ == nullptr) {
        hdrDarkenBlenderEffect_ = Drawing::RuntimeEffect::CreateForBlender(prog);
    }
    std::shared_ptr<Drawing::RuntimeBlenderBuilder> builder =
        std::make_shared<Drawing::RuntimeBlenderBuilder>(hdrDarkenBlenderEffect_);
    if (!builder) {
        ROSEN_LOGE("RSBlenderDrawableUtils::MakeHdrDarkenBlender make builder fail");
        return nullptr;
    }
    builder->SetUniform("hdrBrightnessRatio", params.hdrBrightnessRatio_);
    builder->SetUniform("grayscaleFactors_r", params.grayscaleFactor_.x_);
    builder->SetUniform("grayscaleFactors_g", params.grayscaleFactor_.y_);
    builder->SetUniform("grayscaleFactors_b", params.grayscaleFactor_.z_);
    RS_OPTIONAL_TRACE_FMT("RSBlenderDrawableUtils::MakeHdrDarkenBlender params[%f,%f,%f,%f]",
        params.hdrBrightnessRatio_, params.grayscaleFactor_.x_, params.grayscaleFactor_.y_, params.grayscaleFactor_.z_);
    return builder->MakeBlender();
}

std::shared_ptr<Drawing::Blender> RSBlenderDrawableUtils::MakeColorfulBrightnessBlender(
    const RSColorfulBrightnessBlenderPara& params)
{
    static thread_local auto colorfulBrightnessBlenderEffect =
        Drawing::RuntimeEffect::CreateForBlender(COLORFUL_BRIGHTNESS_BLENDER_PROG);
    if (colorfulBrightnessBlenderEffect == nullptr) {
        ROSEN_LOGE("RSBlenderDrawableUtils::MakeColorfulBrightnessBlender create effect fail");
        return nullptr;
    }
    std::shared_ptr<Drawing::RuntimeBlenderBuilder> builder =
        std::make_shared<Drawing::RuntimeBlenderBuilder>(colorfulBrightnessBlenderEffect);
    constexpr float PENETRATION_RATIO = 0.1538f;
    auto mixF = [](float x, float y, float t) { return x * (1.0f - t) + y * t; };
    float vs = params.vibrancyStrength_;
    float activeRatesX = mixF(0.0f, params.cubicRate_, vs);
    float activeRatesY = mixF(0.0f, params.quadRate_, vs);
    float activeKBSx = mixF(1.0f, params.linearRate_, vs);
    float activeKBSy = mixF(0.0f, params.degree_, vs);
    float activeKBSz = mixF(1.0f, params.saturation_, vs);
    float activePosX = mixF(0.0f, params.positiveCoeff_.x_, vs);
    float activePosY = mixF(0.0f, params.positiveCoeff_.y_, vs);
    float activePosZ = mixF(0.0f, params.positiveCoeff_.z_, vs);
    float activeNegX = mixF(0.0f, params.negativeCoeff_.x_, vs);
    float activeNegY = mixF(0.0f, params.negativeCoeff_.y_, vs);
    float activeNegZ = mixF(0.0f, params.negativeCoeff_.z_, vs);

    builder->SetUniform("darkenWeight", params.darkenWeight_);
    builder->SetUniform("fraction", params.fraction_);
    builder->SetUniform("activeRatesX", activeRatesX);
    builder->SetUniform("activeRatesY", activeRatesY);
    builder->SetUniform("activeKBSx", activeKBSx);
    builder->SetUniform("activeKBSy", activeKBSy);
    builder->SetUniform("activeKBSz", activeKBSz);
    builder->SetUniform("activePosX", activePosX);
    builder->SetUniform("activePosY", activePosY);
    builder->SetUniform("activePosZ", activePosZ);
    builder->SetUniform("activeNegX", activeNegX);
    builder->SetUniform("activeNegY", activeNegY);
    builder->SetUniform("activeNegZ", activeNegZ);
    builder->SetUniform("lumaDiff", params.lumaDiff_);
    builder->SetUniform("colorLimit", params.hdrEnabled_ ? 2.0f : 1.0f);
    builder->SetUniform("tintedColorPercent", params.tintedColorPercent_);
    builder->SetUniform("penetration", PENETRATION_RATIO * params.darkenWeight_);
    RS_OPTIONAL_TRACE_FMT("RSBlenderDrawableUtils::MakeColorfulBrightnessBlender dw=%f,fr=%f,vs=%f",
        params.darkenWeight_, params.fraction_, params.vibrancyStrength_);
    return builder->MakeBlender();
}

bool RSBlenderDrawableUtils::IsDangerousBlendMode(int blendMode, int blendApplyType)
{
    static const uint32_t fastDangerousBit =
        (1 << static_cast<int>(Drawing::BlendMode::CLEAR)) +
        (1 << static_cast<int>(Drawing::BlendMode::SRC_OUT)) +
        (1 << static_cast<int>(Drawing::BlendMode::DST_OUT)) +
        (1 << static_cast<int>(Drawing::BlendMode::XOR));
    static const uint32_t offscreenDangerousBit =
        (1 << static_cast<int>(Drawing::BlendMode::CLEAR)) +
        (1 << static_cast<int>(Drawing::BlendMode::SRC)) +
        (1 << static_cast<int>(Drawing::BlendMode::SRC_IN)) +
        (1 << static_cast<int>(Drawing::BlendMode::DST_IN)) +
        (1 << static_cast<int>(Drawing::BlendMode::SRC_OUT)) +
        (1 << static_cast<int>(Drawing::BlendMode::DST_OUT)) +
        (1 << static_cast<int>(Drawing::BlendMode::DST_ATOP)) +
        (1 << static_cast<int>(Drawing::BlendMode::XOR)) +
        (1 << static_cast<int>(Drawing::BlendMode::MODULATE));
    uint32_t tmp = 1 << blendMode;
    if (blendApplyType == static_cast<int>(RSColorBlendApplyType::FAST)) {
        return tmp & fastDangerousBit;
    }
    return tmp & offscreenDangerousBit;
}

void RSBlenderDrawableUtils::BeginBlender(RSPaintFilterCanvas& canvas,
    std::shared_ptr<Drawing::Blender> blender, int blendModeApplyType, bool isDangerous)
{
    if (isDangerous && !canvas.HasOffscreenLayer()) {
        Drawing::SaveLayerOps maskLayerRec(nullptr, nullptr, 0);
        canvas.SaveLayer(maskLayerRec);
        ROSEN_LOGD("Dangerous offscreen blendmode may produce transparent pixels, add extra offscreen here.");
    }

    // fast blender
    if (blendModeApplyType == static_cast<int>(RSColorBlendApplyType::FAST)) {
        canvas.SetBlender(blender);
        return;
    }

    // save layer mode
    Drawing::Brush blendBrush_;

    // The savelayer in the RSPaintFilterCanvas will automatically apply alpha to the brush.
    // If the alpha of the canvas is set to the brush here, the final transparency will be
    // alpha * alpha, not alpha.
    if (blendModeApplyType == static_cast<int>(RSColorBlendApplyType::SAVE_LAYER_ALPHA)) {
        blendBrush_.SetAlphaF(canvas.GetAlpha());
    }
    blendBrush_.SetBlender(blender);
    uint32_t saveLayerFlag = 0;
    if (blendModeApplyType == static_cast<int>(RSColorBlendApplyType::SAVE_LAYER_INIT_WITH_PREVIOUS_CONTENT)) {
        // currently we only support DDGR backend, we thus use 1 << 1 as indicated in their code.
        saveLayerFlag = 1 << 1;
    }
    Drawing::SaveLayerOps maskLayerRec(nullptr, &blendBrush_, saveLayerFlag);
    canvas.SaveLayer(maskLayerRec);
    canvas.SetBlender(nullptr);
    canvas.SaveAlpha();
    canvas.SetAlpha(1.0f);
}

void RSBlenderDrawableUtils::EndBlender(RSPaintFilterCanvas& canvas, int blendModeApplyType)
{
    // RSRenderNodeDrawable will do other necessary work (restore canvas & env), we only need to restore alpha
    if (blendModeApplyType != static_cast<int>(RSColorBlendApplyType::FAST)) {
        canvas.RestoreAlpha();
    }
}
} // namespace OHOS::Rosen
