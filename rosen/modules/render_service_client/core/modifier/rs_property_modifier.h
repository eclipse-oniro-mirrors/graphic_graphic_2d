/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#ifndef RENDER_SERVICE_CLIENT_CORE_MODIFIER_RS_PROPERTY_MODIFIER_H
#define RENDER_SERVICE_CLIENT_CORE_MODIFIER_RS_PROPERTY_MODIFIER_H

#include "modifier/rs_modifier.h"

namespace OHOS {
namespace Rosen {
class RSC_EXPORT RSBoundsModifier : public RSGeometryModifier {
public:
    explicit RSBoundsModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSBoundsModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
    void Apply(const std::shared_ptr<RSObjAbsGeometry>& geometry) override;
};

class RSC_EXPORT RSBoundsSizeModifier : public RSGeometryModifier {
public:
    explicit RSBoundsSizeModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSBoundsSizeModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
    void Apply(const std::shared_ptr<RSObjAbsGeometry>& geometry) override;
};

class RSC_EXPORT RSBoundsPositionModifier : public RSGeometryModifier {
public:
    explicit RSBoundsPositionModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSBoundsPositionModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
    void Apply(const std::shared_ptr<RSObjAbsGeometry>& geometry) override;
};

class RSC_EXPORT RSFrameModifier : public RSGeometryModifier {
public:
    explicit RSFrameModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSFrameModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSPositionZModifier : public RSGeometryModifier {
public:
    explicit RSPositionZModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSPositionZModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSSandBoxModifier : public RSGeometryModifier {
public:
    explicit RSSandBoxModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSSandBoxModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSPivotModifier : public RSGeometryModifier {
public:
    explicit RSPivotModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSPivotModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
    void Apply(const std::shared_ptr<RSObjAbsGeometry>& geometry) override;
};

class RSC_EXPORT RSPivotZModifier : public RSGeometryModifier {
public:
    explicit RSPivotZModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSPivotZModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
    void Apply(const std::shared_ptr<RSObjAbsGeometry>& geometry) override;
};

class RSC_EXPORT RSQuaternionModifier : public RSGeometryModifier {
public:
    explicit RSQuaternionModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSQuaternionModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
    void Apply(const std::shared_ptr<RSObjAbsGeometry>& geometry) override;
};

class RSC_EXPORT RSRotationModifier : public RSGeometryModifier {
public:
    explicit RSRotationModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSRotationModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
    void Apply(const std::shared_ptr<RSObjAbsGeometry>& geometry) override;
};

class RSC_EXPORT RSRotationXModifier : public RSGeometryModifier {
public:
    explicit RSRotationXModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSRotationXModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
    void Apply(const std::shared_ptr<RSObjAbsGeometry>& geometry) override;
};

class RSC_EXPORT RSRotationYModifier : public RSGeometryModifier {
public:
    explicit RSRotationYModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSRotationYModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
    void Apply(const std::shared_ptr<RSObjAbsGeometry>& geometry) override;
};

class RSC_EXPORT RSCameraDistanceModifier : public RSGeometryModifier {
public:
    explicit RSCameraDistanceModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSCameraDistanceModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
    void Apply(const std::shared_ptr<RSObjAbsGeometry>& geometry) override;
};

class RSC_EXPORT RSScaleModifier : public RSGeometryModifier {
public:
    explicit RSScaleModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSScaleModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
    void Apply(const std::shared_ptr<RSObjAbsGeometry>& geometry) override;
};

class RSC_EXPORT RSSkewModifier : public RSGeometryModifier {
public:
    explicit RSSkewModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSSkewModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
    void Apply(const std::shared_ptr<RSObjAbsGeometry>& geometry) override;
};

class RSC_EXPORT RSPerspModifier : public RSGeometryModifier {
public:
    explicit RSPerspModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSPerspModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
    void Apply(const std::shared_ptr<RSObjAbsGeometry>& geometry) override;
};

class RSC_EXPORT RSTranslateModifier : public RSGeometryModifier {
public:
    explicit RSTranslateModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSTranslateModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
    void Apply(const std::shared_ptr<RSObjAbsGeometry>& geometry) override;
};

class RSC_EXPORT RSTranslateZModifier : public RSGeometryModifier {
public:
    explicit RSTranslateZModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSTranslateZModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
    void Apply(const std::shared_ptr<RSObjAbsGeometry>& geometry) override;
};

class RSC_EXPORT RSCornerRadiusModifier : public RSAppearanceModifier {
public:
    explicit RSCornerRadiusModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSCornerRadiusModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSAlphaModifier : public RSAppearanceModifier {
public:
    explicit RSAlphaModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSAlphaModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSAlphaOffscreenModifier : public RSAppearanceModifier {
public:
    explicit RSAlphaOffscreenModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSAlphaOffscreenModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RS_EXPORT RSEnvForegroundColorModifier : public RSForegroundModifier {
public:
    explicit RSEnvForegroundColorModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSEnvForegroundColorModifier() = default;

protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RS_EXPORT RSEnvForegroundColorStrategyModifier : public RSForegroundModifier {
public:
    explicit RSEnvForegroundColorStrategyModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSEnvForegroundColorStrategyModifier() = default;

protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSForegroundColorModifier : public RSForegroundModifier {
public:
    explicit RSForegroundColorModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSForegroundColorModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSUseShadowBatchingModifier : public RSBackgroundModifier {
public:
    explicit RSUseShadowBatchingModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSUseShadowBatchingModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSBackgroundColorModifier : public RSBackgroundModifier {
public:
    explicit RSBackgroundColorModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSBackgroundColorModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSBackgroundShaderModifier : public RSBackgroundModifier {
public:
    explicit RSBackgroundShaderModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSBackgroundShaderModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSBgImageModifier : public RSBackgroundModifier {
public:
    explicit RSBgImageModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSBgImageModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSBgImageInnerRectModifier : public RSBackgroundModifier {
public:
    explicit RSBgImageInnerRectModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSBgImageInnerRectModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSBgImageWidthModifier : public RSBackgroundModifier {
public:
    explicit RSBgImageWidthModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSBgImageWidthModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSBgImageHeightModifier : public RSBackgroundModifier {
public:
    explicit RSBgImageHeightModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSBgImageHeightModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSBgImagePositionXModifier : public RSBackgroundModifier {
public:
    explicit RSBgImagePositionXModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSBgImagePositionXModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSBgImagePositionYModifier : public RSBackgroundModifier {
public:
    explicit RSBgImagePositionYModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSBgImagePositionYModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSBorderColorModifier : public RSForegroundModifier {
public:
    explicit RSBorderColorModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSBorderColorModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSBorderWidthModifier : public RSForegroundModifier {
public:
    explicit RSBorderWidthModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSBorderWidthModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSBorderStyleModifier : public RSForegroundModifier {
public:
    explicit RSBorderStyleModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSBorderStyleModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSBorderDashWidthModifier : public RSForegroundModifier {
public:
    explicit RSBorderDashWidthModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSBorderDashWidthModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSBorderDashGapModifier : public RSForegroundModifier {
public:
    explicit RSBorderDashGapModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSBorderDashGapModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSOutlineColorModifier : public RSForegroundModifier {
public:
    explicit RSOutlineColorModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSOutlineColorModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSOutlineWidthModifier : public RSForegroundModifier {
public:
    explicit RSOutlineWidthModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSOutlineWidthModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSOutlineDashWidthModifier : public RSForegroundModifier {
public:
    explicit RSOutlineDashWidthModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSOutlineDashWidthModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSOutlineDashGapModifier : public RSForegroundModifier {
public:
    explicit RSOutlineDashGapModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSOutlineDashGapModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSOutlineStyleModifier : public RSForegroundModifier {
public:
    explicit RSOutlineStyleModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSOutlineStyleModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSOutlineRadiusModifier : public RSForegroundModifier {
public:
    explicit RSOutlineRadiusModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSOutlineRadiusModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSForegroundEffectRadiusModifier : public RSForegroundModifier {
public:
    explicit RSForegroundEffectRadiusModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSForegroundEffectRadiusModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSFilterModifier : public RSForegroundModifier {
public:
    explicit RSFilterModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSFilterModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSBackgroundBlurRadiusModifier : public RSBackgroundModifier {
public:
    explicit RSBackgroundBlurRadiusModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSBackgroundBlurRadiusModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSBackgroundBlurSaturationModifier : public RSBackgroundModifier {
public:
    explicit RSBackgroundBlurSaturationModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSBackgroundBlurSaturationModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSBackgroundBlurBrightnessModifier : public RSBackgroundModifier {
public:
    explicit RSBackgroundBlurBrightnessModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSBackgroundBlurBrightnessModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSBackgroundBlurMaskColorModifier : public RSBackgroundModifier {
public:
    explicit RSBackgroundBlurMaskColorModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSBackgroundBlurMaskColorModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSBackgroundBlurColorModeModifier : public RSBackgroundModifier {
public:
    explicit RSBackgroundBlurColorModeModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSBackgroundBlurColorModeModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSBackgroundBlurRadiusXModifier : public RSBackgroundModifier {
public:
    explicit RSBackgroundBlurRadiusXModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSBackgroundBlurRadiusXModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSBackgroundBlurRadiusYModifier : public RSBackgroundModifier {
public:
    explicit RSBackgroundBlurRadiusYModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSBackgroundBlurRadiusYModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSForegroundBlurRadiusModifier : public RSForegroundModifier {
public:
    explicit RSForegroundBlurRadiusModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSForegroundBlurRadiusModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSForegroundBlurSaturationModifier : public RSForegroundModifier {
public:
    explicit RSForegroundBlurSaturationModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSForegroundBlurSaturationModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSForegroundBlurBrightnessModifier : public RSForegroundModifier {
public:
    explicit RSForegroundBlurBrightnessModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSForegroundBlurBrightnessModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSForegroundBlurMaskColorModifier : public RSForegroundModifier {
public:
    explicit RSForegroundBlurMaskColorModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSForegroundBlurMaskColorModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSForegroundBlurColorModeModifier : public RSForegroundModifier {
 public:
    explicit RSForegroundBlurColorModeModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSForegroundBlurColorModeModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSForegroundBlurRadiusXModifier : public RSForegroundModifier {
public:
    explicit RSForegroundBlurRadiusXModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSForegroundBlurRadiusXModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSForegroundBlurRadiusYModifier : public RSForegroundModifier {
public:
    explicit RSForegroundBlurRadiusYModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSForegroundBlurRadiusYModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSLightUpEffectModifier : public RSForegroundModifier {
public:
    explicit RSLightUpEffectModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSLightUpEffectModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSDynamicLightUpRateModifier : public RSForegroundModifier {
public:
    explicit RSDynamicLightUpRateModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSDynamicLightUpRateModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSDynamicLightUpDegreeModifier : public RSForegroundModifier {
public:
    explicit RSDynamicLightUpDegreeModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSDynamicLightUpDegreeModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSWaterRippleParamsModifier : public RSBackgroundModifier {
public:
    explicit RSWaterRippleParamsModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSWaterRippleParamsModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};
 
class RSC_EXPORT RSWaterRippleProgressModifier : public RSBackgroundModifier {
public:
    explicit RSWaterRippleProgressModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSWaterRippleProgressModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSFlyOutParamsModifier : public RSForegroundModifier {
public:
    explicit RSFlyOutParamsModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSFlyOutParamsModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};
 
class RSC_EXPORT RSFlyOutDegreeModifier : public RSForegroundModifier {
public:
    explicit RSFlyOutDegreeModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSFlyOutDegreeModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSFgBrightnessRatesModifier : public RSForegroundModifier {
public:
    explicit RSFgBrightnessRatesModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSFgBrightnessRatesModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSFgBrightnessSaturationModifier : public RSForegroundModifier {
public:
    explicit RSFgBrightnessSaturationModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSFgBrightnessSaturationModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSFgBrightnessPosCoeffModifier : public RSForegroundModifier {
public:
    explicit RSFgBrightnessPosCoeffModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSFgBrightnessPosCoeffModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSFgBrightnessNegCoeffModifier : public RSForegroundModifier {
public:
    explicit RSFgBrightnessNegCoeffModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSFgBrightnessNegCoeffModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};
 
class RSC_EXPORT RSFgBrightnessFractModifier : public RSForegroundModifier {
public:
    explicit RSFgBrightnessFractModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSFgBrightnessFractModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};
 
class RSC_EXPORT RSBgBrightnessRatesModifier : public RSBackgroundModifier {
public:
    explicit RSBgBrightnessRatesModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSBgBrightnessRatesModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSBgBrightnessSaturationModifier : public RSBackgroundModifier {
public:
    explicit RSBgBrightnessSaturationModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSBgBrightnessSaturationModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSBgBrightnessPosCoeffModifier : public RSBackgroundModifier {
public:
    explicit RSBgBrightnessPosCoeffModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSBgBrightnessPosCoeffModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSBgBrightnessNegCoeffModifier : public RSBackgroundModifier {
public:
    explicit RSBgBrightnessNegCoeffModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSBgBrightnessNegCoeffModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};
 
class RSC_EXPORT RSBgBrightnessFractModifier : public RSBackgroundModifier {
public:
    explicit RSBgBrightnessFractModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSBgBrightnessFractModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSEmitterUpdaterModifier : public RSForegroundModifier {
public:
    explicit RSEmitterUpdaterModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSEmitterUpdaterModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSParticleNoiseFieldsModifier : public RSForegroundModifier {
public:
    explicit RSParticleNoiseFieldsModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSParticleNoiseFieldsModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSDynamicDimDegreeModifier : public RSForegroundModifier {
public:
    explicit RSDynamicDimDegreeModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSDynamicDimDegreeModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSLinearGradientBlurParaModifier : public RSForegroundModifier {
public:
    explicit RSLinearGradientBlurParaModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSLinearGradientBlurParaModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSMotionBlurParaModifier : public RSForegroundModifier {
public:
    explicit RSMotionBlurParaModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSMotionBlurParaModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSMagnifierParamsModifier : public RSForegroundModifier {
public:
    explicit RSMagnifierParamsModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSMagnifierParamsModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSBackgroundFilterModifier : public RSBackgroundModifier {
public:
    explicit RSBackgroundFilterModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSBackgroundFilterModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSFrameGravityModifier : public RSAppearanceModifier {
public:
    explicit RSFrameGravityModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSFrameGravityModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSClipRRectModifier : public RSAppearanceModifier {
public:
    explicit RSClipRRectModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSClipRRectModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSClipBoundsModifier : public RSAppearanceModifier {
public:
    explicit RSClipBoundsModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSClipBoundsModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSClipToBoundsModifier : public RSAppearanceModifier {
public:
    explicit RSClipToBoundsModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSClipToBoundsModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSClipToFrameModifier : public RSAppearanceModifier {
public:
    explicit RSClipToFrameModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSClipToFrameModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSVisibleModifier : public RSAppearanceModifier {
public:
    explicit RSVisibleModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSVisibleModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSSpherizeModifier : public RSAppearanceModifier {
public:
    explicit RSSpherizeModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSSpherizeModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSAttractionFractionModifier : public RSAppearanceModifier {
public:
    explicit RSAttractionFractionModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSAttractionFractionModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSAttractionDstPointModifier : public RSAppearanceModifier {
public:
    explicit RSAttractionDstPointModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSAttractionDstPointModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSShadowColorModifier : public RSBackgroundModifier {
public:
    explicit RSShadowColorModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSShadowColorModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSShadowOffsetXModifier : public RSBackgroundModifier {
public:
    explicit RSShadowOffsetXModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSShadowOffsetXModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSShadowOffsetYModifier : public RSBackgroundModifier {
public:
    explicit RSShadowOffsetYModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSShadowOffsetYModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSShadowAlphaModifier : public RSBackgroundModifier {
public:
    explicit RSShadowAlphaModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSShadowAlphaModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSShadowElevationModifier : public RSBackgroundModifier {
public:
    explicit RSShadowElevationModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSShadowElevationModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSShadowRadiusModifier : public RSBackgroundModifier {
public:
    explicit RSShadowRadiusModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSShadowRadiusModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSShadowPathModifier : public RSBackgroundModifier {
public:
    explicit RSShadowPathModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSShadowPathModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSShadowMaskModifier : public RSBackgroundModifier {
public:
    explicit RSShadowMaskModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSShadowMaskModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSShadowIsFilledModifier : public RSBackgroundModifier {
public:
    explicit RSShadowIsFilledModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSShadowIsFilledModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSGreyCoefModifier : public RSBackgroundModifier {
public:
    explicit RSGreyCoefModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSGreyCoefModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSMaskModifier : public RSForegroundModifier {
public:
    explicit RSMaskModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSMaskModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSPixelStretchModifier : public RSGeometryModifier {
public:
    explicit RSPixelStretchModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSPixelStretchModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSPixelStretchPercentModifier : public RSGeometryModifier {
public:
    explicit RSPixelStretchPercentModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSPixelStretchPercentModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSPixelStretchTileModeModifier : public RSGeometryModifier {
public:
    explicit RSPixelStretchTileModeModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSPixelStretchTileModeModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSGrayScaleModifier : public RSForegroundModifier {
public:
    explicit RSGrayScaleModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSGrayScaleModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSLightIntensityModifier : public RSForegroundModifier {
public:
    explicit RSLightIntensityModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSLightIntensityModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSLightColorModifier : public RSForegroundModifier {
public:
    explicit RSLightColorModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSLightColorModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSIlluminatedTypeModifier : public RSForegroundModifier {
public:
    explicit RSIlluminatedTypeModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSIlluminatedTypeModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSLightPositionModifier : public RSForegroundModifier {
public:
    explicit RSLightPositionModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSLightPositionModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSIlluminatedBorderWidthModifier : public RSForegroundModifier {
public:
    explicit RSIlluminatedBorderWidthModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSIlluminatedBorderWidthModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSBloomModifier : public RSForegroundModifier {
public:
    explicit RSBloomModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSBloomModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSBrightnessModifier : public RSForegroundModifier {
public:
    explicit RSBrightnessModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSBrightnessModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSContrastModifier : public RSForegroundModifier {
public:
    explicit RSContrastModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSContrastModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSSaturateModifier : public RSForegroundModifier {
public:
    explicit RSSaturateModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSSaturateModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSSepiaModifier : public RSForegroundModifier {
public:
    explicit RSSepiaModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSSepiaModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSInvertModifier : public RSForegroundModifier {
public:
    explicit RSInvertModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSInvertModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSAiInvertModifier : public RSForegroundModifier {
public:
    explicit RSAiInvertModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSAiInvertModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSSystemBarEffectModifier : public RSBackgroundModifier {
public:
    explicit RSSystemBarEffectModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSSystemBarEffectModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSHueRotateModifier : public RSForegroundModifier {
public:
    explicit RSHueRotateModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSHueRotateModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSColorBlendModifier : public RSForegroundModifier {
public:
    explicit RSColorBlendModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSColorBlendModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSUseEffectModifier : public RSBackgroundModifier {
public:
    explicit RSUseEffectModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSUseEffectModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSColorBlendModeModifier : public RSBackgroundModifier {
public:
    explicit RSColorBlendModeModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSColorBlendModeModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSColorBlendApplyTypeModifier : public RSBackgroundModifier {
public:
    explicit RSColorBlendApplyTypeModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSColorBlendApplyTypeModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};

class RSC_EXPORT RSShadowColorStrategyModifier : public RSBackgroundModifier {
public:
    explicit RSShadowColorStrategyModifier(const std::shared_ptr<RSPropertyBase>& property);
    virtual ~RSShadowColorStrategyModifier() = default;
protected:
    RSModifierType GetModifierType() const override;
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() const override;
};
} // namespace Rosen
} // namespace OHOS

#endif // RENDER_SERVICE_CLIENT_CORE_MODIFIER_RS_PROPERTY_MODIFIER_H
