/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef RENDER_SERVICE_CLIENT_CORE_ANIMATION_RS_MODIFIER_H
#define RENDER_SERVICE_CLIENT_CORE_ANIMATION_RS_MODIFIER_H

#include "modifier/rs_modifier_base.h"

namespace OHOS {
namespace Rosen {
// declare RenderModifiers like RSBoundsModifier
class RS_EXPORT RSBoundsModifier : public RSAnimatableModifier<Vector4f> {
public:
    RSBoundsModifier(const std::shared_ptr<RSProperty<Vector4f>> property);
    virtual ~RSBoundsModifier() = default;
    void Draw(RSDrawingContext& context) override {}
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() override;
    RSModifierType GetModifierType() override;
};

class RS_EXPORT RSBoundsSizeModifier : public RSAnimatableModifier<Vector2f> {
public:
    RSBoundsSizeModifier(const std::shared_ptr<RSProperty<Vector2f>> property);
    virtual ~RSBoundsSizeModifier() = default;
    void Draw(RSDrawingContext& context) override {}
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() override;
    RSModifierType GetModifierType() override;
};

class RS_EXPORT RSBoundsPositionModifier : public RSAnimatableModifier<Vector2f> {
public:
    RSBoundsPositionModifier(const std::shared_ptr<RSProperty<Vector2f>> property);
    virtual ~RSBoundsPositionModifier() = default;
    void Draw(RSDrawingContext& context) override {}
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() override;
    RSModifierType GetModifierType() override;
};

class RS_EXPORT RSFrameModifier : public RSAnimatableModifier<Vector4f> {
public:
    RSFrameModifier(const std::shared_ptr<RSProperty<Vector4f>> property);
    virtual ~RSFrameModifier() = default;
    void Draw(RSDrawingContext& context) override {}
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() override;
    RSModifierType GetModifierType() override;
};

class RS_EXPORT RSPositionZModifier : public RSAnimatableModifier<float> {
public:
    RSPositionZModifier(const std::shared_ptr<RSProperty<float>> property);
    virtual ~RSPositionZModifier() = default;
    void Draw(RSDrawingContext& context) override {}
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() override;
    RSModifierType GetModifierType() override;
};

class RS_EXPORT RSPivotModifier : public RSAnimatableModifier<Vector2f> {
public:
    RSPivotModifier(const std::shared_ptr<RSProperty<Vector2f>> property);
    virtual ~RSPivotModifier() = default;
    void Draw(RSDrawingContext& context) override {}
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() override;
    RSModifierType GetModifierType() override;
};

class RS_EXPORT RSQuaternionModifier : public RSAnimatableModifier<Quaternion> {
public:
    RSQuaternionModifier(const std::shared_ptr<RSProperty<Quaternion>> property);
    virtual ~RSQuaternionModifier() = default;
    void Draw(RSDrawingContext& context) override {}
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() override;
    RSModifierType GetModifierType() override;
};

class RS_EXPORT RSRotationModifier : public RSAnimatableModifier<float> {
public:
    RSRotationModifier(const std::shared_ptr<RSProperty<float>> property);
    virtual ~RSRotationModifier() = default;
    void Draw(RSDrawingContext& context) override {}
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() override;
    RSModifierType GetModifierType() override;
};

class RS_EXPORT RSRotationXModifier : public RSAnimatableModifier<float> {
public:
    RSRotationXModifier(const std::shared_ptr<RSProperty<float>> property);
    virtual ~RSRotationXModifier() = default;
    void Draw(RSDrawingContext& context) override {}
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() override;
    RSModifierType GetModifierType() override;
};

class RS_EXPORT RSRotationYModifier : public RSAnimatableModifier<float> {
public:
    RSRotationYModifier(const std::shared_ptr<RSProperty<float>> property);
    virtual ~RSRotationYModifier() = default;
    void Draw(RSDrawingContext& context) override {}
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() override;
    RSModifierType GetModifierType() override;
};

class RS_EXPORT RSScaleModifier : public RSAnimatableModifier<Vector2f> {
public:
    RSScaleModifier(const std::shared_ptr<RSProperty<Vector2f>> property);
    virtual ~RSScaleModifier() = default;
    void Draw(RSDrawingContext& context) override {}
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() override;
    RSModifierType GetModifierType() override;
};

class RS_EXPORT RSTranslateModifier : public RSAnimatableModifier<Vector2f> {
public:
    RSTranslateModifier(const std::shared_ptr<RSProperty<Vector2f>> property);
    virtual ~RSTranslateModifier() = default;
    void Draw(RSDrawingContext& context) override {}
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() override;
    RSModifierType GetModifierType() override;
};

class RS_EXPORT RSTranslateZModifier : public RSAnimatableModifier<float> {
public:
    RSTranslateZModifier(const std::shared_ptr<RSProperty<float>> property);
    virtual ~RSTranslateZModifier() = default;
    void Draw(RSDrawingContext& context) override {}
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() override;
    RSModifierType GetModifierType() override;
};

class RS_EXPORT RSCornerRadiusModifier : public RSAnimatableModifier<Vector4f> {
public:
    RSCornerRadiusModifier(const std::shared_ptr<RSProperty<Vector4f>> property);
    virtual ~RSCornerRadiusModifier() = default;
    void Draw(RSDrawingContext& context) override {}
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() override;
    RSModifierType GetModifierType() override;
};

class RS_EXPORT RSAlphaModifier : public RSAnimatableModifier<float> {
public:
    RSAlphaModifier(const std::shared_ptr<RSProperty<float>> property);
    virtual ~RSAlphaModifier() = default;
    void Draw(RSDrawingContext& context) override {}
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() override;
    RSModifierType GetModifierType() override;
};

class RS_EXPORT RSForegroundColorModifier : public RSAnimatableModifier<Color> {
public:
    RSForegroundColorModifier(const std::shared_ptr<RSProperty<Color>> property);
    virtual ~RSForegroundColorModifier() = default;
    void Draw(RSDrawingContext& context) override {}
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() override;
    RSModifierType GetModifierType() override;
};

class RS_EXPORT RSBackgroundColorModifier : public RSAnimatableModifier<Color> {
public:
    RSBackgroundColorModifier(const std::shared_ptr<RSProperty<Color>> property);
    virtual ~RSBackgroundColorModifier() = default;
    void Draw(RSDrawingContext& context) override {}
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() override;
    RSModifierType GetModifierType() override;
};

class RS_EXPORT RSBackgroundShaderModifier : public RSAnimatableModifier<std::shared_ptr<RSShader>> {
public:
    RSBackgroundShaderModifier(const std::shared_ptr<RSProperty<std::shared_ptr<RSShader>>> property);
    virtual ~RSBackgroundShaderModifier() = default;
    void Draw(RSDrawingContext& context) override {}
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() override;
    RSModifierType GetModifierType() override;
};

class RS_EXPORT RSBgImageModifier : public RSAnimatableModifier<std::shared_ptr<RSImage>> {
public:
    RSBgImageModifier(const std::shared_ptr<RSProperty<std::shared_ptr<RSImage>>> property);
    virtual ~RSBgImageModifier() = default;
    void Draw(RSDrawingContext& context) override {}
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() override;
    RSModifierType GetModifierType() override;
};

class RS_EXPORT RSBgImageWidthModifier : public RSAnimatableModifier<float> {
public:
    RSBgImageWidthModifier(const std::shared_ptr<RSProperty<float>> property);
    virtual ~RSBgImageWidthModifier() = default;
    void Draw(RSDrawingContext& context) override {}
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() override;
    RSModifierType GetModifierType() override;
};

class RS_EXPORT RSBgImageHeightModifier : public RSAnimatableModifier<float> {
public:
    RSBgImageHeightModifier(const std::shared_ptr<RSProperty<float>> property);
    virtual ~RSBgImageHeightModifier() = default;
    void Draw(RSDrawingContext& context) override {}
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() override;
    RSModifierType GetModifierType() override;
};

class RS_EXPORT RSBgImagePositionXModifier : public RSAnimatableModifier<float> {
public:
    RSBgImagePositionXModifier(const std::shared_ptr<RSProperty<float>> property);
    virtual ~RSBgImagePositionXModifier() = default;
    void Draw(RSDrawingContext& context) override {}
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() override;
    RSModifierType GetModifierType() override;
};

class RS_EXPORT RSBgImagePositionYModifier : public RSAnimatableModifier<float> {
public:
    RSBgImagePositionYModifier(const std::shared_ptr<RSProperty<float>> property);
    virtual ~RSBgImagePositionYModifier() = default;
    void Draw(RSDrawingContext& context) override {}
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() override;
    RSModifierType GetModifierType() override;
};

class RS_EXPORT RSBorderColorModifier : public RSAnimatableModifier<Vector4<Color>> {
public:
    RSBorderColorModifier(const std::shared_ptr<RSProperty<Vector4<Color>>> property);
    virtual ~RSBorderColorModifier() = default;
    void Draw(RSDrawingContext& context) override {}
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() override;
    RSModifierType GetModifierType() override;
};

class RS_EXPORT RSBorderWidthModifier : public RSAnimatableModifier<Vector4f> {
public:
    RSBorderWidthModifier(const std::shared_ptr<RSProperty<Vector4f>> property);
    virtual ~RSBorderWidthModifier() = default;
    void Draw(RSDrawingContext& context) override {}
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() override;
    RSModifierType GetModifierType() override;
};

class RS_EXPORT RSBorderStyleModifier : public RSAnimatableModifier<Vector4<uint32_t>> {
public:
    RSBorderStyleModifier(const std::shared_ptr<RSProperty<Vector4<uint32_t>>> property);
    virtual ~RSBorderStyleModifier() = default;
    void Draw(RSDrawingContext& context) override {}
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() override;
    RSModifierType GetModifierType() override;
};

class RS_EXPORT RSFilterModifier : public RSAnimatableModifier<std::shared_ptr<RSFilter>> {
public:
    RSFilterModifier(const std::shared_ptr<RSProperty<std::shared_ptr<RSFilter>>> property);
    virtual ~RSFilterModifier() = default;
    void Draw(RSDrawingContext& context) override {}
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() override;
    RSModifierType GetModifierType() override;
};

class RS_EXPORT RSBackgroundFilterModifier : public RSAnimatableModifier<std::shared_ptr<RSFilter>> {
public:
    RSBackgroundFilterModifier(const std::shared_ptr<RSProperty<std::shared_ptr<RSFilter>>> property);
    virtual ~RSBackgroundFilterModifier() = default;
    void Draw(RSDrawingContext& context) override {}
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() override;
    RSModifierType GetModifierType() override;
};

class RS_EXPORT RSFrameGravityModifier : public RSAnimatableModifier<Gravity> {
public:
    RSFrameGravityModifier(const std::shared_ptr<RSProperty<Gravity>> property);
    virtual ~RSFrameGravityModifier() = default;
    void Draw(RSDrawingContext& context) override {}
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() override;
    RSModifierType GetModifierType() override;
};

class RS_EXPORT RSClipBoundsModifier : public RSAnimatableModifier<std::shared_ptr<RSPath>> {
public:
    RSClipBoundsModifier(const std::shared_ptr<RSProperty<std::shared_ptr<RSPath>>> property);
    virtual ~RSClipBoundsModifier() = default;
    void Draw(RSDrawingContext& context) override {}
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() override;
    RSModifierType GetModifierType() override;
};

class RS_EXPORT RSClipToBoundsModifier : public RSAnimatableModifier<bool> {
public:
    RSClipToBoundsModifier(const std::shared_ptr<RSProperty<bool>> property);
    virtual ~RSClipToBoundsModifier() = default;
    void Draw(RSDrawingContext& context) override {}
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() override;
    RSModifierType GetModifierType() override;
};

class RS_EXPORT RSClipToFrameModifier : public RSAnimatableModifier<bool> {
public:
    RSClipToFrameModifier(const std::shared_ptr<RSProperty<bool>> property);
    virtual ~RSClipToFrameModifier() = default;
    void Draw(RSDrawingContext& context) override {}
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() override;
    RSModifierType GetModifierType() override;
};

class RS_EXPORT RSVisibleModifier : public RSAnimatableModifier<bool> {
public:
    RSVisibleModifier(const std::shared_ptr<RSProperty<bool>> property);
    virtual ~RSVisibleModifier() = default;
    void Draw(RSDrawingContext& context) override {}
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() override;
    RSModifierType GetModifierType() override;
};

class RS_EXPORT RSShadowColorModifier : public RSAnimatableModifier<Color> {
public:
    RSShadowColorModifier(const std::shared_ptr<RSProperty<Color>> property);
    virtual ~RSShadowColorModifier() = default;
    void Draw(RSDrawingContext& context) override {}
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() override;
    RSModifierType GetModifierType() override;
};

class RS_EXPORT RSShadowOffsetXModifier : public RSAnimatableModifier<float> {
public:
    RSShadowOffsetXModifier(const std::shared_ptr<RSProperty<float>> property);
    virtual ~RSShadowOffsetXModifier() = default;
    void Draw(RSDrawingContext& context) override {}
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() override;
    RSModifierType GetModifierType() override;
};

class RS_EXPORT RSShadowOffsetYModifier : public RSAnimatableModifier<float> {
public:
    RSShadowOffsetYModifier(const std::shared_ptr<RSProperty<float>> property);
    virtual ~RSShadowOffsetYModifier() = default;
    void Draw(RSDrawingContext& context) override {}
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() override;
    RSModifierType GetModifierType() override;
};

class RS_EXPORT RSShadowAlphaModifier : public RSAnimatableModifier<float> {
public:
    RSShadowAlphaModifier(const std::shared_ptr<RSProperty<float>> property);
    virtual ~RSShadowAlphaModifier() = default;
    void Draw(RSDrawingContext& context) override {}
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() override;
    RSModifierType GetModifierType() override;
};

class RS_EXPORT RSShadowElevationModifier : public RSAnimatableModifier<float> {
public:
    RSShadowElevationModifier(const std::shared_ptr<RSProperty<float>> property);
    virtual ~RSShadowElevationModifier() = default;
    void Draw(RSDrawingContext& context) override {}
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() override;
    RSModifierType GetModifierType() override;
};

class RS_EXPORT RSShadowRadiusModifier : public RSAnimatableModifier<float> {
public:
    RSShadowRadiusModifier(const std::shared_ptr<RSProperty<float>> property);
    virtual ~RSShadowRadiusModifier() = default;
    void Draw(RSDrawingContext& context) override {}
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() override;
    RSModifierType GetModifierType() override;
};

class RS_EXPORT RSShadowPathModifier : public RSAnimatableModifier<std::shared_ptr<RSPath>> {
public:
    RSShadowPathModifier(const std::shared_ptr<RSProperty<std::shared_ptr<RSPath>>> property);
    virtual ~RSShadowPathModifier() = default;
    void Draw(RSDrawingContext& context) override {}
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() override;
    RSModifierType GetModifierType() override;
};

class RS_EXPORT RSMaskModifier : public RSAnimatableModifier<std::shared_ptr<RSMask>> {
public:
    RSMaskModifier(const std::shared_ptr<RSProperty<std::shared_ptr<RSMask>>> property);
    virtual ~RSMaskModifier() = default;
    void Draw(RSDrawingContext& context) override {}
    std::shared_ptr<RSRenderModifier> CreateRenderModifier() override;
    RSModifierType GetModifierType() override;
};
} // namespace Rosen
} // namespace OHOS

#endif // RENDER_SERVICE_CLIENT_CORE_ANIMATION_RS_MODIFIER_H
