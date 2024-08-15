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

#include "property/rs_properties.h"

#include <algorithm>
#include <securec.h>

#include "animation/rs_render_particle_animation.h"
#include "common/rs_common_def.h"
#include "common/rs_obj_abs_geometry.h"
#include "common/rs_vector4.h"
#include "pipeline/rs_uni_render_judgement.h"
#include "platform/common/rs_log.h"
#include "platform/common/rs_system_properties.h"
#include "property/rs_point_light_manager.h"
#include "property/rs_properties_def.h"
#include "render/rs_aibar_shader_filter.h"
#include "render/rs_colorful_shadow_filter.h"
#include "render/rs_filter.h"
#include "render/rs_foreground_effect_filter.h"
#include "render/rs_grey_shader_filter.h"
#include "render/rs_hps_blur_shader_filter.h"
#include "render/rs_kawase_blur_shader_filter.h"
#include "render/rs_linear_gradient_blur_filter.h"
#include "render/rs_linear_gradient_blur_shader_filter.h"
#include "render/rs_magnifier_shader_filter.h"
#include "render/rs_maskcolor_shader_filter.h"
#include "render/rs_spherize_effect_filter.h"
#include "render/rs_attraction_effect_filter.h"
#include "src/core/SkOpts.h"
#include "render/rs_water_ripple_shader_filter.h"

namespace OHOS {
namespace Rosen {
namespace {
constexpr int32_t INDEX_2 = 2;
constexpr int32_t INDEX_4 = 4;
constexpr int32_t INDEX_5 = 5;
constexpr int32_t INDEX_6 = 6;
constexpr int32_t INDEX_7 = 7;
constexpr int32_t INDEX_9 = 9;
constexpr int32_t INDEX_10 = 10;
constexpr int32_t INDEX_11 = 11;
constexpr int32_t INDEX_12 = 12;
constexpr int32_t INDEX_14 = 14;
constexpr int32_t INDEX_18 = 18;

const Vector4f Vector4fZero { 0.f, 0.f, 0.f, 0.f };
const auto EMPTY_RECT = RectF();
constexpr float SPHERIZE_VALID_EPSILON = 0.001f; // used to judge if spherize valid
constexpr float ATTRACTION_VALID_EPSILON = 0.001f; // used to judge if attraction valid
constexpr uint8_t BORDER_TYPE_NONE = (uint32_t)BorderStyle::NONE;
constexpr int BORDER_NUM = 4;
constexpr int16_t BORDER_TRANSPARENT = 255;

using ResetPropertyFunc = void (*)(RSProperties* prop);
// Every modifier before RSModifierType::CUSTOM is property modifier, and it should have a ResetPropertyFunc
// NOTE: alway add new resetter when adding new property modifier
constexpr static std::array<ResetPropertyFunc, static_cast<int>(RSModifierType::CUSTOM)> g_propertyResetterLUT = {
    nullptr,                                                             // INVALID
    nullptr,                                                             // BOUNDS
    nullptr,                                                             // FRAME
    [](RSProperties* prop) { prop->SetPositionZ(0.f); },                 // POSITION_Z
    [](RSProperties* prop) { prop->SetPivot(Vector2f(0.5f, 0.5f)); },    // PIVOT
    [](RSProperties* prop) { prop->SetPivotZ(0.f); },                    // PIVOT_Z
    [](RSProperties* prop) { prop->SetQuaternion(Quaternion()); },       // QUATERNION
    [](RSProperties* prop) { prop->SetRotation(0.f); },                  // ROTATION
    [](RSProperties* prop) { prop->SetRotationX(0.f); },                 // ROTATION_X
    [](RSProperties* prop) { prop->SetRotationY(0.f); },                 // ROTATION_Y
    [](RSProperties* prop) { prop->SetCameraDistance(0.f); },            // CAMERA_DISTANCE
    [](RSProperties* prop) { prop->SetScale(Vector2f(1.f, 1.f)); },      // SCALE
    [](RSProperties* prop) { prop->SetSkew(Vector2f(0.f, 0.f)); },       // SKEW
    [](RSProperties* prop) { prop->SetPersp(Vector2f(0.f, 0.f)); },      // PERSP
    [](RSProperties* prop) { prop->SetTranslate(Vector2f(0.f, 0.f)); },  // TRANSLATE
    [](RSProperties* prop) { prop->SetTranslateZ(0.f); },                // TRANSLATE_Z
    [](RSProperties* prop) { prop->SetSublayerTransform({}); },          // SUBLAYER_TRANSFORM
    [](RSProperties* prop) { prop->SetCornerRadius(0.f); },              // CORNER_RADIUS
    [](RSProperties* prop) { prop->SetAlpha(1.f); },                     // ALPHA
    [](RSProperties* prop) { prop->SetAlphaOffscreen(false); },          // ALPHA_OFFSCREEN
    [](RSProperties* prop) { prop->SetForegroundColor({}); },            // FOREGROUND_COLOR
    [](RSProperties* prop) { prop->SetBackgroundColor({}); },            // BACKGROUND_COLOR
    [](RSProperties* prop) { prop->SetBackgroundShader({}); },           // BACKGROUND_SHADER
    [](RSProperties* prop) { prop->SetBgImage({}); },                    // BG_IMAGE
    [](RSProperties* prop) { prop->SetBgImageInnerRect({}); },           // Bg_Image_Inner_Rect
    [](RSProperties* prop) { prop->SetBgImageWidth(0.f); },              // BG_IMAGE_WIDTH
    [](RSProperties* prop) { prop->SetBgImageHeight(0.f); },             // BG_IMAGE_HEIGHT
    [](RSProperties* prop) { prop->SetBgImagePositionX(0.f); },          // BG_IMAGE_POSITION_X
    [](RSProperties* prop) { prop->SetBgImagePositionY(0.f); },          // BG_IMAGE_POSITION_Y
    nullptr,                                                             // SURFACE_BG_COLOR
    [](RSProperties* prop) { prop->SetBorderColor(RSColor()); },         // BORDER_COLOR
    [](RSProperties* prop) { prop->SetBorderWidth(0.f); },               // BORDER_WIDTH
    [](RSProperties* prop) { prop->SetBorderStyle(BORDER_TYPE_NONE); },  // BORDER_STYLE
    [](RSProperties* prop) { prop->SetBorderDashWidth({-1.f}); },        // BORDER_DASH_WIDTH
    [](RSProperties* prop) { prop->SetBorderDashGap({-1.f}); },          // BORDER_DASH_GAP
    [](RSProperties* prop) { prop->SetFilter({}); },                     // FILTER
    [](RSProperties* prop) { prop->SetBackgroundFilter({}); },           // BACKGROUND_FILTER
    [](RSProperties* prop) { prop->SetLinearGradientBlurPara({}); },     // LINEAR_GRADIENT_BLUR_PARA
    [](RSProperties* prop) { prop->SetDynamicLightUpRate({}); },         // DYNAMIC_LIGHT_UP_RATE
    [](RSProperties* prop) { prop->SetDynamicLightUpDegree({}); },       // DYNAMIC_LIGHT_UP_DEGREE
    [](RSProperties* prop) { prop->SetFgBrightnessRates({}); },          // FG_BRIGHTNESS_PARAMS
    [](RSProperties* prop) { prop->SetFgBrightnessSaturation(0.0); },     // FG_BRIGHTNESS_PARAMS
    [](RSProperties* prop) { prop->SetFgBrightnessPosCoeff({}); },       // FG_BRIGHTNESS_PARAMS
    [](RSProperties* prop) { prop->SetFgBrightnessNegCoeff({}); },       // FG_BRIGHTNESS_PARAMS
    [](RSProperties* prop) { prop->SetFgBrightnessFract({}); },          // FG_BRIGHTNESS_FRACTION
    [](RSProperties* prop) { prop->SetBgBrightnessRates({}); },          // BG_BRIGHTNESS_PARAMS
    [](RSProperties* prop) { prop->SetBgBrightnessSaturation(0.0); },     // BG_BRIGHTNESS_PARAMS
    [](RSProperties* prop) { prop->SetBgBrightnessPosCoeff({}); },       // BG_BRIGHTNESS_PARAMS
    [](RSProperties* prop) { prop->SetBgBrightnessNegCoeff({}); },       // BG_BRIGHTNESS_PARAMS
    [](RSProperties* prop) { prop->SetBgBrightnessFract(1.0); },          // BG_BRIGHTNESS_FRACTION
    [](RSProperties* prop) { prop->SetFrameGravity(Gravity::DEFAULT); }, // FRAME_GRAVITY
    [](RSProperties* prop) { prop->SetClipRRect({}); },                  // CLIP_RRECT
    [](RSProperties* prop) { prop->SetClipBounds({}); },                 // CLIP_BOUNDS
    [](RSProperties* prop) { prop->SetClipToBounds(false); },            // CLIP_TO_BOUNDS
    [](RSProperties* prop) { prop->SetClipToFrame(false); },             // CLIP_TO_FRAME
    [](RSProperties* prop) { prop->SetVisible(true); },                  // VISIBLE
    [](RSProperties* prop) { prop->SetShadowColor({}); },                // SHADOW_COLOR
    [](RSProperties* prop) { prop->SetShadowOffsetX(0.f); },             // SHADOW_OFFSET_X
    [](RSProperties* prop) { prop->SetShadowOffsetY(0.f); },             // SHADOW_OFFSET_Y
    [](RSProperties* prop) { prop->SetShadowAlpha(0.f); },               // SHADOW_ALPHA
    [](RSProperties* prop) { prop->SetShadowElevation(0.f); },           // SHADOW_ELEVATION
    [](RSProperties* prop) { prop->SetShadowRadius(0.f); },              // SHADOW_RADIUS
    [](RSProperties* prop) { prop->SetShadowPath({}); },                 // SHADOW_PATH
    [](RSProperties* prop) { prop->SetShadowMask(false); },              // SHADOW_MASK
    [](RSProperties* prop) { prop->SetShadowColorStrategy(0); },         // ShadowColorStrategy
    [](RSProperties* prop) { prop->SetMask({}); },                       // MASK
    [](RSProperties* prop) { prop->SetSpherize(0.f); },                  // SPHERIZE
    [](RSProperties* prop) { prop->SetLightUpEffect(1.f); },             // LIGHT_UP_EFFECT
    [](RSProperties* prop) { prop->SetPixelStretch({}); },               // PIXEL_STRETCH
    [](RSProperties* prop) { prop->SetPixelStretchPercent({}); },        // PIXEL_STRETCH_PERCENT
    [](RSProperties* prop) { prop->SetPixelStretchTileMode(0); },        // PIXEL_STRETCH_TILE_MODE
    [](RSProperties* prop) { prop->SetUseEffect(false); },               // USE_EFFECT
    [](RSProperties* prop) { prop->SetColorBlendMode(0); },              // COLOR_BLENDMODE
    [](RSProperties* prop) { prop->SetColorBlendApplyType(0); },         // COLOR_BLENDAPPLY_TYPE
    [](RSProperties* prop) { prop->ResetSandBox(); },                    // SANDBOX
    [](RSProperties* prop) { prop->SetGrayScale({}); },                  // GRAY_SCALE
    [](RSProperties* prop) { prop->SetBrightness({}); },                 // BRIGHTNESS
    [](RSProperties* prop) { prop->SetContrast({}); },                   // CONTRAST
    [](RSProperties* prop) { prop->SetSaturate({}); },                   // SATURATE
    [](RSProperties* prop) { prop->SetSepia({}); },                      // SEPIA
    [](RSProperties* prop) { prop->SetInvert({}); },                     // INVERT
    [](RSProperties* prop) { prop->SetAiInvert({}); },                   // AIINVERT
    [](RSProperties* prop) { prop->SetSystemBarEffect({}); },            // SYSTEMBAREFFECT
    [](RSProperties* prop) { prop->SetWaterRippleProgress(0.0f); },      // WATER_RIPPLE_PROGRESS
    [](RSProperties* prop) { prop->SetWaterRippleParams({}); },          // WATER_RIPPLE_PARAMS
    [](RSProperties* prop) { prop->SetHueRotate({}); },                  // HUE_ROTATE
    [](RSProperties* prop) { prop->SetColorBlend({}); },                 // COLOR_BLEND
    [](RSProperties* prop) { prop->SetParticles({}); },                  // PARTICLE
    [](RSProperties* prop) { prop->SetShadowIsFilled(false); },          // SHADOW_IS_FILLED
    [](RSProperties* prop) { prop->SetOutlineColor(RSColor()); },        // OUTLINE_COLOR
    [](RSProperties* prop) { prop->SetOutlineWidth(0.f); },              // OUTLINE_WIDTH
    [](RSProperties* prop) { prop->SetOutlineStyle(BORDER_TYPE_NONE); }, // OUTLINE_STYLE
    [](RSProperties* prop) { prop->SetOutlineDashWidth({-1.f}); },       // OUTLINE_DASH_WIDTH
    [](RSProperties* prop) { prop->SetOutlineDashGap({-1.f}); },         // OUTLINE_DASH_GAP
    [](RSProperties* prop) { prop->SetOutlineRadius(0.f); },             // OUTLINE_RADIUS
    [](RSProperties* prop) { prop->SetUseShadowBatching(false); },       // USE_SHADOW_BATCHING
    [](RSProperties* prop) { prop->SetGreyCoef(std::nullopt); },         // GREY_COEF
    [](RSProperties* prop) { prop->SetLightIntensity(-1.f); },           // LIGHT_INTENSITY
    [](RSProperties* prop) { prop->SetLightColor({}); },                 // LIGHT_COLOR
    [](RSProperties* prop) { prop->SetLightPosition({}); },              // LIGHT_POSITION
    [](RSProperties* prop) { prop->SetIlluminatedBorderWidth({}); },     // ILLUMINATED_BORDER_WIDTH
    [](RSProperties* prop) { prop->SetIlluminatedType(-1); },            // ILLUMINATED_TYPE
    [](RSProperties* prop) { prop->SetBloom({}); },                      // BLOOM
    [](RSProperties* prop) { prop->SetEmitterUpdater({}); },             // PARTICLE_EMITTER_UPDATER
    [](RSProperties* prop) { prop->SetParticleNoiseFields({}); },         // PARTICLE_NOISE_FIELD
    [](RSProperties* prop) { prop->SetForegroundEffectRadius(0.f); },    // FOREGROUND_EFFECT_RADIUS
    [](RSProperties* prop) { prop->SetMotionBlurPara({}); },             // MOTION_BLUR_PARA
    [](RSProperties* prop) { prop->SetDynamicDimDegree({}); },           // DYNAMIC_LIGHT_UP_DEGREE
    [](RSProperties* prop) { prop->SetMagnifierParams({}); },            // MAGNIFIER_PARA
    [](RSProperties* prop) { prop->SetBackgroundBlurRadius(0.f); },      // BACKGROUND_BLUR_RADIUS
    [](RSProperties* prop) { prop->SetBackgroundBlurSaturation({}); },   // BACKGROUND_BLUR_SATURATION
    [](RSProperties* prop) { prop->SetBackgroundBlurBrightness({}); },   // BACKGROUND_BLUR_BRIGHTNESS
    [](RSProperties* prop) { prop->SetBackgroundBlurMaskColor(RSColor()); }, // BACKGROUND_BLUR_MASKCOLOR
    [](RSProperties* prop) { prop->SetBackgroundBlurColorMode(BLUR_COLOR_MODE::DEFAULT); }, // BACKGROUND_BLUR_COLORMODE
    [](RSProperties* prop) { prop->SetBackgroundBlurRadiusX(0.f); },     // BACKGROUND_BLUR_RADIUS_X
    [](RSProperties* prop) { prop->SetBackgroundBlurRadiusY(0.f); },     // BACKGROUND_BLUR_RADIUS_Y
    [](RSProperties* prop) { prop->SetForegroundBlurRadius(0.f); },      // FOREGROUND_BLUR_RADIUS
    [](RSProperties* prop) { prop->SetForegroundBlurSaturation({}); },   // FOREGROUND_BLUR_SATURATION
    [](RSProperties* prop) { prop->SetForegroundBlurBrightness({}); },   // FOREGROUND_BLUR_BRIGHTNESS
    [](RSProperties* prop) { prop->SetForegroundBlurMaskColor(RSColor()); }, // FOREGROUND_BLUR_MASKCOLOR
    [](RSProperties* prop) { prop->SetForegroundBlurColorMode(BLUR_COLOR_MODE::DEFAULT); }, // FOREGROUND_BLUR_COLORMODE
    [](RSProperties* prop) { prop->SetForegroundBlurRadiusX(0.f); },     // FOREGROUND_BLUR_RADIUS_X
    [](RSProperties* prop) { prop->SetForegroundBlurRadiusY(0.f); },     // FOREGROUND_BLUR_RADIUS_Y
    [](RSProperties* prop) { prop->SetAttractionFraction(0.f); },        // ATTRACTION_FRACTION
    [](RSProperties* prop) { prop->SetAttractionDstPoint({}); },         // ATTRACTION_DSTPOINT
};

// Check if g_propertyResetterLUT size match and is fully initialized (the last element should never be nullptr)
static_assert(g_propertyResetterLUT.size() == static_cast<size_t>(RSModifierType::CUSTOM));
static_assert(g_propertyResetterLUT.back() != nullptr);
} // namespace

// Only enable filter cache when uni-render is enabled and filter cache is enabled

#if defined(NEW_SKIA) && (defined(RS_ENABLE_GL) || defined(RS_ENABLE_VK))
#ifndef ROSEN_ARKUI_X
const bool RSProperties::FilterCacheEnabled =
    RSSystemProperties::GetFilterCacheEnabled() && RSUniRenderJudgement::IsUniRender();
#else
const bool RSProperties::FilterCacheEnabled = false;
#endif
#endif

const bool RSProperties::IS_UNI_RENDER = RSUniRenderJudgement::IsUniRender();
const bool RSProperties::FOREGROUND_FILTER_ENABLED = RSSystemProperties::GetForegroundFilterEnabled();

RSProperties::RSProperties()
{
    boundsGeo_ = std::make_shared<RSObjAbsGeometry>();
    frameGeo_ = std::make_shared<RSObjGeometry>();
}

RSProperties::~RSProperties() = default;

void RSProperties::ResetProperty(const ModifierDirtyTypes& dirtyTypes)
{
    if (dirtyTypes.none()) {
        return;
    }
    for (uint8_t type = 0; type < static_cast<size_t>(RSModifierType::CUSTOM); type++) {
        if (dirtyTypes.test(type)) {
            if (auto& resetFunc = g_propertyResetterLUT[type]) {
                resetFunc(this);
            }
        }
    }
}

void RSProperties::SetBounds(Vector4f bounds)
{
    if (bounds.z_ != boundsGeo_->GetWidth() || bounds.w_ != boundsGeo_->GetHeight()) {
        contentDirty_ = true;
    }
    boundsGeo_->SetRect(bounds.x_, bounds.y_, bounds.z_, bounds.w_);
    hasBounds_ = true;
    geoDirty_ = true;
    SetDirty();
}

void RSProperties::SetBoundsSize(Vector2f size)
{
    boundsGeo_->SetSize(size.x_, size.y_);
    hasBounds_ = true;
    geoDirty_ = true;
    contentDirty_ = true;
    SetDirty();
}

void RSProperties::SetBoundsWidth(float width)
{
    boundsGeo_->SetWidth(width);
    hasBounds_ = true;
    geoDirty_ = true;
    contentDirty_ = true;
    SetDirty();
}

void RSProperties::SetBoundsHeight(float height)
{
    boundsGeo_->SetHeight(height);
    hasBounds_ = true;
    geoDirty_ = true;
    contentDirty_ = true;
    SetDirty();
}

void RSProperties::SetBoundsPosition(Vector2f position)
{
    boundsGeo_->SetPosition(position.x_, position.y_);
    geoDirty_ = true;
    SetDirty();
}

void RSProperties::SetBoundsPositionX(float positionX)
{
    boundsGeo_->SetX(positionX);
    geoDirty_ = true;
    SetDirty();
}

void RSProperties::SetBoundsPositionY(float positionY)
{
    boundsGeo_->SetY(positionY);
    geoDirty_ = true;
    SetDirty();
}

Vector4f RSProperties::GetBounds() const
{
    return { boundsGeo_->GetX(), boundsGeo_->GetY(), boundsGeo_->GetWidth(), boundsGeo_->GetHeight() };
}

Vector2f RSProperties::GetBoundsSize() const
{
    return { boundsGeo_->GetWidth(), boundsGeo_->GetHeight() };
}

float RSProperties::GetBoundsWidth() const
{
    return boundsGeo_->GetWidth();
}

float RSProperties::GetBoundsHeight() const
{
    return boundsGeo_->GetHeight();
}

float RSProperties::GetBoundsPositionX() const
{
    return boundsGeo_->GetX();
}

float RSProperties::GetBoundsPositionY() const
{
    return boundsGeo_->GetY();
}

Vector2f RSProperties::GetBoundsPosition() const
{
    return { GetBoundsPositionX(), GetBoundsPositionY() };
}

void RSProperties::SetFrame(Vector4f frame)
{
    if (frame.z_ != frameGeo_->GetWidth() || frame.w_ != frameGeo_->GetHeight()) {
        contentDirty_ = true;
    }
    frameGeo_->SetRect(frame.x_, frame.y_, frame.z_, frame.w_);
    geoDirty_ = true;
    SetDirty();
}

void RSProperties::SetFrameSize(Vector2f size)
{
    frameGeo_->SetSize(size.x_, size.y_);
    geoDirty_ = true;
    contentDirty_ = true;
    SetDirty();
}

void RSProperties::SetFrameWidth(float width)
{
    frameGeo_->SetWidth(width);
    geoDirty_ = true;
    contentDirty_ = true;
    SetDirty();
}

void RSProperties::SetFrameHeight(float height)
{
    frameGeo_->SetHeight(height);
    geoDirty_ = true;
    contentDirty_ = true;
    SetDirty();
}

void RSProperties::SetFramePosition(Vector2f position)
{
    frameGeo_->SetPosition(position.x_, position.y_);
    geoDirty_ = true;
    SetDirty();
}

void RSProperties::SetFramePositionX(float positionX)
{
    frameGeo_->SetX(positionX);
    geoDirty_ = true;
    SetDirty();
}

void RSProperties::SetFramePositionY(float positionY)
{
    frameGeo_->SetY(positionY);
    geoDirty_ = true;
    SetDirty();
}

Vector4f RSProperties::GetFrame() const
{
    return { frameGeo_->GetX(), frameGeo_->GetY(), frameGeo_->GetWidth(), frameGeo_->GetHeight() };
}

Vector2f RSProperties::GetFrameSize() const
{
    return { frameGeo_->GetWidth(), frameGeo_->GetHeight() };
}

float RSProperties::GetFrameWidth() const
{
    return frameGeo_->GetWidth();
}

float RSProperties::GetFrameHeight() const
{
    return frameGeo_->GetHeight();
}

float RSProperties::GetFramePositionX() const
{
    return frameGeo_->GetX();
}

float RSProperties::GetFramePositionY() const
{
    return frameGeo_->GetY();
}

Vector2f RSProperties::GetFramePosition() const
{
    return { GetFramePositionX(), GetFramePositionY() };
}

float RSProperties::GetFrameOffsetX() const
{
    return frameOffsetX_;
}

float RSProperties::GetFrameOffsetY() const
{
    return frameOffsetY_;
}

const std::shared_ptr<RSObjAbsGeometry>& RSProperties::GetBoundsGeometry() const
{
    return boundsGeo_;
}

const std::shared_ptr<RSObjGeometry>& RSProperties::GetFrameGeometry() const
{
    return frameGeo_;
}

bool RSProperties::UpdateGeometryByParent(const Drawing::Matrix* parentMatrix,
    const std::optional<Drawing::Point>& offset)
{
    static thread_local Drawing::Matrix prevAbsMatrix;
    prevAbsMatrix.Swap(prevAbsMatrix_);
    boundsGeo_->UpdateMatrix(parentMatrix, offset);
    prevAbsMatrix_ = boundsGeo_->GetAbsMatrix();
    if (!RSSystemProperties::GetSkipGeometryNotChangeEnabled()) {
        return true;
    }
    const auto& rect = boundsGeo_->GetAbsRect();
    if (!lastRect_.has_value()) {
        lastRect_ = rect;
        return true;
    }
    auto dirtyFlag = (rect != lastRect_.value()) || !(prevAbsMatrix == prevAbsMatrix_);
    lastRect_ = rect;
    return dirtyFlag;
}

bool RSProperties::UpdateGeometry(
    const RSProperties* parent, bool dirtyFlag, const std::optional<Drawing::Point>& offset)
{
    if (!dirtyFlag && !geoDirty_) {
        return false;
    }
    auto parentMatrix = parent == nullptr ? nullptr : &(parent->GetBoundsGeometry()->GetAbsMatrix());
    if (parentMatrix && sandbox_ && sandbox_->matrix_) {
        parentMatrix = &(sandbox_->matrix_.value());
    }
    CheckEmptyBounds();
    boundsGeo_->UpdateMatrix(parentMatrix, offset);
    if (lightSourcePtr_ && lightSourcePtr_->IsLightSourceValid()) {
        CalculateAbsLightPosition();
        RSPointLightManager::Instance()->AddDirtyLightSource(backref_);
    }
    if (illuminatedPtr_ && illuminatedPtr_->IsIlluminatedValid()) {
        RSPointLightManager::Instance()->AddDirtyIlluminated(backref_);
    }
    if (RSSystemProperties::GetSkipGeometryNotChangeEnabled()) {
        auto rect = boundsGeo_->GetAbsRect();
        if (!lastRect_.has_value()) {
            lastRect_ = rect;
            return true;
        }
        dirtyFlag = dirtyFlag || rect != lastRect_.value();
        lastRect_ = rect;
        return dirtyFlag;
    } else {
        return true;
    }
}

void RSProperties::SetSandBox(const std::optional<Vector2f>& parentPosition)
{
    if (!sandbox_) {
        sandbox_ = std::make_unique<Sandbox>();
    }
    sandbox_->position_ = parentPosition;
    geoDirty_ = true;
    SetDirty();
}

std::optional<Vector2f> RSProperties::GetSandBox() const
{
    return sandbox_ ? sandbox_->position_ : std::nullopt;
}

void RSProperties::ResetSandBox()
{
    sandbox_ = nullptr;
}

void RSProperties::UpdateSandBoxMatrix(const std::optional<Drawing::Matrix>& rootMatrix)
{
    if (!sandbox_) {
        return;
    }
    if (!rootMatrix || !sandbox_->position_) {
        sandbox_->matrix_ = std::nullopt;
        return;
    }
    auto rootMat = rootMatrix.value();
    bool hasScale = false;
    // scaleFactors[0]-minimum scaling factor, scaleFactors[1]-maximum scaling factor
    Drawing::scalar scaleFactors[2];
    bool getMinMaxScales = rootMat.GetMinMaxScales(scaleFactors);
    if (getMinMaxScales) {
        hasScale = !ROSEN_EQ(scaleFactors[0], 1.f) || !ROSEN_EQ(scaleFactors[1], 1.f);
    }
    if (hasScale) {
        sandbox_->matrix_ = std::nullopt;
        return;
    }
    Drawing::Matrix matrix = rootMatrix.value();
    matrix.PreTranslate(sandbox_->position_->x_, sandbox_->position_->y_);
    sandbox_->matrix_ = matrix;
}

std::optional<Drawing::Matrix> RSProperties::GetSandBoxMatrix() const
{
    return sandbox_ ? sandbox_->matrix_ : std::nullopt;
}

void RSProperties::SetPositionZ(float positionZ)
{
    boundsGeo_->SetZ(positionZ);
    frameGeo_->SetZ(positionZ);
    geoDirty_ = true;
    SetDirty();
}

float RSProperties::GetPositionZ() const
{
    return boundsGeo_->GetZ();
}

void RSProperties::SetPivot(Vector2f pivot)
{
    boundsGeo_->SetPivot(pivot.x_, pivot.y_);
    geoDirty_ = true;
    SetDirty();
}

void RSProperties::SetPivotX(float pivotX)
{
    boundsGeo_->SetPivotX(pivotX);
    geoDirty_ = true;
    SetDirty();
}

void RSProperties::SetPivotY(float pivotY)
{
    boundsGeo_->SetPivotY(pivotY);
    geoDirty_ = true;
    SetDirty();
}

void RSProperties::SetPivotZ(float pivotZ)
{
    boundsGeo_->SetPivotZ(pivotZ);
    geoDirty_ = true;
    SetDirty();
}

Vector2f RSProperties::GetPivot() const
{
    return { boundsGeo_->GetPivotX(), boundsGeo_->GetPivotY() };
}

float RSProperties::GetPivotX() const
{
    return boundsGeo_->GetPivotX();
}

float RSProperties::GetPivotY() const
{
    return boundsGeo_->GetPivotY();
}

float RSProperties::GetPivotZ() const
{
    return boundsGeo_->GetPivotZ();
}

void RSProperties::SetCornerRadius(const Vector4f& cornerRadius)
{
    cornerRadius_ = cornerRadius;
    SetDirty();
}

const Vector4f& RSProperties::GetCornerRadius() const
{
    return cornerRadius_ ? cornerRadius_.value() : Vector4fZero;
}

void RSProperties::SetQuaternion(Quaternion quaternion)
{
    boundsGeo_->SetQuaternion(quaternion);
    geoDirty_ = true;
    SetDirty();
}

void RSProperties::SetRotation(float degree)
{
    boundsGeo_->SetRotation(degree);
    geoDirty_ = true;
    SetDirty();
}

void RSProperties::SetRotationX(float degree)
{
    boundsGeo_->SetRotationX(degree);
    geoDirty_ = true;
    SetDirty();
}

void RSProperties::SetRotationY(float degree)
{
    boundsGeo_->SetRotationY(degree);
    geoDirty_ = true;
    SetDirty();
}

void RSProperties::SetCameraDistance(float cameraDistance)
{
    boundsGeo_->SetCameraDistance(cameraDistance);
    geoDirty_ = true;
    SetDirty();
}

void RSProperties::SetScale(Vector2f scale)
{
    boundsGeo_->SetScale(scale.x_, scale.y_);
    geoDirty_ = true;
    SetDirty();
}

void RSProperties::SetScaleX(float sx)
{
    boundsGeo_->SetScaleX(sx);
    geoDirty_ = true;
    SetDirty();
}

void RSProperties::SetScaleY(float sy)
{
    boundsGeo_->SetScaleY(sy);
    geoDirty_ = true;
    SetDirty();
}

void RSProperties::SetSkew(Vector2f skew)
{
    boundsGeo_->SetSkew(skew.x_, skew.y_);
    geoDirty_ = true;
    SetDirty();
}

void RSProperties::SetSkewX(float skewX)
{
    boundsGeo_->SetSkewX(skewX);
    geoDirty_ = true;
    SetDirty();
}

void RSProperties::SetSkewY(float skewY)
{
    boundsGeo_->SetSkewY(skewY);
    geoDirty_ = true;
    SetDirty();
}

void RSProperties::SetPersp(Vector2f persp)
{
    boundsGeo_->SetPersp(persp.x_, persp.y_);
    geoDirty_ = true;
    SetDirty();
}

void RSProperties::SetPerspX(float perspX)
{
    boundsGeo_->SetPerspX(perspX);
    geoDirty_ = true;
    SetDirty();
}

void RSProperties::SetPerspY(float perspY)
{
    boundsGeo_->SetPerspY(perspY);
    geoDirty_ = true;
    SetDirty();
}

void RSProperties::SetTranslate(Vector2f translate)
{
    boundsGeo_->SetTranslateX(translate[0]);
    boundsGeo_->SetTranslateY(translate[1]);
    geoDirty_ = true;
    SetDirty();
}

void RSProperties::SetTranslateX(float translate)
{
    boundsGeo_->SetTranslateX(translate);
    geoDirty_ = true;
    SetDirty();
}

void RSProperties::SetTranslateY(float translate)
{
    boundsGeo_->SetTranslateY(translate);
    geoDirty_ = true;
    SetDirty();
}

void RSProperties::SetTranslateZ(float translate)
{
    boundsGeo_->SetTranslateZ(translate);
    geoDirty_ = true;
    SetDirty();
}

Quaternion RSProperties::GetQuaternion() const
{
    return boundsGeo_->GetQuaternion();
}

float RSProperties::GetRotation() const
{
    return boundsGeo_->GetRotation();
}

float RSProperties::GetRotationX() const
{
    return boundsGeo_->GetRotationX();
}

float RSProperties::GetRotationY() const
{
    return boundsGeo_->GetRotationY();
}

float RSProperties::GetCameraDistance() const
{
    return boundsGeo_->GetCameraDistance();
}

float RSProperties::GetScaleX() const
{
    return boundsGeo_->GetScaleX();
}

float RSProperties::GetScaleY() const
{
    return boundsGeo_->GetScaleY();
}

Vector2f RSProperties::GetScale() const
{
    return { boundsGeo_->GetScaleX(), boundsGeo_->GetScaleY() };
}

float RSProperties::GetSkewX() const
{
    return boundsGeo_->GetSkewX();
}

float RSProperties::GetSkewY() const
{
    return boundsGeo_->GetSkewY();
}

Vector2f RSProperties::GetSkew() const
{
    return { boundsGeo_->GetSkewX(), boundsGeo_->GetSkewY() };
}

float RSProperties::GetPerspX() const
{
    return boundsGeo_->GetPerspX();
}

float RSProperties::GetPerspY() const
{
    return boundsGeo_->GetPerspY();
}

Vector2f RSProperties::GetPersp() const
{
    return { boundsGeo_->GetPerspX(), boundsGeo_->GetPerspY() };
}

Vector2f RSProperties::GetTranslate() const
{
    return Vector2f(GetTranslateX(), GetTranslateY());
}

float RSProperties::GetTranslateX() const
{
    return boundsGeo_->GetTranslateX();
}

float RSProperties::GetTranslateY() const
{
    return boundsGeo_->GetTranslateY();
}

float RSProperties::GetTranslateZ() const
{
    return boundsGeo_->GetTranslateZ();
}

void RSProperties::SetParticles(const RSRenderParticleVector& particles)
{
    particles_ = particles;
    if (particles_.GetParticleSize() > 0) {
        isDrawn_ = true;
    }
    SetDirty();
    contentDirty_ = true;
}

const RSRenderParticleVector& RSProperties::GetParticles() const
{
    return particles_;
}

void RSProperties::SetAlpha(float alpha)
{
    alpha_ = alpha;
    if (alpha_ < 1.f) {
        alphaNeedApply_ = true;
    }
    SetDirty();
}

float RSProperties::GetAlpha() const
{
    return alpha_;
}
void RSProperties::SetAlphaOffscreen(bool alphaOffscreen)
{
    alphaOffscreen_ = alphaOffscreen;
    SetDirty();
    contentDirty_ = true;
}

bool RSProperties::GetAlphaOffscreen() const
{
    return alphaOffscreen_;
}

void RSProperties::SetSublayerTransform(const std::optional<Matrix3f>& sublayerTransform)
{
    sublayerTransform_ = sublayerTransform;
    SetDirty();
}

const std::optional<Matrix3f>& RSProperties::GetSublayerTransform() const
{
    return sublayerTransform_;
}

// foreground properties
void RSProperties::SetForegroundColor(Color color)
{
    if (!decoration_) {
        decoration_ = std::make_optional<Decoration>();
    }
    decoration_->foregroundColor_ = color;
    SetDirty();
    contentDirty_ = true;
}

Color RSProperties::GetForegroundColor() const
{
    return decoration_ ? decoration_->foregroundColor_ : RgbPalette::Transparent();
}

// background properties
void RSProperties::SetBackgroundColor(Color color)
{
    if (!decoration_) {
        decoration_ = std::make_optional<Decoration>();
    }
    if (color.GetAlpha() > 0) {
        isDrawn_ = true;
    }
    decoration_->backgroundColor_ = color;
    SetDirty();
    contentDirty_ = true;
}

const Color& RSProperties::GetBackgroundColor() const
{
    return decoration_ ? decoration_->backgroundColor_ : RgbPalette::Transparent();
}

void RSProperties::SetBackgroundShader(const std::shared_ptr<RSShader>& shader)
{
    if (!decoration_) {
        decoration_ = std::make_optional<Decoration>();
    }
    if (shader) {
        isDrawn_ = true;
    }
    decoration_->bgShader_ = shader;
    SetDirty();
    contentDirty_ = true;
}

std::shared_ptr<RSShader> RSProperties::GetBackgroundShader() const
{
    return decoration_ ? decoration_->bgShader_ : nullptr;
}

void RSProperties::SetBgImage(const std::shared_ptr<RSImage>& image)
{
    if (!decoration_) {
        decoration_ = std::make_optional<Decoration>();
    }
    if (image) {
        isDrawn_ = true;
    }
    decoration_->bgImage_ = image;
    SetDirty();
    contentDirty_ = true;
}

std::shared_ptr<RSImage> RSProperties::GetBgImage() const
{
    return decoration_ ? decoration_->bgImage_ : nullptr;
}

void RSProperties::SetBgImageInnerRect(const Vector4f& rect)
{
    if (!decoration_) {
        decoration_ = std::make_optional<Decoration>();
    }
    decoration_->bgImageInnerRect_ = rect;
    SetDirty();
    contentDirty_ = true;
}

Vector4f RSProperties::GetBgImageInnerRect() const
{
    return decoration_ ? decoration_->bgImageInnerRect_ : Vector4f();
}

void RSProperties::SetBgImageWidth(float width)
{
    if (!decoration_) {
        decoration_ = std::make_optional<Decoration>();
    }
    decoration_->bgImageRect_.width_ = width;
    SetDirty();
    contentDirty_ = true;
}

void RSProperties::SetBgImageHeight(float height)
{
    if (!decoration_) {
        decoration_ = std::make_optional<Decoration>();
    }
    decoration_->bgImageRect_.height_ = height;
    SetDirty();
    contentDirty_ = true;
}

void RSProperties::SetBgImagePositionX(float positionX)
{
    if (!decoration_) {
        decoration_ = std::make_optional<Decoration>();
    }
    decoration_->bgImageRect_.left_ = positionX;
    SetDirty();
    contentDirty_ = true;
}

void RSProperties::SetBgImagePositionY(float positionY)
{
    if (!decoration_) {
        decoration_ = std::make_optional<Decoration>();
    }
    decoration_->bgImageRect_.top_ = positionY;
    SetDirty();
    contentDirty_ = true;
}

float RSProperties::GetBgImageWidth() const
{
    return decoration_ ? decoration_->bgImageRect_.width_ : 0.f;
}

float RSProperties::GetBgImageHeight() const
{
    return decoration_ ? decoration_->bgImageRect_.height_ : 0.f;
}

float RSProperties::GetBgImagePositionX() const
{
    return decoration_ ? decoration_->bgImageRect_.left_ : 0.f;
}

float RSProperties::GetBgImagePositionY() const
{
    return decoration_ ? decoration_->bgImageRect_.top_ : 0.f;
}

// border properties
void RSProperties::SetBorderColor(Vector4<Color> color)
{
    if (!border_) {
        border_ = std::make_shared<RSBorder>();
    }
    border_->SetColorFour(color);
    if (border_->GetColor().GetAlpha() > 0) {
        isDrawn_ = true;
    }
    SetDirty();
    contentDirty_ = true;
}

void RSProperties::SetBorderWidth(Vector4f width)
{
    if (!border_) {
        border_ = std::make_shared<RSBorder>();
    }
    border_->SetWidthFour(width);
    if (!width.IsZero()) {
        isDrawn_ = true;
    }
    SetDirty();
    contentDirty_ = true;
}

void RSProperties::SetBorderStyle(Vector4<uint32_t> style)
{
    if (!border_) {
        border_ = std::make_shared<RSBorder>();
    }
    border_->SetStyleFour(style);
    SetDirty();
    contentDirty_ = true;
}

void RSProperties::SetBorderDashWidth(const Vector4f& dashWidth)
{
    if (!border_) {
        border_ = std::make_shared<RSBorder>();
    }
    border_->SetDashWidthFour(dashWidth);
    SetDirty();
    contentDirty_ = true;
}

void RSProperties::SetBorderDashGap(const Vector4f& dashGap)
{
    if (!border_) {
        border_ = std::make_shared<RSBorder>();
    }
    border_->SetDashGapFour(dashGap);
    SetDirty();
    contentDirty_ = true;
}

Vector4<Color> RSProperties::GetBorderColor() const
{
    return border_ ? border_->GetColorFour() : Vector4<Color>(RgbPalette::Transparent());
}

Vector4f RSProperties::GetBorderWidth() const
{
    return border_ ? border_->GetWidthFour() : Vector4f(0.f);
}

Vector4<uint32_t> RSProperties::GetBorderStyle() const
{
    return border_ ? border_->GetStyleFour() : Vector4<uint32_t>(static_cast<uint32_t>(BorderStyle::NONE));
}

Vector4f RSProperties::GetBorderDashWidth() const
{
    return border_ ? border_->GetDashWidthFour() : Vector4f(0.f);
}

Vector4f RSProperties::GetBorderDashGap() const
{
    return border_ ? border_->GetDashGapFour() : Vector4f(0.f);
}

const std::shared_ptr<RSBorder>& RSProperties::GetBorder() const
{
    return border_;
}

bool RSProperties::GetBorderColorIsTransparent() const
{
    if (border_) {
        for (int i = 0; i < BORDER_NUM; i++) {
            auto alpha = border_->GetColorFour()[i].GetAlpha();
            if (alpha < BORDER_TRANSPARENT) {
                return true;
            }
        }
    }
    return false;
}

void RSProperties::SetOutlineColor(Vector4<Color> color)
{
    if (!outline_) {
        outline_ = std::make_shared<RSBorder>(true);
    }
    outline_->SetColorFour(color);
    if (outline_->GetColor().GetAlpha() > 0) {
        isDrawn_ = true;
    }
    SetDirty();
    contentDirty_ = true;
}

void RSProperties::SetOutlineWidth(Vector4f width)
{
    if (!outline_) {
        outline_ = std::make_shared<RSBorder>(true);
    }
    outline_->SetWidthFour(width);
    if (!width.IsZero()) {
        isDrawn_ = true;
    }
    SetDirty();
    contentDirty_ = true;
}

void RSProperties::SetOutlineStyle(Vector4<uint32_t> style)
{
    if (!outline_) {
        outline_ = std::make_shared<RSBorder>(true);
    }
    outline_->SetStyleFour(style);
    SetDirty();
    contentDirty_ = true;
}

void RSProperties::SetOutlineDashWidth(const Vector4f& dashWidth)
{
    if (!outline_) {
        outline_ = std::make_shared<RSBorder>();
    }
    outline_->SetDashWidthFour(dashWidth);
    SetDirty();
    contentDirty_ = true;
}

void RSProperties::SetOutlineDashGap(const Vector4f& dashGap)
{
    if (!outline_) {
        outline_ = std::make_shared<RSBorder>();
    }
    outline_->SetDashGapFour(dashGap);
    SetDirty();
    contentDirty_ = true;
}

void RSProperties::SetOutlineRadius(Vector4f radius)
{
    if (!outline_) {
        outline_ = std::make_shared<RSBorder>(true);
    }
    outline_->SetRadiusFour(radius);
    isDrawn_ = true;
    SetDirty();
    contentDirty_ = true;
}

Vector4<Color> RSProperties::GetOutlineColor() const
{
    return outline_ ? outline_->GetColorFour() : Vector4<Color>(RgbPalette::Transparent());
}

Vector4f RSProperties::GetOutlineWidth() const
{
    return outline_ ? outline_->GetWidthFour() : Vector4f(0.f);
}

Vector4<uint32_t> RSProperties::GetOutlineStyle() const
{
    return outline_ ? outline_->GetStyleFour() : Vector4<uint32_t>(static_cast<uint32_t>(BorderStyle::NONE));
}

Vector4f RSProperties::GetOutlineDashWidth() const
{
    return outline_ ? outline_->GetDashWidthFour() : Vector4f(0.f);
}

Vector4f RSProperties::GetOutlineDashGap() const
{
    return outline_ ? outline_->GetDashGapFour() : Vector4f(0.f);
}

Vector4f RSProperties::GetOutlineRadius() const
{
    return outline_ ? outline_->GetRadiusFour() : Vector4fZero;
}

const std::shared_ptr<RSBorder>& RSProperties::GetOutline() const
{
    return outline_;
}

void RSProperties::SetForegroundEffectRadius(const float foregroundEffectRadius)
{
    foregroundEffectRadius_ = foregroundEffectRadius;
    if (IsForegroundEffectRadiusValid()) {
        isDrawn_ = true;
    }
    filterNeedUpdate_ = true;
    SetDirty();
}

float RSProperties::GetForegroundEffectRadius() const
{
    return foregroundEffectRadius_;
}

bool RSProperties::IsForegroundEffectRadiusValid() const
{
    return ROSEN_GNE(foregroundEffectRadius_, 0.0);
}

void RSProperties::SetForegroundEffectDirty(bool dirty)
{
    foregroundEffectDirty_ = dirty;
}

bool RSProperties::GetForegroundEffectDirty() const
{
    return foregroundEffectDirty_;
}

const std::shared_ptr<RSFilter>& RSProperties::GetForegroundFilterCache() const
{
    return foregroundFilterCache_;
}

void RSProperties::SetForegroundFilterCache(const std::shared_ptr<RSFilter>& foregroundFilterCache)
{
    foregroundFilterCache_ = foregroundFilterCache;
    if (foregroundFilterCache) {
        isDrawn_ = true;
    }
    SetDirty();
    filterNeedUpdate_ = true;
    contentDirty_ = true;
}

void RSProperties::SetBackgroundFilter(const std::shared_ptr<RSFilter>& backgroundFilter)
{
    backgroundFilter_ = backgroundFilter;
    if (backgroundFilter_) {
        isDrawn_ = true;
    }
    SetDirty();
    filterNeedUpdate_ = true;
    contentDirty_ = true;
}

void RSProperties::SetLinearGradientBlurPara(const std::shared_ptr<RSLinearGradientBlurPara>& para)
{
    linearGradientBlurPara_ = para;
    if (para && para->blurRadius_ > 0.f) {
        isDrawn_ = true;
    }
    filterNeedUpdate_ = true;
    SetDirty();
    contentDirty_ = true;
}

void RSProperties::SetEmitterUpdater(const std::vector<std::shared_ptr<EmitterUpdater>>& para)
{
    emitterUpdater_ = para;
    if (!emitterUpdater_.empty()) {
        isDrawn_ = true;
        auto renderNode = backref_.lock();
        if (renderNode == nullptr) {
            return;
        }
        auto animation = renderNode->GetAnimationManager().GetParticleAnimation();
        if (animation == nullptr) {
            return;
        }
        auto particleAnimation = std::static_pointer_cast<RSRenderParticleAnimation>(animation);
        if (particleAnimation) {
            particleAnimation->UpdateEmitter(emitterUpdater_);
        }
    }
    filterNeedUpdate_ = true;
    SetDirty();
    contentDirty_ = true;
}

void RSProperties::SetParticleNoiseFields(const std::shared_ptr<ParticleNoiseFields>& para)
{
    particleNoiseFields_ = para;
    if (particleNoiseFields_) {
        isDrawn_ = true;
        auto renderNode = backref_.lock();
        if (renderNode == nullptr) {
            return;
        }
        auto animation = renderNode->GetAnimationManager().GetParticleAnimation();
        if (animation == nullptr) {
            return;
        }
        auto particleAnimation = std::static_pointer_cast<RSRenderParticleAnimation>(animation);
        if (particleAnimation) {
            particleAnimation->UpdateNoiseField(particleNoiseFields_);
        }
    }
    filterNeedUpdate_ = true;
    SetDirty();
    contentDirty_ = true;
}

void RSProperties::SetDynamicLightUpRate(const std::optional<float>& rate)
{
    dynamicLightUpRate_ = rate;
    if (rate.has_value()) {
        isDrawn_ = true;
    }
    filterNeedUpdate_ = true;
    SetDirty();
    contentDirty_ = true;
}

void RSProperties::SetDynamicLightUpDegree(const std::optional<float>& lightUpDegree)
{
    dynamicLightUpDegree_ = lightUpDegree;
    if (lightUpDegree.has_value()) {
        isDrawn_ = true;
    }
    filterNeedUpdate_ = true;
    SetDirty();
    contentDirty_ = true;
}

void RSProperties::SetWaterRippleProgress(const float& progress)
{
    waterRippleProgress_ = progress;
    isDrawn_ = true;
    filterNeedUpdate_ = true;
    SetDirty();
    contentDirty_ = true;
}
 
float RSProperties::GetWaterRippleProgress() const
{
    return waterRippleProgress_;
}
 
void RSProperties::SetWaterRippleParams(const std::optional<RSWaterRipplePara>& params)
{
    waterRippleParams_ = params;
    if (params.has_value()) {
        isDrawn_ = true;
    }
    filterNeedUpdate_ = true;
    SetDirty();
    contentDirty_ = true;
}
 
std::optional<RSWaterRipplePara> RSProperties::GetWaterRippleParams() const
{
    return waterRippleParams_;
}
 
bool RSProperties::IsWaterRippleValid() const
{
    return ROSEN_GE(waterRippleProgress_, 0.0f) && ROSEN_LE(waterRippleProgress_, 1.0f) &&
           waterRippleParams_.has_value() && ROSEN_GE(waterRippleParams_->waveCount, 1.0f) &&
           ROSEN_LE(waterRippleParams_->waveCount, 3.0f);
}

void RSProperties::SetFgBrightnessRates(const Vector4f& rates)
{
    if (!fgBrightnessParams_.has_value()) {
        fgBrightnessParams_ = std::make_optional<RSDynamicBrightnessPara>();
    }
    fgBrightnessParams_->rates_ = rates;
    isDrawn_ = true;
    filterNeedUpdate_ = true;
    SetDirty();
    contentDirty_ = true;
}

Vector4f RSProperties::GetFgBrightnessRates() const
{
    return fgBrightnessParams_ ? fgBrightnessParams_->rates_ : Vector4f();
}

void RSProperties::SetFgBrightnessSaturation(const float& saturation)
{
    if (!fgBrightnessParams_.has_value()) {
        fgBrightnessParams_ = std::make_optional<RSDynamicBrightnessPara>();
    }
    fgBrightnessParams_->saturation_ = saturation;
    isDrawn_ = true;
    filterNeedUpdate_ = true;
    SetDirty();
    contentDirty_ = true;
}

float RSProperties::GetFgBrightnessSaturation() const
{
    return fgBrightnessParams_ ? fgBrightnessParams_->saturation_ : 0.0f;
}

void RSProperties::SetFgBrightnessPosCoeff(const Vector4f& coeff)
{
    if (!fgBrightnessParams_.has_value()) {
        fgBrightnessParams_ = std::make_optional<RSDynamicBrightnessPara>();
    }
    fgBrightnessParams_->posCoeff_ = coeff;
    isDrawn_ = true;
    filterNeedUpdate_ = true;
    SetDirty();
    contentDirty_ = true;
}

Vector4f RSProperties::GetFgBrightnessPosCoeff() const
{
    return fgBrightnessParams_ ? fgBrightnessParams_->posCoeff_ : Vector4f();
}

void RSProperties::SetFgBrightnessNegCoeff(const Vector4f& coeff)
{
    if (!fgBrightnessParams_.has_value()) {
        fgBrightnessParams_ = std::make_optional<RSDynamicBrightnessPara>();
    }
    fgBrightnessParams_->negCoeff_ = coeff;
    isDrawn_ = true;
    filterNeedUpdate_ = true;
    SetDirty();
    contentDirty_ = true;
}

Vector4f RSProperties::GetFgBrightnessNegCoeff() const
{
    return fgBrightnessParams_ ? fgBrightnessParams_->negCoeff_ : Vector4f();
}

void RSProperties::SetFgBrightnessFract(const float& fraction)
{
    if (!fgBrightnessParams_.has_value()) {
        fgBrightnessParams_ = std::make_optional<RSDynamicBrightnessPara>();
    }
    fgBrightnessParams_->fraction_ = fraction;
    isDrawn_ = true;
    filterNeedUpdate_ = true;
    SetDirty();
    contentDirty_ = true;
}

float RSProperties::GetFgBrightnessFract() const
{
    return fgBrightnessParams_ ? fgBrightnessParams_->fraction_ : 1.0f;
}

void RSProperties::SetFgBrightnessParams(const std::optional<RSDynamicBrightnessPara>& params)
{
    fgBrightnessParams_ = params;
    if (params.has_value()) {
        isDrawn_ = true;
    }
    filterNeedUpdate_ = true;
    SetDirty();
    contentDirty_ = true;
}

std::optional<RSDynamicBrightnessPara> RSProperties::GetFgBrightnessParams() const
{
    return fgBrightnessParams_;
}

void RSProperties::SetBgBrightnessRates(const Vector4f& rates)
{
    if (!bgBrightnessParams_.has_value()) {
        bgBrightnessParams_ = std::make_optional<RSDynamicBrightnessPara>();
    }
    bgBrightnessParams_->rates_ = rates;
    isDrawn_ = true;
    filterNeedUpdate_ = true;
    SetDirty();
    contentDirty_ = true;
}

Vector4f RSProperties::GetBgBrightnessRates() const
{
    return bgBrightnessParams_ ? bgBrightnessParams_->rates_ : Vector4f();
}

void RSProperties::SetBgBrightnessSaturation(const float& saturation)
{
    if (!bgBrightnessParams_.has_value()) {
        bgBrightnessParams_ = std::make_optional<RSDynamicBrightnessPara>();
    }
    bgBrightnessParams_->saturation_ = saturation;
    isDrawn_ = true;
    filterNeedUpdate_ = true;
    SetDirty();
    contentDirty_ = true;
}

float RSProperties::GetBgBrightnessSaturation() const
{
    return bgBrightnessParams_ ? bgBrightnessParams_->saturation_ : 0.0f;
}

void RSProperties::SetBgBrightnessPosCoeff(const Vector4f& coeff)
{
    if (!bgBrightnessParams_.has_value()) {
        bgBrightnessParams_ = std::make_optional<RSDynamicBrightnessPara>();
    }
    bgBrightnessParams_->posCoeff_ = coeff;
    isDrawn_ = true;
    filterNeedUpdate_ = true;
    SetDirty();
    contentDirty_ = true;
}

Vector4f RSProperties::GetBgBrightnessPosCoeff() const
{
    return bgBrightnessParams_ ? bgBrightnessParams_->posCoeff_ : Vector4f();
}

void RSProperties::SetBgBrightnessNegCoeff(const Vector4f& coeff)
{
    if (!bgBrightnessParams_.has_value()) {
        bgBrightnessParams_ = std::make_optional<RSDynamicBrightnessPara>();
    }
    bgBrightnessParams_->negCoeff_ = coeff;
    isDrawn_ = true;
    filterNeedUpdate_ = true;
    SetDirty();
    contentDirty_ = true;
}

Vector4f RSProperties::GetBgBrightnessNegCoeff() const
{
    return bgBrightnessParams_ ? bgBrightnessParams_->negCoeff_ : Vector4f();
}

void RSProperties::SetBgBrightnessFract(const float& fraction)
{
    if (!bgBrightnessParams_.has_value()) {
        bgBrightnessParams_ = std::make_optional<RSDynamicBrightnessPara>();
    }
    bgBrightnessParams_->fraction_ = fraction;
    isDrawn_ = true;
    filterNeedUpdate_ = true;
    SetDirty();
    contentDirty_ = true;
}

float RSProperties::GetBgBrightnessFract() const
{
    return bgBrightnessParams_ ? bgBrightnessParams_->fraction_ : 1.0f;
}

void RSProperties::SetBgBrightnessParams(const std::optional<RSDynamicBrightnessPara>& params)
{
    bgBrightnessParams_ = params;
    if (params.has_value()) {
        isDrawn_ = true;
    }
    filterNeedUpdate_ = true;
    SetDirty();
    contentDirty_ = true;
}

std::optional<RSDynamicBrightnessPara> RSProperties::GetBgBrightnessParams() const
{
    return bgBrightnessParams_;
}

bool RSProperties::IsFgBrightnessValid() const
{
    return fgBrightnessParams_.has_value() && ROSEN_LNE(fgBrightnessParams_->fraction_, 1.0);
}

bool RSProperties::IsBgBrightnessValid() const
{
    return bgBrightnessParams_.has_value() && ROSEN_LNE(bgBrightnessParams_->fraction_, 1.0);
}

std::string RSProperties::GetFgBrightnessDescription() const
{
    if (!fgBrightnessParams_.has_value()) {
        return "fgBrightnessParams_ is nullopt";
    }
    std::string description =
        "ForegroundBrightness, cubicCoeff: " + std::to_string(fgBrightnessParams_->rates_.x_) +
        ", quadCoeff: " + std::to_string(fgBrightnessParams_->rates_.y_) +
        ", rate: " + std::to_string(fgBrightnessParams_->rates_.z_) +
        ", lightUpDegree: " + std::to_string(fgBrightnessParams_->rates_.w_) +
        ", saturation: " + std::to_string(fgBrightnessParams_->saturation_) +
        ", fgBrightnessFract: " + std::to_string(fgBrightnessParams_->fraction_);
    return description;
}

std::string RSProperties::GetBgBrightnessDescription() const
{
    if (!bgBrightnessParams_.has_value()) {
        return "bgBrightnessParams_ is nullopt";
    }
    std::string description =
        "BackgroundBrightnessInternal, cubicCoeff: " + std::to_string(bgBrightnessParams_->rates_.x_) +
        ", quadCoeff: " + std::to_string(bgBrightnessParams_->rates_.y_) +
        ", rate: " + std::to_string(bgBrightnessParams_->rates_.z_) +
        ", lightUpDegree: " + std::to_string(bgBrightnessParams_->rates_.w_) +
        ", saturation: " + std::to_string(bgBrightnessParams_->saturation_) +
        ", fgBrightnessFract: " + std::to_string(bgBrightnessParams_->fraction_);
    return description;
}

void RSProperties::SetGreyCoef(const std::optional<Vector2f>& greyCoef)
{
    greyCoef_ = greyCoef;
    greyCoefNeedUpdate_ = true;
    SetDirty();
    contentDirty_ = true;
}

void RSProperties::SetDynamicDimDegree(const std::optional<float>& DimDegree)
{
    dynamicDimDegree_ = DimDegree;
    if (DimDegree.has_value()) {
        isDrawn_ = true;
    }
    filterNeedUpdate_ = true;
    SetDirty();
    contentDirty_ = true;
}

void RSProperties::SetFilter(const std::shared_ptr<RSFilter>& filter)
{
    filter_ = filter;
    if (filter) {
        isDrawn_ = true;
    }
    SetDirty();
    filterNeedUpdate_ = true;
    contentDirty_ = true;
}

void RSProperties::SetMotionBlurPara(const std::shared_ptr<MotionBlurParam>& para)
{
    motionBlurPara_ = para;

    if (para && para->radius > 0.f) {
        isDrawn_ = true;
    }
    SetDirty();
    filterNeedUpdate_ = true;
    contentDirty_ = true;
}

void RSProperties::SetMagnifierParams(const std::shared_ptr<RSMagnifierParams>& para)
{
    magnifierPara_ = para;

    if (para) {
        isDrawn_ = true;
    }
    SetDirty();
    filterNeedUpdate_ = true;
    contentDirty_ = true;
}

const std::shared_ptr<RSMagnifierParams>& RSProperties::GetMagnifierPara() const
{
    return magnifierPara_;
}

const std::shared_ptr<RSFilter>& RSProperties::GetBackgroundFilter() const
{
    return backgroundFilter_;
}

const std::shared_ptr<RSLinearGradientBlurPara>& RSProperties::GetLinearGradientBlurPara() const
{
    return linearGradientBlurPara_;
}

const std::vector<std::shared_ptr<EmitterUpdater>>& RSProperties::GetEmitterUpdater() const
{
    return emitterUpdater_;
}

const std::shared_ptr<ParticleNoiseFields>& RSProperties::GetParticleNoiseFields() const
{
    return particleNoiseFields_;
}

void RSProperties::IfLinearGradientBlurInvalid()
{
    if (linearGradientBlurPara_ != nullptr) {
        bool isValid = ROSEN_GE(linearGradientBlurPara_->blurRadius_, 0.0);
        if (!isValid) {
            linearGradientBlurPara_.reset();
        }
    }
}

const std::optional<float>& RSProperties::GetDynamicLightUpRate() const
{
    return dynamicLightUpRate_;
}

const std::optional<float>& RSProperties::GetDynamicLightUpDegree() const
{
    return dynamicLightUpDegree_;
}

const std::optional<float>& RSProperties::GetDynamicDimDegree() const
{
    return dynamicDimDegree_;
}

const std::optional<Vector2f>& RSProperties::GetGreyCoef() const
{
    return greyCoef_;
}

bool RSProperties::IsDynamicDimValid() const
{
    return dynamicDimDegree_.has_value() &&
           ROSEN_GE(*dynamicDimDegree_, 0.0) && ROSEN_LNE(*dynamicDimDegree_, 1.0);
}

const std::shared_ptr<RSFilter>& RSProperties::GetFilter() const
{
    return filter_;
}

const std::shared_ptr<MotionBlurParam>& RSProperties::GetMotionBlurPara() const
{
    return motionBlurPara_;
}

bool RSProperties::IsDynamicLightUpValid() const
{
    return dynamicLightUpRate_.has_value() && dynamicLightUpDegree_.has_value() &&
           ROSEN_GNE(*dynamicLightUpRate_, 0.0) && ROSEN_GE(*dynamicLightUpDegree_, -1.0) &&
           ROSEN_LE(*dynamicLightUpDegree_, 1.0);
}

const std::shared_ptr<RSFilter>& RSProperties::GetForegroundFilter() const
{
    return foregroundFilter_;
}

void RSProperties::SetForegroundFilter(const std::shared_ptr<RSFilter>& foregroundFilter)
{
    foregroundFilter_ = foregroundFilter;
    if (foregroundFilter) {
        isDrawn_ = true;
    }
    SetDirty();
    filterNeedUpdate_ = true;
    contentDirty_ = true;
}

// shadow properties
void RSProperties::SetShadowColor(Color color)
{
    if (!shadow_.has_value()) {
        shadow_ = std::make_optional<RSShadow>();
    }
    shadow_->SetColor(color);
    SetDirty();
    // [planning] if shadow stores as texture and out of node
    // node content would not be affected
    contentDirty_ = true;
}

void RSProperties::SetShadowOffsetX(float offsetX)
{
    if (!shadow_.has_value()) {
        shadow_ = std::make_optional<RSShadow>();
    }
    shadow_->SetOffsetX(offsetX);
    SetDirty();
    filterNeedUpdate_ = true;
    // [planning] if shadow stores as texture and out of node
    // node content would not be affected
    contentDirty_ = true;
}

void RSProperties::SetShadowOffsetY(float offsetY)
{
    if (!shadow_.has_value()) {
        shadow_ = std::make_optional<RSShadow>();
    }
    shadow_->SetOffsetY(offsetY);
    SetDirty();
    filterNeedUpdate_ = true;
    // [planning] if shadow stores as texture and out of node
    // node content would not be affected
    contentDirty_ = true;
}

void RSProperties::SetShadowAlpha(float alpha)
{
    if (!shadow_.has_value()) {
        shadow_ = std::make_optional<RSShadow>();
    }
    shadow_->SetAlpha(alpha);
    if (shadow_->IsValid()) {
        isDrawn_ = true;
    }
    SetDirty();
    // [planning] if shadow stores as texture and out of node
    // node content would not be affected
    contentDirty_ = true;
}

void RSProperties::SetShadowElevation(float elevation)
{
    if (!shadow_.has_value()) {
        shadow_ = std::make_optional<RSShadow>();
    }
    shadow_->SetElevation(elevation);
    if (shadow_->IsValid()) {
        isDrawn_ = true;
    }
    SetDirty();
    // [planning] if shadow stores as texture and out of node
    // node content would not be affected
    contentDirty_ = true;
}

void RSProperties::SetShadowRadius(float radius)
{
    if (!shadow_.has_value()) {
        shadow_ = std::make_optional<RSShadow>();
    }
    shadow_->SetRadius(radius);
    if (shadow_->IsValid()) {
        isDrawn_ = true;
    }
    SetDirty();
    filterNeedUpdate_ = true;
    // [planning] if shadow stores as texture and out of node
    // node content would not be affected
    contentDirty_ = true;
}

void RSProperties::SetShadowPath(std::shared_ptr<RSPath> shadowPath)
{
    if (!shadow_.has_value()) {
        shadow_ = std::make_optional<RSShadow>();
    }
    shadow_->SetPath(shadowPath);
    SetDirty();
    // [planning] if shadow stores as texture and out of node
    // node content would not be affected
    contentDirty_ = true;
}

void RSProperties::SetShadowMask(bool shadowMask)
{
    if (!shadow_.has_value()) {
        shadow_ = std::make_optional<RSShadow>();
    }
    shadow_->SetMask(shadowMask);
    SetDirty();
    filterNeedUpdate_ = true;
    // [planning] if shadow stores as texture and out of node
    // node content would not be affected
    contentDirty_ = true;
}

void RSProperties::SetShadowIsFilled(bool shadowIsFilled)
{
    if (!shadow_.has_value()) {
        shadow_ = std::make_optional<RSShadow>();
    }
    shadow_->SetIsFilled(shadowIsFilled);
    SetDirty();
    // [planning] if shadow stores as texture and out of node
    // node content would not be affected
    contentDirty_ = true;
}

void RSProperties::SetShadowColorStrategy(int shadowColorStrategy)
{
    if (!shadow_.has_value()) {
        shadow_ = std::make_optional<RSShadow>();
    }
    shadow_->SetColorStrategy(shadowColorStrategy);
    SetDirty();
    filterNeedUpdate_ = true;
    // [planning] if shadow stores as texture and out of node
    // node content would not be affected
    contentDirty_ = true;
    if (shadowColorStrategy != SHADOW_COLOR_STRATEGY::COLOR_STRATEGY_NONE &&
        shadow_->GetColorPickerCacheTask() == nullptr) {
        auto colorPickerTaskShadow = std::make_shared<RSColorPickerCacheTask>();
        colorPickerTaskShadow->SetShadowColorStrategy(shadowColorStrategy);
        shadow_->SetColorPickerCacheTask(colorPickerTaskShadow);
    }
}

const Color& RSProperties::GetShadowColor() const
{
    static const auto DEFAULT_SPOT_COLOR_VALUE = Color::FromArgbInt(DEFAULT_SPOT_COLOR);
    return shadow_ ? shadow_->GetColor() : DEFAULT_SPOT_COLOR_VALUE;
}

float RSProperties::GetShadowOffsetX() const
{
    return shadow_ ? shadow_->GetOffsetX() : DEFAULT_SHADOW_OFFSET_X;
}

float RSProperties::GetShadowOffsetY() const
{
    return shadow_ ? shadow_->GetOffsetY() : DEFAULT_SHADOW_OFFSET_Y;
}

float RSProperties::GetShadowAlpha() const
{
    return shadow_ ? shadow_->GetAlpha() : 0.f;
}

float RSProperties::GetShadowElevation() const
{
    return shadow_ ? shadow_->GetElevation() : 0.f;
}

float RSProperties::GetShadowRadius() const
{
    return shadow_ ? shadow_->GetRadius() : DEFAULT_SHADOW_RADIUS;
}

std::shared_ptr<RSPath> RSProperties::GetShadowPath() const
{
    return shadow_ ? shadow_->GetPath() : nullptr;
}

bool RSProperties::GetShadowMask() const
{
    return shadow_ ? shadow_->GetMask() : false;
}

bool RSProperties::GetShadowIsFilled() const
{
    return shadow_ ? shadow_->GetIsFilled() : false;
}

int RSProperties::GetShadowColorStrategy() const
{
    return shadow_ ? shadow_->GetColorStrategy() : SHADOW_COLOR_STRATEGY::COLOR_STRATEGY_NONE;
}

const std::optional<RSShadow>& RSProperties::GetShadow() const
{
    return shadow_;
}

bool RSProperties::IsShadowValid() const
{
    return shadow_ && shadow_->IsValid();
}

void RSProperties::SetFrameGravity(Gravity gravity)
{
    if (frameGravity_ != gravity) {
        frameGravity_ = gravity;
        SetDirty();
        contentDirty_ = true;
    }
}

Gravity RSProperties::GetFrameGravity() const
{
    return frameGravity_;
}

void RSProperties::SetDrawRegion(const std::shared_ptr<RectF>& rect)
{
    drawRegion_ = rect;
    SetDirty();
    geoDirty_ = true;  // since drawRegion affect dirtyRegion, mark it as geoDirty
}

std::shared_ptr<RectF> RSProperties::GetDrawRegion() const
{
    return drawRegion_;
}

void RSProperties::SetClipRRect(RRect clipRRect)
{
    clipRRect_ = clipRRect;
    if (GetClipToRRect()) {
        isDrawn_ = true;
    }
    SetDirty();
    geoDirty_ = true;  // [planning] all clip ops should be checked
}

RRect RSProperties::GetClipRRect() const
{
    return clipRRect_ ? *clipRRect_ : RRect();
}

bool RSProperties::GetClipToRRect() const
{
    return clipRRect_.has_value() && !clipRRect_->rect_.IsEmpty();
}

void RSProperties::SetClipBounds(const std::shared_ptr<RSPath>& path)
{
    if (path) {
        isDrawn_ = true;
    }
    if (clipPath_ != path) {
        clipPath_ = path;
        SetDirty();
        geoDirty_ = true;  // [planning] all clip ops should be checked
    }
}

const std::shared_ptr<RSPath>& RSProperties::GetClipBounds() const
{
    return clipPath_;
}

void RSProperties::SetClipToBounds(bool clipToBounds)
{
    if (clipToBounds) {
        isDrawn_ = true;
    }
    if (clipToBounds_ != clipToBounds) {
        clipToBounds_ = clipToBounds;
        SetDirty();
        geoDirty_ = true;  // [planning] all clip ops should be checked
    }
}

bool RSProperties::GetClipToBounds() const
{
    return clipToBounds_;
}

void RSProperties::SetClipToFrame(bool clipToFrame)
{
    if (clipToFrame) {
        isDrawn_ = true;
    }
    if (clipToFrame_ != clipToFrame) {
        clipToFrame_ = clipToFrame;
        SetDirty();
        geoDirty_ = true;  // [planning] all clip ops should be checked
    }
}

bool RSProperties::GetClipToFrame() const
{
    return clipToFrame_;
}

RectF RSProperties::GetLocalBoundsAndFramesRect() const
{
    auto rect = GetBoundsRect();
    if (!clipToBounds_ && !std::isinf(GetFrameWidth()) && !std::isinf(GetFrameHeight())) {
        rect = rect.JoinRect(RectF(GetFrameOffsetX(), GetFrameOffsetY(), GetFrameWidth(), GetFrameHeight()));
    }
    return rect;
}

RectF RSProperties::GetBoundsRect() const
{
    auto rect = RectF();
    if (boundsGeo_->IsEmpty()) {
        if (!std::isinf(GetFrameWidth()) && !std::isinf(GetFrameHeight())) {
            return {0, 0, GetFrameWidth(), GetFrameHeight()};
        }
    } else {
        if (!std::isinf(GetBoundsWidth()) && !std::isinf(GetBoundsHeight())) {
            return {0, 0, GetBoundsWidth(), GetBoundsHeight()};
        }
    }
    return rect;
}

RectF RSProperties::GetFrameRect() const
{
    return {0, 0, GetFrameWidth(), GetFrameHeight()};
}

const RectF& RSProperties::GetBgImageRect() const
{
    return decoration_ ? decoration_->bgImageRect_ : EMPTY_RECT;
}

void RSProperties::SetVisible(bool visible)
{
    if (visible_ != visible) {
        visible_ = visible;
        SetDirty();
        contentDirty_ = true;
    }
}

bool RSProperties::GetVisible() const
{
    return visible_;
}

const RRect& RSProperties::GetRRect() const
{
    return rrect_;
}

void RSProperties::GenerateRRect()
{
    RectF rect = GetBoundsRect();
    rrect_ = RRect(rect, GetCornerRadius());
}

RRect RSProperties::GetInnerRRect() const
{
    auto rect = GetBoundsRect();
    Vector4f cornerRadius = GetCornerRadius();
    if (border_) {
        rect.left_ += border_->GetWidth(RSBorder::LEFT);
        rect.top_ += border_->GetWidth(RSBorder::TOP);
        rect.width_ -= border_->GetWidth(RSBorder::LEFT) + border_->GetWidth(RSBorder::RIGHT);
        rect.height_ -= border_->GetWidth(RSBorder::TOP) + border_->GetWidth(RSBorder::BOTTOM);
    }
    RRect rrect = RRect(rect, cornerRadius);
    if (border_) {
        rrect.radius_[0] -= { border_->GetWidth(RSBorder::LEFT), border_->GetWidth(RSBorder::TOP) };
        rrect.radius_[1] -= { border_->GetWidth(RSBorder::RIGHT), border_->GetWidth(RSBorder::TOP) };
        rrect.radius_[2] -= { border_->GetWidth(RSBorder::RIGHT), border_->GetWidth(RSBorder::BOTTOM) };
        rrect.radius_[3] -= { border_->GetWidth(RSBorder::LEFT), border_->GetWidth(RSBorder::BOTTOM) };
    }
    return rrect;
}

bool RSProperties::NeedFilter() const
{
    return needFilter_;
}

bool RSProperties::NeedClip() const
{
    return clipToBounds_ || clipToFrame_;
}

void RSProperties::SetDirty()
{
    isDirty_ = true;
}

void RSProperties::ResetDirty()
{
    isDirty_ = false;
    geoDirty_ = false;
    contentDirty_ = false;
}

void RSProperties::RecordCurDirtyStatus()
{
    curIsDirty_ = isDirty_;
    curGeoDirty_ = geoDirty_;
    curContentDirty_ = contentDirty_;
}

void RSProperties::AccmulateDirtyStatus()
{
    isDirty_ = isDirty_ || curIsDirty_;
    geoDirty_ = geoDirty_ || curGeoDirty_;
    contentDirty_ = contentDirty_ || curContentDirty_;
}

bool RSProperties::IsDirty() const
{
    return isDirty_;
}

bool RSProperties::IsGeoDirty() const
{
    return geoDirty_;
}

bool RSProperties::IsCurGeoDirty() const
{
    return curGeoDirty_;
}

bool RSProperties::IsContentDirty() const
{
    return contentDirty_;
}

RectI RSProperties::GetDirtyRect() const
{
    RectI dirtyRect = boundsGeo_->MapAbsRect(GetLocalBoundsAndFramesRect());
    if (drawRegion_ == nullptr || drawRegion_->IsEmpty()) {
        return dirtyRect;
    } else {
        auto drawRegion = boundsGeo_->MapAbsRect(*drawRegion_);
        // this is used to fix the scene with drawRegion problem, which is need to be optimized
        drawRegion.SetRight(drawRegion.GetRight() + 1);
        drawRegion.SetBottom(drawRegion.GetBottom() + 1);
        drawRegion.SetAll(drawRegion.left_ - 1, drawRegion.top_ - 1,
            drawRegion.width_ + 1, drawRegion.height_ + 1);
        return dirtyRect.JoinRect(drawRegion);
    }
}

RectI RSProperties::GetDirtyRect(RectI& drawRegion) const
{
    RectI dirtyRect;
    if (clipToBounds_ || std::isinf(GetFrameWidth()) || std::isinf(GetFrameHeight())) {
        dirtyRect = boundsGeo_->GetAbsRect();
    } else {
        auto frameRect =
            boundsGeo_->MapAbsRect(RectF(GetFrameOffsetX(), GetFrameOffsetY(), GetFrameWidth(), GetFrameHeight()));
        dirtyRect = boundsGeo_->GetAbsRect().JoinRect(frameRect);
    }
    if (drawRegion_ == nullptr || drawRegion_->IsEmpty()) {
        drawRegion = RectI();
        return dirtyRect;
    } else {
        drawRegion = boundsGeo_->MapAbsRect(*drawRegion_);
        // this is used to fix the scene with drawRegion problem, which is need to be optimized
        drawRegion.SetRight(drawRegion.GetRight() + 1);
        drawRegion.SetBottom(drawRegion.GetBottom() + 1);
        drawRegion.SetAll(drawRegion.left_ - 1, drawRegion.top_ - 1,
            drawRegion.width_ + 1, drawRegion.height_ + 1);
        return dirtyRect.JoinRect(drawRegion);
    }
}

void RSProperties::CheckEmptyBounds()
{
    // [planning] remove this func and fallback to framerect after surfacenode using frame
    if (!hasBounds_) {
        boundsGeo_->SetRect(frameGeo_->GetX(), frameGeo_->GetY(), frameGeo_->GetWidth(), frameGeo_->GetHeight());
    }
}

// mask properties
void RSProperties::SetMask(const std::shared_ptr<RSMask>& mask)
{
    mask_ = mask;
    if (mask_) {
        isDrawn_ = true;
    }
    SetDirty();
    contentDirty_ = true;
}

std::shared_ptr<RSMask> RSProperties::GetMask() const
{
    return mask_;
}

void RSProperties::SetSpherize(float spherizeDegree)
{
    spherizeDegree_ = spherizeDegree;
    isSpherizeValid_ = spherizeDegree_ > SPHERIZE_VALID_EPSILON;
    if (isSpherizeValid_) {
        isDrawn_ = true;
    }
    filterNeedUpdate_ = true;
    SetDirty();
}

float RSProperties::GetSpherize() const
{
    return spherizeDegree_;
}

bool RSProperties::IsSpherizeValid() const
{
    return isSpherizeValid_;
}

void RSProperties::CreateSphereEffectFilter()
{
    auto spherizeEffectFilter = std::make_shared<RSSpherizeEffectFilter>(spherizeDegree_);
    if (IS_UNI_RENDER) {
        foregroundFilterCache_ = spherizeEffectFilter;
    } else {
        foregroundFilter_ = spherizeEffectFilter;
    }
}

void RSProperties::CreateAttractionEffectFilter()
{
    float canvasWidth = GetBoundsRect().GetWidth();
    float canvasHeight = GetBoundsRect().GetHeight();
    Vector2f destinationPoint = GetAttractionDstPoint();
    float windowLeftPoint = GetFramePositionX();
    float windowTopPoint = GetFramePositionY();
    auto attractionEffectFilter = std::make_shared<RSAttractionEffectFilter>(attractFraction_);
    attractionEffectFilter->CalculateWindowStatus(canvasWidth, canvasHeight, destinationPoint);
    attractionEffectFilter->UpdateDirtyRegion(windowLeftPoint, windowTopPoint);
    attractionEffectCurrentDirtyRegion_ = attractionEffectFilter->GetAttractionDirtyRegion();
    foregroundFilter_ = attractionEffectFilter;
}

RectI RSProperties::GetAttractionEffectCurrentDirtyRegion() const
{
    return attractionEffectCurrentDirtyRegion_;
}

float RSProperties::GetAttractionFraction() const
{
    return attractFraction_;
}

void RSProperties::SetAttractionDstPoint(Vector2f dstPoint)
{
    attractDstPoint_ = dstPoint;
}

Vector2f  RSProperties::GetAttractionDstPoint() const
{
    return attractDstPoint_;
}

void RSProperties::SetAttractionFraction(float fraction)
{
    attractFraction_ = fraction;
    isAttractionValid_ = attractFraction_ > ATTRACTION_VALID_EPSILON;
    if (isAttractionValid_) {
        isDrawn_ = true;
    }
    filterNeedUpdate_ = true;
    SetDirty();
    contentDirty_ = true;
}

bool RSProperties::IsAttractionValid() const
{
    return isAttractionValid_;
}

void RSProperties::SetLightUpEffect(float lightUpEffectDegree)
{
    lightUpEffectDegree_ = lightUpEffectDegree;
    if (IsLightUpEffectValid()) {
        isDrawn_ = true;
    }
    filterNeedUpdate_ = true;
    SetDirty();
    contentDirty_ = true;
}

float RSProperties::GetLightUpEffect() const
{
    return lightUpEffectDegree_;
}

bool RSProperties::IsLightUpEffectValid() const
{
    return ROSEN_GE(GetLightUpEffect(), 0.0) && ROSEN_LNE(GetLightUpEffect(), 1.0);
}

// filter property
void RSProperties::SetBackgroundBlurRadius(float backgroundBlurRadius)
{
    backgroundBlurRadius_ = backgroundBlurRadius;
    if (IsBackgroundBlurRadiusValid()) {
        isDrawn_ = true;
    }
    filterNeedUpdate_ = true;
    SetDirty();
    contentDirty_ = true;
}

float RSProperties::GetBackgroundBlurRadius() const
{
    return backgroundBlurRadius_;
}

bool RSProperties::IsBackgroundBlurRadiusValid() const
{
    return ROSEN_GNE(GetBackgroundBlurRadius(), 0.9f); // Adjust the materialBlur radius to 0.9 for the spring curve
}

void RSProperties::SetBackgroundBlurSaturation(float backgroundBlurSaturation)
{
    backgroundBlurSaturation_ = backgroundBlurSaturation;
    if (IsBackgroundBlurSaturationValid()) {
        isDrawn_ = true;
    }
    filterNeedUpdate_ = true;
    SetDirty();
    contentDirty_ = true;
}

float RSProperties::GetBackgroundBlurSaturation() const
{
    return backgroundBlurSaturation_;
}

bool RSProperties::IsBackgroundBlurSaturationValid() const
{
    return (!ROSEN_EQ(GetBackgroundBlurSaturation(), 1.0f)) && ROSEN_GE(GetBackgroundBlurSaturation(), 0.0f);
}

void RSProperties::SetBackgroundBlurBrightness(float backgroundBlurBrightness)
{
    backgroundBlurBrightness_ = backgroundBlurBrightness;
    if (IsBackgroundBlurBrightnessValid()) {
        isDrawn_ = true;
    }
    filterNeedUpdate_ = true;
    SetDirty();
    contentDirty_ = true;
}

float RSProperties::GetBackgroundBlurBrightness() const
{
    return backgroundBlurBrightness_;
}

bool RSProperties::IsBackgroundBlurBrightnessValid() const
{
    return (!ROSEN_EQ(GetBackgroundBlurBrightness(), 1.0f)) && ROSEN_GE(GetBackgroundBlurBrightness(), 0.0f);
}

void RSProperties::SetBackgroundBlurMaskColor(Color backgroundMaskColor)
{
    backgroundMaskColor_ = backgroundMaskColor;
    if (IsBackgroundBlurMaskColorValid()) {
        isDrawn_ = true;
    }
    filterNeedUpdate_ = true;
    SetDirty();
    contentDirty_ = true;
}

const Color& RSProperties::GetBackgroundBlurMaskColor() const
{
    return backgroundMaskColor_;
}

bool RSProperties::IsBackgroundBlurMaskColorValid() const
{
    return backgroundMaskColor_ != RSColor();
}

void RSProperties::SetBackgroundBlurColorMode(int backgroundColorMode)
{
    backgroundColorMode_ = backgroundColorMode;
    filterNeedUpdate_ = true;
    SetDirty();
    contentDirty_ = true;
}

int RSProperties::GetBackgroundBlurColorMode() const
{
    return backgroundColorMode_;
}

void RSProperties::SetBackgroundBlurRadiusX(float backgroundBlurRadiusX)
{
    backgroundBlurRadiusX_ = backgroundBlurRadiusX;
    if (IsBackgroundBlurRadiusXValid()) {
        isDrawn_ = true;
    }
    filterNeedUpdate_ = true;
    SetDirty();
    contentDirty_ = true;
}

float RSProperties::GetBackgroundBlurRadiusX() const
{
    return backgroundBlurRadiusX_;
}

bool RSProperties::IsBackgroundBlurRadiusXValid() const
{
    return ROSEN_GNE(GetBackgroundBlurRadiusX(), 0.999f);
}

void RSProperties::SetBackgroundBlurRadiusY(float backgroundBlurRadiusY)
{
    backgroundBlurRadiusY_ = backgroundBlurRadiusY;
    if (IsBackgroundBlurRadiusYValid()) {
        isDrawn_ = true;
    }
    filterNeedUpdate_ = true;
    SetDirty();
    contentDirty_ = true;
}

float RSProperties::GetBackgroundBlurRadiusY() const
{
    return backgroundBlurRadiusY_;
}

bool RSProperties::IsBackgroundBlurRadiusYValid() const
{
    return ROSEN_GNE(GetBackgroundBlurRadiusY(), 0.999f);
}

void RSProperties::SetForegroundBlurRadius(float foregroundBlurRadius)
{
    foregroundBlurRadius_ = foregroundBlurRadius;
    if (IsForegroundBlurRadiusValid()) {
        isDrawn_ = true;
    }
    filterNeedUpdate_ = true;
    SetDirty();
    contentDirty_ = true;
}

float RSProperties::GetForegroundBlurRadius() const
{
    return foregroundBlurRadius_;
}

bool RSProperties::IsForegroundBlurRadiusValid() const
{
    return ROSEN_GNE(GetForegroundBlurRadius(), 0.9f); // Adjust the materialBlur radius to 0.9 for the spring curve
}

void RSProperties::SetForegroundBlurSaturation(float foregroundBlurSaturation)
{
    foregroundBlurSaturation_ = foregroundBlurSaturation;
    if (IsForegroundBlurSaturationValid()) {
        isDrawn_ = true;
    }
    filterNeedUpdate_ = true;
    SetDirty();
    contentDirty_ = true;
}

float RSProperties::GetForegroundBlurSaturation() const
{
    return foregroundBlurSaturation_;
}

bool RSProperties::IsForegroundBlurSaturationValid() const
{
    return ROSEN_GE(GetForegroundBlurSaturation(), 1.0);
}

void RSProperties::SetForegroundBlurBrightness(float foregroundBlurBrightness)
{
    foregroundBlurBrightness_ = foregroundBlurBrightness;
    if (IsForegroundBlurBrightnessValid()) {
        isDrawn_ = true;
    }
    filterNeedUpdate_ = true;
    SetDirty();
    contentDirty_ = true;
}

float RSProperties::GetForegroundBlurBrightness() const
{
    return foregroundBlurBrightness_;
}

bool RSProperties::IsForegroundBlurBrightnessValid() const
{
    return ROSEN_GE(GetForegroundBlurBrightness(), 1.0);
}

void RSProperties::SetForegroundBlurMaskColor(Color foregroundMaskColor)
{
    foregroundMaskColor_ = foregroundMaskColor;
    if (IsForegroundBlurMaskColorValid()) {
        isDrawn_ = true;
    }
    filterNeedUpdate_ = true;
    SetDirty();
    contentDirty_ = true;
}

const Color& RSProperties::GetForegroundBlurMaskColor() const
{
    return foregroundMaskColor_;
}

bool RSProperties::IsForegroundBlurMaskColorValid() const
{
    return foregroundMaskColor_ != RSColor();
}

void RSProperties::SetForegroundBlurColorMode(int foregroundColorMode)
{
    foregroundColorMode_ = foregroundColorMode;
    filterNeedUpdate_ = true;
    SetDirty();
    contentDirty_ = true;
}

int RSProperties::GetForegroundBlurColorMode() const
{
    return foregroundColorMode_;
}

void RSProperties::SetForegroundBlurRadiusX(float foregroundBlurRadiusX)
{
    foregroundBlurRadiusX_ = foregroundBlurRadiusX;
    if (IsForegroundBlurRadiusXValid()) {
        isDrawn_ = true;
    }
    filterNeedUpdate_ = true;
    SetDirty();
    contentDirty_ = true;
}

float RSProperties::GetForegroundBlurRadiusX() const
{
    return foregroundBlurRadiusX_;
}

bool RSProperties::IsForegroundBlurRadiusXValid() const
{
    return ROSEN_GNE(GetForegroundBlurRadiusX(), 0.999f);
}

void RSProperties::SetForegroundBlurRadiusY(float foregroundBlurRadiusY)
{
    foregroundBlurRadiusY_ = foregroundBlurRadiusY;
    if (IsForegroundBlurRadiusYValid()) {
        isDrawn_ = true;
    }
    filterNeedUpdate_ = true;
    SetDirty();
    contentDirty_ = true;
}

float RSProperties::GetForegroundBlurRadiusY() const
{
    return foregroundBlurRadiusY_;
}

bool RSProperties::IsForegroundBlurRadiusYValid() const
{
    return ROSEN_GNE(GetForegroundBlurRadiusY(), 0.999f);
}

bool RSProperties::IsBackgroundMaterialFilterValid() const
{
    return IsBackgroundBlurRadiusValid() || IsBackgroundBlurBrightnessValid() || IsBackgroundBlurSaturationValid();
}

bool RSProperties::IsForegroundMaterialFilterVaild() const
{
    return IsForegroundBlurRadiusValid();
}

std::shared_ptr<Drawing::ColorFilter> RSProperties::GetMaterialColorFilter(float sat, float brightness)
{
    float normalizedDegree = brightness - 1.0;
    const float brightnessMat[] = {
        1.000000f, 0.000000f, 0.000000f, 0.000000f, normalizedDegree,
        0.000000f, 1.000000f, 0.000000f, 0.000000f, normalizedDegree,
        0.000000f, 0.000000f, 1.000000f, 0.000000f, normalizedDegree,
        0.000000f, 0.000000f, 0.000000f, 1.000000f, 0.000000f,
    };
    Drawing::ColorMatrix cm;
    cm.SetSaturation(sat);
    float cmArray[Drawing::ColorMatrix::MATRIX_SIZE];
    cm.GetArray(cmArray);
    std::shared_ptr<Drawing::ColorFilter> filterCompose =
        Drawing::ColorFilter::CreateComposeColorFilter(cmArray, brightnessMat);
    return filterCompose;
}

void RSProperties::GenerateBackgroundBlurFilter()
{
    std::shared_ptr<Drawing::ImageFilter> blurFilter = Drawing::ImageFilter::CreateBlurImageFilter(
        backgroundBlurRadiusX_, backgroundBlurRadiusY_, Drawing::TileMode::CLAMP, nullptr);
    uint32_t hash = SkOpts::hash(&backgroundBlurRadiusX_, sizeof(backgroundBlurRadiusX_), 0);
    std::shared_ptr<RSDrawingFilter> originalFilter = nullptr;
    if (greyCoef_.has_value()) {
        std::shared_ptr<RSGreyShaderFilter> greyShaderFilter =
            std::make_shared<RSGreyShaderFilter>(greyCoef_->x_, greyCoef_->y_);
        originalFilter = std::make_shared<RSDrawingFilter>(greyShaderFilter);
    }

    if (RSSystemProperties::GetHpsBlurEnabled() && false) {
        std::shared_ptr<RSHpsBlurShaderFilter> hpsBlurFilter =
            std::make_shared<RSHpsBlurShaderFilter>(backgroundBlurRadiusX_, 1.f, 1.f);
        originalFilter =
            originalFilter ? originalFilter->Compose(std::static_pointer_cast<RSShaderFilter>(hpsBlurFilter))
                           : std::make_shared<RSDrawingFilter>(hpsBlurFilter);
    } else if (RSSystemProperties::GetKawaseEnabled()) {
        std::shared_ptr<RSKawaseBlurShaderFilter> kawaseBlurFilter =
            std::make_shared<RSKawaseBlurShaderFilter>(backgroundBlurRadiusX_);
        if (originalFilter == nullptr) {
            originalFilter = std::make_shared<RSDrawingFilter>(kawaseBlurFilter);
        } else {
            originalFilter = originalFilter->Compose(std::static_pointer_cast<RSShaderFilter>(kawaseBlurFilter));
        }
    } else {
        if (originalFilter == nullptr) {
            originalFilter = std::make_shared<RSDrawingFilter>(blurFilter, hash);
        } else {
            originalFilter = originalFilter->Compose(blurFilter, hash);
        }
    }
    originalFilter->SetSkipFrame(RSDrawingFilter::CanSkipFrame(backgroundBlurRadiusX_));
    backgroundFilter_ = originalFilter;
    backgroundFilter_->SetFilterType(RSFilter::BLUR);
}

void RSProperties::GenerateBackgroundMaterialBlurFilter()
{
    if (backgroundColorMode_ == BLUR_COLOR_MODE::FASTAVERAGE) {
        backgroundColorMode_ = BLUR_COLOR_MODE::AVERAGE;
    }
    uint32_t hash = SkOpts::hash(&backgroundBlurRadius_, sizeof(backgroundBlurRadius_), 0);
    std::shared_ptr<Drawing::ColorFilter> colorFilter = GetMaterialColorFilter(
        backgroundBlurSaturation_, backgroundBlurBrightness_);
    std::shared_ptr<Drawing::ImageFilter> blurColorFilter =
        Drawing::ImageFilter::CreateColorBlurImageFilter(*colorFilter, backgroundBlurRadius_, backgroundBlurRadius_);

    std::shared_ptr<RSDrawingFilter> originalFilter = nullptr;
    if (greyCoef_.has_value()) {
        std::shared_ptr<RSGreyShaderFilter> greyShaderFilter =
            std::make_shared<RSGreyShaderFilter>(greyCoef_->x_, greyCoef_->y_);
        originalFilter = std::make_shared<RSDrawingFilter>(greyShaderFilter);
    }

    static constexpr float epsilon = 0.999f;
    if (ROSEN_LE(backgroundBlurRadius_, epsilon) && (colorFilter != nullptr)) {
        auto colorImageFilter = Drawing::ImageFilter::CreateColorFilterImageFilter(*colorFilter, nullptr);
        originalFilter = originalFilter ? originalFilter->Compose(colorImageFilter, hash)
                                        : std::make_shared<RSDrawingFilter>(colorImageFilter, hash);
    } else if (RSSystemProperties::GetKawaseEnabled()) {
        std::shared_ptr<RSKawaseBlurShaderFilter> kawaseBlurFilter =
            std::make_shared<RSKawaseBlurShaderFilter>(backgroundBlurRadius_);
        auto colorImageFilter = Drawing::ImageFilter::CreateColorFilterImageFilter(*colorFilter, nullptr);
        originalFilter = originalFilter?
            originalFilter->Compose(colorImageFilter, hash) : std::make_shared<RSDrawingFilter>(colorImageFilter, hash);
        originalFilter = originalFilter->Compose(std::static_pointer_cast<RSShaderFilter>(kawaseBlurFilter));
    } else {
        hash = SkOpts::hash(&backgroundBlurSaturation_, sizeof(backgroundBlurSaturation_), hash);
        hash = SkOpts::hash(&backgroundBlurBrightness_, sizeof(backgroundBlurBrightness_), hash);
        originalFilter = originalFilter?
            originalFilter->Compose(blurColorFilter, hash) : std::make_shared<RSDrawingFilter>(blurColorFilter, hash);
    }
    std::shared_ptr<RSMaskColorShaderFilter> maskColorShaderFilter = std::make_shared<RSMaskColorShaderFilter>(
        backgroundColorMode_, backgroundMaskColor_);
    originalFilter = originalFilter->Compose(std::static_pointer_cast<RSShaderFilter>(maskColorShaderFilter));
    originalFilter->SetSkipFrame(RSDrawingFilter::CanSkipFrame(backgroundBlurRadius_));
    originalFilter->SetSaturationForHPS(backgroundBlurSaturation_);
    originalFilter->SetBrightnessForHPS(backgroundBlurBrightness_);
    backgroundFilter_ = originalFilter;
    maskColorShaderFilter->InitColorMod();
    backgroundFilter_->SetFilterType(RSFilter::MATERIAL);
}

void RSProperties::GenerateForegroundBlurFilter()
{
    std::shared_ptr<Drawing::ImageFilter> blurFilter = Drawing::ImageFilter::CreateBlurImageFilter(
        foregroundBlurRadiusX_, foregroundBlurRadiusY_, Drawing::TileMode::CLAMP, nullptr);
    uint32_t hash = SkOpts::hash(&foregroundBlurRadiusX_, sizeof(foregroundBlurRadiusX_), 0);
    std::shared_ptr<RSDrawingFilter> originalFilter = nullptr;
    if (greyCoef_.has_value()) {
        std::shared_ptr<RSGreyShaderFilter> greyShaderFilter =
            std::make_shared<RSGreyShaderFilter>(greyCoef_->x_, greyCoef_->y_);
        originalFilter = std::make_shared<RSDrawingFilter>(greyShaderFilter);
    }

    if (RSSystemProperties::GetHpsBlurEnabled() && false) {
        std::shared_ptr<RSHpsBlurShaderFilter> hpsBlurFilter =
            std::make_shared<RSHpsBlurShaderFilter>(foregroundBlurRadiusX_, 1.f, 1.f);
        originalFilter =
            originalFilter ? originalFilter->Compose(std::static_pointer_cast<RSShaderFilter>(hpsBlurFilter))
                           : std::make_shared<RSDrawingFilter>(hpsBlurFilter);
    } else if (RSSystemProperties::GetKawaseEnabled()) {
        std::shared_ptr<RSKawaseBlurShaderFilter> kawaseBlurFilter =
            std::make_shared<RSKawaseBlurShaderFilter>(foregroundBlurRadiusX_);
        if (originalFilter == nullptr) {
            originalFilter = std::make_shared<RSDrawingFilter>(kawaseBlurFilter);
        } else {
            originalFilter = originalFilter->Compose(std::static_pointer_cast<RSShaderFilter>(kawaseBlurFilter));
        }
    } else {
        if (originalFilter == nullptr) {
            originalFilter = std::make_shared<RSDrawingFilter>(blurFilter, hash);
        } else {
            originalFilter = originalFilter->Compose(blurFilter, hash);
        }
    }
    originalFilter->SetSkipFrame(RSDrawingFilter::CanSkipFrame(foregroundBlurRadiusX_));
    filter_ = originalFilter;
    filter_->SetFilterType(RSFilter::BLUR);
}

void RSProperties::GenerateForegroundMaterialBlurFilter()
{
    if (foregroundColorMode_ == BLUR_COLOR_MODE::FASTAVERAGE) {
        foregroundColorMode_ = BLUR_COLOR_MODE::AVERAGE;
    }
    uint32_t hash = SkOpts::hash(&foregroundBlurRadius_, sizeof(foregroundBlurRadius_), 0);
    std::shared_ptr<Drawing::ColorFilter> colorFilter = GetMaterialColorFilter(
        foregroundBlurSaturation_, foregroundBlurBrightness_);
    std::shared_ptr<Drawing::ImageFilter> blurColorFilter =
        Drawing::ImageFilter::CreateColorBlurImageFilter(*colorFilter, foregroundBlurRadius_, foregroundBlurRadius_);

    std::shared_ptr<RSDrawingFilter> originalFilter = nullptr;

    if (greyCoef_.has_value()) {
        std::shared_ptr<RSGreyShaderFilter> greyShaderFilter =
            std::make_shared<RSGreyShaderFilter>(greyCoef_->x_, greyCoef_->y_);
        originalFilter = std::make_shared<RSDrawingFilter>(greyShaderFilter);
    }

    static constexpr float epsilon = 0.999f;
    if (ROSEN_LE(foregroundBlurRadius_, epsilon) && (colorFilter != nullptr)) {
        auto colorImageFilter = Drawing::ImageFilter::CreateColorFilterImageFilter(*colorFilter, nullptr);
        originalFilter = originalFilter ? originalFilter->Compose(colorImageFilter, hash)
                                        : std::make_shared<RSDrawingFilter>(colorImageFilter, hash);
    } else if (RSSystemProperties::GetKawaseEnabled()) {
        std::shared_ptr<RSKawaseBlurShaderFilter> kawaseBlurFilter =
            std::make_shared<RSKawaseBlurShaderFilter>(foregroundBlurRadius_);
        auto colorImageFilter = Drawing::ImageFilter::CreateColorFilterImageFilter(*colorFilter, nullptr);
        originalFilter = originalFilter?
            originalFilter->Compose(colorImageFilter, hash) : std::make_shared<RSDrawingFilter>(colorImageFilter, hash);
        originalFilter = originalFilter->Compose(std::static_pointer_cast<RSShaderFilter>(kawaseBlurFilter));
    } else {
        hash = SkOpts::hash(&foregroundBlurSaturation_, sizeof(foregroundBlurSaturation_), hash);
        hash = SkOpts::hash(&foregroundBlurBrightness_, sizeof(foregroundBlurBrightness_), hash);
        originalFilter = originalFilter?
            originalFilter->Compose(blurColorFilter, hash) : std::make_shared<RSDrawingFilter>(blurColorFilter, hash);
    }
    std::shared_ptr<RSMaskColorShaderFilter> maskColorShaderFilter = std::make_shared<RSMaskColorShaderFilter>(
        foregroundColorMode_, foregroundMaskColor_);
    originalFilter = originalFilter->Compose(std::static_pointer_cast<RSShaderFilter>(maskColorShaderFilter));
    originalFilter->SetSkipFrame(RSDrawingFilter::CanSkipFrame(foregroundBlurRadius_));
    originalFilter->SetSaturationForHPS(foregroundBlurSaturation_);
    originalFilter->SetBrightnessForHPS(foregroundBlurBrightness_);
    filter_ = originalFilter;
    maskColorShaderFilter->InitColorMod();
    filter_->SetFilterType(RSFilter::MATERIAL);
}

void RSProperties::GenerateAIBarFilter()
{
    std::vector<float> aiInvertCoef = RSAIBarShaderFilter::GetAiInvertCoef();
    float aiBarRadius = aiInvertCoef[5]; // aiInvertCoef[5] is filter_radius
    std::shared_ptr<Drawing::ImageFilter> blurFilter =
        Drawing::ImageFilter::CreateBlurImageFilter(aiBarRadius, aiBarRadius, Drawing::TileMode::CLAMP, nullptr);
    std::shared_ptr<RSAIBarShaderFilter> aiBarShaderFilter = std::make_shared<RSAIBarShaderFilter>();
    std::shared_ptr<RSDrawingFilter> originalFilter = std::make_shared<RSDrawingFilter>(aiBarShaderFilter);

    if (originalFilter == nullptr) {
        ROSEN_LOGE("RSProperties::GenerateAIBarFilter originalFilter is null");
        return;
    }

    if (RSSystemProperties::GetKawaseEnabled()) {
        std::shared_ptr<RSKawaseBlurShaderFilter> kawaseBlurFilter =
            std::make_shared<RSKawaseBlurShaderFilter>(aiBarRadius);
        originalFilter = originalFilter->Compose(std::static_pointer_cast<RSShaderFilter>(kawaseBlurFilter));
    } else {
        uint32_t hash = SkOpts::hash(&aiBarRadius, sizeof(aiBarRadius), 0);
        originalFilter = originalFilter->Compose(blurFilter, hash);
    }
    backgroundFilter_ = originalFilter;
    backgroundFilter_->SetFilterType(RSFilter::AIBAR);
}

void RSProperties::GenerateLinearGradientBlurFilter()
{
    auto linearBlurFilter = std::make_shared<RSLinearGradientBlurShaderFilter>(linearGradientBlurPara_,
        frameGeo_->GetWidth(), frameGeo_->GetHeight());
    std::shared_ptr<RSDrawingFilter> originalFilter = std::make_shared<RSDrawingFilter>(linearBlurFilter);

    filter_ = originalFilter;
    filter_->SetFilterType(RSFilter::LINEAR_GRADIENT_BLUR);
}

void RSProperties::GenerateMagnifierFilter()
{
    auto magnifierFilter = std::make_shared<RSMagnifierShaderFilter>(magnifierPara_);

    std::shared_ptr<RSDrawingFilter> originalFilter = std::make_shared<RSDrawingFilter>(magnifierFilter);
    backgroundFilter_ = originalFilter;
    backgroundFilter_->SetFilterType(RSFilter::MAGNIFIER);
}

void RSProperties::GenerateWaterRippleFilter()
{
    float waveCount = waterRippleParams_->waveCount;
    float rippleCenterX = waterRippleParams_->rippleCenterX;
    float rippleCenterY = waterRippleParams_->rippleCenterY;
    std::shared_ptr<RSWaterRippleShaderFilter> waterRippleFilter =
        std::make_shared<RSWaterRippleShaderFilter>(waterRippleProgress_, waveCount, rippleCenterX, rippleCenterY);
    std::shared_ptr<RSDrawingFilter> originalFilter = std::make_shared<RSDrawingFilter>(waterRippleFilter);
    if (!backgroundFilter_) {
        backgroundFilter_ = originalFilter;
        backgroundFilter_->SetFilterType(RSFilter::WATER_RIPPLE);
    } else {
        auto backgroudDrawingFilter = std::static_pointer_cast<RSDrawingFilter>(backgroundFilter_);
        backgroudDrawingFilter->Compose(waterRippleFilter);
        backgroudDrawingFilter->SetFilterType(RSFilter::COMPOUND_EFFECT);
        backgroundFilter_ = backgroudDrawingFilter;
    }
}

void RSProperties::GenerateBackgroundFilter()
{
    if (aiInvert_.has_value() || systemBarEffect_) {
        GenerateAIBarFilter();
    } else if (magnifierPara_ && ROSEN_GNE(magnifierPara_->factor_, 0.f)) {
        GenerateMagnifierFilter();
    } else if (IsBackgroundMaterialFilterValid()) {
        GenerateBackgroundMaterialBlurFilter();
    } else if (IsBackgroundBlurRadiusXValid() && IsBackgroundBlurRadiusYValid()) {
        GenerateBackgroundBlurFilter();
    } else {
        backgroundFilter_ = nullptr;
    }
    if (IsWaterRippleValid()) {
        GenerateWaterRippleFilter();
    }
    if (backgroundFilter_ == nullptr) {
        ROSEN_LOGD("RSProperties::GenerateBackgroundFilter failed");
    }
}

void RSProperties::GenerateForegroundFilter()
{
    IfLinearGradientBlurInvalid();
    if (linearGradientBlurPara_) {
        GenerateLinearGradientBlurFilter();
    } else if (IsForegroundMaterialFilterVaild()) {
        GenerateForegroundMaterialBlurFilter();
    } else if (IsForegroundBlurRadiusXValid() && IsForegroundBlurRadiusYValid()) {
        GenerateForegroundBlurFilter();
    } else {
        filter_ = nullptr;
    }
    if (filter_ == nullptr) {
        ROSEN_LOGD("RSProperties::GenerateForegroundFilter failed");
    }
}

void RSProperties::SetUseEffect(bool useEffect)
{
    useEffect_ = useEffect;
    if (GetUseEffect()) {
        isDrawn_ = true;
    }
    filterNeedUpdate_ = true;
    SetDirty();
}

bool RSProperties::GetUseEffect() const
{
    return useEffect_;
}

void RSProperties::SetUseShadowBatching(bool useShadowBatching)
{
    if (useShadowBatching) {
        isDrawn_ = true;
    }
    useShadowBatching_ = useShadowBatching;
    SetDirty();
}

void RSProperties::SetPixelStretch(const std::optional<Vector4f>& stretchSize)
{
    pixelStretch_ = stretchSize;
    SetDirty();
    pixelStretchNeedUpdate_ = true;
    contentDirty_ = true;
    if (pixelStretch_.has_value() && pixelStretch_->IsZero()) {
        pixelStretch_ = std::nullopt;
    }
}

RectI RSProperties::GetPixelStretchDirtyRect() const
{
    auto dirtyRect = GetDirtyRect();

    auto scaledBounds = RectF(dirtyRect.left_ - pixelStretch_->x_, dirtyRect.top_ - pixelStretch_->y_,
        dirtyRect.width_ + pixelStretch_->x_ + pixelStretch_->z_,
        dirtyRect.height_ + pixelStretch_->y_ + pixelStretch_->w_);

    auto scaledIBounds = RectI(std::floor(scaledBounds.left_), std::floor(scaledBounds.top_),
        std::ceil(scaledBounds.width_) + 1, std::ceil(scaledBounds.height_) + 1);
    return dirtyRect.JoinRect(scaledIBounds);
}

void RSProperties::SetPixelStretchPercent(const std::optional<Vector4f>& stretchPercent)
{
    pixelStretchPercent_ = stretchPercent;
    SetDirty();
    pixelStretchNeedUpdate_ = true;
    contentDirty_ = true;
    if (pixelStretchPercent_.has_value() && pixelStretchPercent_->IsZero()) {
        pixelStretchPercent_ = std::nullopt;
    }
}

void RSProperties::SetPixelStretchTileMode(int stretchTileMode)
{
    pixelStretchTileMode_ = std::clamp<int>(stretchTileMode, static_cast<int>(Drawing::TileMode::CLAMP),
        static_cast<int>(Drawing::TileMode::DECAL));
    SetDirty();
    pixelStretchNeedUpdate_ = true;
    contentDirty_ = true;
}

int RSProperties::GetPixelStretchTileMode() const
{
    return pixelStretchTileMode_;
}

// Image effect properties
void RSProperties::SetGrayScale(const std::optional<float>& grayScale)
{
    grayScale_ = grayScale;
    colorFilterNeedUpdate_ = true;
    SetDirty();
    contentDirty_ = true;
}

void RSProperties::SetLightIntensity(float lightIntensity)
{
    if (!lightSourcePtr_) {
        lightSourcePtr_ = std::make_shared<RSLightSource>();
    }
    lightSourcePtr_->SetLightIntensity(lightIntensity);
    SetDirty();
    contentDirty_ = true;

    if (ROSEN_EQ(lightIntensity, INVALID_INTENSITY)) { // skip when resetFunc call
        return;
    }
    auto preIntensity = lightSourcePtr_->GetPreLightIntensity();
    auto renderNode = backref_.lock();
    bool preIntensityIsZero = ROSEN_EQ(preIntensity, 0.f);
    bool curIntensityIsZero = ROSEN_EQ(lightIntensity, 0.f);
    if (preIntensityIsZero && !curIntensityIsZero) { // 0 --> non-zero
        RSPointLightManager::Instance()->RegisterLightSource(renderNode);
    } else if (!preIntensityIsZero && curIntensityIsZero) { // non-zero --> 0
        RSPointLightManager::Instance()->UnRegisterLightSource(renderNode);
    }
}

void RSProperties::SetLightColor(Color lightColor)
{
    if (!lightSourcePtr_) {
        lightSourcePtr_ = std::make_shared<RSLightSource>();
    }
    lightSourcePtr_->SetLightColor(lightColor);
    SetDirty();
    contentDirty_ = true;
}

void RSProperties::SetLightPosition(const Vector4f& lightPosition)
{
    if (!lightSourcePtr_) {
        lightSourcePtr_ = std::make_shared<RSLightSource>();
    }
    lightSourcePtr_->SetLightPosition(lightPosition);
    SetDirty();
    contentDirty_ = true;
}

void RSProperties::SetIlluminatedBorderWidth(float illuminatedBorderWidth)
{
    if (!illuminatedPtr_) {
        illuminatedPtr_ = std::make_shared<RSIlluminated>();
    }
    illuminatedPtr_->SetIlluminatedBorderWidth(illuminatedBorderWidth);
    SetDirty();
    contentDirty_ = true;
}

void RSProperties::SetIlluminatedType(int illuminatedType)
{
    if (!illuminatedPtr_) {
        illuminatedPtr_ = std::make_shared<RSIlluminated>();
    }
    auto curIlluminateType = IlluminatedType(illuminatedType);
    illuminatedPtr_->SetIlluminatedType(curIlluminateType);
    isDrawn_ = true;
    SetDirty();
    contentDirty_ = true;

    if (curIlluminateType == IlluminatedType::INVALID) { // skip when resetFunc call
        return;
    }
    auto renderNode = backref_.lock();
    auto preIlluminatedType = illuminatedPtr_->GetPreIlluminatedType();
    bool preTypeIsNone = preIlluminatedType == IlluminatedType::NONE;
    bool curTypeIsNone = curIlluminateType == IlluminatedType::NONE;
    if (preTypeIsNone && !curTypeIsNone) {
        RSPointLightManager::Instance()->RegisterIlluminated(renderNode);
    } else if (!preTypeIsNone && curTypeIsNone) {
        RSPointLightManager::Instance()->UnRegisterIlluminated(renderNode);
    }
}

void RSProperties::SetBloom(float bloomIntensity)
{
    if (!illuminatedPtr_) {
        illuminatedPtr_ = std::make_shared<RSIlluminated>();
    }
    illuminatedPtr_->SetBloomIntensity(bloomIntensity);
    isDrawn_ = true;
    SetDirty();
    contentDirty_ = true;
}

float RSProperties::GetLightIntensity() const
{
    return lightSourcePtr_ ? lightSourcePtr_->GetLightIntensity() : 0.f;
}

Color RSProperties::GetLightColor() const
{
    return lightSourcePtr_ ? lightSourcePtr_->GetLightColor() : RgbPalette::White();
}

Vector4f RSProperties::GetLightPosition() const
{
    return lightSourcePtr_ ? lightSourcePtr_->GetLightPosition() : Vector4f(0.f);
}

int RSProperties::GetIlluminatedType() const
{
    return illuminatedPtr_ ? static_cast<int>(illuminatedPtr_->GetIlluminatedType()) : 0;
}

void RSProperties::CalculateAbsLightPosition()
{
    auto lightSourceAbsRect = boundsGeo_->GetAbsRect();
    auto rotation = RSPointLightManager::Instance()->GetScreenRotation();
    Vector4f lightAbsPosition = Vector4f();
    auto lightPos = lightSourcePtr_->GetLightPosition();
    switch (rotation) {
        case ScreenRotation::ROTATION_0:
            lightAbsPosition.x_ = static_cast<int>(lightSourceAbsRect.GetLeft() + lightPos.x_);
            lightAbsPosition.y_ = static_cast<int>(lightSourceAbsRect.GetTop() + lightPos.y_);
            break;
        case ScreenRotation::ROTATION_90:
            lightAbsPosition.x_ = static_cast<int>(lightSourceAbsRect.GetBottom() - lightPos.x_);
            lightAbsPosition.y_ = static_cast<int>(lightSourceAbsRect.GetLeft() + lightPos.y_);
            break;
        case ScreenRotation::ROTATION_180:
            lightAbsPosition.x_ = static_cast<int>(lightSourceAbsRect.GetRight() - lightPos.x_);
            lightAbsPosition.y_ = static_cast<int>(lightSourceAbsRect.GetBottom() - lightPos.y_);
            break;
        case ScreenRotation::ROTATION_270:
            lightAbsPosition.x_ = static_cast<int>(lightSourceAbsRect.GetTop() + lightPos.x_);
            lightAbsPosition.y_ = static_cast<int>(lightSourceAbsRect.GetRight() - lightPos.y_);
            break;
        default:
            break;
    }
    lightAbsPosition.z_ = lightPos.z_;
    lightAbsPosition.w_ = lightPos.w_;
    lightSourcePtr_->SetAbsLightPosition(lightAbsPosition);
}

void RSProperties::SetBrightness(const std::optional<float>& brightness)
{
    brightness_ = brightness;
    colorFilterNeedUpdate_ = true;
    SetDirty();
    contentDirty_ = true;
}

const std::optional<float>& RSProperties::GetBrightness() const
{
    return brightness_;
}

void RSProperties::SetContrast(const std::optional<float>& contrast)
{
    contrast_ = contrast;
    colorFilterNeedUpdate_ = true;
    SetDirty();
    contentDirty_ = true;
}

const std::optional<float>& RSProperties::GetContrast() const
{
    return contrast_;
}

void RSProperties::SetSaturate(const std::optional<float>& saturate)
{
    saturate_ = saturate;
    colorFilterNeedUpdate_ = true;
    SetDirty();
    contentDirty_ = true;
}

const std::optional<float>& RSProperties::GetSaturate() const
{
    return saturate_;
}

void RSProperties::SetSepia(const std::optional<float>& sepia)
{
    sepia_ = sepia;
    colorFilterNeedUpdate_ = true;
    SetDirty();
    contentDirty_ = true;
}

const std::optional<float>& RSProperties::GetSepia() const
{
    return sepia_;
}

void RSProperties::SetInvert(const std::optional<float>& invert)
{
    invert_ = invert;
    colorFilterNeedUpdate_ = true;
    SetDirty();
    contentDirty_ = true;
}

const std::optional<float>& RSProperties::GetInvert() const
{
    return invert_;
}


void RSProperties::SetAiInvert(const std::optional<Vector4f>& aiInvert)
{
    aiInvert_ = aiInvert;
    colorFilterNeedUpdate_ = true;
    SetDirty();
    contentDirty_ = true;
    isDrawn_ = true;
}

const std::optional<Vector4f>& RSProperties::GetAiInvert() const
{
    return aiInvert_;
}

void RSProperties::SetSystemBarEffect(bool systemBarEffect)
{
    systemBarEffect_ = systemBarEffect;
    colorFilterNeedUpdate_ = true;
    filterNeedUpdate_ = true;
    SetDirty();
    contentDirty_ = true;
    isDrawn_ = true;
}

bool RSProperties::GetSystemBarEffect() const
{
    return systemBarEffect_;
}

void RSProperties::SetHueRotate(const std::optional<float>& hueRotate)
{
    hueRotate_ = hueRotate;
    colorFilterNeedUpdate_ = true;
    SetDirty();
    contentDirty_ = true;
}

const std::optional<float>& RSProperties::GetHueRotate() const
{
    return hueRotate_;
}

void RSProperties::SetColorBlend(const std::optional<Color>& colorBlend)
{
    colorBlend_ = colorBlend;
    colorFilterNeedUpdate_ = true;
    SetDirty();
    contentDirty_ = true;
}

const std::optional<Color>& RSProperties::GetColorBlend() const
{
    return colorBlend_;
}

static bool GreatNotEqual(double left, double right)
{
    constexpr double epsilon = 0.001f;
    return (left - right) > epsilon;
}

static bool NearEqual(const double left, const double right)
{
    constexpr double epsilon = 0.001f;
    return (std::abs(left - right) <= epsilon);
}

static bool GreatOrEqual(double left, double right)
{
    constexpr double epsilon = -0.001f;
    return (left - right) > epsilon;
}

const std::shared_ptr<Drawing::ColorFilter>& RSProperties::GetColorFilter() const
{
    return colorFilter_;
}

void RSProperties::GenerateColorFilter()
{
    // No update needed if color filter is valid
    if (!colorFilterNeedUpdate_) {
        return;
    }

    colorFilterNeedUpdate_ = false;
    colorFilter_ = nullptr;
    if (!grayScale_ && !brightness_ && !contrast_ && !saturate_ && !sepia_ && !invert_ && !hueRotate_ && !colorBlend_) {
        return;
    }

    std::shared_ptr<Drawing::ColorFilter> filter = nullptr;

    if (grayScale_.has_value() && GreatNotEqual(*grayScale_, 0.f)) {
        auto grayScale = grayScale_.value();
        float matrix[20] = { 0.0f }; // 20 : matrix size
        matrix[0] = matrix[INDEX_5] = matrix[INDEX_10] = 0.2126f * grayScale; // 0.2126 : gray scale coefficient
        matrix[1] = matrix[INDEX_6] = matrix[INDEX_11] = 0.7152f * grayScale; // 0.7152 : gray scale coefficient
        matrix[INDEX_2] = matrix[INDEX_7] = matrix[INDEX_12] = 0.0722f * grayScale; // 0.0722 : gray scale coefficient
        matrix[INDEX_18] = 1.0 * grayScale;
        filter = Drawing::ColorFilter::CreateFloatColorFilter(matrix);
        if (colorFilter_) {
            filter->Compose(*colorFilter_);
        }
        colorFilter_ = filter;
    }
    if (brightness_.has_value() && !NearEqual(*brightness_, 1.0)) {
        auto brightness = brightness_.value();
        float matrix[20] = { 0.0f }; // 20 : matrix size
        // shift brightness to (-1, 1)
        brightness = brightness - 1;
        matrix[0] = matrix[INDEX_6] = matrix[INDEX_12] = matrix[INDEX_18] = 1.0f;
        matrix[INDEX_4] = matrix[INDEX_9] = matrix[INDEX_14] = brightness;
        filter = Drawing::ColorFilter::CreateFloatColorFilter(matrix);
        if (colorFilter_) {
            filter->Compose(*colorFilter_);
        }
        colorFilter_ = filter;
    }
    if (contrast_.has_value() && !NearEqual(*contrast_, 1.0)) {
        auto contrast = contrast_.value();
        uint32_t contrastValue128 = 128;
        uint32_t contrastValue255 = 255;
        float matrix[20] = { 0.0f }; // 20 : matrix size
        matrix[0] = matrix[INDEX_6] = matrix[INDEX_12] = contrast;
        matrix[INDEX_4] = matrix[INDEX_9] = matrix[INDEX_14] = contrastValue128 * (1 - contrast) / contrastValue255;
        matrix[INDEX_18] = 1.0f;
        filter = Drawing::ColorFilter::CreateFloatColorFilter(matrix);
        if (colorFilter_) {
            filter->Compose(*colorFilter_);
        }
        colorFilter_ = filter;
    }
    if (saturate_.has_value() && !NearEqual(*saturate_, 1.0) && GreatOrEqual(*saturate_, 0.0)) {
        auto saturate = saturate_.value();
        float matrix[20] = { 0.0f }; // 20 : matrix size
        matrix[0] = 0.3086f * (1 - saturate) + saturate; // 0.3086 : saturate coefficient
        matrix[1] = matrix[INDEX_11] = 0.6094f * (1 - saturate); // 0.6094 : saturate coefficient
        matrix[INDEX_2] = matrix[INDEX_7] = 0.0820f * (1 - saturate); // 0.0820 : saturate coefficient
        matrix[INDEX_5] = matrix[INDEX_10] = 0.3086f * (1 - saturate); // 0.3086 : saturate coefficient
        matrix[INDEX_6] = 0.6094f * (1 - saturate) + saturate; // 0.6094 : saturate coefficient
        matrix[INDEX_12] = 0.0820f * (1 - saturate) + saturate; // 0.0820 : saturate coefficient
        matrix[INDEX_18] = 1.0f;
        filter = Drawing::ColorFilter::CreateFloatColorFilter(matrix);
        if (colorFilter_) {
            filter->Compose(*colorFilter_);
        }
        colorFilter_ = filter;
    }
    if (sepia_.has_value() && GreatNotEqual(*sepia_, 0.0)) {
        auto sepia = sepia_.value();
        float matrix[20] = { 0.0f }; // 20 : matrix size
        matrix[0] = 0.393f * sepia;
        matrix[1] = 0.769f * sepia;
        matrix[INDEX_2] = 0.189f * sepia;

        matrix[INDEX_5] = 0.349f * sepia;
        matrix[INDEX_6] = 0.686f * sepia;
        matrix[INDEX_7] = 0.168f * sepia;

        matrix[INDEX_10] = 0.272f * sepia;
        matrix[INDEX_11] = 0.534f * sepia;
        matrix[INDEX_12] = 0.131f * sepia;
        matrix[INDEX_18] = 1.0f * sepia;
        filter = Drawing::ColorFilter::CreateFloatColorFilter(matrix);
        if (colorFilter_) {
            filter->Compose(*colorFilter_);
        }
        colorFilter_ = filter;
    }
    if (invert_.has_value() && GreatNotEqual(*invert_, 0.0)) {
        auto invert = invert_.value();
        float matrix[20] = { 0.0f }; // 20 : matrix size
        if (invert > 1.0) {
            invert = 1.0;
        }
        // complete color invert when dstRGB = 1 - srcRGB
        // map (0, 1) to (1, -1)
        matrix[0] = matrix[INDEX_6] = matrix[INDEX_12] = 1.0 - 2.0 * invert; // 2.0: invert
        matrix[INDEX_18] = 1.0f;
        // invert = 0.5 -> RGB = (0.5, 0.5, 0.5) -> image completely gray
        matrix[INDEX_4] = matrix[INDEX_9] = matrix[INDEX_14] = invert;
        filter = Drawing::ColorFilter::CreateFloatColorFilter(matrix);
        if (colorFilter_) {
            filter->Compose(*colorFilter_);
        }
        colorFilter_ = filter;
    }
    if (hueRotate_.has_value() && GreatNotEqual(*hueRotate_, 0.0)) {
        auto hueRotate = hueRotate_.value();
        while (GreatOrEqual(hueRotate, 360)) { // 360 : degree
            hueRotate -= 360; // 360 : degree
        }
        float matrix[20] = { 0.0f }; // 20 : matrix size
        int32_t type = hueRotate / 120; // 120 : degree
        float N = (hueRotate - 120 * type) / 120; // 120 : degree
        switch (type) {
            case 0:
                // color change = R->G, G->B, B->R
                matrix[INDEX_2] = matrix[INDEX_5] = matrix[INDEX_11] = N;
                matrix[0] = matrix[INDEX_6] = matrix[INDEX_12] = 1 - N;
                matrix[INDEX_18] = 1.0f;
                break;
            case 1:
                // compare to original: R->B, G->R, B->G
                matrix[1] = matrix[INDEX_7] = matrix[INDEX_10] = N;
                matrix[INDEX_2] = matrix[INDEX_5] = matrix[INDEX_11] = 1 - N;
                matrix[INDEX_18] = 1.0f;
                break;
            case 2: // 2: back to normal color
                matrix[0] = matrix[INDEX_6] = matrix[INDEX_12] = N;
                matrix[1] = matrix[INDEX_7] = matrix[INDEX_10] = 1 - N;
                matrix[INDEX_18] = 1.0f;
                break;
            default:
                break;
        }
        filter = Drawing::ColorFilter::CreateFloatColorFilter(matrix);
        if (colorFilter_) {
            filter->Compose(*colorFilter_);
        }
        colorFilter_ = filter;
    }
    if (colorBlend_.has_value() && *colorBlend_ != RgbPalette::Transparent()) {
        auto colorBlend = colorBlend_.value();
        filter = Drawing::ColorFilter::CreateBlendModeColorFilter(Drawing::Color::ColorQuadSetARGB(
            colorBlend.GetAlpha(), colorBlend.GetRed(), colorBlend.GetGreen(), colorBlend.GetBlue()),
            Drawing::BlendMode::PLUS);
        if (colorFilter_) {
            filter->Compose(*colorFilter_);
        }
        colorFilter_ = filter;
    }
    isDrawn_ = true;
}

std::string RSProperties::Dump() const
{
    std::string dumpInfo;
    char buffer[UINT8_MAX] = { 0 };
    if (sprintf_s(buffer, UINT8_MAX, "Bounds[%.1f %.1f %.1f %.1f] Frame[%.1f %.1f %.1f %.1f]",
        GetBoundsPositionX(), GetBoundsPositionY(), GetBoundsWidth(), GetBoundsHeight(),
        GetFramePositionX(), GetFramePositionY(), GetFrameWidth(), GetFrameHeight()) != -1) {
        dumpInfo.append(buffer);
    }

    errno_t ret;
    if (clipToBounds_) {
        // clipToBounds
        ret = memset_s(buffer, UINT8_MAX, 0, UINT8_MAX);
        if (ret != EOK) {
            return "Failed to memset_s for clipToBounds, ret=" + std::to_string(ret);
        }
        if (sprintf_s(buffer, UINT8_MAX, ", ClipToBounds[True]") != -1) {
            dumpInfo.append(buffer);
        }
    }
    if (clipToFrame_) {
        // clipToFrame
        ret = memset_s(buffer, UINT8_MAX, 0, UINT8_MAX);
        if (ret != EOK) {
            return "Failed to memset_s for clipToFrame, ret=" + std::to_string(ret);
        }
        if (sprintf_s(buffer, UINT8_MAX, ", ClipToFrame[True]") != -1) {
            dumpInfo.append(buffer);
        }
    }

    // PositionZ
    ret = memset_s(buffer, UINT8_MAX, 0, UINT8_MAX);
    if (ret != EOK) {
        return "Failed to memset_s for PositionZ, ret=" + std::to_string(ret);
    }
    if (!ROSEN_EQ(GetPositionZ(), 0.f) &&
        sprintf_s(buffer, UINT8_MAX, ", PositionZ[%.1f]", GetPositionZ()) != -1) {
        dumpInfo.append(buffer);
    }

    // Pivot
    std::unique_ptr<RSTransform> defaultTrans = std::make_unique<RSTransform>();
    ret = memset_s(buffer, UINT8_MAX, 0, UINT8_MAX);
    if (ret != EOK) {
        return "Failed to memset_s for Pivot, ret=" + std::to_string(ret);
    }
    Vector2f pivot = GetPivot();
    if ((!ROSEN_EQ(pivot[0], defaultTrans->pivotX_) || !ROSEN_EQ(pivot[1], defaultTrans->pivotY_)) &&
        sprintf_s(buffer, UINT8_MAX, ", Pivot[%.1f,%.1f]", pivot[0], pivot[1]) != -1) {
        dumpInfo.append(buffer);
    }

    // CornerRadius
    ret = memset_s(buffer, UINT8_MAX, 0, UINT8_MAX);
    if (ret != EOK) {
        return "Failed to memset_s for CornerRadius, ret=" + std::to_string(ret);
    }
    if (!GetCornerRadius().IsZero() &&
        sprintf_s(buffer, UINT8_MAX, ", CornerRadius[%.1f %.1f %.1f %.1f]",
            GetCornerRadius().x_, GetCornerRadius().y_, GetCornerRadius().z_, GetCornerRadius().w_) != -1) {
        dumpInfo.append(buffer);
    }

    // PixelStretch PixelStretchPercent
    ret = memset_s(buffer, UINT8_MAX, 0, UINT8_MAX);
    if (ret != EOK) {
        return "Failed to memset_s for PixelStretch, ret=" + std::to_string(ret);
    }
    if (pixelStretch_.has_value() &&
        sprintf_s(buffer, UINT8_MAX, ", PixelStretch[left:%.1f top:%.1f right:%.1f bottom:%.1f]",
            pixelStretch_->x_, pixelStretch_->y_, pixelStretch_->z_, pixelStretch_->w_) != -1) {
        dumpInfo.append(buffer);
    }

    // Rotation
    ret = memset_s(buffer, UINT8_MAX, 0, UINT8_MAX);
    if (ret != EOK) {
        return "Failed to memset_s for Rotation, ret=" + std::to_string(ret);
    }
    if (!ROSEN_EQ(GetRotation(), defaultTrans->rotation_) &&
        sprintf_s(buffer, UINT8_MAX, ", Rotation[%.1f]", GetRotation()) != -1) {
        dumpInfo.append(buffer);
    }
    // RotationX
    ret = memset_s(buffer, UINT8_MAX, 0, UINT8_MAX);
    if (ret != EOK) {
        return "Failed to memset_s for RotationX, ret=" + std::to_string(ret);
    }
    if (!ROSEN_EQ(GetRotationX(), defaultTrans->rotationX_) &&
        sprintf_s(buffer, UINT8_MAX, ", RotationX[%.1f]", GetRotationX()) != -1) {
        dumpInfo.append(buffer);
    }
    // RotationY
    ret = memset_s(buffer, UINT8_MAX, 0, UINT8_MAX);
    if (ret != EOK) {
        return "Failed to memset_s for RotationY, ret=" + std::to_string(ret);
    }
    if (!ROSEN_EQ(GetRotationY(), defaultTrans->rotationY_) &&
        sprintf_s(buffer, UINT8_MAX, ", RotationY[%.1f]", GetRotationY()) != -1) {
        dumpInfo.append(buffer);
    }

    // TranslateX
    ret = memset_s(buffer, UINT8_MAX, 0, UINT8_MAX);
    if (ret != EOK) {
        return "Failed to memset_s for TranslateX, ret=" + std::to_string(ret);
    }
    if (!ROSEN_EQ(GetTranslateX(), defaultTrans->translateX_) &&
        sprintf_s(buffer, UINT8_MAX, ", TranslateX[%.1f]", GetTranslateX()) != -1) {
        dumpInfo.append(buffer);
    }

    // TranslateY
    ret = memset_s(buffer, UINT8_MAX, 0, UINT8_MAX);
    if (ret != EOK) {
        return "Failed to memset_s for TranslateY, ret=" + std::to_string(ret);
    }
    if (!ROSEN_EQ(GetTranslateY(), defaultTrans->translateY_) &&
        sprintf_s(buffer, UINT8_MAX, ", TranslateY[%.1f]", GetTranslateY()) != -1) {
        dumpInfo.append(buffer);
    }

    // TranslateZ
    ret = memset_s(buffer, UINT8_MAX, 0, UINT8_MAX);
    if (ret != EOK) {
        return "Failed to memset_s for TranslateZ, ret=" + std::to_string(ret);
    }
    if (!ROSEN_EQ(GetTranslateZ(), defaultTrans->translateZ_) &&
        sprintf_s(buffer, UINT8_MAX, ", TranslateZ[%.1f]", GetTranslateZ()) != -1) {
        dumpInfo.append(buffer);
    }

    // ScaleX
    ret = memset_s(buffer, UINT8_MAX, 0, UINT8_MAX);
    if (ret != EOK) {
        return "Failed to memset_s for ScaleX, ret=" + std::to_string(ret);
    }
    if (!ROSEN_EQ(GetScaleX(), defaultTrans->scaleX_) &&
        sprintf_s(buffer, UINT8_MAX, ", ScaleX[%.1f]", GetScaleX()) != -1) {
        dumpInfo.append(buffer);
    }

    // ScaleY
    ret = memset_s(buffer, UINT8_MAX, 0, UINT8_MAX);
    if (ret != EOK) {
        return "Failed to memset_s for ScaleY, ret=" + std::to_string(ret);
    }
    if (!ROSEN_EQ(GetScaleY(), defaultTrans->scaleY_) &&
        sprintf_s(buffer, UINT8_MAX, ", ScaleY[%.1f]", GetScaleY()) != -1) {
        dumpInfo.append(buffer);
    }

    // Alpha
    ret = memset_s(buffer, UINT8_MAX, 0, UINT8_MAX);
    if (ret != EOK) {
        return "Failed to memset_s for Alpha, ret=" + std::to_string(ret);
    }
    if (!ROSEN_EQ(GetAlpha(), 1.f) &&
        sprintf_s(buffer, UINT8_MAX, ", Alpha[%.3f]", GetAlpha()) != -1) {
        dumpInfo.append(buffer);
    }

    // Spherize
    ret = memset_s(buffer, UINT8_MAX, 0, UINT8_MAX);
    if (ret != EOK) {
        return "Failed to memset_s for Spherize, ret=" + std::to_string(ret);
    }
    if (!ROSEN_EQ(GetSpherize(), 0.f) &&
        sprintf_s(buffer, UINT8_MAX, ", Spherize[%.1f]", GetSpherize()) != -1) {
        dumpInfo.append(buffer);
    }

    // AttractFraction
    ret = memset_s(buffer, UINT8_MAX, 0, UINT8_MAX);
    if (ret != EOK) {
        return "Failed to memset_s for AttractFraction, ret=" + std::to_string(ret);
    }
    if (!ROSEN_EQ(GetAttractionFraction(), 0.f) &&
        sprintf_s(buffer, UINT8_MAX, ", MiniFraction[%.1f]",  GetAttractionFraction()) != -1) {
        dumpInfo.append(buffer);
    }

    // Attraction Destination Position
    ret = memset_s(buffer, UINT8_MAX, 0, UINT8_MAX);
    if (ret != EOK) {
        return "Failed to memset_s for MiniDstpoint, ret=" + std::to_string(ret);
    }
    Vector2f attractionDstpoint = GetAttractionDstPoint();
    if ((!ROSEN_EQ(attractionDstpoint[0], 0.f) || !ROSEN_EQ(attractionDstpoint[1], 0.f)) &&
        sprintf_s(buffer, UINT8_MAX, ", AttractionFraction DstPointY[%.1f,%.1f]",
        attractionDstpoint[0], attractionDstpoint[1]) != -1) {
        dumpInfo.append(buffer);
    }

    // blendmode
    ret = memset_s(buffer, UINT8_MAX, 0, UINT8_MAX);
    if (ret != EOK) {
        return "Failed to memset_s for blendmode, ret=" + std::to_string(ret);
    }
    if (!ROSEN_EQ(GetColorBlendMode(), 0) &&
        sprintf_s(buffer, UINT8_MAX, ", skblendmode[%d], blendType[%d]",
        GetColorBlendMode() - 1, GetColorBlendApplyType()) != -1) {
        dumpInfo.append(buffer);
    }

    // LightUpEffect
    ret = memset_s(buffer, UINT8_MAX, 0, UINT8_MAX);
    if (ret != EOK) {
        return "Failed to memset_s for LightUpEffect, ret=" + std::to_string(ret);
    }
    if (!ROSEN_EQ(GetLightUpEffect(), 1.f) &&
        sprintf_s(buffer, UINT8_MAX, ", LightUpEffect[%.1f]", GetLightUpEffect()) != -1) {
        dumpInfo.append(buffer);
    }

    // ForegroundColor
    ret = memset_s(buffer, UINT8_MAX, 0, UINT8_MAX);
    if (ret != EOK) {
        return "Failed to memset_s for ForegroundColor, ret=" + std::to_string(ret);
    }
    if (!ROSEN_EQ(GetForegroundColor(), RgbPalette::Transparent()) &&
        sprintf_s(buffer, UINT8_MAX, ", ForegroundColor[#%08X]", GetForegroundColor().AsArgbInt()) != -1) {
        dumpInfo.append(buffer);
    }

    // BackgroundColor
    ret = memset_s(buffer, UINT8_MAX, 0, UINT8_MAX);
    if (ret != EOK) {
        return "Failed to memset_s for BackgroundColor, ret=" + std::to_string(ret);
    }
    if (!ROSEN_EQ(GetBackgroundColor(), RgbPalette::Transparent()) &&
        sprintf_s(buffer, UINT8_MAX, ", BackgroundColor[#%08X]", GetBackgroundColor().AsArgbInt()) != -1) {
        dumpInfo.append(buffer);
    }

    // BgImage
    std::unique_ptr<Decoration> defaultDecoration = std::make_unique<Decoration>();
    ret = memset_s(buffer, UINT8_MAX, 0, UINT8_MAX);
    if (ret != EOK) {
        return "Failed to memset_s for BgImage, ret=" + std::to_string(ret);
    }
    if ((!ROSEN_EQ(GetBgImagePositionX(), defaultDecoration->bgImageRect_.left_) ||
        !ROSEN_EQ(GetBgImagePositionY(), defaultDecoration->bgImageRect_.top_) ||
        !ROSEN_EQ(GetBgImageWidth(), defaultDecoration->bgImageRect_.width_) ||
        !ROSEN_EQ(GetBgImageHeight(), defaultDecoration->bgImageRect_.height_)) &&
        sprintf_s(buffer, UINT8_MAX, ", BgImage[%.1f %.1f %.1f %.1f]", GetBgImagePositionX(),
            GetBgImagePositionY(), GetBgImageWidth(), GetBgImageHeight()) != -1) {
        dumpInfo.append(buffer);
    }

    // Border
    ret = memset_s(buffer, UINT8_MAX, 0, UINT8_MAX);
    if (ret != EOK) {
        return "Failed to memset_s for Border, ret=" + std::to_string(ret);
    }
    if (border_ && border_->HasBorder() &&
        sprintf_s(buffer, UINT8_MAX, ", Border[%s]", border_->ToString().c_str()) != -1) {
        dumpInfo.append(buffer);
    }

    // Filter
    ret = memset_s(buffer, UINT8_MAX, 0, UINT8_MAX);
    if (ret != EOK) {
        return "Failed to memset_s for Filter, ret=" + std::to_string(ret);
    }
    auto filter_ = GetFilter();
    if (filter_ && filter_->IsValid() &&
        sprintf_s(buffer, UINT8_MAX, ", Filter[%s]", filter_->GetDescription().c_str()) != -1) {
        dumpInfo.append(buffer);
    }

    // BackgroundFilter
    ret = memset_s(buffer, UINT8_MAX, 0, UINT8_MAX);
    if (ret != EOK) {
        return "Failed to memset_s for BackgroundFilter, ret=" + std::to_string(ret);
    }
    auto backgroundFilter_ = GetBackgroundFilter();
    if (backgroundFilter_ && backgroundFilter_->IsValid() &&
        sprintf_s(buffer, UINT8_MAX, ", BackgroundFilter[%s]", backgroundFilter_->GetDescription().c_str()) != -1) {
        dumpInfo.append(buffer);
    }

    // ForegroundFilter
    ret = memset_s(buffer, UINT8_MAX, 0, UINT8_MAX);
    if (ret != EOK) {
        return "Failed to memset_s for ForegroundFilter, ret=" + std::to_string(ret);
    }
    auto foregroundFilterCache_ = GetForegroundFilterCache();
    if (foregroundFilterCache_ && foregroundFilterCache_->IsValid() &&
        sprintf_s(buffer, UINT8_MAX, ", ForegroundFilter[%s]", foregroundFilterCache_->GetDescription().c_str()) !=
        -1) {
        dumpInfo.append(buffer);
    }

    // Outline
    ret = memset_s(buffer, UINT8_MAX, 0, UINT8_MAX);
    if (ret != EOK) {
        return "Failed to memset_s for Outline, ret=" + std::to_string(ret);
    }
    if (outline_ && outline_->HasBorder() &&
        sprintf_s(buffer, UINT8_MAX, ", Outline[%s]", outline_->ToString().c_str()) != -1) {
        dumpInfo.append(buffer);
    }

    // ShadowColor
    ret = memset_s(buffer, UINT8_MAX, 0, UINT8_MAX);
    if (ret != EOK) {
        return "Failed to memset_s for ShadowColor, ret=" + std::to_string(ret);
    }
    if (!ROSEN_EQ(GetShadowColor(), Color(DEFAULT_SPOT_COLOR)) &&
        sprintf_s(buffer, UINT8_MAX, ", ShadowColor[#%08X]", GetShadowColor().AsArgbInt()) != -1) {
        dumpInfo.append(buffer);
    }

    // ShadowOffsetX
    ret = memset_s(buffer, UINT8_MAX, 0, UINT8_MAX);
    if (ret != EOK) {
        return "Failed to memset_s for ShadowOffsetX, ret=" + std::to_string(ret);
    }
    if (!ROSEN_EQ(GetShadowOffsetX(), DEFAULT_SHADOW_OFFSET_X) &&
        sprintf_s(buffer, UINT8_MAX, ", ShadowOffsetX[%.1f]", GetShadowOffsetX()) != -1) {
        dumpInfo.append(buffer);
    }

    // ShadowOffsetY
    ret = memset_s(buffer, UINT8_MAX, 0, UINT8_MAX);
    if (ret != EOK) {
        return "Failed to memset_s for ShadowOffsetY, ret=" + std::to_string(ret);
    }
    if (!ROSEN_EQ(GetShadowOffsetY(), DEFAULT_SHADOW_OFFSET_Y) &&
        sprintf_s(buffer, UINT8_MAX, ", ShadowOffsetY[%.1f]", GetShadowOffsetY()) != -1) {
        dumpInfo.append(buffer);
    }

    // ShadowAlpha
    ret = memset_s(buffer, UINT8_MAX, 0, UINT8_MAX);
    if (ret != EOK) {
        return "Failed to memset_s for ShadowAlpha, ret=" + std::to_string(ret);
    }
    if (!ROSEN_EQ(GetShadowAlpha(), 0.f) &&
        sprintf_s(buffer, UINT8_MAX, ", ShadowAlpha[%.1f]", GetShadowAlpha()) != -1) {
        dumpInfo.append(buffer);
    }

    // ShadowElevation
    ret = memset_s(buffer, UINT8_MAX, 0, UINT8_MAX);
    if (ret != EOK) {
        return "Failed to memset_s for ShadowElevation, ret=" + std::to_string(ret);
    }
    if (!ROSEN_EQ(GetShadowElevation(), 0.f) &&
        sprintf_s(buffer, UINT8_MAX, ", ShadowElevation[%.1f]", GetShadowElevation()) != -1) {
        dumpInfo.append(buffer);
    }

    // ShadowRadius
    ret = memset_s(buffer, UINT8_MAX, 0, UINT8_MAX);
    if (ret != EOK) {
        return "Failed to memset_s for ShadowRadius, ret=" + std::to_string(ret);
    }
    if (!ROSEN_EQ(GetShadowRadius(), 0.f) &&
        sprintf_s(buffer, UINT8_MAX, ", ShadowRadius[%.1f]", GetShadowRadius()) != -1) {
        dumpInfo.append(buffer);
    }

    // ShadowIsFilled
    ret = memset_s(buffer, UINT8_MAX, 0, UINT8_MAX);
    if (ret != EOK) {
        return "Failed to memset_s for ShadowIsFilled, ret=" + std::to_string(ret);
    }
    if (!ROSEN_EQ(GetShadowIsFilled(), false) &&
        sprintf_s(buffer, UINT8_MAX, ", ShadowIsFilled[%d]", GetShadowIsFilled()) != -1) {
        dumpInfo.append(buffer);
    }

    // FrameGravity
    ret = memset_s(buffer, UINT8_MAX, 0, UINT8_MAX);
    if (ret != EOK) {
        return "Failed to memset_s for FrameGravity, ret=" + std::to_string(ret);
    }
    if (!ROSEN_EQ(GetFrameGravity(), Gravity::DEFAULT) &&
        sprintf_s(buffer, UINT8_MAX, ", FrameGravity[%d]", GetFrameGravity()) != -1) {
        dumpInfo.append(buffer);
    }

    // IsVisible
    if (!GetVisible()) {
        dumpInfo.append(", IsVisible[false]");
    }

    // UseEffect
    if (GetUseEffect()) {
        dumpInfo.append(", GetUseEffect[true]");
    }

    // Gray Scale
    ret = memset_s(buffer, UINT8_MAX, 0, UINT8_MAX);
    if (ret != EOK) {
        return "Failed to memset_s for GrayScale, ret=" + std::to_string(ret);
    }
    auto grayScale = GetGrayScale();
    if (grayScale.has_value() && !ROSEN_EQ(*grayScale, 0.f) &&
        sprintf_s(buffer, UINT8_MAX, ", GrayScale[%.1f]", *grayScale) != -1) {
        dumpInfo.append(buffer);
    }

    // DynamicLightUpRate
    ret = memset_s(buffer, UINT8_MAX, 0, UINT8_MAX);
    if (ret != EOK) {
        return "Failed to memset_s for DynamicLightUpRate, ret=" + std::to_string(ret);
    }
    auto dynamicLightUpRate = GetDynamicLightUpRate();
    if (dynamicLightUpRate.has_value() && !ROSEN_EQ(*dynamicLightUpRate, 0.f) &&
        sprintf_s(buffer, UINT8_MAX, ", DynamicLightUpRate[%.1f]", *dynamicLightUpRate) != -1) {
        dumpInfo.append(buffer);
    }

    // DynamicLightUpDegree
    ret = memset_s(buffer, UINT8_MAX, 0, UINT8_MAX);
    if (ret != EOK) {
        return "Failed to memset_s for DynamicLightUpDegree, ret=" + std::to_string(ret);
    }
    auto dynamicLightUpDegree = GetDynamicLightUpDegree();
    if (dynamicLightUpDegree.has_value() && !ROSEN_EQ(*dynamicLightUpDegree, 0.f) &&
        sprintf_s(buffer, UINT8_MAX, ", DynamicLightUpDegree[%.1f]", *dynamicLightUpDegree) != -1) {
        dumpInfo.append(buffer);
    }

    // Brightness
    ret = memset_s(buffer, UINT8_MAX, 0, UINT8_MAX);
    if (ret != EOK) {
        return "Failed to memset_s for Brightness, ret=" + std::to_string(ret);
    }
    auto brightness = GetBrightness();
    if (brightness.has_value() && !ROSEN_EQ(*brightness, 1.f) &&
        sprintf_s(buffer, UINT8_MAX, ", Brightness[%.1f]", *brightness) != -1) {
        dumpInfo.append(buffer);
    }

    // Contrast
    ret = memset_s(buffer, UINT8_MAX, 0, UINT8_MAX);
    if (ret != EOK) {
        return "Failed to memset_s for Contrast, ret=" + std::to_string(ret);
    }
    auto contrast = GetContrast();
    if (contrast.has_value() && !ROSEN_EQ(*contrast, 1.f) &&
        sprintf_s(buffer, UINT8_MAX, ", Contrast[%.1f]", *contrast) != -1) {
        dumpInfo.append(buffer);
    }

    // Saturate
    ret = memset_s(buffer, UINT8_MAX, 0, UINT8_MAX);
    if (ret != EOK) {
        return "Failed to memset_s for Saturate, ret=" + std::to_string(ret);
    }
    auto saturate = GetSaturate();
    if (saturate.has_value() && !ROSEN_EQ(*saturate, 1.f) &&
        sprintf_s(buffer, UINT8_MAX, ", Saturate[%.1f]", *saturate) != -1) {
        dumpInfo.append(buffer);
    }

    // Sepia
    ret = memset_s(buffer, UINT8_MAX, 0, UINT8_MAX);
    if (ret != EOK) {
        return "Failed to memset_s for Sepia, ret=" + std::to_string(ret);
    }
    auto sepia = GetSepia();
    if (sepia.has_value() && !ROSEN_EQ(*sepia, 0.f) &&
        sprintf_s(buffer, UINT8_MAX, ", Sepia[%.1f]", *sepia) != -1) {
        dumpInfo.append(buffer);
    }

    // Invert
    ret = memset_s(buffer, UINT8_MAX, 0, UINT8_MAX);
    if (ret != EOK) {
        return "Failed to memset_s for Invert, ret=" + std::to_string(ret);
    }
    auto invert = GetInvert();
    if (invert.has_value() && !ROSEN_EQ(*invert, 0.f) &&
        sprintf_s(buffer, UINT8_MAX, ", Invert[%.1f]", *invert) != -1) {
        dumpInfo.append(buffer);
    }

    // Hue Rotate
    ret = memset_s(buffer, UINT8_MAX, 0, UINT8_MAX);
    if (ret != EOK) {
        return "Failed to memset_s for HueRotate, ret=" + std::to_string(ret);
    }
    auto hueRotate = GetHueRotate();
    if (hueRotate.has_value() && !ROSEN_EQ(*hueRotate, 0.f) &&
        sprintf_s(buffer, UINT8_MAX, ", HueRotate[%.1f]", *hueRotate) != -1) {
        dumpInfo.append(buffer);
    }

    // Color Blend
    ret = memset_s(buffer, UINT8_MAX, 0, UINT8_MAX);
    if (ret != EOK) {
        return "Failed to memset_s for ColorBlend, ret=" + std::to_string(ret);
    }
    auto colorBlend = GetColorBlend();
    if (colorBlend.has_value() && !ROSEN_EQ(*colorBlend, RgbPalette::Transparent()) &&
        sprintf_s(buffer, UINT8_MAX, ", ColorBlend[#%08X]", colorBlend->AsArgbInt()) != -1) {
        dumpInfo.append(buffer);
    }

    return dumpInfo;
}

// planning: need to delete, cachemanager moved to filter drawable
#if defined(NEW_SKIA) && (defined(RS_ENABLE_GL) || defined(RS_ENABLE_VK))
void RSProperties::CreateFilterCacheManagerIfNeed()
{
    if (!FilterCacheEnabled) {
        return;
    }
    if (auto& filter = GetBackgroundFilter()) {
        auto& cacheManager = backgroundFilterCacheManager_;
        if (cacheManager == nullptr) {
            cacheManager = std::make_unique<RSFilterCacheManager>();
        }
        cacheManager->UpdateCacheStateWithFilterHash(filter);
    } else {
        backgroundFilterCacheManager_.reset();
    }
    if (auto& filter = GetFilter()) {
        auto& cacheManager = foregroundFilterCacheManager_;
        if (cacheManager == nullptr) {
            cacheManager = std::make_unique<RSFilterCacheManager>();
        }
        cacheManager->UpdateCacheStateWithFilterHash(filter);
    } else {
        foregroundFilterCacheManager_.reset();
    }
}

const std::unique_ptr<RSFilterCacheManager>& RSProperties::GetFilterCacheManager(bool isForeground) const
{
    return isForeground ? foregroundFilterCacheManager_ : backgroundFilterCacheManager_;
}

void RSProperties::ClearFilterCache()
{
    if (foregroundFilterCacheManager_ != nullptr) {
        foregroundFilterCacheManager_->ReleaseCacheOffTree();
    }
    if (backgroundFilterCacheManager_ != nullptr) {
        backgroundFilterCacheManager_->ReleaseCacheOffTree();
    }
    if (backgroundFilter_ != nullptr) {
        auto drawingFilter = std::static_pointer_cast<RSDrawingFilter>(backgroundFilter_);
        std::shared_ptr<RSShaderFilter> rsShaderFilter =
            drawingFilter->GetShaderFilterWithType(RSShaderFilter::MASK_COLOR);
        if (rsShaderFilter != nullptr) {
            auto maskColorShaderFilter = std::static_pointer_cast<RSMaskColorShaderFilter>(rsShaderFilter);
            maskColorShaderFilter->ReleaseColorPickerFilter();
        }
    }
    if (filter_ != nullptr) {
        auto drawingFilter = std::static_pointer_cast<RSDrawingFilter>(filter_);
        std::shared_ptr<RSShaderFilter> rsShaderFilter =
            drawingFilter->GetShaderFilterWithType(RSShaderFilter::MASK_COLOR);
        if (rsShaderFilter != nullptr) {
            auto maskColorShaderFilter = std::static_pointer_cast<RSMaskColorShaderFilter>(rsShaderFilter);
            maskColorShaderFilter->ReleaseColorPickerFilter();
        }
    }
}
#endif

void RSProperties::OnApplyModifiers()
{
    if (geoDirty_) {
        if (!hasBounds_) {
            CheckEmptyBounds();
        } else {
            CalculateFrameOffset();
        }
        // frame and bounds are the same, no need to clip twice
        if (clipToFrame_ && clipToBounds_ && frameOffsetX_ == 0 && frameOffsetY_ == 0) {
            clipToFrame_ = false;
        }
        // planning: temporary fix to calculate relative matrix in OnApplyModifiers, later RSRenderNode::Update will
        // overwrite it.
        boundsGeo_->UpdateByMatrixFromSelf();
    }
    if (colorFilterNeedUpdate_) {
        GenerateColorFilter();
        needFilter_ = needFilter_ || (colorFilter_ != nullptr);
    }
    if (pixelStretchNeedUpdate_ || geoDirty_) {
        CalculatePixelStretch();
    }
    if (greyCoefNeedUpdate_) {
        CheckGreyCoef();
        greyCoefNeedUpdate_ = false;
        filterNeedUpdate_ = true;
    }
    if (filterNeedUpdate_) {
        UpdateFilter();
    }
    GenerateRRect();
}

void RSProperties::UpdateFilter()
{
    filterNeedUpdate_ = false;
    GenerateBackgroundFilter();
    GenerateForegroundFilter();
    if (GetShadowColorStrategy() != SHADOW_COLOR_STRATEGY::COLOR_STRATEGY_NONE) {
        filterNeedUpdate_ = true;
    }
    if (backgroundFilter_ != nullptr && !backgroundFilter_->IsValid()) {
        backgroundFilter_.reset();
    }
    if (filter_ != nullptr && !filter_->IsValid()) {
        filter_.reset();
    }

    if (FOREGROUND_FILTER_ENABLED) {
        UpdateForegroundFilter();
    }

    needFilter_ = backgroundFilter_ != nullptr || filter_ != nullptr || useEffect_ || IsLightUpEffectValid() ||
                  IsDynamicLightUpValid() || greyCoef_.has_value() || linearGradientBlurPara_ != nullptr ||
                  IsDynamicDimValid() || GetShadowColorStrategy() != SHADOW_COLOR_STRATEGY::COLOR_STRATEGY_NONE ||
                  foregroundFilter_ != nullptr || IsFgBrightnessValid() ||
                  IsBgBrightnessValid() || foregroundFilterCache_ != nullptr || IsWaterRippleValid();
}

void RSProperties::UpdateForegroundFilter()
{
    if (motionBlurPara_ && ROSEN_GNE(motionBlurPara_->radius, 0.0)) {
        auto motionBlurFilter = std::make_shared<RSMotionBlurFilter>(motionBlurPara_);
        if (IS_UNI_RENDER) {
            foregroundFilterCache_ = motionBlurFilter;
        } else {
            foregroundFilter_ = motionBlurFilter;
        }
    } else if (IsForegroundEffectRadiusValid()) {
        auto foregroundEffectFilter = std::make_shared<RSForegroundEffectFilter>(foregroundEffectRadius_);
        if (IS_UNI_RENDER) {
            foregroundFilterCache_ = foregroundEffectFilter;
        } else {
            foregroundFilter_ = foregroundEffectFilter;
        }
    } else if (IsSpherizeValid()) {
        CreateSphereEffectFilter();
    } else if (IsAttractionValid()) {
        CreateAttractionEffectFilter();
    } else if (GetShadowMask()) {
        float elevation = GetShadowElevation();
        Drawing::scalar n1 = 0.25f * elevation * (1 + elevation / 128.0f);  // 0.25f 128.0f
        Drawing::scalar blurRadius = elevation > 0.0f ? n1 : GetShadowRadius();
        auto colorfulShadowFilter =
            std::make_shared<RSColorfulShadowFilter>(blurRadius, GetShadowOffsetX(), GetShadowOffsetY());
        if (IS_UNI_RENDER) {
            foregroundFilterCache_ = colorfulShadowFilter;
        } else {
            foregroundFilter_ = colorfulShadowFilter;
        }
    } else {
        foregroundFilter_.reset();
        foregroundFilterCache_.reset();
    }
}

void RSProperties::CalculatePixelStretch()
{
    pixelStretchNeedUpdate_ = false;
    // no pixel stretch
    if (!pixelStretch_.has_value() && !pixelStretchPercent_.has_value()) {
        return;
    }
    // convert pixel stretch percent to pixel stretch
    if (pixelStretchPercent_) {
        auto width = GetBoundsWidth();
        auto height = GetBoundsHeight();
        if (isinf(width) || isinf(height)) {
            return;
        }
        pixelStretch_ = *pixelStretchPercent_ * Vector4f(width, height, width, height);
    }
    constexpr static float EPS = 1e-5f;
    // parameter check: near zero
    if (abs(pixelStretch_->x_) < EPS && abs(pixelStretch_->y_) < EPS && abs(pixelStretch_->z_) < EPS &&
        abs(pixelStretch_->w_) < EPS) {
        pixelStretch_ = std::nullopt;
        return;
    }
    // parameter check: all >= 0 or all <= 0
    if ((pixelStretch_->x_ < EPS && pixelStretch_->y_ < EPS && pixelStretch_->z_ < EPS && pixelStretch_->w_ < EPS) ||
        (pixelStretch_->x_ > -EPS && pixelStretch_->y_ > -EPS && pixelStretch_->z_ > -EPS &&
            pixelStretch_->w_ > -EPS)) {
        isDrawn_ = true;
        return;
    }
    pixelStretch_ = std::nullopt;
}

void RSProperties::CalculateFrameOffset()
{
    frameOffsetX_ = frameGeo_->GetX() - boundsGeo_->GetX();
    frameOffsetY_ = frameGeo_->GetY() - boundsGeo_->GetY();
    if (isinf(frameOffsetX_)) {
        frameOffsetX_ = 0.;
    }
    if (isinf(frameOffsetY_)) {
        frameOffsetY_ = 0.;
    }
    if (frameOffsetX_ != 0. || frameOffsetY_ != 0.) {
        isDrawn_ = true;
    }
}

void RSProperties::CheckGreyCoef()
{
    if (!greyCoef_.has_value()) {
        return;
    }
    // 127.0 half of 255.0
    if (greyCoef_->x_ < 0.0f || greyCoef_->x_ > 127.0f || greyCoef_->y_ < 0.0f || greyCoef_->y_ > 127.0f) {
        greyCoef_ = std::nullopt;
    }
}

// blend with background
void RSProperties::SetColorBlendMode(int colorBlendMode)
{
    colorBlendMode_ = std::clamp<int>(colorBlendMode, 0, static_cast<int>(RSColorBlendMode::MAX));
    if (colorBlendMode_ != static_cast<int>(RSColorBlendMode::NONE)) {
        isDrawn_ = true;
    }
    SetDirty();
    contentDirty_ = true;
}

int RSProperties::GetColorBlendMode() const
{
    return colorBlendMode_;
}

void RSProperties::SetColorBlendApplyType(int colorBlendApplyType)
{
    colorBlendApplyType_ = std::clamp<int>(colorBlendApplyType, 0, static_cast<int>(RSColorBlendApplyType::MAX));
    isDrawn_ = true;
    SetDirty();
    contentDirty_ = true;
}

int RSProperties::GetColorBlendApplyType() const
{
    return colorBlendApplyType_;
}

std::shared_ptr<RSColorPickerCacheTask> RSProperties::GetColorPickerCacheTaskShadow() const
{
    return shadow_ ? shadow_->GetColorPickerCacheTask() : nullptr;
}

void RSProperties::ReleaseColorPickerTaskShadow() const
{
    if (!shadow_ || shadow_->GetColorPickerCacheTask() == nullptr) {
        return;
    }
    shadow_->GetColorPickerCacheTask()->ReleaseColorPicker();
}

bool RSProperties::GetHaveEffectRegion() const
{
    return haveEffectRegion_;
}

void RSProperties::SetHaveEffectRegion(bool haveEffectRegion)
{
    // clear cache if new region is null or outside current region
    if (auto& manager = GetFilterCacheManager(false);
        manager && manager->IsCacheValid() && haveEffectRegion == false) {
        manager->UpdateCacheStateWithFilterRegion();
    }
    haveEffectRegion_ = haveEffectRegion;
}
} // namespace Rosen
} // namespace OHOS
