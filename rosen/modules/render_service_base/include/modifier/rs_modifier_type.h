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

#ifndef RENDER_SERVICE_CLIENT_CORE_ANIMATION_RS_MODIFIER_TYPE_H
#define RENDER_SERVICE_CLIENT_CORE_ANIMATION_RS_MODIFIER_TYPE_H

#include <bitset>
#include <cstdint>
#include <map>

namespace OHOS {
namespace Rosen {
// NOTE:
// 1. Following LUTs must be updated according when this enum is updated :
//    a. g_propertyResetterLUT in rs_properties.cpp
//    b. g_propertyToDrawableLut in rs_drawable_content.cpp
// 2. Property modifier(i.e. to be applied to RSProperties) MUST be added before CUSTOM enum, else wise it will not work
enum class RSModifierType : int16_t {
    INVALID = 0,
    BOUNDS,
    FRAME,
    POSITION_Z,
    PIVOT,
    PIVOT_Z,
    QUATERNION,
    ROTATION,
    ROTATION_X,
    ROTATION_Y,
    CAMERA_DISTANCE,
    SCALE,
    SKEW,
    PERSP,
    TRANSLATE,
    TRANSLATE_Z,
    SUBLAYER_TRANSFORM,
    CORNER_RADIUS,
    ALPHA,
    ALPHA_OFFSCREEN,
    FOREGROUND_COLOR,
    BACKGROUND_COLOR,
    BACKGROUND_SHADER,
    BG_IMAGE,
    BG_IMAGE_INNER_RECT,
    BG_IMAGE_WIDTH,
    BG_IMAGE_HEIGHT,
    BG_IMAGE_POSITION_X,
    BG_IMAGE_POSITION_Y,
    SURFACE_BG_COLOR,
    BORDER_COLOR,
    BORDER_WIDTH,
    BORDER_STYLE,
    BORDER_DASH_WIDTH,
    BORDER_DASH_GAP,
    FILTER,
    BACKGROUND_FILTER,
    LINEAR_GRADIENT_BLUR_PARA,
    DYNAMIC_LIGHT_UP_RATE,
    DYNAMIC_LIGHT_UP_DEGREE,
    FG_BRIGHTNESS_RATES,
    FG_BRIGHTNESS_SATURATION,
    FG_BRIGHTNESS_POSCOEFF,
    FG_BRIGHTNESS_NEGCOEFF,
    FG_BRIGHTNESS_FRACTION,
    BG_BRIGHTNESS_RATES,
    BG_BRIGHTNESS_SATURATION,
    BG_BRIGHTNESS_POSCOEFF,
    BG_BRIGHTNESS_NEGCOEFF,
    BG_BRIGHTNESS_FRACTION,
    FRAME_GRAVITY,
    CLIP_RRECT,
    CLIP_BOUNDS,
    CLIP_TO_BOUNDS,
    CLIP_TO_FRAME,
    VISIBLE,
    SHADOW_COLOR,
    SHADOW_OFFSET_X,
    SHADOW_OFFSET_Y,
    SHADOW_ALPHA,
    SHADOW_ELEVATION,
    SHADOW_RADIUS,
    SHADOW_PATH,
    SHADOW_MASK,
    SHADOW_COLOR_STRATEGY,
    MASK,
    SPHERIZE,
    LIGHT_UP_EFFECT,
    PIXEL_STRETCH,
    PIXEL_STRETCH_PERCENT,
    PIXEL_STRETCH_TILE_MODE,
    USE_EFFECT,
    COLOR_BLEND_MODE,
    COLOR_BLEND_APPLY_TYPE,
    SANDBOX,
    GRAY_SCALE,
    BRIGHTNESS,
    CONTRAST,
    SATURATE,
    SEPIA,
    INVERT,
    AIINVERT,
    SYSTEMBAREFFECT,
    WATER_RIPPLE_PROGRESS,
    WATER_RIPPLE_PARAMS,
    HUE_ROTATE,
    COLOR_BLEND,
    PARTICLE,
    SHADOW_IS_FILLED,
    OUTLINE_COLOR,
    OUTLINE_WIDTH,
    OUTLINE_STYLE,
    OUTLINE_DASH_WIDTH,
    OUTLINE_DASH_GAP,
    OUTLINE_RADIUS,
    USE_SHADOW_BATCHING,
    GREY_COEF,
    LIGHT_INTENSITY,
    LIGHT_COLOR,
    LIGHT_POSITION,
    ILLUMINATED_BORDER_WIDTH,
    ILLUMINATED_TYPE,
    BLOOM,
    PARTICLE_EMITTER_UPDATER,
    PARTICLE_NOISE_FIELD,
    FOREGROUND_EFFECT_RADIUS,
    MOTION_BLUR_PARA,
    FLY_OUT_DEGREE,
    FLY_OUT_PARAMS,
    DYNAMIC_DIM_DEGREE,
    MAGNIFIER_PARA,
    BACKGROUND_BLUR_RADIUS,
    BACKGROUND_BLUR_SATURATION,
    BACKGROUND_BLUR_BRIGHTNESS,
    BACKGROUND_BLUR_MASK_COLOR,
    BACKGROUND_BLUR_COLOR_MODE,
    BACKGROUND_BLUR_RADIUS_X,
    BACKGROUND_BLUR_RADIUS_Y,
    FOREGROUND_BLUR_RADIUS,
    FOREGROUND_BLUR_SATURATION,
    FOREGROUND_BLUR_BRIGHTNESS,
    FOREGROUND_BLUR_MASK_COLOR,
    FOREGROUND_BLUR_COLOR_MODE,
    FOREGROUND_BLUR_RADIUS_X,
    FOREGROUND_BLUR_RADIUS_Y,
    ATTRACTION_FRACTION,
    ATTRACTION_DSTPOINT,
    CUSTOM,
    EXTENDED,
    TRANSITION,
    BACKGROUND_STYLE,
    CONTENT_STYLE,
    FOREGROUND_STYLE,
    OVERLAY_STYLE,
    NODE_MODIFIER,
    ENV_FOREGROUND_COLOR,
    ENV_FOREGROUND_COLOR_STRATEGY,
    GEOMETRYTRANS,
    CHILDREN, // PLACEHOLDER, no such modifier, but we need a dirty flag
    MAX_RS_MODIFIER_TYPE,
};

using ModifierDirtyTypes = std::bitset<static_cast<int>(RSModifierType::MAX_RS_MODIFIER_TYPE)>;
enum class RSRenderPropertyType : int16_t {
    INVALID = 0,
    PROPERTY_FLOAT,
    PROPERTY_COLOR,
    PROPERTY_MATRIX3F,
    PROPERTY_QUATERNION,
    PROPERTY_FILTER,
    PROPERTY_VECTOR2F,
    PROPERTY_VECTOR4F,
    PROPERTY_VECTOR4_COLOR,
    PROPERTY_SKMATRIX,
    PROPERTY_RRECT,
};

enum class RSPropertyUnit : int16_t {
    UNKNOWN = 0,
    PIXEL_POSITION,
    PIXEL_SIZE,
    RATIO_SCALE,
    ANGLE_ROTATION,
};

const std::map<RSModifierType, std::string> RS_MODIFIER_TYPE_TO_STRING = {
    { RSModifierType::INVALID, "Invalid" },
    { RSModifierType::BOUNDS, "Bounds" },
    { RSModifierType::FRAME, "Frame" },
    { RSModifierType::POSITION_Z, "PositionZ" },
    { RSModifierType::PIVOT, "Pivot" },
    { RSModifierType::PIVOT_Z, "PivotZ" },
    { RSModifierType::QUATERNION, "Quaternion" },
    { RSModifierType::ROTATION, "Rotation" },
    { RSModifierType::ROTATION_X, "RotationX" },
    { RSModifierType::ROTATION_Y, "RotationY" },
    { RSModifierType::CAMERA_DISTANCE, "CameraDistance" },
    { RSModifierType::SCALE, "Scale" },
    { RSModifierType::SKEW, "Skew" },
    { RSModifierType::PERSP, "Persp" },
    { RSModifierType::TRANSLATE, "Translate" },
    { RSModifierType::TRANSLATE_Z, "TranslateZ" },
    { RSModifierType::SUBLAYER_TRANSFORM, "SublayerTransform" },
    { RSModifierType::CORNER_RADIUS, "CornerRadius" },
    { RSModifierType::ALPHA, "Alpha" },
    { RSModifierType::ALPHA_OFFSCREEN, "AlphaOffscreen" },
    { RSModifierType::FOREGROUND_COLOR, "ForegroundColor" },
    { RSModifierType::BACKGROUND_COLOR, "BackgroundColor" },
    { RSModifierType::BACKGROUND_SHADER, "BackgroundShader" },
    { RSModifierType::BG_IMAGE, "BgImage" },
    { RSModifierType::BG_IMAGE_INNER_RECT, "BgImageInnerRect" },
    { RSModifierType::BG_IMAGE_WIDTH, "BgImageWidth" },
    { RSModifierType::BG_IMAGE_HEIGHT, "BgImageHeight" },
    { RSModifierType::BG_IMAGE_POSITION_X, "BgImagePositionX" },
    { RSModifierType::BG_IMAGE_POSITION_Y, "BgImagePositionY" },
    { RSModifierType::SURFACE_BG_COLOR, "SurfaceBgColor" },
    { RSModifierType::BORDER_COLOR, "BorderColor" },
    { RSModifierType::BORDER_WIDTH, "BorderWidth" },
    { RSModifierType::BORDER_STYLE, "BorderStyle" },
    { RSModifierType::BORDER_DASH_WIDTH, "BorderDashWidth" },
    { RSModifierType::BORDER_DASH_GAP, "BorderDashGap" },
    { RSModifierType::FILTER, "Filter" },
    { RSModifierType::BACKGROUND_FILTER, "BackgroundFilter" },
    { RSModifierType::LINEAR_GRADIENT_BLUR_PARA, "LinearGradientBlurPara" },
    { RSModifierType::DYNAMIC_LIGHT_UP_RATE, "DynamicLightUpRate" },
    { RSModifierType::DYNAMIC_LIGHT_UP_DEGREE, "DynamicLightUpDegree" },
    { RSModifierType::FG_BRIGHTNESS_RATES, "FgBrightnessRates" },
    { RSModifierType::FG_BRIGHTNESS_SATURATION, "FgBrightnessSaturation" },
    { RSModifierType::FG_BRIGHTNESS_POSCOEFF, "FgBrightnessPoscoeff" },
    { RSModifierType::FG_BRIGHTNESS_NEGCOEFF, "FgBrightnessNegcoeff" },
    { RSModifierType::FG_BRIGHTNESS_FRACTION, "FgBrightnessFraction" },
    { RSModifierType::BG_BRIGHTNESS_RATES, "BgBrightnessRates" },
    { RSModifierType::BG_BRIGHTNESS_SATURATION, "BgBrightnessSaturation" },
    { RSModifierType::BG_BRIGHTNESS_POSCOEFF, "BgBrightnessPoscoeff" },
    { RSModifierType::BG_BRIGHTNESS_NEGCOEFF, "BgBrightnessNegcoeff" },
    { RSModifierType::BG_BRIGHTNESS_FRACTION, "BgBrightnessFraction" },
    { RSModifierType::FRAME_GRAVITY, "FrameGravity" },
    { RSModifierType::CLIP_RRECT, "ClipRrect" },
    { RSModifierType::CLIP_BOUNDS, "ClipBounds" },
    { RSModifierType::CLIP_TO_BOUNDS, "ClipToBounds" },
    { RSModifierType::CLIP_TO_FRAME, "ClipToFrame" },
    { RSModifierType::VISIBLE, "Visible" },
    { RSModifierType::SHADOW_COLOR, "ShadowColor" },
    { RSModifierType::SHADOW_OFFSET_X, "ShadowOffsetX" },
    { RSModifierType::SHADOW_OFFSET_Y, "ShadowOffsetY" },
    { RSModifierType::SHADOW_ALPHA, "ShadowAlpha" },
    { RSModifierType::SHADOW_ELEVATION, "ShadowElevation" },
    { RSModifierType::SHADOW_RADIUS, "ShadowRadius" },
    { RSModifierType::SHADOW_PATH, "ShadowPath" },
    { RSModifierType::SHADOW_MASK, "ShadowMask" },
    { RSModifierType::SHADOW_COLOR_STRATEGY, "ShadowColorStrategy" },
    { RSModifierType::MASK, "Mask" },
    { RSModifierType::SPHERIZE, "Spherize" },
    { RSModifierType::LIGHT_UP_EFFECT, "LightUpEffect" },
    { RSModifierType::PIXEL_STRETCH, "PixelStretch" },
    { RSModifierType::PIXEL_STRETCH_PERCENT, "PixelStretchPercent" },
    { RSModifierType::PIXEL_STRETCH_TILE_MODE, "PixelStretchTileMode" },
    { RSModifierType::USE_EFFECT, "UseEffect" },
    { RSModifierType::COLOR_BLEND_MODE, "ColorBlendMode" },
    { RSModifierType::COLOR_BLEND_APPLY_TYPE, "ColorBlendApplyType" },
    { RSModifierType::SANDBOX, "Sandbox" },
    { RSModifierType::GRAY_SCALE, "GrayScale" },
    { RSModifierType::BRIGHTNESS, "Brightness" },
    { RSModifierType::CONTRAST, "Contrast" },
    { RSModifierType::SATURATE, "Saturate" },
    { RSModifierType::SEPIA, "Sepia" },
    { RSModifierType::INVERT, "Invert" },
    { RSModifierType::AIINVERT, "Aiinvert" },
    { RSModifierType::SYSTEMBAREFFECT, "Systembareffect" },
    { RSModifierType::HUE_ROTATE, "HueRotate" },
    { RSModifierType::COLOR_BLEND, "ColorBlend" },
    { RSModifierType::PARTICLE, "Particle" },
    { RSModifierType::SHADOW_IS_FILLED, "ShadowIsFilled" },
    { RSModifierType::OUTLINE_COLOR, "OutlineColor" },
    { RSModifierType::OUTLINE_WIDTH, "OutlineWidth" },
    { RSModifierType::OUTLINE_STYLE, "OutlineStyle" },
    { RSModifierType::OUTLINE_DASH_WIDTH, "OutlineDashWidth" },
    { RSModifierType::OUTLINE_DASH_GAP, "OutlineDashGap" },
    { RSModifierType::OUTLINE_RADIUS, "OutlineRadius" },
    { RSModifierType::GREY_COEF, "GreyCoef" },
    { RSModifierType::LIGHT_INTENSITY, "LightIntensity" },
    { RSModifierType::LIGHT_COLOR, "LightColor" },
    { RSModifierType::LIGHT_POSITION, "LightPosition" },
    { RSModifierType::ILLUMINATED_BORDER_WIDTH, "IlluminatedBorderWidth" },
    { RSModifierType::ILLUMINATED_TYPE, "IlluminatedType" },
    { RSModifierType::BLOOM, "Bloom" },
    { RSModifierType::FOREGROUND_EFFECT_RADIUS, "ForegroundEffectRadius" },
    { RSModifierType::USE_SHADOW_BATCHING, "UseShadowBatching" },
    { RSModifierType::MOTION_BLUR_PARA, "MotionBlurPara" },
    { RSModifierType::PARTICLE_EMITTER_UPDATER, "ParticleEmitterUpdater" },
    { RSModifierType::PARTICLE_NOISE_FIELD, "ParticleNoiseField" },
    { RSModifierType::DYNAMIC_DIM_DEGREE, "DynamicDimDegree" },
    { RSModifierType::MAGNIFIER_PARA, "MagnifierPara" },
    { RSModifierType::BACKGROUND_BLUR_RADIUS, "BackgroundBlurRadius" },
    { RSModifierType::BACKGROUND_BLUR_SATURATION, "BackgroundBlurSaturation" },
    { RSModifierType::BACKGROUND_BLUR_BRIGHTNESS, "BackgroundBlurBrightness" },
    { RSModifierType::BACKGROUND_BLUR_MASK_COLOR, "BackgroundBlurMaskColor" },
    { RSModifierType::BACKGROUND_BLUR_COLOR_MODE, "BackgroundBlurColorMode" },
    { RSModifierType::BACKGROUND_BLUR_RADIUS_X, "BackgroundBlurRadiusX" },
    { RSModifierType::BACKGROUND_BLUR_RADIUS_Y, "BackgroundBlurRadiusY" },
    { RSModifierType::FOREGROUND_BLUR_RADIUS, "ForegroundBlurRadius" },
    { RSModifierType::FOREGROUND_BLUR_SATURATION, "ForegroundBlurSaturation" },
    { RSModifierType::FOREGROUND_BLUR_BRIGHTNESS, "ForegroundBlurBrightness" },
    { RSModifierType::FOREGROUND_BLUR_MASK_COLOR, "ForegroundBlurMaskColor" },
    { RSModifierType::FOREGROUND_BLUR_COLOR_MODE, "ForegroundBlurColorMode" },
    { RSModifierType::FOREGROUND_BLUR_RADIUS_X, "ForegroundBlurRadiusX" },
    { RSModifierType::FOREGROUND_BLUR_RADIUS_Y, "ForegroundBlurRadiusY" },
    { RSModifierType::CUSTOM, "Custom" },
    { RSModifierType::EXTENDED, "Extended" },
    { RSModifierType::TRANSITION, "Transition" },
    { RSModifierType::BACKGROUND_STYLE, "BackgroundStyle" },
    { RSModifierType::CONTENT_STYLE, "ContentStyle" },
    { RSModifierType::FOREGROUND_STYLE, "ForegroundStyle" },
    { RSModifierType::OVERLAY_STYLE, "OverlayStyle" },
    { RSModifierType::NODE_MODIFIER, "NodeModifier" },
    { RSModifierType::ENV_FOREGROUND_COLOR, "EnvForegroundColor" },
    { RSModifierType::ENV_FOREGROUND_COLOR_STRATEGY, "EnvForegroundColorStrategy" },
    { RSModifierType::GEOMETRYTRANS, "Geometrytrans" },
    { RSModifierType::CHILDREN, "Children" },
    { RSModifierType::MAX_RS_MODIFIER_TYPE, "MaxRsModifierType" },
};

} // namespace Rosen
} // namespace OHOS

#endif // RENDER_SERVICE_CLIENT_CORE_ANIMATION_RS_MODIFIER_TYPE_H
