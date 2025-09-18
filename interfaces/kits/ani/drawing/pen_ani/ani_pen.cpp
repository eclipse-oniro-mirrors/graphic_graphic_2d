/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "ani_pen.h"
#include "path_ani/ani_path.h"
#include "color_filter_ani/ani_color_filter.h"
#include "interop_js/arkts_esvalue.h"
#include "interop_js/arkts_interop_js_api.h"
#include "interop_js/hybridgref_ani.h"
#include "interop_js/hybridgref_napi.h"
#include "drawing/pen_napi/js_pen.h"
#include "shadow_layer_ani/ani_shadow_layer.h"
#include "shader_effect_ani/ani_shader_effect.h"
#include "path_effect_ani/ani_path_effect.h"
#include "mask_filter_ani/ani_mask_filter.h"
#include "image_filter_ani/ani_image_filter.h"

namespace OHOS::Rosen {
namespace Drawing {
const char* ANI_CLASS_PEN_NAME = "@ohos.graphics.drawing.drawing.Pen";
const char* ANI_CLASS_JOIN_STYLE_NAME = "@ohos.graphics.drawing.drawing.JoinStyle";
const char* ANI_CLASS_CAP_STYLE_NAME = "@ohos.graphics.drawing.drawing.CapStyle";

ani_status AniPen::AniInit(ani_env *env)
{
    ani_class cls = nullptr;
    ani_status ret = env->FindClass(ANI_CLASS_PEN_NAME, &cls);
    if (ret != ANI_OK) {
        ROSEN_LOGE("[ANI] can't find class: %{public}s", ANI_CLASS_PEN_NAME);
        return ANI_NOT_FOUND;
    }

    std::array methods = {
        ani_native_function { "constructorNative", ":", reinterpret_cast<void*>(Constructor) },
        ani_native_function { "constructorNative", "C{@ohos.graphics.drawing.drawing.Pen}:",
            reinterpret_cast<void*>(ConstructorWithPen) },
        ani_native_function { "getAlpha", ":i", reinterpret_cast<void*>(GetAlpha) },
        ani_native_function { "reset", ":", reinterpret_cast<void*>(Reset) },
        ani_native_function { "setAlpha", "i:", reinterpret_cast<void*>(SetAlpha) },
        ani_native_function { "setBlendMode", "C{@ohos.graphics.drawing.drawing.BlendMode}:",
            reinterpret_cast<void*>(SetBlendMode) },
        ani_native_function { "setColorFilter", nullptr,
            reinterpret_cast<void*>(SetColorFilter) },
        ani_native_function { "getColorFilter", ":C{@ohos.graphics.drawing.drawing.ColorFilter}",
            reinterpret_cast<void*>(GetColorFilter) },
        ani_native_function { "getHexColor", ":i", reinterpret_cast<void*>(GetHexColor) },
        ani_native_function { "setColor", "i:", reinterpret_cast<void*>(SetColor) },
        ani_native_function { "setColor", "C{@ohos.graphics.common2D.common2D.Color}:",
            reinterpret_cast<void*>(SetColorWithColor) },
        ani_native_function { "setColor", "iiii:", reinterpret_cast<void*>(SetColorWithNumber) },
        ani_native_function { "setDither", "z:", reinterpret_cast<void*>(SetDither) },
        ani_native_function { "setAntiAlias", "z:", reinterpret_cast<void*>(SetAntiAlias) },
        ani_native_function { "setStrokeWidth", "d:", reinterpret_cast<void*>(SetStrokeWidth) },
        ani_native_function { "setCapStyle", nullptr, reinterpret_cast<void*>(SetCapStyle) },
        ani_native_function { "getFillPath", "C{@ohos.graphics.drawing.drawing.Path}"
            "C{@ohos.graphics.drawing.drawing.Path}:z", reinterpret_cast<void*>(GetFillPath) },
        ani_native_function { "setMiterLimit", "d:", reinterpret_cast<void*>(SetMiterLimit) },
        ani_native_function { "getCapStyle", nullptr, reinterpret_cast<void*>(GetCapStyle) },
        ani_native_function { "setMaskFilter", nullptr, reinterpret_cast<void*>(SetMaskFilter) },
        ani_native_function { "isAntiAlias", ":z", reinterpret_cast<void*>(IsAntiAlias) },
        ani_native_function { "getColor", ":C{@ohos.graphics.common2D.common2D.Color}",
            reinterpret_cast<void*>(GetColor) },
        ani_native_function { "setJoinStyle", nullptr, reinterpret_cast<void*>(SetJoinStyle) },
        ani_native_function { "getJoinStyle", nullptr, reinterpret_cast<void*>(GetJoinStyle) },
        ani_native_function { "getWidth", ":d", reinterpret_cast<void*>(GetWidth) },
        ani_native_function { "getMiterLimit", ":d", reinterpret_cast<void*>(GetMiterLimit) },
        ani_native_function { "setPathEffect", nullptr, reinterpret_cast<void*>(SetPathEffect) },
        ani_native_function { "setImageFilter", nullptr, reinterpret_cast<void*>(SetImageFilter) },
        ani_native_function { "setShadowLayer", nullptr, reinterpret_cast<void*>(SetShadowLayer) },
        ani_native_function { "setShaderEffect", nullptr, reinterpret_cast<void*>(SetShaderEffect) },
    };

    ret = env->Class_BindNativeMethods(cls, methods.data(), methods.size());
    if (ret != ANI_OK) {
        ROSEN_LOGE("[ANI] bind methods fail: %{public}s", ANI_CLASS_PEN_NAME);
        return ANI_NOT_FOUND;
    }

    std::array staticMethods = {
        ani_native_function { "penTransferStaticNative", nullptr, reinterpret_cast<void*>(PenTransferStatic) },
        ani_native_function { "getPenAddr", nullptr, reinterpret_cast<void*>(GetPenAddr) },
    };

    ret = env->Class_BindStaticNativeMethods(cls, staticMethods.data(), staticMethods.size());
    if (ret != ANI_OK) {
        ROSEN_LOGE("[ANI] bind static methods fail: %{public}s", ANI_CLASS_PEN_NAME);
        return ANI_NOT_FOUND;
    }

    return ANI_OK;
}

void AniPen::Constructor(ani_env* env, ani_object obj)
{
    std::shared_ptr<Pen> pen = std::make_shared<Pen>();
    AniPen* aniPen = new AniPen(pen);
    if (ANI_OK != env->Object_SetFieldByName_Long(obj, NATIVE_OBJ, reinterpret_cast<ani_long>(aniPen))) {
        ROSEN_LOGE("AniPen::Constructor failed create aniPen");
        delete aniPen;
        return;
    }
}

void AniPen::ConstructorWithPen(ani_env* env, ani_object obj, ani_object aniPenObj)
{
    auto aniPen = GetNativeFromObj<AniPen>(env, aniPenObj);
    if (aniPen == nullptr) {
        ThrowBusinessError(env, DrawingErrorCode::ERROR_INVALID_PARAM, "Invalid params. ");
        return;
    }
    std::shared_ptr<Pen> other = aniPen->GetPen();
    std::shared_ptr<Pen> pen = other == nullptr ? std::make_shared<Pen>() : std::make_shared<Pen>(*other);
    AniPen* newAniPen = new AniPen(pen);
    if (ANI_OK != env->Object_SetFieldByName_Long(obj, NATIVE_OBJ, reinterpret_cast<ani_long>(newAniPen))) {
        ROSEN_LOGE("AniPen::Constructor failed create aniPen");
        delete newAniPen;
        return;
    }
}

ani_int AniPen::GetAlpha(ani_env* env, ani_object obj)
{
    auto aniPen = GetNativeFromObj<AniPen>(env, obj);
    if (aniPen == nullptr || aniPen->GetPen() == nullptr) {
        ThrowBusinessError(env, DrawingErrorCode::ERROR_INVALID_PARAM, "Invalid params. ");
        return -1;
    }

    return aniPen->GetPen()->GetAlpha();
}

void AniPen::Reset(ani_env* env, ani_object obj)
{
    auto aniPen = GetNativeFromObj<AniPen>(env, obj);
    if (aniPen == nullptr || aniPen->GetPen() == nullptr) {
        ThrowBusinessError(env, DrawingErrorCode::ERROR_INVALID_PARAM, "Invalid params. ");
        return;
    }

    aniPen->GetPen()->Reset();
}

void AniPen::SetAlpha(ani_env* env, ani_object obj, ani_int alpha)
{
    auto aniPen = GetNativeFromObj<AniPen>(env, obj);
    if (aniPen == nullptr || aniPen->GetPen() == nullptr) {
        ThrowBusinessError(env, DrawingErrorCode::ERROR_INVALID_PARAM, "Invalid params. ");
        return;
    }

    if (CheckDoubleOutOfRange(alpha, 0, Color::RGB_MAX)) {
        ThrowBusinessError(env, DrawingErrorCode::ERROR_INVALID_PARAM, "alpha out of range. ");
        return;
    }

    aniPen->GetPen()->SetAlpha(alpha);
}

void AniPen::SetBlendMode(ani_env* env, ani_object obj, ani_enum_item aniBlendMode)
{
    auto aniPen = GetNativeFromObj<AniPen>(env, obj);
    if (aniPen == nullptr || aniPen->GetPen() == nullptr) {
        ThrowBusinessError(env, DrawingErrorCode::ERROR_INVALID_PARAM, "Invalid params. ");
        return;
    }

    ani_int blendMode;
    if (ANI_OK != env->EnumItem_GetValue_Int(aniBlendMode, &blendMode)) {
        ThrowBusinessError(env, DrawingErrorCode::ERROR_INVALID_PARAM, "Invalid params. ");
        return;
    }

    aniPen->GetPen()->SetBlendMode(static_cast<BlendMode>(blendMode));
}


void AniPen::SetColorFilter(ani_env* env, ani_object obj, ani_object objColorFilter)
{
    auto aniPen = GetNativeFromObj<AniPen>(env, obj);
    if (aniPen == nullptr || aniPen->GetPen() == nullptr) {
        ThrowBusinessError(env, DrawingErrorCode::ERROR_INVALID_PARAM, "Invalid params. ");
        return;
    }

    ani_boolean isNull = ANI_TRUE;
    env->Reference_IsNull(objColorFilter, &isNull);
    AniColorFilter* aniColorFilter = nullptr;
    if (!isNull) {
        aniColorFilter = GetNativeFromObj<AniColorFilter>(env, objColorFilter);
        if (aniColorFilter == nullptr) {
            ThrowBusinessError(env, DrawingErrorCode::ERROR_INVALID_PARAM, "Invalid param colorFilter.");
            return;
        }
    }

    Filter filter = aniPen->GetPen()->GetFilter();
    filter.SetColorFilter(aniColorFilter ? aniColorFilter->GetColorFilter() : nullptr);
    aniPen->GetPen()->SetFilter(filter);
}

ani_object AniPen::GetColorFilter(ani_env* env, ani_object obj)
{
    auto aniPen = GetNativeFromObj<AniPen>(env, obj);
    if (aniPen == nullptr || aniPen->GetPen() == nullptr) {
        ThrowBusinessError(env, DrawingErrorCode::ERROR_INVALID_PARAM, "AniPen::GetColorFilter aniPen is nullptr.");
        return CreateAniUndefined(env);
    }
    if (!aniPen->GetPen()->HasFilter()) {
        return CreateAniUndefined(env);
    }
    AniColorFilter* aniColorFilter = new AniColorFilter(aniPen->GetPen()->GetFilter().GetColorFilter());
    ani_object aniObj = CreateAniObject(env, "@ohos.graphics.drawing.drawing.ColorFilter", nullptr);
    if (ANI_OK != env->Object_SetFieldByName_Long(aniObj,
        NATIVE_OBJ, reinterpret_cast<ani_long>(aniColorFilter))) {
        ROSEN_LOGE(" AniPen::GetColorFilter failed cause by Object_SetFieldByName_Long");
        delete aniColorFilter;
        return CreateAniUndefined(env);
    }
    return aniObj;
}

ani_int AniPen::GetHexColor(ani_env* env, ani_object obj)
{
    auto aniPen = GetNativeFromObj<AniPen>(env, obj);
    if (aniPen == nullptr || aniPen->GetPen() == nullptr) {
        ThrowBusinessError(env, DrawingErrorCode::ERROR_INVALID_PARAM, "AniPen::GetHexColor aniPen is nullptr.");
        return -1;
    }
    return aniPen->GetPen()->GetColor().CastToColorQuad();
}

void AniPen::SetColor(ani_env* env, ani_object obj, ani_int color)
{
    auto aniPen = GetNativeFromObj<AniPen>(env, obj);
    if (aniPen == nullptr || aniPen->GetPen() == nullptr) {
        ThrowBusinessError(env, DrawingErrorCode::ERROR_INVALID_PARAM, "AniPen::SetColor aniPen is nullptr.");
        return;
    }
    ColorQuad colorQuad = static_cast<ColorQuad>(color);
    Drawing::Color drawingColor;
    drawingColor.SetColorQuad(colorQuad);
    aniPen->GetPen()->SetColor(drawingColor);
}

void AniPen::SetColorWithColor(ani_env* env, ani_object obj,  ani_object colorObj)
{
    auto aniPen = GetNativeFromObj<AniPen>(env, obj);
    if (aniPen == nullptr || aniPen->GetPen() == nullptr) {
        ThrowBusinessError(env, DrawingErrorCode::ERROR_INVALID_PARAM, "AniPen::SetColor aniPen is nullptr.");
        return;
    }
    ColorQuad color;
    if (!GetColorQuadFromColorObj(env, colorObj, color)) {
        ROSEN_LOGE("AniPen::SetColor failed cause by colorObj");
        ThrowBusinessError(env, DrawingErrorCode::ERROR_INVALID_PARAM,
            "Parameter verification failed. The range of color channels must be [0, 255].");
        return;
    }
    Drawing::Color drawingColor;
    drawingColor.SetColorQuad(color);
    aniPen->GetPen()->SetColor(drawingColor);
}

void AniPen::SetColorWithNumber(ani_env* env, ani_object obj, ani_int alpha,
    ani_int red, ani_int green, ani_int blue)
{
    auto aniPen = GetNativeFromObj<AniPen>(env, obj);
    if (aniPen == nullptr || aniPen->GetPen() == nullptr) {
        ThrowBusinessError(env, DrawingErrorCode::ERROR_INVALID_PARAM, "AniPen::SetColor aniPen is nullptr.");
        return;
    }

    if (CheckDoubleOutOfRange(alpha, 0, Color::RGB_MAX)) {
        ThrowBusinessError(env, DrawingErrorCode::ERROR_INVALID_PARAM, "alpha out of range.");
        return;
    }

    if (CheckDoubleOutOfRange(red, 0, Color::RGB_MAX)) {
        ThrowBusinessError(env, DrawingErrorCode::ERROR_INVALID_PARAM, "red out of range.");
        return;
    }

    if (CheckDoubleOutOfRange(green, 0, Color::RGB_MAX)) {
        ThrowBusinessError(env, DrawingErrorCode::ERROR_INVALID_PARAM, "green out of range.");
        return;
    }

    if (CheckDoubleOutOfRange(blue, 0, Color::RGB_MAX)) {
        ThrowBusinessError(env, DrawingErrorCode::ERROR_INVALID_PARAM, "blue out of range.");
        return;
    }
    Drawing::Color drawingColor = Color::ColorQuadSetARGB(alpha, red, green, blue);
    aniPen->GetPen()->SetColor(drawingColor);
}

void AniPen::SetDither(ani_env* env, ani_object obj, ani_boolean dither)
{
    auto aniPen = GetNativeFromObj<AniPen>(env, obj);
    if (aniPen == nullptr || aniPen->GetPen() == nullptr) {
        ThrowBusinessError(env, DrawingErrorCode::ERROR_INVALID_PARAM, "AniPen::SetDither aniPen is nullptr.");
        return;
    }
}

void AniPen::SetAntiAlias(ani_env* env, ani_object obj, ani_boolean antiAlias)
{
    auto aniPen = GetNativeFromObj<AniPen>(env, obj);
    if (aniPen == nullptr || aniPen->GetPen() == nullptr) {
        ThrowBusinessError(env, DrawingErrorCode::ERROR_INVALID_PARAM, "AniPen::SetAntiAlias aniPen is nullptr.");
        return;
    }
    aniPen->GetPen()->SetAntiAlias(antiAlias);
}

void AniPen::SetStrokeWidth(ani_env* env, ani_object obj, ani_double width)
{
    auto aniPen = GetNativeFromObj<AniPen>(env, obj);
    if (aniPen == nullptr || aniPen->GetPen() == nullptr) {
        ThrowBusinessError(env, DrawingErrorCode::ERROR_INVALID_PARAM, "AniPen::SetStrokeWidth aniPen is nullptr.");
        return;
    }
    aniPen->GetPen()->SetWidth(static_cast<float>(width));
}

static int32_t CapCastToTsCap(Pen::CapStyle cap)
{
    int32_t tsCap = 0; // 0: CapStyle::FLAT_CAP
    switch (cap) {
        case Pen::CapStyle::FLAT_CAP:
            tsCap = 0; // 0: CapStyle::FLAT_CAP
            break;
        case Pen::CapStyle::SQUARE_CAP:
            tsCap = 1; // 1: CapStyle::SQUARE_CAP
            break;
        case Pen::CapStyle::ROUND_CAP:
            tsCap = 2; // 2: CapStyle::ROUND_CAP
            break;
        default:
            break;
    }
    return tsCap;
}

static Pen::CapStyle TsCapCastToCap(int32_t tsCap)
{
    Pen::CapStyle cap = Pen::CapStyle::FLAT_CAP;
    switch (tsCap) {
        case 0: // 0: CapStyle::FLAT_CAP
            cap = Pen::CapStyle::FLAT_CAP;
            break;
        case 1: // 1: CapStyle::SQUARE_CAP
            cap = Pen::CapStyle::SQUARE_CAP;
            break;
        case 2: // 2: CapStyle::ROUND_CAP
            cap = Pen::CapStyle::ROUND_CAP;
            break;
        default:
            break;
    }
    return cap;
}

void AniPen::SetCapStyle(ani_env* env, ani_object obj, ani_enum_item aniCapstyle)
{
    auto aniPen = GetNativeFromObj<AniPen>(env, obj);
    if (aniPen == nullptr || aniPen->GetPen() == nullptr) {
        ThrowBusinessError(env, DrawingErrorCode::ERROR_INVALID_PARAM, "AniPen::SetCapStyle aniPen is nullptr.");
        return;
    }
    ani_int capStyle;
    if (ANI_OK != env->EnumItem_GetValue_Int(aniCapstyle, &capStyle)) {
        ThrowBusinessError(env, DrawingErrorCode::ERROR_INVALID_PARAM, "AniPen::SetCapStyle get CapStyle enum failed.");
        return;
    }
    aniPen->GetPen()->SetCapStyle(TsCapCastToCap(static_cast<int32_t>(capStyle)));
}

ani_boolean AniPen::GetFillPath(ani_env* env, ani_object obj, ani_object src, ani_object dst)
{
    auto aniPen = GetNativeFromObj<AniPen>(env, obj);
    if (aniPen == nullptr || aniPen->GetPen() == nullptr) {
        ThrowBusinessError(env, DrawingErrorCode::ERROR_INVALID_PARAM, "AniPen::GetFillPath aniPen is nullptr.");
        return false;
    }
    auto aniSrcPath = GetNativeFromObj<AniPath>(env, src);
    if (aniSrcPath == nullptr) {
        ThrowBusinessError(env, DrawingErrorCode::ERROR_INVALID_PARAM, "AniPen::GetFillPath aniSrcPath is nullptr.");
        return false;
    }
    if (aniSrcPath->GetPath() == nullptr) {
        ROSEN_LOGE("AniPen::GetFillPath src path is nullptr");
        return false;
    }
    auto aniDstPath = GetNativeFromObj<AniPath>(env, dst);
    if (aniDstPath == nullptr) {
        ThrowBusinessError(env, DrawingErrorCode::ERROR_INVALID_PARAM, "AniPen::GetFillPath aniDstPath is nullptr.");
        return false;
    }
    if (aniDstPath->GetPath() == nullptr) {
        ROSEN_LOGE("AniPen::GetFillPath dst path is nullptr");
        return false;
    }
    return aniPen->GetPen()->GetFillPath(*aniSrcPath->GetPath(), *aniDstPath->GetPath(), nullptr, Matrix());
}

void AniPen::SetMiterLimit(ani_env* env, ani_object obj, ani_double miter)
{
    auto aniPen = GetNativeFromObj<AniPen>(env, obj);
    if (aniPen == nullptr || aniPen->GetPen() == nullptr) {
        ThrowBusinessError(env, DrawingErrorCode::ERROR_INVALID_PARAM, "AniPen::SetMiterLimit aniPen is nullptr.");
        return;
    }
    aniPen->GetPen()->SetMiterLimit(miter);
}

ani_enum_item AniPen::GetCapStyle(ani_env* env, ani_object obj)
{
    ani_enum_item value = nullptr;
    auto aniPen = GetNativeFromObj<AniPen>(env, obj);
    if (aniPen == nullptr || aniPen->GetPen() == nullptr) {
        ThrowBusinessError(env, DrawingErrorCode::ERROR_INVALID_PARAM, "AniPen::SetMiterLimit aniPen is nullptr.");
        return value;
    }
    ani_enum enumType;
    if (ANI_OK != env->FindEnum(ANI_CLASS_CAP_STYLE_NAME, &enumType)) {
        ROSEN_LOGE("AniPen::GetCapStyle failed cause by FindEnum");
        return value;
    }
    Pen::CapStyle capStyle = aniPen->GetPen()->GetCapStyle();
    env->Enum_GetEnumItemByIndex(enumType, static_cast<ani_size>(CapCastToTsCap(capStyle)), &value);
    return value;
}

ani_boolean AniPen::IsAntiAlias(ani_env* env, ani_object obj)
{
    auto aniPen = GetNativeFromObj<AniPen>(env, obj);
    if (aniPen == nullptr || aniPen->GetPen() == nullptr) {
        ThrowBusinessError(env, DrawingErrorCode::ERROR_INVALID_PARAM, "AniPen::IsAntiAlias aniPen is nullptr.");
        return false;
    }
    return aniPen->GetPen()->IsAntiAlias();
}

ani_object AniPen::GetColor(ani_env* env, ani_object obj)
{
    auto aniPen = GetNativeFromObj<AniPen>(env, obj);
    if (aniPen == nullptr || aniPen->GetPen() == nullptr) {
        ThrowBusinessError(env, DrawingErrorCode::ERROR_INVALID_PARAM, "AniPen::GetColor aniPen is nullptr.");
        return CreateAniUndefined(env);
    }
    Color color = aniPen->GetPen()->GetColor();
    ani_object colorObj = nullptr;
    CreateColorObj(env, color, colorObj);
    return colorObj;
}

void AniPen::SetJoinStyle(ani_env* env, ani_object obj, ani_enum_item aniJoinStyle)
{
    auto aniPen = GetNativeFromObj<AniPen>(env, obj);
    if (aniPen == nullptr || aniPen->GetPen() == nullptr) {
        ThrowBusinessError(env, DrawingErrorCode::ERROR_INVALID_PARAM, "AniPen::SetJoinStyle aniPen is nullptr.");
        return;
    }
    ani_int joinStyle;
    if (ANI_OK != env->EnumItem_GetValue_Int(aniJoinStyle, &joinStyle)) {
        ThrowBusinessError(env, DrawingErrorCode::ERROR_INVALID_PARAM,
            "AniPen::SetJoinStyle get JoinStyle enum failed.");
        return;
    }
    aniPen->GetPen()->SetJoinStyle(static_cast<Pen::JoinStyle>(joinStyle));
}

ani_enum_item AniPen::GetJoinStyle(ani_env* env, ani_object obj)
{
    ani_enum_item value = nullptr;
    auto aniPen = GetNativeFromObj<AniPen>(env, obj);
    if (aniPen == nullptr || aniPen->GetPen() == nullptr) {
        ThrowBusinessError(env, DrawingErrorCode::ERROR_INVALID_PARAM, "AniPen::GetJoinStyle aniPen is nullptr.");
        return value;
    }
    ani_enum enumType;
    if (ANI_OK != env->FindEnum(ANI_CLASS_JOIN_STYLE_NAME, &enumType)) {
        ROSEN_LOGE(" AniPen::GetJoinStyle failed cause by FindEnum");
        return value;
    }
    env->Enum_GetEnumItemByIndex(enumType, static_cast<ani_size>(aniPen->GetPen()->GetJoinStyle()), &value);
    return value;
}

ani_double AniPen::GetWidth(ani_env* env, ani_object obj)
{
    auto aniPen = GetNativeFromObj<AniPen>(env, obj);
    if (aniPen == nullptr || aniPen->GetPen() == nullptr) {
        ThrowBusinessError(env, DrawingErrorCode::ERROR_INVALID_PARAM, "AniPen::GetWidth aniPen is nullptr.");
        return -1;
    }
    return aniPen->GetPen()->GetWidth();
}

ani_double AniPen::GetMiterLimit(ani_env* env, ani_object obj)
{
    auto aniPen = GetNativeFromObj<AniPen>(env, obj);
    if (aniPen == nullptr || aniPen->GetPen() == nullptr) {
        ThrowBusinessError(env, DrawingErrorCode::ERROR_INVALID_PARAM, "AniPen::GetMiterLimit aniPen is nullptr.");
        return -1;
    }
    return aniPen->GetPen()->GetMiterLimit();
}

void AniPen::SetPathEffect(ani_env* env, ani_object obj, ani_object aniPathEffectObj)
{
    auto aniPen = GetNativeFromObj<AniPen>(env, obj);
    if (aniPen == nullptr || aniPen->GetPen() == nullptr) {
        ThrowBusinessError(env, DrawingErrorCode::ERROR_INVALID_PARAM, "AniPen::SetPathEffect aniPen is nullptr.");
        return;
    }
    ani_boolean isNull = ANI_TRUE;
    env->Reference_IsNull(aniPathEffectObj, &isNull);
    AniPathEffect* aniPathEffect = nullptr;
    if (!isNull) {
        aniPathEffect = GetNativeFromObj<AniPathEffect>(env, aniPathEffectObj);
        if (aniPathEffect == nullptr) {
            ThrowBusinessError(env, DrawingErrorCode::ERROR_INVALID_PARAM, "Invalid param pathEffect.");
            return;
        }
    }
    aniPen->GetPen()->SetPathEffect(aniPathEffect ? aniPathEffect->GetPathEffect() : nullptr);
}

void AniPen::SetImageFilter(ani_env* env, ani_object obj, ani_object aniImageFilterObj)
{
    auto aniPen = GetNativeFromObj<AniPen>(env, obj);
    if (aniPen == nullptr || aniPen->GetPen() == nullptr) {
        ThrowBusinessError(env, DrawingErrorCode::ERROR_INVALID_PARAM, "AniPen::SetImageFilter aniPen is nullptr.");
        return;
    }
    ani_boolean isNull = ANI_TRUE;
    env->Reference_IsNull(aniImageFilterObj, &isNull);
    AniImageFilter* aniImageFilter = nullptr;
    if (!isNull) {
        aniImageFilter = GetNativeFromObj<AniImageFilter>(env, aniImageFilterObj);
        if (aniImageFilter == nullptr) {
            ThrowBusinessError(env, DrawingErrorCode::ERROR_INVALID_PARAM, "Invalid param imageFilter.");
            return;
        }
    }
    Filter filter = aniPen->GetPen()->GetFilter();
    filter.SetImageFilter(aniImageFilter ? aniImageFilter->GetImageFilter() : nullptr);
    aniPen->GetPen()->SetFilter(filter);
}

void AniPen::SetMaskFilter(ani_env* env, ani_object obj, ani_object aniMaskFilterObj)
{
    auto aniPen = GetNativeFromObj<AniPen>(env, obj);
    if (aniPen == nullptr) {
        ThrowBusinessError(env, DrawingErrorCode::ERROR_INVALID_PARAM, "AniPen::SetMaskFilter aniPen is nullptr.");
        return;
    }
    ani_boolean isNull = ANI_TRUE;
    env->Reference_IsNull(aniMaskFilterObj, &isNull);
    AniMaskFilter* aniMaskFilter = nullptr;
    if (!isNull) {
        aniMaskFilter = GetNativeFromObj<AniMaskFilter>(env, aniMaskFilterObj);
        if (aniMaskFilter == nullptr) {
            ThrowBusinessError(env, DrawingErrorCode::ERROR_INVALID_PARAM, "Invalid param maskFilter.");
            return;
        }
    }
    Filter filter = aniPen->GetPen()->GetFilter();
    filter.SetMaskFilter(aniMaskFilter ? aniMaskFilter->GetMaskFilter() : nullptr);
    aniPen->GetPen()->SetFilter(filter);
}

void AniPen::SetShadowLayer(ani_env* env, ani_object obj, ani_object aniShadowLayerObj)
{
    auto aniPen = GetNativeFromObj<AniPen>(env, obj);
    if (aniPen == nullptr || aniPen->GetPen() == nullptr) {
        ThrowBusinessError(env, DrawingErrorCode::ERROR_INVALID_PARAM, "AniPen::SetShadowLayer aniPen is nullptr.");
        return;
    }
    ani_boolean isNull = ANI_TRUE;
    env->Reference_IsNull(aniShadowLayerObj, &isNull);
    AniShadowLayer* aniShadowLayer = nullptr;
    if (!isNull) {
        aniShadowLayer = GetNativeFromObj<AniShadowLayer>(env, aniShadowLayerObj);
        if (aniShadowLayer == nullptr) {
            ThrowBusinessError(env, DrawingErrorCode::ERROR_INVALID_PARAM, "Invalid param shadowLayer.");
            return;
        }
    }
    aniPen->GetPen()->SetLooper(aniShadowLayer ? aniShadowLayer->GetBlurDrawLooper() : nullptr);
}

void AniPen::SetShaderEffect(ani_env* env, ani_object obj, ani_object aniShaderEffectObj)
{
    auto aniPen = GetNativeFromObj<AniPen>(env, obj);
    if (aniPen == nullptr || aniPen->GetPen() == nullptr) {
        ThrowBusinessError(env, DrawingErrorCode::ERROR_INVALID_PARAM, "AniPen::SetShaderEffect aniPen is nullptr.");
        return;
    }
    ani_boolean isNull = ANI_TRUE;
    env->Reference_IsNull(aniShaderEffectObj, &isNull);
    AniShaderEffect* aniShaderEffect = nullptr;
    if (!isNull) {
        aniShaderEffect = GetNativeFromObj<AniShaderEffect>(env, aniShaderEffectObj);
        if (aniShaderEffect == nullptr) {
            ThrowBusinessError(env, DrawingErrorCode::ERROR_INVALID_PARAM, "Invalid param shaderEffect.");
            return;
        }
    }
    aniPen->GetPen()->SetShaderEffect(aniShaderEffect ? aniShaderEffect->GetShaderEffect() : nullptr);
}

ani_object AniPen::PenTransferStatic(ani_env* env, [[maybe_unused]]ani_object obj, ani_object output, ani_object input)
{
    void* unwrapResult = nullptr;
    bool success = arkts_esvalue_unwrap(env, input, &unwrapResult);
    if (!success) {
        ROSEN_LOGE("AniPen::PenTransferStatic failed to unwrap");
        return nullptr;
    }
    if (unwrapResult == nullptr) {
        ROSEN_LOGE("AniPen::PenTransferStatic unwrapResult is null");
        return nullptr;
    }
    auto jsPen = reinterpret_cast<JsPen*>(unwrapResult);
    if (jsPen->GetPen() == nullptr) {
        ROSEN_LOGE("AniPen::PenTransferStatic jsPen is null");
        return nullptr;
    }

    auto aniPen = new AniPen(jsPen->GetPen());
    if (ANI_OK != env->Object_SetFieldByName_Long(output, NATIVE_OBJ, reinterpret_cast<ani_long>(aniPen))) {
        ROSEN_LOGE("AniPen::PenTransferStatic failed create aniPen");
        delete aniPen;
        return nullptr;
    }
    return output;
}

ani_long AniPen::GetPenAddr(ani_env* env, [[maybe_unused]]ani_object obj, ani_object input)
{
    auto aniPen = GetNativeFromObj<AniPen>(env, input);
    if (aniPen == nullptr || aniPen->GetPen() == nullptr) {
        ROSEN_LOGE("AniPen::GetPenAddr aniPen is null");
        return 0;
    }
    return reinterpret_cast<ani_long>(aniPen->GetPenPtrAddr());
}

std::shared_ptr<Pen>* AniPen::GetPenPtrAddr()
{
    return &pen_;
}

AniPen::~AniPen()
{
    pen_ = nullptr;
}

std::shared_ptr<Pen> AniPen::GetPen()
{
    return pen_;
}
} // namespace Drawing
} // namespace OHOS::Rosen