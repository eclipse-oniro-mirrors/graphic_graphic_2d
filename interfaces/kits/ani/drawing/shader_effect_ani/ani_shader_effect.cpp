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

#include "ani_shader_effect.h"
#include "matrix_ani/ani_matrix.h"

namespace OHOS::Rosen {
namespace Drawing {
const char* ANI_CLASS_SHADER_EFFECT_NAME = "@ohos.graphics.drawing.drawing.ShaderEffect";

ani_status AniShaderEffect::AniInit(ani_env *env)
{
    ani_class cls = nullptr;
    ani_status ret = env->FindClass(ANI_CLASS_SHADER_EFFECT_NAME, &cls);
    if (ret != ANI_OK) {
        ROSEN_LOGE("[ANI] can't find class: %{public}s", ANI_CLASS_SHADER_EFFECT_NAME);
        return ANI_NOT_FOUND;
    }

    std::array methods = {
        ani_native_function { "createColorShader", "i:C{@ohos.graphics.drawing.drawing.ShaderEffect}",
            reinterpret_cast<void*>(CreateColorShader) },
        ani_native_function { "createLinearGradient", nullptr,
            reinterpret_cast<void*>(CreateLinearGradient) },
        ani_native_function { "createConicalGradient", nullptr, reinterpret_cast<void*>(CreateConicalGradient) },
        ani_native_function { "createSweepGradient", nullptr, reinterpret_cast<void*>(CreateSweepGradient) },
        ani_native_function { "createRadialGradient", nullptr, reinterpret_cast<void*>(CreateRadialGradient) },
    };

    ret = env->Class_BindStaticNativeMethods(cls, methods.data(), methods.size());
    if (ret != ANI_OK) {
        ROSEN_LOGE("[ANI] bind methods fail: %{public}s", ANI_CLASS_SHADER_EFFECT_NAME);
        return ANI_NOT_FOUND;
    }

    return ANI_OK;
}

bool GetColorsArray(ani_env* env, ani_object corlorsArray, std::vector<ColorQuad>& colors)
{
    ani_int aniLength;
    if (ANI_OK != env->Object_GetPropertyByName_Int(corlorsArray, "length", &aniLength)) {
        ROSEN_LOGE("colors are invalid");
        return false;
    }
    uint32_t colorsSize = static_cast<uint32_t>(aniLength);
    colors.reserve(colorsSize);
    for (uint32_t i = 0; i < colorsSize; i++) {
        ani_int color;
        ani_ref colorRef;
        if (ANI_OK != env->Object_CallMethodByName_Ref(corlorsArray,
            "$_get", "i:C{std.core.Object}", &colorRef, (ani_int)i) ||
            ANI_OK != env->Object_CallMethodByName_Int(static_cast<ani_object>(colorRef), "toInt", ":i", &color)) {
            ROSEN_LOGE("get color ref failed.");
            return false;
        }
        colors.push_back(static_cast<Drawing::ColorQuad>(color));
    }
    return true;
}

bool GetPosArray(ani_env* env, ani_object posArray, std::vector<float>& pos)
{
    ani_int aniLength;
    if (ANI_OK != env->Object_GetPropertyByName_Int(posArray, "length", &aniLength)) {
        ROSEN_LOGE("pos are invalid");
        return false;
    }
    uint32_t size = static_cast<uint32_t>(aniLength);
    pos.reserve(size);
    for (uint32_t i = 0; i < size; i++) {
        ani_double value;
        ani_ref posRef;
        if (ANI_OK != env->Object_CallMethodByName_Ref(
            posArray, "$_get", "i:C{std.core.Object}", &posRef, (ani_int)i) ||
            ANI_OK != env->Object_CallMethodByName_Double(static_cast<ani_object>(posRef), "toDouble", ":d", &value)) {
            ROSEN_LOGE("get pos ref failed.");
            return false;
        }
        pos.push_back(static_cast<float>(value));
    }
    return true;
}

bool GetTileMode(ani_env* env, ani_enum_item aniTileMode, TileMode& mode)
{
    ani_int tileMode;
    if (ANI_OK != env->EnumItem_GetValue_Int(aniTileMode, &tileMode)) {
        return false;
    }

    mode = static_cast<TileMode>(tileMode);
    if (mode < TileMode::CLAMP || mode > TileMode::DECAL) {
        return false;
    }
    return true;
}

ani_object AniShaderEffect::CreateAniShaderEffect(ani_env* env, std::shared_ptr<ShaderEffect> shaderEffect)
{
    AniShaderEffect* aniShaderEffect = new AniShaderEffect(shaderEffect);
    ani_object aniObj = CreateAniObjectStatic(env, ANI_CLASS_SHADER_EFFECT_NAME, aniShaderEffect);
    ani_boolean isUndefined = ANI_TRUE;
    env->Reference_IsUndefined(aniObj, &isUndefined);
    if (isUndefined) {
        delete aniShaderEffect;
        ROSEN_LOGE("AniShaderEffect::CreateAniShaderEffect failed cause aniObj is undefined");
    }
    return aniObj;
}

ani_boolean AniShaderEffect::IsReferenceValid(ani_env* env, ani_object obj)
{
    ani_boolean isUndefined = ANI_TRUE;
    ani_boolean isNull = ANI_TRUE;
    env->Reference_IsUndefined(obj, &isUndefined);
    env->Reference_IsNull(obj, &isNull);
    return !isUndefined && !isNull;
}

ani_object AniShaderEffect::CreateColorShader(ani_env* env, ani_object obj, ani_int color)
{
    std::shared_ptr<ShaderEffect> shaderEffect = ShaderEffect::CreateColorShader(color);
    return CreateAniShaderEffect(env, shaderEffect);
}

ani_object AniShaderEffect::CreateLinearGradient(ani_env* env, ani_object obj, ani_object startPt, ani_object endPt,
    ani_object colorsArray, ani_enum_item aniTileMode, ani_object aniPos, ani_object aniMatrix)
{
    Drawing::Point startPoint;
    if (GetPointFromPointObj(env, startPt, startPoint) != ANI_OK) {
        ThrowBusinessError(env, DrawingErrorCode::ERROR_INVALID_PARAM,
            "AniShaderEffect::CreateLinearGradient get startPoint failed.");
        return CreateAniUndefined(env);
    }
    Drawing::Point endPoint;
    if (GetPointFromPointObj(env, endPt, endPoint) != ANI_OK) {
        ThrowBusinessError(env, DrawingErrorCode::ERROR_INVALID_PARAM,
            "AniShaderEffect::CreateLinearGradient get endPoint failed.");
        return CreateAniUndefined(env);
    }
    std::vector<ColorQuad> colors;
    if (!GetColorsArray(env, colorsArray, colors)) {
        ThrowBusinessError(env, DrawingErrorCode::ERROR_INVALID_PARAM,
            "AniShaderEffect::CreateLinearGradient get colorsArray failed.");
        return CreateAniUndefined(env);
    }

    TileMode mode;
    if (!GetTileMode(env, aniTileMode, mode)) {
        ThrowBusinessError(env, DrawingErrorCode::ERROR_INVALID_PARAM,
            "AniShaderEffect::CreateLinearGradient get TileMode enum failed.");
        return CreateAniUndefined(env);
    }

    std::vector<scalar> pos;
    if (IsReferenceValid(env, aniPos)) {
        if (!GetPosArray(env, aniPos, pos)) {
            ThrowBusinessError(env, DrawingErrorCode::ERROR_INVALID_PARAM,
                "AniShaderEffect::CreateLinearGradient get posArray failed.");
            return CreateAniUndefined(env);
        }
    }

    Drawing::Matrix* drawingMatrixPtr = nullptr;
    if (IsReferenceValid(env, aniMatrix)) {
        auto aniMatrixObj = GetNativeFromObj<AniMatrix>(env, aniMatrix);
        if (aniMatrixObj == nullptr) {
            ThrowBusinessError(env, DrawingErrorCode::ERROR_INVALID_PARAM,
                "AniShaderEffect::CreateLinearGradient get matrix failed.");
            return CreateAniUndefined(env);
        }
        drawingMatrixPtr = aniMatrixObj->GetMatrix().get();
    }
    std::shared_ptr<ShaderEffect> shaderEffect =
        ShaderEffect::CreateLinearGradient(startPoint, endPoint, colors, pos, mode, drawingMatrixPtr);
    return CreateAniShaderEffect(env, shaderEffect);
}

ani_object AniShaderEffect::CreateConicalGradient(ani_env* env, ani_object obj, ani_object startPt,
    ani_double startRadius, ani_object endPt, ani_double endRadius, ani_object colorsArray,
    ani_enum_item aniTileMode, ani_object aniPos, ani_object aniMatrix)
{
    Drawing::Point startPoint;
    if (GetPointFromPointObj(env, startPt, startPoint) != ANI_OK) {
        ThrowBusinessError(env, DrawingErrorCode::ERROR_INVALID_PARAM,
            "AniShaderEffect::CreateConicalGradient get startPoint failed.");
        return CreateAniUndefined(env);
    }
    Drawing::Point endPoint;
    if (GetPointFromPointObj(env, endPt, endPoint) != ANI_OK) {
        ThrowBusinessError(env, DrawingErrorCode::ERROR_INVALID_PARAM,
            "AniShaderEffect::CreateConicalGradient get endPoint failed.");
        return CreateAniUndefined(env);
    }
    std::vector<ColorQuad> colors;
    if (!GetColorsArray(env, colorsArray, colors)) {
        ThrowBusinessError(env, DrawingErrorCode::ERROR_INVALID_PARAM,
            "AniShaderEffect::CreateConicalGradient get colorsArray failed.");
        return CreateAniUndefined(env);
    }

    TileMode mode;
    if (!GetTileMode(env, aniTileMode, mode)) {
        ThrowBusinessError(env, DrawingErrorCode::ERROR_INVALID_PARAM,
            "AniShaderEffect::CreateConicalGradient get TileMode enum failed.");
        return CreateAniUndefined(env);
    }

    std::vector<scalar> pos;
    if (IsReferenceValid(env, aniPos)) {
        if (!GetPosArray(env, aniPos, pos)) {
            ThrowBusinessError(env, DrawingErrorCode::ERROR_INVALID_PARAM,
                "AniShaderEffect::CreateConicalGradient get posArray failed.");
            return CreateAniUndefined(env);
        }
    }

    Drawing::Matrix* drawingMatrixPtr = nullptr;
    if (IsReferenceValid(env, aniMatrix)) {
        auto aniMatrixObj = GetNativeFromObj<AniMatrix>(env, aniMatrix);
        if (aniMatrixObj == nullptr) {
            ThrowBusinessError(env, DrawingErrorCode::ERROR_INVALID_PARAM,
                "AniShaderEffect::CreateConicalGradient get matrix failed.");
            return CreateAniUndefined(env);
        }
        drawingMatrixPtr = aniMatrixObj->GetMatrix().get();
    }
    std::shared_ptr<ShaderEffect> shaderEffect = ShaderEffect::CreateTwoPointConical(
        startPoint, startRadius, endPoint, endRadius, colors, pos, mode, drawingMatrixPtr);
    return CreateAniShaderEffect(env, shaderEffect);
}

ani_object AniShaderEffect::CreateSweepGradient(
    ani_env* env, ani_object obj, ani_object centerPt, ani_object colorsArray, ani_enum_item aniTileMode,
    ani_double startAngle, ani_double endAngle, ani_object aniPos, ani_object aniMatrix)
{
    Drawing::Point centerPoint;
    if (GetPointFromPointObj(env, centerPt, centerPoint) != ANI_OK) {
        ThrowBusinessError(env, DrawingErrorCode::ERROR_INVALID_PARAM,
            "AniShaderEffect::CreateSweepGradient get centerPoint failed.");
        return CreateAniUndefined(env);
    }

    std::vector<ColorQuad> colors;
    if (!GetColorsArray(env, colorsArray, colors)) {
        ThrowBusinessError(env, DrawingErrorCode::ERROR_INVALID_PARAM,
            "AniShaderEffect::CreateSweepGradient get colorsArray failed.");
        return CreateAniUndefined(env);
    }

    TileMode mode;
    if (!GetTileMode(env, aniTileMode, mode)) {
        ThrowBusinessError(env, DrawingErrorCode::ERROR_INVALID_PARAM,
            "AniShaderEffect::CreateSweepGradient get TileMode enum failed.");
        return CreateAniUndefined(env);
    }

    std::vector<scalar> pos;
    if (IsReferenceValid(env, aniPos)) {
        if (!GetPosArray(env, aniPos, pos)) {
            ThrowBusinessError(env, DrawingErrorCode::ERROR_INVALID_PARAM,
                "AniShaderEffect::CreateSweepGradient get posArray failed.");
            return CreateAniUndefined(env);
        }
    }

    Drawing::Matrix* drawingMatrixPtr = nullptr;
    if (IsReferenceValid(env, aniMatrix)) {
        auto aniMatrixObj = GetNativeFromObj<AniMatrix>(env, aniMatrix);
        if (aniMatrixObj == nullptr) {
            ThrowBusinessError(env, DrawingErrorCode::ERROR_INVALID_PARAM,
                "AniShaderEffect::CreateSweepGradient get matrix failed.");
            return CreateAniUndefined(env);
        }
        drawingMatrixPtr = aniMatrixObj->GetMatrix().get();
    }
    std::shared_ptr<ShaderEffect> shaderEffect =
       ShaderEffect::CreateSweepGradient(centerPoint, colors, pos, mode, startAngle, endAngle, drawingMatrixPtr);
    return CreateAniShaderEffect(env, shaderEffect);
}

ani_object AniShaderEffect::CreateRadialGradient(ani_env* env, ani_object obj, ani_object centerPt, ani_double radius,
    ani_object colorsArray, ani_enum_item aniTileMode, ani_object aniPos, ani_object aniMatrix)
{
    Drawing::Point centerPoint;
    if (GetPointFromPointObj(env, centerPt, centerPoint) != ANI_OK) {
        ThrowBusinessError(env, DrawingErrorCode::ERROR_INVALID_PARAM,
            "AniShaderEffect::CreateRadialGradient get centerPoint failed.");
        return CreateAniUndefined(env);
    }

    std::vector<ColorQuad> colors;
    if (!GetColorsArray(env, colorsArray, colors)) {
        ThrowBusinessError(env, DrawingErrorCode::ERROR_INVALID_PARAM,
            "AniShaderEffect::CreateRadialGradient get colorsArray failed.");
        return CreateAniUndefined(env);
    }

    TileMode mode;
    if (!GetTileMode(env, aniTileMode, mode)) {
        ThrowBusinessError(env, DrawingErrorCode::ERROR_INVALID_PARAM,
            "AniShaderEffect::CreateRadialGradient get TileMode enum failed.");
        return CreateAniUndefined(env);
    }

    std::vector<scalar> pos;
    if (IsReferenceValid(env, aniPos)) {
        if (!GetPosArray(env, aniPos, pos)) {
            ThrowBusinessError(env, DrawingErrorCode::ERROR_INVALID_PARAM,
                "AniShaderEffect::CreateRadialGradient get posArray failed.");
            return CreateAniUndefined(env);
        }
    }

    Drawing::Matrix* drawingMatrixPtr = nullptr;
    if (IsReferenceValid(env, aniMatrix)) {
        auto aniMatrixObj = GetNativeFromObj<AniMatrix>(env, aniMatrix);
        if (aniMatrixObj == nullptr) {
            ThrowBusinessError(env, DrawingErrorCode::ERROR_INVALID_PARAM,
                "AniShaderEffect::CreateRadialGradient get matrix failed.");
            return CreateAniUndefined(env);
        }
        drawingMatrixPtr = aniMatrixObj->GetMatrix().get();
    }
    std::shared_ptr<ShaderEffect> shaderEffect =
       ShaderEffect::CreateRadialGradient(centerPoint, radius, colors, pos, mode, drawingMatrixPtr);
    return CreateAniShaderEffect(env, shaderEffect);
}


AniShaderEffect::~AniShaderEffect()
{
    shaderEffect_ = nullptr;
}

std::shared_ptr<ShaderEffect> AniShaderEffect::GetShaderEffect()
{
    return shaderEffect_;
}
} // namespace Drawing
} // namespace OHOS::Rosen