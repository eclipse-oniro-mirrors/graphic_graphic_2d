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

#include "ani_color_filter.h"
#include "draw/color.h"

namespace OHOS::Rosen {
namespace Drawing {

const char* ANI_CLASS_COLORFILTER_NAME = "L@ohos/graphics/drawing/drawing/ColorFilter;";

ani_status AniColorFilter::AniInit(ani_env *env)
{
    ani_class cls = nullptr;
    ani_status ret = env->FindClass(ANI_CLASS_COLORFILTER_NAME, &cls);
    if (ret != ANI_OK) {
        ROSEN_LOGE("[ANI] can't find class: %{public}s", ANI_CLASS_COLORFILTER_NAME);
        return ANI_NOT_FOUND;
    }

    std::array methods = {
        ani_native_function { "createBlendModeColorFilter", nullptr,
            reinterpret_cast<void*>(CreateBlendModeColorFilter) },
    };

    ret = env->Class_BindNativeMethods(cls, methods.data(), methods.size());
    if (ret != ANI_OK) {
        ROSEN_LOGE("[ANI] bind methods fail: %{public}s", ANI_CLASS_COLORFILTER_NAME);
        return ANI_NOT_FOUND;
    }

    return ANI_OK;
}


AniColorFilter::~AniColorFilter()
{
    m_ColorFilter = nullptr;
}

ani_object AniColorFilter::CreateBlendModeColorFilter(
    ani_env* env, [[maybe_unused]] ani_object obj, ani_object objColor, ani_enum_item aniBlendMode)
{
    ColorQuad color;
    if (!GetColorQuadFromParam(env, objColor, color)) {
        ROSEN_LOGE("AniColorFilter::CreateBlendModeColorFilter failed cause by colorObj");
        AniThrowError(env, "Invalid params. "); // message length must be a multiple of 4, for example 16, 20, etc
        return CreateAniUndefined(env);
    }

    ani_int blendMode;
    if (ANI_OK != env->EnumItem_GetValue_Int(aniBlendMode, &blendMode)) {
        ROSEN_LOGE("AniColorFilter::CreateBlendModeColorFilter failed cause by blendMode");
        AniThrowError(env, "Invalid params. "); // message length must be a multiple of 4, for example 16, 20, etc
        return CreateAniUndefined(env);
    }

    AniColorFilter* colorFilter = new AniColorFilter(
        ColorFilter::CreateBlendModeColorFilter(color, static_cast<BlendMode>(blendMode)));
    ani_object aniObj = CreateAniObject(env, ANI_CLASS_COLORFILTER_NAME, nullptr);
    if (ANI_OK != env->Object_SetFieldByName_Long(aniObj,
        NATIVE_OBJ, reinterpret_cast<ani_long>(colorFilter))) {
        ROSEN_LOGE("AniColorFilter::CreateBlendModeColorFilter failed cause by Object_SetFieldByName_Long");
        delete colorFilter;
        return CreateAniUndefined(env);
    }
    return aniObj;
}

std::shared_ptr<ColorFilter> AniColorFilter::GetColorFilter()
{
    return m_ColorFilter;
}
} // namespace Drawing
} // namespace OHOS::Rosen
