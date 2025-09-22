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

#include "ani_text_rect_converter.h"

#include <cstddef>

#include "ani_common.h"
#include "ani_drawing_utils.h"
#include "ani_text_utils.h"

namespace OHOS::Text::ANI {
using namespace OHOS::Rosen;
ani_status AniTextRectConverter::ParseRangeToNative(ani_env* env, ani_object obj, RectRange& rectRange)
{
    ani_class cls = nullptr;
    ani_status ret = AniTextUtils::FindClassWithCache(env, ANI_INTERFACE_RANGE, cls);
    if (ret != ANI_OK) {
        TEXT_LOGE("Failed to find class, ret %{public}d", ret);
        return ret;
    }
    ani_boolean isObj = false;
    ret = env->Object_InstanceOf(obj, cls, &isObj);
    if (!isObj || ret != ANI_OK) {
        TEXT_LOGE("Object mismatch:%{public}d", ret);
        return ret;
    }
    ani_int startTmp = 0;
    ret = env->Object_GetPropertyByName_Int(obj, "start", &startTmp);
    if (ret != ANI_OK) {
        TEXT_LOGE("Failed to get start, ret %{public}d", ret);
        return ANI_INVALID_ARGS;
    }
    ani_int endTmp = 0;
    ret = env->Object_GetPropertyByName_Int(obj, "end", &endTmp);
    if (ret != ANI_OK) {
        TEXT_LOGE("Failed to get end, ret %{public}d", ret);
        return ANI_INVALID_ARGS;
    }
    rectRange.start = static_cast<size_t>(startTmp);
    rectRange.end = static_cast<size_t>(endTmp);
    return ANI_OK;
}

ani_status AniTextRectConverter::ParseWidthStyleToNative(
    ani_env* env, ani_object obj, OHOS::Rosen::TextRectWidthStyle& widthStyle)
{
    ani_size index = 0;
    ani_status result = env->EnumItem_GetIndex(static_cast<ani_enum_item>(obj), &index);
    if (result != ANI_OK) {
        TEXT_LOGE("Failed to enum widthStyle, ret %{public}d", result);
        return result;
    }
    widthStyle = static_cast<TextRectWidthStyle>(index);
    return ANI_OK;
}

ani_status AniTextRectConverter::ParseHeightStyleToNative(
    ani_env* env, ani_object obj, OHOS::Rosen::TextRectHeightStyle& heightStyle)
{
    ani_size index = 0;
    ani_status result = env->EnumItem_GetIndex(static_cast<ani_enum_item>(obj), &index);
    if (result != ANI_OK) {
        TEXT_LOGE("Failed to enum heightStyle, ret %{public}d", result);
        return result;
    }
    heightStyle = static_cast<TextRectHeightStyle>(index);
    return ANI_OK;
}

ani_status AniTextRectConverter::ParseTextBoxToAni(
    ani_env* env, const OHOS::Rosen::TextRect& textRect, ani_object& aniObj)
{
    ani_object rectObj = nullptr;
    ani_status ret = AniDrawingConverter::ParseRectToAni(env, textRect.rect, rectObj);
    if (ret != ANI_OK) {
        TEXT_LOGE("Failed to parse rect to ani, ret %{public}d", ret);
        rectObj = AniTextUtils::CreateAniUndefined(env);
    }

    static std::string sign = std::string(ANI_INTERFACE_RECT) + std::string(ANI_ENUM_TEXT_DIRECTION) + ":V";
    aniObj = AniTextUtils::CreateAniObject(env, ANI_CLASS_TEXT_BOX, sign.c_str(),
        rectObj,
        AniTextUtils::CreateAniEnum(env, ANI_ENUM_TEXT_DIRECTION, static_cast<int>(textRect.direction))
    );
    return ANI_OK;
}

ani_status AniTextRectConverter::ParseBoundaryToAni(
    ani_env* env, const OHOS::Rosen::Boundary& boundary, ani_object& aniObj)
{
    aniObj = AniTextUtils::CreateAniObject(env, ANI_CLASS_RANGE, "II:V",
        ani_int(boundary.leftIndex),
        ani_int(boundary.rightIndex)
    );
    return ANI_OK;
}
} // namespace OHOS::Text::ANI