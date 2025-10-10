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

#include "ani_rect_utils.h"

namespace OHOS::Rosen {
namespace Drawing {
const char* ANI_CLASS_RECT_UTILS_NAME = "@ohos.graphics.drawing.drawing.RectUtils;";

ani_status AniRectUtils::AniInit(ani_env *env)
{
    ani_class cls = nullptr;
    ani_status ret = env->FindClass(ANI_CLASS_RECT_UTILS_NAME, &cls);
    if (ret != ANI_OK) {
        ROSEN_LOGE("[ANI] can't find class: %{public}s", ANI_CLASS_RECT_UTILS_NAME);
        return ANI_NOT_FOUND;
    }

    std::array methods = {
        ani_native_function { "contains", nullptr, reinterpret_cast<void*>(Contains) },
        ani_native_function { "inset", nullptr, reinterpret_cast<void*>(Inset) },
    };

    ret = env->Class_BindStaticNativeMethods(cls, methods.data(), methods.size());
    if (ret != ANI_OK) {
        ROSEN_LOGE("[ANI] bind methods fail: %{public}s", ANI_CLASS_RECT_UTILS_NAME);
        return ANI_NOT_FOUND;
    }

    return ANI_OK;
}

ani_boolean AniRectUtils::Contains(ani_env* env, ani_object obj, ani_object aniRectObj, ani_object aniOtherRect)
{
    Drawing::Rect drawingRect;
    if (!GetRectFromAniRectObj(env, aniRectObj, drawingRect)) {
        AniThrowError(env, "AniRectUtils::Contains invalid params: aniRectObj. ");
        return false;
    }
    Drawing::Rect otherRect;
    if (!GetRectFromAniRectObj(env, aniOtherRect, otherRect)) {
        AniThrowError(env, "AniRectUtils::Contains invalid params: aniOtherRect. ");
        return false;
    }
    bool isContains = drawingRect.Contains(otherRect);
    return isContains;
}

void AniRectUtils::Inset(ani_env* env, ani_object obj, ani_object aniRectObj,
    ani_double left, ani_double top, ani_double right, ani_double bottom)
{
    Drawing::Rect drawingRect;
    if (!GetRectFromAniRectObj(env, aniRectObj, drawingRect)) {
        AniThrowError(env, "AniRectUtils::Inset invalid params: aniRectObj. ");
    }

    float originalLeft = drawingRect.GetLeft();
    float originalTop = drawingRect.GetTop();
    float originalRight = drawingRect.GetRight();
    float originalBottom = drawingRect.GetBottom();
    drawingRect.SetLeft(originalLeft + left);
    drawingRect.SetTop(originalTop + top);
    drawingRect.SetRight(originalRight - right);
    drawingRect.SetBottom(originalBottom - bottom);
    env->Object_SetPropertyByName_Double(aniRectObj, "left", drawingRect.GetLeft());
    env->Object_SetPropertyByName_Double(aniRectObj, "top", drawingRect.GetTop());
    env->Object_SetPropertyByName_Double(aniRectObj, "right", drawingRect.GetRight());
    env->Object_SetPropertyByName_Double(aniRectObj, "bottom", drawingRect.GetBottom());
}
} // namespace Drawing
} // namespace OHOS::Rosen