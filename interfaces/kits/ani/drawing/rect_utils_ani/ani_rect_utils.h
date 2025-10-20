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

#ifndef OHOS_ROSEN_ANI_RECT_UTILS_H
#define OHOS_ROSEN_ANI_RECT_UTILS_H

#include "ani_drawing_utils.h"

namespace OHOS::Rosen {
namespace Drawing {
class AniRectUtils final {
public:
    AniRectUtils() = default;
    ~AniRectUtils() = default;

    static ani_status AniInit(ani_env *env);

    static ani_boolean Contains(ani_env* env, ani_object obj, ani_object aniRectObj, ani_object aniOtherRect);
    static void Inset(ani_env* env, ani_object obj, ani_object aniRectObj,
        ani_double left, ani_double top, ani_double right, ani_double bottom);
    static void Sort(ani_env* env, ani_object obj, ani_object aniRectObj);
    static ani_boolean IsEqual(ani_env* env, ani_object obj, ani_object aniRectObj, ani_object aniOtherRect);
    static ani_double GetHeight(ani_env* env, ani_object obj, ani_object aniRectObj);
    static ani_double GetWidth(ani_env* env, ani_object obj, ani_object aniRectObj);
    static ani_boolean IsEmpty(ani_env* env, ani_object obj, ani_object aniRectObj);
    static ani_boolean Intersect(ani_env* env, ani_object obj, ani_object aniRectObj, ani_object aniOtherRect);
    static void Offset(ani_env* env, ani_object obj, ani_object aniRectObj, ani_double dx, ani_double dy);
};
} // namespace Drawing
} // namespace OHOS::Rosen
#endif // OHOS_ROSEN_ANI_RECT_UTILS_H