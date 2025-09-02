/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#include "ani_drawing_utils.h"

namespace OHOS {
namespace Rosen {
namespace Drawing {

ani_status AniThrowError(ani_env* env, const std::string& message)
{
    ani_class errCls;
    const char* className = "Lescompat/Error;";
    if (ANI_OK != env->FindClass(className, &errCls)) {
        ROSEN_LOGE("Not found %{public}s", className);
        return ANI_ERROR;
    }

    ani_method errCtor;
    if (ANI_OK != env->Class_FindMethod(errCls, "<ctor>", "Lstd/core/String;Lescompat/ErrorOptions;:V", &errCtor)) {
        ROSEN_LOGE("get errCtor Failed %{public}s", className);
        return ANI_ERROR;
    }

    ani_object errObj;
    if (ANI_OK != env->Object_New(errCls, errCtor, &errObj, CreateAniString(env, message), CreateAniUndefined(env))) {
        ROSEN_LOGE("Create Object Failed %{public}s", className);
        return ANI_ERROR;
    }

    env->ThrowError(static_cast<ani_error>(errObj));
    return ANI_OK;
}

ani_status ThrowBusinessError(ani_env* env, DrawingErrorCode errorCode, const char* message)
{
    ani_object aniError;
    ani_status status = CreateBusinessError(env, static_cast<int32_t>(errorCode), message, aniError);
    if (status != ANI_OK) {
        ROSEN_LOGE("Failed to create business, status:%{public}d", static_cast<int32_t>(status));
        return status;
    }
    status = env->ThrowError(static_cast<ani_error>(aniError));
    if (status != ANI_OK) {
        ROSEN_LOGE("Fail to throw err, status:%{public}d", static_cast<int32_t>(status));
        return status;
    }
    return ANI_OK;
}

ani_status CreateBusinessError(ani_env* env, int32_t error, const char* message, ani_object& err)
{
    ani_class aniClass;
    ani_status status = env->FindClass("L@ohos/base/BusinessError;", &aniClass);
    if (status != ANI_OK) {
        ROSEN_LOGE("Failed to find class, status:%{public}d", static_cast<int32_t>(status));
        return status;
    }
    ani_method aniCtor;
    status = env->Class_FindMethod(aniClass, "<ctor>", "Lstd/core/String;Lescompat/ErrorOptions;:V", &aniCtor);
    if (status != ANI_OK) {
        ROSEN_LOGE("Failed to find ctor, status:%{public}d", static_cast<int32_t>(status));
        return status;
    }
    ani_string aniMsg = CreateAniString(env, message);
    status = env->Object_New(aniClass, aniCtor, &err, aniMsg, CreateAniUndefined(env));
    if (status != ANI_OK) {
        ROSEN_LOGE("Failed to new err, status:%{public}d", static_cast<int32_t>(status));
        return status;
    }
    status = env->Object_SetPropertyByName_Double(err, "code", static_cast<ani_int>(error));
    if (status != ANI_OK) {
        ROSEN_LOGE("Failed to set code, status:%{public}d", static_cast<int32_t>(status));
        return status;
    }
    return ANI_OK;
}


bool GetColorQuadFromColorObj(ani_env* env, ani_object obj, Drawing::ColorQuad &color)
{
    ani_class colorClass;
    env->FindClass("L@ohos/graphics/common2D/common2D/Color;", &colorClass);
    ani_boolean isColorClass;
    env->Object_InstanceOf(obj, colorClass, &isColorClass);

    if (!isColorClass) {
        return false;
    }
    
    ani_int alpha;
    ani_int red;
    ani_int green;
    ani_int blue;

    if ((env->Object_GetPropertyByName_Int(obj, "alpha", &alpha) != ANI_OK) ||
        (env->Object_GetPropertyByName_Int(obj, "red", &red) != ANI_OK) ||
        (env->Object_GetPropertyByName_Int(obj, "green", &green) != ANI_OK) ||
        (env->Object_GetPropertyByName_Int(obj, "blue", &blue) != ANI_OK)) {
        ROSEN_LOGE("GetColorQuadFromParam failed by Color class");
        return false;
    }

    if (alpha < 0 || alpha > Color::RGB_MAX ||
        red < 0 || red > Color::RGB_MAX ||
        green < 0 || green > Color::RGB_MAX ||
        blue < 0 || blue > Color::RGB_MAX) {
        ROSEN_LOGE("GetColorQuadFromParam failed by Color class invaild value");
        return false;
    }

    color = Color::ColorQuadSetARGB(static_cast<uint32_t>(alpha), static_cast<uint32_t>(red),
        static_cast<uint32_t>(green), static_cast<uint32_t>(blue));
    return true;
}

bool GetColorQuadFromParam(ani_env* env, ani_object obj, Drawing::ColorQuad &color)
{
    ani_class doubleClass;
    env->FindClass("Lstd/core/Double;", &doubleClass);
    
    ani_boolean isNumber;
    env->Object_InstanceOf(obj, doubleClass, &isNumber);
    if (isNumber) {
        ani_double aniColor;
        if (ANI_OK != env->Object_CallMethodByName_Double(obj, "unboxed", nullptr, &aniColor)) {
            ROSEN_LOGE("GetColorQuadFromParam failed by double vaule");
            return false;
        }
        color = static_cast<ColorQuad>(aniColor);
        return true;
    }

    return GetColorQuadFromColorObj(env, obj, color);
}

ani_status CreateColorObj(ani_env* env, const Drawing::Color& color, ani_object& obj)
{
    obj = CreateAniObject(env, "L@ohos/graphics/common2D/common2D/ColorInternal;", "IIII:V",
        ani_int(color.GetAlpha()),
        ani_int(color.GetRed()),
        ani_int(color.GetGreen()),
        ani_int(color.GetBlue())
    );
    return ANI_OK;
}

bool GetRectFromAniRectObj(ani_env* env, ani_object obj, Drawing::Rect& rect)
{
    ani_class rectClass;
    env->FindClass("L@ohos/graphics/common2D/common2D/Rect;", &rectClass);
    ani_boolean isRectClass;
    env->Object_InstanceOf(obj, rectClass, &isRectClass);

    if (!isRectClass) {
        return false;
    }

    ani_double left;
    ani_double top;
    ani_double right;
    ani_double bottom;

    if ((env->Object_GetPropertyByName_Double(obj, "left", &left) != ANI_OK) ||
        (env->Object_GetPropertyByName_Double(obj, "top", &top) != ANI_OK) ||
        (env->Object_GetPropertyByName_Double(obj, "right", &right) != ANI_OK) ||
        (env->Object_GetPropertyByName_Double(obj, "bottom", &bottom) != ANI_OK)) {
        ROSEN_LOGE("GetRectFromAniRectObj failed");
        return false;
    }

    rect.SetLeft(left);
    rect.SetTop(top);
    rect.SetRight(right);
    rect.SetBottom(bottom);
    return true;
}

ani_status CreateRectObj(ani_env* env, const Drawing::Rect& rect, ani_object& obj)
{
    obj = CreateAniObject(env, "L@ohos/graphics/common2D/common2D/RectInternal;", "DDDD:V",
        ani_double(rect.left_),
        ani_double(rect.top_),
        ani_double(rect.right_),
        ani_double(rect.bottom_)
    );
    return ANI_OK;
}

ani_status GetPointFromPointObj(ani_env* env, ani_object obj, Drawing::Point& point)
{
    ani_double x = 0;
    ani_status ret = env->Object_GetPropertyByName_Double(obj, "x", &x);
    if (ret != ANI_OK) {
        ROSEN_LOGE("Param x is invalid, ret %{public}d", ret);
        return ret;
    }

    ani_double y = 0;
    ret = env->Object_GetPropertyByName_Double(obj, "y", &y);
    if (ret != ANI_OK) {
        ROSEN_LOGE("Param y is invalid, ret %{public}d", ret);
        return ret;
    }
    point.SetX(x);
    point.SetY(y);
    return ret;
}

ani_status CreatePointObj(ani_env* env, const Drawing::Point& point, ani_object& obj)
{
    obj = CreateAniObject(env, "L@ohos/graphics/common2D/common2D/PointInternal;", "DD:V",
        ani_double(point.GetX()),
        ani_double(point.GetY())
    );
    return ANI_OK;
}

ani_object CreateAniUndefined(ani_env* env)
{
    ani_ref aniRef;
    env->GetUndefined(&aniRef);
    return static_cast<ani_object>(aniRef);
}

ani_object CreateAniObject(ani_env* env, const char* className, const char* methodSig, ...)
{
    ani_class aniClass;
    if (env->FindClass(className, &aniClass) != ANI_OK) {
        ROSEN_LOGE("[Drawing] CreateAniObject FindClass failed");
        return CreateAniUndefined(env);
    }

    ani_method aniConstructor;
    if (env->Class_FindMethod(aniClass, "<ctor>", methodSig, &aniConstructor) != ANI_OK) {
        ROSEN_LOGE("[Drawing] CreateAniObject Class_FindMethod failed");
        return CreateAniUndefined(env);
    }

    ani_object aniObject;
    va_list args;
    va_start(args, methodSig);
    if (env->Object_New_V(aniClass, aniConstructor, &aniObject, args) != ANI_OK) {
        ROSEN_LOGE("[Drawing] CreateAniObject Object_New failed");
        va_end(args);
        return CreateAniUndefined(env);
    }
    va_end(args);

    return aniObject;
}
} // namespace Drawing
} // namespace Rosen
} // namespace OHOS