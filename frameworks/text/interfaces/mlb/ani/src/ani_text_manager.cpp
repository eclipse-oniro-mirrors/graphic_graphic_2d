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
#include <ani.h>

#include "ani_common.h"
#include "ani_font_collection.h"
#include "ani_paragraph.h"
#include "ani_paragraph_builder.h"
#include "ani_text_utils.h"
#include "utils/text_log.h"

namespace OHOS::Text::ANI {
#define STRUCT_LIST(...) using AniTypes = std::tuple<__VA_ARGS__>

// add new struct in this macro
STRUCT_LIST(AniFontCollection, AniParagraph, AniParagraphBuilder);

template <typename T>
static ani_status InitOneStruct(ani_vm* vm, uint32_t* result)
{
    return T::AniInit(vm, result);
}

template <typename Tuple, size_t... Is>
static ani_status InitAllStruct(ani_vm* vm, uint32_t* result, std::index_sequence<Is...>)
{
    ani_status ret;
    [[maybe_unused]] bool _ = (((ret = InitOneStruct<std::tuple_element_t<Is, Tuple>>(vm, result)) == ANI_OK) && ...);
    return ret;
}

template <typename T>
void SafeDelete(ani_long& ptr)
{
    if (ptr != 0) {
        T* pointer = reinterpret_cast<T*>(ptr);
        delete pointer;
        pointer = nullptr;
        ptr = 0;
    }
}

static void Clean(ani_env* env, ani_object object)
{
    ani_long ptr;
    ani_status ret = env->Object_GetFieldByName_Long(object, "ptr", &ptr);
    if (ret != ANI_OK) {
        return;
    }
    ani_ref stringRef = nullptr;
    ret = env->Object_GetFieldByName_Ref(object, "className", &stringRef);
    if (ret != ANI_OK) {
        return;
    }

    std::string familyName;
    ret = AniTextUtils::AniToStdStringUtf8(env, reinterpret_cast<ani_string>(stringRef), familyName);
    if (ret != ANI_OK) {
        return;
    }
    using DeleteFunc = void (*)(ani_long&);
    static const std::unordered_map<std::string, DeleteFunc> deleteMap = {
        {"ParagraphBuilder", SafeDelete<AniParagraphBuilder>}, {"Paragraph", SafeDelete<AniParagraph>},
        {"FontCollection", SafeDelete<AniFontCollection>}};

    if (deleteMap.count(familyName)) {
        TEXT_LOGE("[ANI] clean %{public}s", familyName.c_str());
        deleteMap.at(familyName)(ptr);
    }
}

static ani_status AniCleanerInit(ani_vm* vm)
{
    ani_env* env;
    ani_status ret = vm->GetEnv(ANI_VERSION_1, &env);
    if (ret != ANI_OK) {
        TEXT_LOGE("[ANI] AniCleaner null env, ret %{public}d", ret);
        return ANI_NOT_FOUND;
    }

    ani_class cls = nullptr;
    ret = env->FindClass(ANI_CLASS_CLEANER, &cls);
    if (ret != ANI_OK) {
        TEXT_LOGE("[ANI] AniCleaner can't find class, ret %{public}d", ret);
        return ANI_NOT_FOUND;
    }

    std::array methods = {
        ani_native_function{"clean", ":V", reinterpret_cast<void*>(Clean)},
    };

    ret = env->Class_BindNativeMethods(cls, methods.data(), methods.size());
    if (ret != ANI_OK) {
        TEXT_LOGE("[ANI] AniCleaner bind methods fail, ret %{public}d", ret);
        return ANI_NOT_FOUND;
    }
    return ANI_OK;
}

static ani_status Init(ani_vm* vm, uint32_t* result)
{
    AniCleanerInit(vm);
    return InitAllStruct<AniTypes>(vm, result, std::make_index_sequence<std::tuple_size_v<AniTypes>>());
}
} // namespace OHOS::Text::ANI

extern "C"
{
    ANI_EXPORT ani_status ANI_Constructor(ani_vm* vm, uint32_t* result)
    {
        ani_status status = OHOS::Text::ANI::Init(vm, result);
        if (status == ANI_OK) {
            *result = ANI_VERSION_1;
        }
        return status;
    }
}