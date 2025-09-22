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

#include "ani_line_typeset.h"

#include <memory>
#include <string>
#include <utility>

#include "ani_common.h"
#include "ani_text_line.h"
#include "ani_text_utils.h"
#include "typography.h"
#include "utils/text_log.h"

namespace OHOS::Text::ANI {
using namespace OHOS::Rosen;

AniLineTypeset::AniLineTypeset(std::shared_ptr<LineTypography> lineTypography) : lineTypography_(lineTypography)
{
}

ani_status AniLineTypeset::AniInit(ani_vm* vm, uint32_t* result)
{
    ani_env* env = nullptr;
    ani_status ret = vm->GetEnv(ANI_VERSION_1, &env);
    if (ret != ANI_OK || env == nullptr) {
        TEXT_LOGE("Failed to get env, ret %{public}d", ret);
        return ANI_NOT_FOUND;
    }

    ani_class cls = nullptr;
    ret = AniTextUtils::FindClassWithCache(env, ANI_CLASS_LINE_TYPESET, cls);
    if (ret != ANI_OK) {
        TEXT_LOGE("Failed to find class, ret %{public}d", ret);
        return ANI_NOT_FOUND;
    }
    std::string createLineSignature = "II:" + std::string(ANI_CLASS_TEXT_LINE);
    std::array methods = {
        ani_native_function{"getLineBreak", "ID:I", reinterpret_cast<void*>(GetLineBreak)},
        ani_native_function{"createLine", createLineSignature.c_str(), reinterpret_cast<void*>(CreateLine)},
    };

    ret = env->Class_BindNativeMethods(cls, methods.data(), methods.size());
    if (ret != ANI_OK) {
        TEXT_LOGE("Failed to bind methods for LineTypeset, ret %{public}d", ret);
        return ANI_NOT_FOUND;
    }
    return ANI_OK;
}

ani_int AniLineTypeset::GetLineBreak(ani_env* env, ani_object object, ani_int startIndex, ani_double width)
{
    AniLineTypeset* aniLineTypeSet = AniTextUtils::GetNativeFromObj<AniLineTypeset>(env, object);
    if (aniLineTypeSet == nullptr || aniLineTypeSet->lineTypography_ == nullptr) {
        TEXT_LOGE("Line typography is null");
        AniTextUtils::ThrowBusinessError(env, TextErrorCode::ERROR_INVALID_PARAM, "Invalid params.");
        return 0;
    }

    return static_cast<ani_int>(aniLineTypeSet->lineTypography_->GetLineBreak(static_cast<size_t>(startIndex), width));
}

ani_object AniLineTypeset::CreateLine(ani_env* env, ani_object object, ani_int startIndex, ani_int count)
{
    AniLineTypeset* aniLineTypeSet = AniTextUtils::GetNativeFromObj<AniLineTypeset>(env, object);
    if (aniLineTypeSet == nullptr || aniLineTypeSet->lineTypography_ == nullptr) {
        TEXT_LOGE("Line typography is null");
        AniTextUtils::ThrowBusinessError(env, TextErrorCode::ERROR_INVALID_PARAM, "Invalid params.");
        return AniTextUtils::CreateAniUndefined(env);
    }

    size_t limitSize = aniLineTypeSet->lineTypography_->GetUnicodeSize();
    if (startIndex < 0 || (limitSize <= static_cast<size_t>(startIndex)) || count < 0
        || (limitSize < static_cast<size_t>(count + startIndex))) {
        TEXT_LOGE("Params exceeds reasonable range. %{public}d %{public}d %{public}zu", startIndex, count, limitSize);
        AniTextUtils::ThrowBusinessError(env, TextErrorCode::ERROR_INVALID_PARAM, "Params exceeds reasonable range.");
        return AniTextUtils::CreateAniUndefined(env);
    }

    std::unique_ptr<TextLineBase> textLineBase =
        aniLineTypeSet->lineTypography_->CreateLine(static_cast<size_t>(startIndex), static_cast<size_t>(count));
    if (textLineBase == nullptr) {
        TEXT_LOGE("Failed to create line. %{public}d %{public}d %{public}zu", startIndex, count, limitSize);
        AniTextUtils::ThrowBusinessError(env, TextErrorCode::ERROR_INVALID_PARAM, "Create line failed.");
        return AniTextUtils::CreateAniUndefined(env);
    }
    TextLineBase* textLineBasePtr = textLineBase.release();
    ani_object textLineObj = AniTextLine::CreateTextLine(env, textLineBasePtr);
    if (AniTextUtils::IsUndefined(env, textLineObj)) {
        TEXT_LOGE("Failed to create ani line, line is undefined");
        delete textLineBasePtr;
        textLineBasePtr = nullptr;
        AniTextUtils::ThrowBusinessError(env, TextErrorCode::ERROR_INVALID_PARAM, "Failed to create TextLine object.");
        return AniTextUtils::CreateAniUndefined(env);
    }
    return textLineObj;
}
} // namespace OHOS::Text::ANI