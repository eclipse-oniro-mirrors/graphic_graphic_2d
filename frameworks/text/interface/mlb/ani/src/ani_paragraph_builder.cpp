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

#include "ani_paragraph_builder.h"

#include <algorithm>
#include <codecvt>
#include <cstdint>

#include "ani_common.h"
#include "ani_font_collection.h"
#include "ani_line_typeset.h"
#include "ani_paragraph.h"
#include "ani_paragraph_style_converter.h"
#include "ani_placeholder_converter.h"
#include "ani_text_style_converter.h"
#include "ani_text_utils.h"
#include "font_collection.h"
#include "text_style.h"
#include "utils/text_log.h"

namespace OHOS::Text::ANI {
using namespace OHOS::Rosen;

namespace {
const std::string CTOR_SIGN =
    "C{" + std::string(ANI_INTERFACE_PARAGRAPH_STYLE) + "}C{" + std::string(ANI_CLASS_FONT_COLLECTION) + "}:";
const std::string PUSH_STYLE_SIGN = "C{" + std::string(ANI_INTERFACE_TEXT_STYLE) + "}:";
const std::string BUILD_STYLE_SIGN = ":C{" + std::string(ANI_CLASS_PARAGRAPH) + "}";
const std::string ADD_PLACEHOLDER_SIGN = "C{" + std::string(ANI_INTERFACE_PLACEHOLDER_SPAN) + "}:";
const std::string BUILD_LINE_TYPE_SET_SIGN = ":C{" + std::string(ANI_CLASS_LINE_TYPESET) + "}";
}

void AniParagraphBuilder::Constructor(
    ani_env* env, ani_object object, ani_object paragraphStyle, ani_object fontCollection)
{
    std::unique_ptr<TypographyStyle> typographyStyleNative =
        AniParagraphStyleConverter::ParseParagraphStyleToNative(env, paragraphStyle);
    if (typographyStyleNative == nullptr) {
        TEXT_LOGE("Failed to parse typographyStyle");
        AniTextUtils::ThrowBusinessError(env, TextErrorCode::ERROR_INVALID_PARAM, "Invalid params.");
        return;
    }

    AniFontCollection* aniFontCollection = AniTextUtils::GetNativeFromObj<AniFontCollection>(env, fontCollection);
    if (aniFontCollection == nullptr) {
        TEXT_LOGE("FontCollection is null");
        AniTextUtils::ThrowBusinessError(env, TextErrorCode::ERROR_INVALID_PARAM, "Invalid params.");
        return;
    }
    std::shared_ptr<FontCollection> fontCollectionNative = aniFontCollection->GetFontCollection();
    if (fontCollectionNative == nullptr) {
        TEXT_LOGE("Failed to get font collection");
        AniTextUtils::ThrowBusinessError(env, TextErrorCode::ERROR_INVALID_PARAM, "Invalid params.");
        return;
    }

    std::unique_ptr<TypographyCreate> typographyCreateNative =
        TypographyCreate::Create(*typographyStyleNative, fontCollectionNative);
    if (typographyCreateNative == nullptr) {
        TEXT_LOGE("Failed to create typography creator");
        AniTextUtils::ThrowBusinessError(env, TextErrorCode::ERROR_INVALID_PARAM, "TypographyCreate create error.");
        return;
    }

    AniParagraphBuilder* paragraphBuilder = new AniParagraphBuilder();
    paragraphBuilder->typographyCreate_ = std::move(typographyCreateNative);
    ani_status ret = env->Object_CallMethodByName_Void(
        object, BIND_NATIVE, "l:", reinterpret_cast<ani_long>(paragraphBuilder));
    if (ret != ANI_OK) {
        TEXT_LOGE("Failed to create ani TypographyCreate obj");
        delete paragraphBuilder;
        paragraphBuilder = nullptr;
        AniTextUtils::ThrowBusinessError(env, TextErrorCode::ERROR_INVALID_PARAM, "AniParagraphBuilder create error.");
        return;
    }
}

ani_status AniParagraphBuilder::AniInit(ani_vm* vm, uint32_t* result)
{
    ani_env* env = nullptr;
    ani_status ret = vm->GetEnv(ANI_VERSION_1, &env);
    if (ret != ANI_OK || env == nullptr) {
        TEXT_LOGE("Failed to get env, ret %{public}d", ret);
        return ret;
    }

    ani_class cls = nullptr;
    ret = AniTextUtils::FindClassWithCache(env, ANI_CLASS_PARAGRAPH_BUILDER, cls);
    if (ret != ANI_OK) {
        TEXT_LOGE("Failed to find class, ret %{public}d", ret);
        return ret;
    }

    std::array methods = {
        ani_native_function{"constructorNative", CTOR_SIGN.c_str(), reinterpret_cast<void*>(Constructor)},
        ani_native_function{"pushStyle", PUSH_STYLE_SIGN.c_str(), reinterpret_cast<void*>(PushStyle)},
        ani_native_function{"popStyle", ":", reinterpret_cast<void*>(PopStyle)},
        ani_native_function{"addText", "C{std.core.String}:", reinterpret_cast<void*>(AddText)},
        ani_native_function{"addPlaceholder", ADD_PLACEHOLDER_SIGN.c_str(), reinterpret_cast<void*>(AddPlaceholder)},
        ani_native_function{"build", BUILD_STYLE_SIGN.c_str(), reinterpret_cast<void*>(Build)},
        ani_native_function{
            "buildLineTypeset", BUILD_LINE_TYPE_SET_SIGN.c_str(), reinterpret_cast<void*>(BuildLineTypeset)},
        ani_native_function{"addSymbol", "i:", reinterpret_cast<void*>(AddSymbol)},
    };

    ret = env->Class_BindNativeMethods(cls, methods.data(), methods.size());
    if (ret != ANI_OK) {
        TEXT_LOGE("Failed to bind methods for TypographyCreate, ret %{public}d", ret);
        return ret;
    }
    return ANI_OK;
}

void AniParagraphBuilder::PushStyle(ani_env* env, ani_object object, ani_object textStyle)
{
    AniParagraphBuilder* paragraphBuilder = AniTextUtils::GetNativeFromObj<AniParagraphBuilder>(env, object);
    if (paragraphBuilder == nullptr || paragraphBuilder->typographyCreate_ == nullptr) {
        TEXT_LOGE("ParagraphBuilder is null");
        AniTextUtils::ThrowBusinessError(env, TextErrorCode::ERROR_INVALID_PARAM, "Invalid params.");
        return;
    }
    TextStyle textStyleNative;
    ani_status status = AniTextStyleConverter::ParseTextStyleToNative(env, textStyle, textStyleNative);
    if (status == ANI_OK) {
        paragraphBuilder->typographyCreate_->PushStyle(textStyleNative);
    }
}

void AniParagraphBuilder::PopStyle(ani_env* env, ani_object object)
{
    AniParagraphBuilder* paragraphBuilder = AniTextUtils::GetNativeFromObj<AniParagraphBuilder>(env, object);
    if (paragraphBuilder == nullptr || paragraphBuilder->typographyCreate_ == nullptr) {
        TEXT_LOGE("ParagraphBuilder is null");
        AniTextUtils::ThrowBusinessError(env, TextErrorCode::ERROR_INVALID_PARAM, "Invalid params.");
        return;
    }

    paragraphBuilder->typographyCreate_->PopStyle();
}

void AniParagraphBuilder::AddText(ani_env* env, ani_object object, ani_string text)
{
    std::u16string textStr;
    ani_status status = AniTextUtils::AniToStdStringUtf16(env, text, textStr);
    if (status != ANI_OK) {
        AniTextUtils::ThrowBusinessError(env, TextErrorCode::ERROR_INVALID_PARAM, "Fail get utf16.");
        return;
    }
    AniParagraphBuilder* paragraphBuilder = AniTextUtils::GetNativeFromObj<AniParagraphBuilder>(env, object);
    if (paragraphBuilder == nullptr || paragraphBuilder->typographyCreate_ == nullptr) {
        TEXT_LOGE("TypographyCreate is null");
        AniTextUtils::ThrowBusinessError(env, TextErrorCode::ERROR_INVALID_PARAM, "Invalid params.");
        return;
    }
    paragraphBuilder->typographyCreate_->AppendText(textStr);
}

void AniParagraphBuilder::AddPlaceholder(ani_env* env, ani_object object, ani_object placeholderSpan)
{
    AniParagraphBuilder* paragraphBuilder = AniTextUtils::GetNativeFromObj<AniParagraphBuilder>(env, object);
    if (paragraphBuilder == nullptr || paragraphBuilder->typographyCreate_ == nullptr) {
        TEXT_LOGE("ParagraphBuilder is null");
        AniTextUtils::ThrowBusinessError(env, TextErrorCode::ERROR_INVALID_PARAM, "Invalid params.");
        return;
    }
    PlaceholderSpan placeholderSpanInner;
    ani_status ret = AniPlaceholderConverter::ParsePlaceholderSpanToNative(env, placeholderSpan, placeholderSpanInner);
    if (ret != ANI_OK) {
        return;
    }
    paragraphBuilder->typographyCreate_->AppendPlaceholder(placeholderSpanInner);
}

ani_object AniParagraphBuilder::Build(ani_env* env, ani_object object)
{
    AniParagraphBuilder* paragraphBuilder = AniTextUtils::GetNativeFromObj<AniParagraphBuilder>(env, object);
    if (paragraphBuilder == nullptr || paragraphBuilder->typographyCreate_ == nullptr) {
        TEXT_LOGE("TypographyCreate is null");
        AniTextUtils::ThrowBusinessError(env, TextErrorCode::ERROR_INVALID_PARAM, "Invalid params.");
        return AniTextUtils::CreateAniUndefined(env);
    }
    std::unique_ptr<OHOS::Rosen::Typography> typography = paragraphBuilder->typographyCreate_->CreateTypography();
    OHOS::Rosen::Typography* typographyPtr = typography.release();
    ani_object typographyObj = AniParagraph::SetTypography(env, typographyPtr);
    if (AniTextUtils::IsUndefined(env, typographyObj)) {
        TEXT_LOGE("Failed to create typography obj");
        delete typographyPtr;
        typographyPtr = nullptr;
    }
    return typographyObj;
}

ani_object AniParagraphBuilder::BuildLineTypeset(ani_env* env, ani_object object)
{
    AniParagraphBuilder* paragraphBuilder = AniTextUtils::GetNativeFromObj<AniParagraphBuilder>(env, object);
    if (paragraphBuilder == nullptr || paragraphBuilder->typographyCreate_ == nullptr) {
        TEXT_LOGE("TypographyCreate is null");
        AniTextUtils::ThrowBusinessError(env, TextErrorCode::ERROR_INVALID_PARAM, "Invalid params.");
        return AniTextUtils::CreateAniUndefined(env);
    }
    std::unique_ptr<OHOS::Rosen::LineTypography> lineTypography =
        paragraphBuilder->typographyCreate_->CreateLineTypography();
    if (lineTypography == nullptr) {
        TEXT_LOGE("TypographyCreate is null");
        AniTextUtils::ThrowBusinessError(env, TextErrorCode::ERROR_INVALID_PARAM, "Failed to create line typography.");
        return AniTextUtils::CreateAniUndefined(env);
    }
    ani_object lineTypographyObj = AniTextUtils::CreateAniObject(env, ANI_CLASS_LINE_TYPESET, ":");
    AniLineTypeset* aniLineTypeSet = new AniLineTypeset(std::move(lineTypography));
    ani_status ret = env->Object_CallMethodByName_Void(
        lineTypographyObj, BIND_NATIVE, "l:", reinterpret_cast<ani_long>(aniLineTypeSet));
    if (ret != ANI_OK) {
        TEXT_LOGE("Failed to create ani Paragraph obj, ret %{public}d", ret);
        delete aniLineTypeSet;
        aniLineTypeSet = nullptr;
        return AniTextUtils::CreateAniUndefined(env);
    }
    return lineTypographyObj;
}

void AniParagraphBuilder::AddSymbol(ani_env* env, ani_object object, ani_int symbolId)
{
    AniParagraphBuilder* paragraphBuilder = AniTextUtils::GetNativeFromObj<AniParagraphBuilder>(env, object);
    if (paragraphBuilder == nullptr || paragraphBuilder->typographyCreate_ == nullptr) {
        TEXT_LOGE("TypographyCreate is null");
        AniTextUtils::ThrowBusinessError(env, TextErrorCode::ERROR_INVALID_PARAM, "Invalid params.");
        return;
    }
    if (symbolId == 0) {
        TEXT_LOGE("Invalid param symbolId");
        return;
    }
    paragraphBuilder->typographyCreate_->AppendSymbol(static_cast<uint32_t>(symbolId));
}
} // namespace OHOS::Text::ANI