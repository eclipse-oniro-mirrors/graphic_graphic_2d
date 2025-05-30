/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "skia_font_style_set.h"

#include "include/core/SkString.h"
#include "include/core/SkTypeface.h"
#include "include/core/SkFontMgr.h"

#include "impl_interface/typeface_impl.h"
#include "skia_adapter/skia_convert_utils.h"
#include "skia_adapter/skia_typeface.h"
#include "utils/log.h"

namespace OHOS {
namespace Rosen {
namespace Drawing {
SkiaFontStyleSet::SkiaFontStyleSet(sk_sp<SkFontStyleSet> skFontStyleSet) : skFontStyleSet_(skFontStyleSet) {}

Typeface* SkiaFontStyleSet::CreateTypeface(int index)
{
    if (!skFontStyleSet_) {
        LOGD("SkiaFontStyleSet::CreateTypeface, skFontStyleSet_ nullptr");
        return nullptr;
    }
#ifdef USE_M133_SKIA
    sk_sp<SkTypeface> skTypeface = skFontStyleSet_->createTypeface(index);
#else
    SkTypeface* skTypeface = skFontStyleSet_->createTypeface(index);
#endif
    if (!skTypeface) {
        return nullptr;
    }
    std::shared_ptr<TypefaceImpl> typefaceImpl = std::make_shared<SkiaTypeface>(sk_sp(skTypeface));
    return new Typeface(typefaceImpl);
}

void SkiaFontStyleSet::GetStyle(int32_t index, FontStyle* fontStyle, std::string* styleName)
{
    if (!skFontStyleSet_) {
        LOGD("SkiaFontStyleSet::GetStyle, skFontStyleSet_ nullptr");
        return;
    }
    SkFontStyle skFontStyle;
    if (fontStyle) {
        SkiaConvertUtils::DrawingFontStyleCastToSkFontStyle(*fontStyle, skFontStyle);
    }
    SkString skStyleName;
    if (styleName) {
        SkiaConvertUtils::StdStringCastToSkString(*styleName, skStyleName);
    }
    skFontStyleSet_->getStyle(index, fontStyle ? &skFontStyle : nullptr, styleName ? &skStyleName : nullptr);
    if (fontStyle) {
        SkiaConvertUtils::SkFontStyleCastToDrawingFontStyle(skFontStyle, *fontStyle);
    }
    if (styleName) {
        SkiaConvertUtils::SkStringCastToStdString(skStyleName, *styleName);
    }
}

Typeface* SkiaFontStyleSet::MatchStyle(const FontStyle& pattern)
{
    if (!skFontStyleSet_) {
        LOGD("SkiaFontStyleSet::MatchStyle, skFontStyleSet_ nullptr");
        return nullptr;
    }
    SkFontStyle skFontStyle;
    SkiaConvertUtils::DrawingFontStyleCastToSkFontStyle(pattern, skFontStyle);

#ifdef USE_M133_SKIA
    sk_sp<SkTypeface> skTypeface = skFontStyleSet_->matchStyle(skFontStyle);
#else
    SkTypeface* skTypeface = skFontStyleSet_->matchStyle(skFontStyle);
#endif
    if (!skTypeface) {
        return nullptr;
    }
    std::shared_ptr<TypefaceImpl> typefaceImpl = std::make_shared<SkiaTypeface>(sk_sp(skTypeface));
    return new Typeface(typefaceImpl);
}

int SkiaFontStyleSet::Count()
{
    if (!skFontStyleSet_) {
        LOGD("SkiaFontStyleSet::Count, skFontStyleSet_ nullptr");
        return 0;
    }
    return skFontStyleSet_->count();
}
} // namespace Drawing
} // namespace Rosen
} // namespace OHOS