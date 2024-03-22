/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.. All rights reserved.
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

#ifndef ROSEN_TEXT_EXPORT_ROSEN_TEXT_TYPOGRAPHY_STYLE_H
#define ROSEN_TEXT_EXPORT_ROSEN_TEXT_TYPOGRAPHY_STYLE_H

#include <string>
#include <vector>

#include "text_style.h"
#include "typography_types.h"

namespace OHOS {
namespace Rosen {
struct TypographyStyle {
    const static inline std::u16string ELLIPSIS = u"\u2026";

    FontWeight fontWeight = FontWeight::W400;
    FontStyle fontStyle = FontStyle::NORMAL;
    std::string fontFamily = "";
    double fontSize = 14.0; // default is libtxt text style fonst size
    double heightScale = 1.0;
    bool halfLeading = false;
    bool heightOnly = false;
    bool useLineStyle = false;

    FontWeight lineStyleFontWeight = FontWeight::W400;
    FontStyle lineStyleFontStyle = FontStyle::NORMAL;
    std::vector<std::string> lineStyleFontFamilies;
    double lineStyleFontSize = 14.0; // default is libtxt text style font size
    double lineStyleHeightScale = 1.0;
    bool lineStyleHeightOnlyInit = false;
    bool lineStyleHeightOnly = false;
    bool lineStyleHalfLeading = false;
    double lineStyleSpacingScale = -1.0;
    bool lineStyleOnly = false;

    TextAlign textAlign = TextAlign::START;
    TextDirection textDirection = TextDirection::LTR;
    size_t maxLines = 1e9;
    std::u16string ellipsis;
    std::string locale;

    BreakStrategy breakStrategy = BreakStrategy::GREEDY;
    WordBreakType wordBreakType = WordBreakType::BREAK_WORD;
    EllipsisModal ellipsisModal = EllipsisModal::TAIL;
    float textSplitRatio = 0.5f;

    TextStyle GetTextStyle() const;
    void SetTextStyle(TextStyle& textstyle);
    TextAlign GetEffectiveAlign() const;
    bool IsUnlimitedLines() const;
    bool IsEllipsized() const;
    bool Ellipsized() const
    {
        return !ellipsis.empty();
    }
    TextStyle insideTextStyle;
    bool customTextStyle = false;
    TextHeightBehavior textHeightBehavior = TextHeightBehavior::ALL;
};
} // namespace Rosen
} // namespace OHOS
#endif // ROSEN_TEXT_EXPORT_ROSEN_TEXT_TYPOGRAPHY_STYLE_H
