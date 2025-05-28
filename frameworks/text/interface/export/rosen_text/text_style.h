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

#ifndef ROSEN_TEXT_EXPORT_ROSEN_TEXT_TEXT_STYLE_H
#define ROSEN_TEXT_EXPORT_ROSEN_TEXT_TEXT_STYLE_H

#include <bitset>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "draw/pen.h"
#include "draw/brush.h"
#include "draw/color.h"
#include "utils/point.h"
#include "utils/scalar.h"

#include "common/rs_macros.h"
#include "typography_types.h"
#include "hm_symbol_txt.h"

namespace OHOS {
namespace Rosen {
enum class TextBadgeType {
    BADGE_NONE,
    SUPERSCRIPT,
    SUBSCRIPT,
};

enum class RelayoutTextStyleAttribute {
    FONT_SIZE = 0,
    FONT_WEIGHT = 1,
    FONT_WIDTH = 2,
    FONT_STYLE = 3,
    FONT_FAMILIES = 4,
    LETTER_SPACING = 5,
    WORD_SPACING = 6,
    HEIGHT_ONLY = 7,
    HEIGHT_SCALE = 8,
    FONT_FEATURES = 9,
    FONT_VARIATIONS = 10,
    BASELINE_SHIFT = 11,
    DECORATION = 12,
    DECORATION_COLOR = 13,
    DECORATION_STYLE = 14,
    DECORATION_THICKNESS_SCALE = 15,
    BACKGROUND_RECT = 16,
    STYLE_ID = 17,
    FONT_COLOR = 18,
    SHADOWS = 19,
    HALF_LEADING = 20,
    FOREGROUND_BRUSH = 21,

    TEXT_STYLE_ATTRIBUTE_BUTT,
};

class RS_EXPORT FontFeatures {
public:
    void SetFeature(std::string tag, int value);
    std::string GetFeatureSettings() const;
    const std::vector<std::pair<std::string, int>> &GetFontFeatures() const;
    bool operator ==(const FontFeatures& rhs) const;
    void Clear();

private:
    std::vector<std::pair<std::string, int>> featureSet_;
};

class RS_EXPORT FontVariations {
public:
    void SetAxisValue(const std::string& tag, float value);
    const std::map<std::string, float>& GetAxisValues() const;
    bool operator ==(const FontVariations& rhs) const;
    void Clear();
private:
    std::map<std::string, float> axis_;
};

struct RS_EXPORT TextShadow {
    Drawing::Color color = Drawing::Color::COLOR_BLACK;
    Drawing::Point offset;
    double blurRadius = 0.0;

    TextShadow();
    TextShadow(Drawing::Color shadowColor, Drawing::Point shadowOffset, double shadowBlurRadius);
    bool operator ==(const TextShadow& rhs) const;
    bool operator !=(const TextShadow& rhs) const;
    bool HasShadow() const;
};

struct RS_EXPORT RectStyle {
    uint32_t color = 0;
    double leftTopRadius = 0.0;
    double rightTopRadius = 0.0;
    double rightBottomRadius = 0.0;
    double leftBottomRadius = 0.0;
    bool operator ==(const RectStyle& rhs) const;
    bool operator !=(const RectStyle& rhs) const;
};

struct TextStyle {
    Drawing::Color color = Drawing::Color::COLOR_WHITE;
    TextDecoration decoration = TextDecoration::NONE;
    Drawing::Color decorationColor = Drawing::Color::COLOR_TRANSPARENT;
    TextDecorationStyle decorationStyle = TextDecorationStyle::SOLID;
    double decorationThicknessScale = 1.0;
    FontWeight fontWeight = FontWeight::W400;
    FontWidth fontWidth = FontWidth::NORMAL;
    FontStyle fontStyle = FontStyle::NORMAL;
    TextBaseline baseline = TextBaseline::ALPHABETIC;
    std::vector<std::string> fontFamilies;
    double fontSize = 14.0; // default is libtxt text style font size
    double letterSpacing = 0.0;
    double wordSpacing = 0.0;
    double heightScale = 1.0;
    bool halfLeading = false;
    bool heightOnly = false;
    std::u16string ellipsis;
    EllipsisModal ellipsisModal = EllipsisModal::TAIL;
    std::string locale;
    std::optional<Drawing::Brush> foregroundBrush;
    std::optional<Drawing::Pen> foregroundPen;
    std::optional<Drawing::Brush> backgroundBrush;
    std::optional<Drawing::Pen> backgroundPen;
    // if Pen and SkPaint are setting, use pen first
    std::vector<TextShadow> shadows;
    FontFeatures fontFeatures;
    FontVariations fontVariations;
    RectStyle backgroundRect{0, 0.0, 0.0, 0.0, 0.0};
    int styleId{0};
    size_t textStyleUid{0};
    bool operator ==(const TextStyle &rhs) const;
    bool EqualByFonts(const TextStyle &rhs) const;
    bool MatchOneAttribute(StyleType styleType, const TextStyle &rhs) const;
    // symbol glyph
    bool isSymbolGlyph{false};
    HMSymbolTxt symbol;
    double baseLineShift{0.0f};
    bool isPlaceholder{false};
    std::bitset<static_cast<size_t>(RelayoutTextStyleAttribute::TEXT_STYLE_ATTRIBUTE_BUTT)> relayoutChangeBitmap;
    TextBadgeType badgeType{TextBadgeType::BADGE_NONE};
};
} // namespace Rosen
} // namespace OHOS

#endif // ROSEN_TEXT_EXPORT_ROSEN_TEXT_TEXT_STYLE_H
