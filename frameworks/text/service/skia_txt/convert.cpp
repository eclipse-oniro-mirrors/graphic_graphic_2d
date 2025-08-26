/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "convert.h"

#include "txt/paint_record.h"

namespace OHOS {
namespace Rosen {
namespace AdapterTxt {
const std::string WGHT_AXIS = "wght";
constexpr float FONT_WEIGHT_MULTIPLE = 100.0;
const std::string SUPS{"sups"};
const std::string SUBS{"subs"};

std::shared_ptr<OHOS::Rosen::AdapterTxt::FontCollection> Convert(
    const std::shared_ptr<OHOS::Rosen::FontCollection>& fontCollection)
{
    return std::static_pointer_cast<OHOS::Rosen::AdapterTxt::FontCollection>(fontCollection);
}

IndexAndAffinity Convert(const SPText::PositionWithAffinity& pos)
{
    return { pos.position, static_cast<Affinity>(pos.affinity) };
}

Boundary Convert(const SPText::Range<size_t>& range)
{
    return { range.start, range.end };
}

TextRect Convert(const SPText::TextBox& box)
{
    Drawing::RectF rect(box.rect.fLeft, box.rect.fTop, box.rect.fRight, box.rect.fBottom);
    return { rect, static_cast<TextDirection>(box.direction) };
}

SPText::RectHeightStyle Convert(const TextRectHeightStyle& style)
{
    return static_cast<SPText::RectHeightStyle>(style);
}

SPText::RectWidthStyle Convert(const TextRectWidthStyle& style)
{
    return static_cast<SPText::RectWidthStyle>(style);
}

SPText::ParagraphStyle Convert(const TypographyStyle& style)
{
    SPText::ParagraphStyle paragraphStyle;
    paragraphStyle.fontWeight = static_cast<SPText::FontWeight>(style.fontWeight);
    paragraphStyle.fontWidth = static_cast<SPText::FontWidth>(style.fontWidth);
    paragraphStyle.fontStyle = static_cast<SPText::FontStyle>(style.fontStyle);
    paragraphStyle.wordBreakType = static_cast<SPText::WordBreakType>(style.wordBreakType);
    paragraphStyle.fontFamily = style.fontFamily;
    paragraphStyle.fontSize = style.fontSize;
    paragraphStyle.height = style.heightScale;
    paragraphStyle.heightOverride = style.heightOnly;
    paragraphStyle.strutEnabled = style.useLineStyle;
    paragraphStyle.strutFontWeight = static_cast<SPText::FontWeight>(style.lineStyleFontWeight);
    paragraphStyle.strutFontWidth = static_cast<SPText::FontWidth>(style.lineStyleFontWidth);
    paragraphStyle.strutFontStyle = static_cast<SPText::FontStyle>(style.lineStyleFontStyle);
    paragraphStyle.strutFontFamilies = style.lineStyleFontFamilies;
    paragraphStyle.strutFontSize = style.lineStyleFontSize;
    paragraphStyle.strutHeight = style.lineStyleHeightScale;
    paragraphStyle.strutHeightOverride = style.lineStyleHeightOnly;
    paragraphStyle.strutHalfLeading = style.lineStyleHalfLeading;
    paragraphStyle.strutLeading = style.lineStyleSpacingScale;
    paragraphStyle.forceStrutHeight = style.lineStyleOnly;
    paragraphStyle.textAlign = static_cast<SPText::TextAlign>(style.textAlign);
    paragraphStyle.textDirection = static_cast<SPText::TextDirection>(style.textDirection);
    paragraphStyle.ellipsisModal = static_cast<SPText::EllipsisModal>(style.ellipsisModal);
    paragraphStyle.maxLines = style.maxLines;
    paragraphStyle.ellipsis = style.ellipsis;
    paragraphStyle.locale = style.locale;
    paragraphStyle.textSplitRatio = style.textSplitRatio;
    paragraphStyle.textOverflower = style.Ellipsized();
    paragraphStyle.spTextStyle = Convert(style.insideTextStyle);
    paragraphStyle.customSpTextStyle = style.customTextStyle;
    paragraphStyle.textHeightBehavior = static_cast<SPText::TextHeightBehavior>(style.textHeightBehavior);
    paragraphStyle.hintingIsOn = style.hintingIsOn;
    paragraphStyle.breakStrategy = static_cast<SPText::BreakStrategy>(style.breakStrategy);
    paragraphStyle.tab = Convert(style.tab);
    paragraphStyle.paragraphSpacing = style.paragraphSpacing;
    paragraphStyle.isEndAddParagraphSpacing = style.isEndAddParagraphSpacing;
    paragraphStyle.relayoutChangeBitmap = style.relayoutChangeBitmap;
    paragraphStyle.defaultTextStyleUid = style.defaultTextStyleUid;
    paragraphStyle.halfLeading = style.halfLeading;
    paragraphStyle.isTrailingSpaceOptimized = style.isTrailingSpaceOptimized;
    paragraphStyle.enableAutoSpace = style.enableAutoSpace;
    paragraphStyle.verticalAlignment = style.verticalAlignment;
    paragraphStyle.maxLineHeight = style.maxLineHeight;
    paragraphStyle.minLineHeight= style.minLineHeight;
    paragraphStyle.lineSpacing = style.lineSpacing;
    paragraphStyle.lineHeightStyle = style.lineHeightStyle;

    return paragraphStyle;
}

SPText::PlaceholderRun Convert(const PlaceholderSpan& run)
{
    return {
        run.width,
        run.height,
        static_cast<SPText::PlaceholderAlignment>(run.alignment),
        static_cast<SPText::TextBaseline>(run.baseline),
        run.baselineOffset,
    };
}

static std::string RemoveQuotes(const std::string& str)
{
    if (str.empty() || str.front() != '\"' || str.back() != '\"') {
        return str;
    }
    const int start = 1; // The starting position of string.
    const int end = static_cast<int>(str.size()) - 2; // End position of string.
    return str.substr(start, end); // Remove quotation marks from both ends.
}

void CopyTextStyleSymbol(const TextStyle& style, SPText::TextStyle& textStyle)
{
    textStyle.symbol.SetSymbolType(style.symbol.GetSymbolType());
    textStyle.symbol.SetRenderMode(style.symbol.GetRenderMode());
    textStyle.symbol.SetSymbolEffect(style.symbol.GetEffectStrategy());
    textStyle.symbol.SetAnimationMode(style.symbol.GetAnimationMode());
    textStyle.symbol.SetRepeatCount(style.symbol.GetRepeatCount());
    textStyle.symbol.SetAnimationStart(style.symbol.GetAnimationStart());
    textStyle.symbol.SetCommonSubType(style.symbol.GetCommonSubType());
    textStyle.symbol.SetSymbolUid(style.symbol.GetSymbolUid());
    textStyle.symbol.SetSymbolBitmap(style.symbol.GetSymbolBitmap());
    textStyle.symbol.SetSymbolColor(style.symbol.GetSymbolColor());
    textStyle.symbol.SetSymbolShadow(style.symbol.GetSymbolShadow());
    for (auto [tag, value] : style.symbol.GetVisualMap()) {
        textStyle.fontFeatures.SetFeature(RemoveQuotes(tag), value);
    }
}

void SplitTextStyleConvert(SPText::TextStyle& textStyle, const TextStyle& style)
{
    if (style.isSymbolGlyph) {
        CopyTextStyleSymbol(style, textStyle);
    }
    if (style.backgroundBrush.has_value() || style.backgroundPen.has_value()) {
        textStyle.background = SPText::PaintRecord(style.backgroundBrush, style.backgroundPen);
    }
    if (style.foregroundBrush.has_value() || style.foregroundPen.has_value()) {
        textStyle.foreground = SPText::PaintRecord(style.foregroundBrush, style.foregroundPen);
    }

    for (const auto& [color, offset, radius] : style.shadows) {
        auto shadowColor = SkColorSetARGB(color.GetAlpha(), color.GetRed(), color.GetGreen(), color.GetBlue());
        auto shadowOffset = SkPoint::Make(offset.GetX(), offset.GetY());
        textStyle.textShadows.emplace_back(shadowColor, shadowOffset, radius);
    }

    for (const auto& [tag, value] : style.fontFeatures.GetFontFeatures()) {
        std::string featureName = RemoveQuotes(tag);
        textStyle.fontFeatures.SetFeature(featureName, value);
        if (textStyle.badgeType != TextBadgeType::BADGE_NONE && ((featureName == SUPS && value == 1) ||
            (featureName == SUBS && value == 1))) {
            textStyle.badgeType = TextBadgeType::BADGE_NONE;
        }
    }

    if (!style.fontVariations.GetAxisValues().empty()) {
        for (const auto& [axis, value] : style.fontVariations.GetAxisValues()) {
            textStyle.fontVariations.SetAxisValue(axis, value);
        }
    } else {
        textStyle.fontVariations.SetAxisValue(WGHT_AXIS,
            (static_cast<float>(style.fontWeight) + 1.0) * FONT_WEIGHT_MULTIPLE);
    }
}

SPText::TextStyle Convert(const TextStyle& style)
{
    SPText::TextStyle textStyle;
    textStyle.color = style.color.CastToColorQuad();
    textStyle.decoration = static_cast<SPText::TextDecoration>(style.decoration);
    auto decorationColor = SkColorSetARGB(style.decorationColor.GetAlpha(), style.decorationColor.GetRed(),
        style.decorationColor.GetGreen(), style.decorationColor.GetBlue());
    textStyle.decorationColor = decorationColor;
    textStyle.decorationStyle = static_cast<SPText::TextDecorationStyle>(style.decorationStyle);
    textStyle.decorationThicknessMultiplier = style.decorationThicknessScale;
    textStyle.fontWeight = static_cast<SPText::FontWeight>(style.fontWeight);
    textStyle.fontWidth = static_cast<SPText::FontWidth>(style.fontWidth);
    textStyle.fontStyle = static_cast<SPText::FontStyle>(style.fontStyle);
    textStyle.baseline = static_cast<SPText::TextBaseline>(style.baseline);
    textStyle.halfLeading = style.halfLeading;
    textStyle.fontFamilies = style.fontFamilies;
    textStyle.fontSize = style.fontSize;
    textStyle.letterSpacing = style.letterSpacing;
    textStyle.wordSpacing = style.wordSpacing;
    textStyle.height = style.heightScale;
    textStyle.heightOverride = style.heightOnly;
    textStyle.locale = style.locale;
    textStyle.backgroundRect = { style.backgroundRect.color, style.backgroundRect.leftTopRadius,
        style.backgroundRect.rightTopRadius, style.backgroundRect.rightBottomRadius,
        style.backgroundRect.leftBottomRadius };
    textStyle.styleId = style.styleId;
    textStyle.textStyleUid = style.textStyleUid;
    textStyle.isSymbolGlyph = style.isSymbolGlyph;
    textStyle.baseLineShift = style.baseLineShift;
    textStyle.isPlaceholder = style.isPlaceholder;
    textStyle.relayoutChangeBitmap = style.relayoutChangeBitmap;
    textStyle.badgeType = style.badgeType;
    textStyle.maxLineHeight = style.maxLineHeight;
    textStyle.minLineHeight = style.minLineHeight;
    textStyle.lineHeightStyle = style.lineHeightStyle;
    SplitTextStyleConvert(textStyle, style);

    return textStyle;
}

void CopyTextStyleSymbol(const SPText::TextStyle& style, TextStyle& textStyle)
{
    textStyle.symbol.SetSymbolColor(style.symbol.GetSymbolColor());
    textStyle.symbol.SetRenderMode(style.symbol.GetRenderMode());
    textStyle.symbol.SetSymbolEffect(style.symbol.GetEffectStrategy());
    textStyle.symbol.SetAnimationMode(style.symbol.GetAnimationMode());
    textStyle.symbol.SetRepeatCount(style.symbol.GetRepeatCount());
    textStyle.symbol.SetAnimationStart(style.symbol.GetAnimationStart());
    textStyle.symbol.SetCommonSubType(style.symbol.GetCommonSubType());
    textStyle.symbol.SetSymbolUid(style.symbol.GetSymbolUid());
    textStyle.symbol.SetSymbolShadow(style.symbol.GetSymbolShadow());
}

void SplitTextStyleConvert(TextStyle& textStyle, const SPText::TextStyle& style)
{
    if (style.isSymbolGlyph) {
        CopyTextStyleSymbol(style, textStyle);
    }

    if (style.background.has_value()) {
        textStyle.backgroundBrush = style.background->brush;
        textStyle.backgroundPen = style.background->pen;
    }

    if (style.foreground.has_value()) {
        textStyle.foregroundBrush = style.foreground->brush;
        textStyle.foregroundPen = style.foreground->pen;
    }

    for (const auto& [color, offset, radius] : style.textShadows) {
        Drawing::Color shadowColor;
        shadowColor.SetColorQuad(color);
        Drawing::Point shadowOffset(offset.x(), offset.y());
        textStyle.shadows.emplace_back(shadowColor, shadowOffset, radius);
    }

    for (const auto& [tag, value] : style.fontFeatures.GetFontFeatures()) {
        textStyle.fontFeatures.SetFeature(RemoveQuotes(tag), value);
    }

    if (!style.fontVariations.GetAxisValues().empty()) {
        for (const auto& [axis, value] : style.fontVariations.GetAxisValues()) {
            textStyle.fontVariations.SetAxisValue(axis, value);
        }
    }
}

TextStyle Convert(const SPText::TextStyle& style)
{
    TextStyle textStyle;
    textStyle.color.SetColorQuad(style.color);
    textStyle.decoration = static_cast<TextDecoration>(style.decoration);
    textStyle.decorationColor.SetColorQuad(style.decorationColor);
    textStyle.decorationStyle = static_cast<TextDecorationStyle>(style.decorationStyle);
    textStyle.decorationThicknessScale = style.decorationThicknessMultiplier;
    textStyle.fontWeight = static_cast<FontWeight>(style.fontWeight);
    textStyle.fontWidth = static_cast<FontWidth>(style.fontWidth);
    textStyle.fontStyle = static_cast<FontStyle>(style.fontStyle);
    textStyle.baseline = static_cast<TextBaseline>(style.baseline);

    textStyle.halfLeading = style.halfLeading;
    textStyle.fontFamilies = style.fontFamilies;
    textStyle.fontSize = style.fontSize;
    textStyle.letterSpacing = style.letterSpacing;
    textStyle.wordSpacing = style.wordSpacing;
    textStyle.heightScale = style.height;
    textStyle.heightOnly = style.heightOverride;
    textStyle.locale = style.locale;
    textStyle.backgroundRect = { style.backgroundRect.color, style.backgroundRect.leftTopRadius,
        style.backgroundRect.rightTopRadius, style.backgroundRect.rightBottomRadius,
        style.backgroundRect.leftBottomRadius };
    textStyle.styleId = style.styleId;
    textStyle.textStyleUid = style.textStyleUid;
    textStyle.isSymbolGlyph = style.isSymbolGlyph;
    textStyle.baseLineShift = style.baseLineShift;
    textStyle.isPlaceholder = style.isPlaceholder;
    textStyle.badgeType = style.badgeType;
    SplitTextStyleConvert(textStyle, style);

    return textStyle;
}

SPText::TextTab Convert(const TextTab& tab)
{
    return {
        static_cast<SPText::TextAlign>(tab.alignment),
        tab.location,
    };
}
} // namespace AdapterTxt
} // namespace Rosen
} // namespace OHOS
