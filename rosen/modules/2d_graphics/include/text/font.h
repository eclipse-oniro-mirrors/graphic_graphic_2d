/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef FONT_H
#define FONT_H

#include <memory>
#include <cstdint>

#include "impl_interface/font_impl.h"
#include "text/font_metrics.h"
#include "text/font_types.h"
#include "text/typeface.h"
#include "utils/rect.h"
#include "utils/scalar.h"
#include "draw/brush.h"
#include "draw/pen.h"

namespace OHOS {
namespace Rosen {
namespace Drawing {
class DRAWING_API Font {
public:
    Font();
    Font(std::shared_ptr<Typeface> typeface, scalar size, scalar scaleX, scalar skewX);
    Font(const Font& font);
    virtual ~Font() = default;

    /**
     * @brief         Set font edge pixels pattern.
     * @param edging  Edge pixels pattern.
     */
    void SetEdging(FontEdging edging);

    /**
     * @brief               Requests that baselines be snapped to pixels when the current
     *                      transformation matrix is axis aligned.
     * @param baselineSnap  Setting for baseline snapping to pixels.
     */
    void SetBaselineSnap(bool baselineSnap);

    /**
     * @brief                     Set whether the font outline is automatically adjusted.
     * @param isForceAutoHinting  Indicate whether the font outline is automatically adjusted.
     */
    void SetForceAutoHinting(bool isForceAutoHinting);

    /**
     * @brief             Set glyphs are drawn at sub-pixel offsets.
     * @param isSubpixel  Glyphs should be drawn at sub-pixel.
     */
    void SetSubpixel(bool isSubpixel);

    /**
     * @brief               Set font hinting pattern.
     * @param hintingLevel  Font hinting level.
     */
    void SetHinting(FontHinting hintingLevel);

    /**
     * @brief                  Set font bitmaps mode.
     * @param embeddedBitmaps  Font bitmaps mode.
     */
    void SetEmbeddedBitmaps(bool embeddedBitmaps);

    /**
     * @brief           Set Typeface to font.
     * @param typeface  A shared point to typeface.
     */
    void SetTypeface(std::shared_ptr<Typeface> typeface);

    /**
     * @brief           Set text size.
     * @param textSize  Text size.
     */
    void SetSize(scalar textSize);

    /**
     * @brief             Set to increase stroke width when creating glyph bitmaps to approximate a bold typeface.
     * @param isEmbolden  Should increase stroke width.
     */
    void SetEmbolden(bool isEmbolden);

    /**
     * @brief         Set text scale on x-axis.
     * @param scaleX  Text horizontal scale.
     */
    void SetScaleX(scalar scaleX);

    /**
     * @brief        Set text skew on x-axis.
     * @param skewX  Additional shear on x-axis relative to y-axis.
     */
    void SetSkewX(scalar skewX);

    /**
     * @brief                  Set Font and glyph metrics should ignore hinting and rounding.
     * @param isLinearMetrics  Should ignore hinting and rounding.
     */
    void SetLinearMetrics(bool isLinearMetrics);

    /**
     * @brief          Get fontMetrics associated with typeface.
     * @param metrics  The fontMetrics value returned to the caller.
     * @return         Recommended spacing between lines.
     */
    scalar GetMetrics(FontMetrics* metrics) const;

    /**
     * @brief         Retrieves the advance and bounds for each glyph in glyphs.
     * @param glyphs  Array of glyph indices to be measured
     * @param count   Number of glyphs
     * @param widths  Text advances for each glyph returned to the caller.
     */
    void GetWidths(const uint16_t glyphs[], int count, scalar widths[]) const;

    /**
     * @brief         Retrieves the advance and bounds for each glyph in glyphs.
     * @param glyphs  Array of glyph indices to be measured
     * @param count   Number of glyphs
     * @param widths  Text advances for each glyph returned to the caller.
     * @param bounds  Bounds for each glyph relative to (0, 0) returned to the caller.
     */
    void GetWidths(const uint16_t glyphs[], int count, scalar widths[], Rect bounds[]) const;

    /**
     * @brief         Returns text size in points.
     * @return        The size of text.
     */
    scalar GetSize() const;

    /**
     * @brief         Returns Typeface if set, or nullptr.
     * @return        Typeface if previously set, nullptr otherwise.
     */
    std::shared_ptr<Typeface> GetTypeface() const;

    /**
     * @brief         Get font edge pixels pattern.
     * @return        Edge pixels pattern.
     */
    FontEdging GetEdging() const;

    /**
     * @brief               Get font hinting pattern.
     * @return              Font hinting level.
     */
    FontHinting GetHinting() const;

    /**
     * @brief         Returns text scale on x-axis.
     * @return        Text horizontal scale.
     */
    scalar GetScaleX() const;

    /**
     * @brief         Returns text skew on x-axis.
     * @return        Additional shear on x-axis relative to y-axis.
     */
    scalar GetSkewX() const;

    /**
     * @brief         Returns true if baselines may be snapped to pixels.
     * @return        True if baselines will be snapped to pixel positions.
     */
    bool IsBaselineSnap() const;

    /**
     * @brief         Returns font bitmaps mode.
     * @return        Font bitmaps mode.
     */
    bool IsEmbeddedBitmaps() const;

    /**
     * @brief         Returns true if bold is approximated by increasing the stroke width.
     * @return        True if bold is approximated through stroke width.
     */
    bool IsEmbolden() const;

    /**
     * @brief         Returns true if the font outline is automatically adjusted.
     * @return        True if the font outline adjusts automatically
     */
    bool IsForceAutoHinting() const;

    /**
     * @brief         Returns true if glyphs may be drawn at sub-pixel offsets.
     * @return        True if glyphs may be drawn at sub-pixel offsets.
     */
    bool IsSubpixel() const;

    /**
     * @brief         Returns true if font and glyph metrics are requested to be linearly scalable.
     * @return        True if font and glyph metrics are requested to be linearly scalable.
     */
    bool IsLinearMetrics() const;

    /**
     * @brief         Returns glyph index for Unicode character.
     * @param uni     Unicode character.
     * @return        Glyph index.
     */
    uint16_t UnicharToGlyph(int32_t uni) const;

    /**
     * @brief               Converts text into glyph indices.
     * @param text          Character storage encoded with TextEncoding.
     * @param byteLength    Length of character storage in bytes.
     * @param glyphs        Storage for glyph indices; may be nullptr.
     * @param maxGlyphCount Storage capacity.
     * @return              Number of glyphs represented by text of length byteLength.
     */
    int TextToGlyphs(const void* text, size_t byteLength, TextEncoding encoding,
        uint16_t glyphs[], int maxGlyphCount) const;

    /**
     * @brief             Measure the width of text.
     * @param text        Character storage encoded with TextEncoding
     * @param byteLength  Length of character storage in bytes
     * @param encoding    Text encoding.
     * @param bounds      Bounding box relative to (0, 0)
     * @return            The width of text.
     */
    scalar MeasureText(const void* text, size_t byteLength, TextEncoding encoding, Rect* bounds = nullptr) const;

    /**
     * @brief             Measures the width of text with brush or pen, brush and pen are both not nullptr.
     * @param text        Character storage encoded with TextEncoding
     * @param byteLength  Length of character storage in bytes
     * @param encoding    Text encoding.
     * @param bounds      Bounding box relative to (0, 0)
     * @param Brush       Brush to apply transparency, filtering, and so on.
     * @param Pen         Pen to apply transparency, filtering, and so on.
     * @return            The width of text.
     */
    scalar MeasureText(const void* text, size_t byteLength, TextEncoding encoding, Rect* bounds, const Brush* brush,
        const Pen* pen) const;

    /**
     * @brief           Retrieves the positions for each glyph, beginning at the specified origin,
     *                  brush and pen are both not nullptr.
     * @param glyphs    Indicates the array of glyph indices to be measured.
     * @param count     Indicates the number of glyphs.
     * @param widths    Indicates the text advances for each glyph returned to the caller.
     * @param bounds    Indicates the text bounding box for each glyph returned to caller.
     * @param brush     Brush to apply transparency, filtering, and so on.
     * @param pen       Pen to apply transparency, filtering, and so on.
     */
    void GetWidthsBounds(
        const uint16_t glyphs[], int count, float widths[], Rect bounds[], const Brush* brush, const Pen* pen) const;

    /**
     * @brief           Retrieves the positions for each glyph, beginning at the specified origin.
     * @param glyphs    Indicates the array of glyph indices to be measured.
     * @param count     Indicates the number of glyphs.
     * @param origin    Indicates the location of the first glyph.
     * @param points    Indicates the relative position for each glyph returned to tha caller.
     */
    void GetPos(const uint16_t glyphs[], int count, Point points[], Point origin) const;

    /**
     * @brief     Returns the recommended spacing between lines.
     * @return    Spacing between lines.
     */
    float GetSpacing() const;

    /**
     * @brief          Measure the width of a single character.
     * @param unicode  unicode encoding of a single character.
     * @return         The width of a single character.
     */
    scalar MeasureSingleCharacter(int32_t unicode) const;

    /**
     * @brief          Gets a font where you can draw a single character.
     * @param unicode  unicode encoding of a single character.
     * @return         A pointer to font, if nullptr is returned, get failed.
     */
    std::shared_ptr<Font> GetFallbackFont(int32_t unicode) const;

    int CountText(const void* text, size_t byteLength, TextEncoding encoding) const;

    /**
     * @brief          Gets the path of specified glyph.
     * @param glyph    The glyph index.
     * @param path     The pointer of path object.
     * @return         True if success, false if no path found.
     */
    bool GetPathForGlyph(uint16_t glyph, Path* path) const;

    /**
     * @brief            Get the text outline path.
     * @param text       Indicates the character storage encoded with text encoding.
     * @param byteLength Indicates the text length in bytes.
     * @param encoding   Indicates the text encoding.
     * @param x          Indicates x coordinates of the text.
     * @param y          Indicates y coordinates of the text.
     * @param path       The pointer of path object.
     */
    void GetTextPath(const void* text, size_t byteLength, TextEncoding encoding, float x, float y, Path* path) const;

    /**
     * @brief             Sets whether to follow the theme font. If the value is true, the theme font is used when typeface is not set.
     * @param followed    Indicates whether to follow the theme font.
     */
    void SetThemeFontFollowed(bool followed);

    /**
     * @brief          Gets whether to follow the theme font.
     * @return         True if follow the theme font.
     */
    bool IsThemeFontFollowed() const;

    template<typename T>
    T* GetImpl() const
    {
        return fontImpl_->DowncastingTo<T>();
    }

private:
    bool themeFontFollowed_ = false; // Only effective for ndk interface and ArkTS interface.
    std::shared_ptr<FontImpl> fontImpl_;
};
} // namespace Drawing
} // namespace Rosen
} // namespace OHOS
#endif