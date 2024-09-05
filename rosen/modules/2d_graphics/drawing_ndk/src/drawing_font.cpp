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

#include "drawing_font.h"

#include "src/utils/SkUTF.h"

#include "drawing_canvas_utils.h"
#include "text/font.h"

using namespace OHOS;
using namespace Rosen;
using namespace Drawing;

static Font* CastToFont(OH_Drawing_Font* cFont)
{
    return reinterpret_cast<Font*>(cFont);
}

static const Font* CastToFont(const OH_Drawing_Font* cFont)
{
    return reinterpret_cast<const Font*>(cFont);
}

static const Font& CastToFont(const OH_Drawing_Font& cFont)
{
    return reinterpret_cast<const Font&>(cFont);
}

static Typeface* CastToTypeface(OH_Drawing_Typeface* cTypeface)
{
    return reinterpret_cast<Typeface*>(cTypeface);
}

void OH_Drawing_FontSetEdging(OH_Drawing_Font* cFont, OH_Drawing_FontEdging cEdging)
{
    Font* font = CastToFont(cFont);
    if (font == nullptr) {
        g_drawingErrorCode = OH_DRAWING_ERROR_INVALID_PARAMETER;
        return;
    }
    if (cEdging < FONT_EDGING_ALIAS || cEdging > FONT_EDGING_SUBPIXEL_ANTI_ALIAS) {
        g_drawingErrorCode = OH_DRAWING_ERROR_PARAMETER_OUT_OF_RANGE;
        return;
    }
    font->SetEdging(static_cast<FontEdging>(cEdging));
}

OH_Drawing_FontEdging OH_Drawing_FontGetEdging(const OH_Drawing_Font* cFont)
{
    const Font* font = CastToFont(cFont);
    if (font == nullptr) {
        g_drawingErrorCode = OH_DRAWING_ERROR_INVALID_PARAMETER;
        return FONT_EDGING_ALIAS;
    }
    return static_cast<OH_Drawing_FontEdging>(font->GetEdging());
}

void OH_Drawing_FontSetHinting(OH_Drawing_Font* cFont, OH_Drawing_FontHinting cHinting)
{
    Font* font = CastToFont(cFont);
    if (font == nullptr) {
        g_drawingErrorCode = OH_DRAWING_ERROR_INVALID_PARAMETER;
        return;
    }
    if (cHinting < FONT_HINTING_NONE || cHinting > FONT_HINTING_FULL) {
        g_drawingErrorCode = OH_DRAWING_ERROR_PARAMETER_OUT_OF_RANGE;
        return;
    }
    font->SetHinting(static_cast<FontHinting>(cHinting));
}

OH_Drawing_FontHinting OH_Drawing_FontGetHinting(const OH_Drawing_Font* cFont)
{
    const Font* font = CastToFont(cFont);
    if (font == nullptr) {
        g_drawingErrorCode = OH_DRAWING_ERROR_INVALID_PARAMETER;
        return FONT_HINTING_NONE;
    }
    return static_cast<OH_Drawing_FontHinting>(font->GetHinting());
}

void OH_Drawing_FontSetForceAutoHinting(OH_Drawing_Font* cFont, bool isForceAutoHinting)
{
    Font* font = CastToFont(cFont);
    if (font == nullptr) {
        g_drawingErrorCode = OH_DRAWING_ERROR_INVALID_PARAMETER;
        return;
    }
    font->SetForceAutoHinting(isForceAutoHinting);
}

bool OH_Drawing_FontIsForceAutoHinting(const OH_Drawing_Font* cFont)
{
    const Font* font = CastToFont(cFont);
    if (font == nullptr) {
        g_drawingErrorCode = OH_DRAWING_ERROR_INVALID_PARAMETER;
        return false;
    }
    return font->IsForceAutoHinting();
}

void OH_Drawing_FontSetBaselineSnap(OH_Drawing_Font* cFont, bool baselineSnap)
{
    Font* font = CastToFont(cFont);
    if (font == nullptr) {
        g_drawingErrorCode = OH_DRAWING_ERROR_INVALID_PARAMETER;
        return;
    }
    font->SetBaselineSnap(baselineSnap);
}

bool OH_Drawing_FontIsBaselineSnap(const OH_Drawing_Font* cFont)
{
    const Font* font = CastToFont(cFont);
    if (font == nullptr) {
        g_drawingErrorCode = OH_DRAWING_ERROR_INVALID_PARAMETER;
        return false;
    }
    return font->IsBaselineSnap();
}

void OH_Drawing_FontSetSubpixel(OH_Drawing_Font* cFont, bool isSubpixel)
{
    Font* font = CastToFont(cFont);
    if (font == nullptr) {
        g_drawingErrorCode = OH_DRAWING_ERROR_INVALID_PARAMETER;
        return;
    }
    font->SetSubpixel(isSubpixel);
}

bool OH_Drawing_FontIsSubpixel(const OH_Drawing_Font* cFont)
{
    const Font* font = CastToFont(cFont);
    if (font == nullptr) {
        g_drawingErrorCode = OH_DRAWING_ERROR_INVALID_PARAMETER;
        return false;
    }
    return font->IsSubpixel();
}

OH_Drawing_Font* OH_Drawing_FontCreate()
{
    Font* font = new Font();
    font->SetTypeface(g_LoadZhCnTypeface());
    return (OH_Drawing_Font*)font;
}

void OH_Drawing_FontSetTypeface(OH_Drawing_Font* cFont, OH_Drawing_Typeface* cTypeface)
{
    Font* font = CastToFont(cFont);
    if (font == nullptr) {
        g_drawingErrorCode = OH_DRAWING_ERROR_INVALID_PARAMETER;
        return;
    }
    font->SetTypeface(std::shared_ptr<Typeface>{CastToTypeface(cTypeface), [](auto p) {}});
}

OH_Drawing_Typeface* OH_Drawing_FontGetTypeface(OH_Drawing_Font* cFont)
{
    Font* font = CastToFont(cFont);
    if (font == nullptr) {
        g_drawingErrorCode = OH_DRAWING_ERROR_INVALID_PARAMETER;
        return nullptr;
    }
    return (OH_Drawing_Typeface*)(font->GetTypeface().get());
}

void OH_Drawing_FontSetTextSize(OH_Drawing_Font* cFont, float textSize)
{
    Font* font = CastToFont(cFont);
    if (font == nullptr) {
        g_drawingErrorCode = OH_DRAWING_ERROR_INVALID_PARAMETER;
        return;
    }
    font->SetSize(textSize);
}

float OH_Drawing_FontGetTextSize(const OH_Drawing_Font* cFont)
{
    const Font* font = CastToFont(cFont);
    if (font == nullptr) {
        g_drawingErrorCode = OH_DRAWING_ERROR_INVALID_PARAMETER;
        return -1.0f;
    }
    return font->GetSize();
}

int OH_Drawing_FontCountText(OH_Drawing_Font* cFont, const void* text, size_t byteLength,
    OH_Drawing_TextEncoding encoding)
{
    if (cFont == nullptr || text == nullptr) {
        g_drawingErrorCode = OH_DRAWING_ERROR_INVALID_PARAMETER;
        return 0;
    }
    Font* font = CastToFont(cFont);
    return font->CountText(text, byteLength, static_cast<TextEncoding>(encoding));
}

uint32_t OH_Drawing_FontTextToGlyphs(const OH_Drawing_Font* cFont, const void* text, uint32_t byteLength,
    OH_Drawing_TextEncoding encoding, uint16_t* glyphs, int maxGlyphCount)
{
    if (cFont == nullptr || text == nullptr || glyphs == nullptr || byteLength == 0 || maxGlyphCount <= 0) {
        g_drawingErrorCode = OH_DRAWING_ERROR_INVALID_PARAMETER;
        return 0;
    }
    return CastToFont(*cFont).TextToGlyphs(text, byteLength,
        static_cast<TextEncoding>(encoding), glyphs, maxGlyphCount);
}

void OH_Drawing_FontGetWidths(const OH_Drawing_Font* cFont, const uint16_t* glyphs, int count, float* widths)
{
    if (cFont == nullptr || glyphs == nullptr || widths == nullptr || count <= 0) {
        g_drawingErrorCode = OH_DRAWING_ERROR_INVALID_PARAMETER;
        return;
    }
    CastToFont(*cFont).GetWidths(glyphs, count, widths);
}

OH_Drawing_ErrorCode OH_Drawing_FontMeasureSingleCharacter(const OH_Drawing_Font* cFont, const char* str,
    float* textWidth)
{
    if (cFont == nullptr || str == nullptr || textWidth == nullptr) {
        return OH_DRAWING_ERROR_INVALID_PARAMETER;
    }
    size_t len = strlen(str);
    if (len == 0) {
        return OH_DRAWING_ERROR_INVALID_PARAMETER;
    }
    const char* currentStr = str;
    int32_t unicode = SkUTF::NextUTF8(&currentStr, currentStr + len);
    *textWidth = CastToFont(*cFont).MeasureSingleCharacter(unicode);
    return OH_DRAWING_SUCCESS;
}

OH_Drawing_ErrorCode OH_Drawing_FontMeasureText(const OH_Drawing_Font* cFont, const void* text, size_t byteLength,
    OH_Drawing_TextEncoding encoding, OH_Drawing_Rect* bounds, float* textWidth)
{
    if (cFont == nullptr || text == nullptr || byteLength == 0 || textWidth == nullptr) {
        return OH_DRAWING_ERROR_INVALID_PARAMETER;
    }

    *textWidth = CastToFont(*cFont).MeasureText(text, byteLength,
        static_cast<TextEncoding>(encoding), reinterpret_cast<Drawing::Rect*>(bounds));
    return OH_DRAWING_SUCCESS;
}

void OH_Drawing_FontSetLinearText(OH_Drawing_Font* cFont, bool isLinearText)
{
    Font* font = CastToFont(cFont);
    if (font == nullptr) {
        g_drawingErrorCode = OH_DRAWING_ERROR_INVALID_PARAMETER;
        return;
    }
    font->SetLinearMetrics(isLinearText);
}

bool OH_Drawing_FontIsLinearText(const OH_Drawing_Font* cFont)
{
    const Font* font = CastToFont(cFont);
    if (font == nullptr) {
        g_drawingErrorCode = OH_DRAWING_ERROR_INVALID_PARAMETER;
        return false;
    }
    return font->IsLinearMetrics();
}

void OH_Drawing_FontSetTextSkewX(OH_Drawing_Font* cFont, float skewX)
{
    Font* font = CastToFont(cFont);
    if (font == nullptr) {
        g_drawingErrorCode = OH_DRAWING_ERROR_INVALID_PARAMETER;
        return;
    }
    font->SetSkewX(skewX);
}

float OH_Drawing_FontGetTextSkewX(const OH_Drawing_Font* cFont)
{
    const Font* font = CastToFont(cFont);
    if (font == nullptr) {
        g_drawingErrorCode = OH_DRAWING_ERROR_INVALID_PARAMETER;
        return -1.0f;
    }
    return font->GetSkewX();
}

void OH_Drawing_FontSetFakeBoldText(OH_Drawing_Font* cFont, bool isFakeBoldText)
{
    Font* font = CastToFont(cFont);
    if (font == nullptr) {
        g_drawingErrorCode = OH_DRAWING_ERROR_INVALID_PARAMETER;
        return;
    }
    font->SetEmbolden(isFakeBoldText);
}

bool OH_Drawing_FontIsFakeBoldText(const OH_Drawing_Font* cFont)
{
    const Font* font = CastToFont(cFont);
    if (font == nullptr) {
        g_drawingErrorCode = OH_DRAWING_ERROR_INVALID_PARAMETER;
        return false;
    }
    return font->IsEmbolden();
}

void OH_Drawing_FontSetScaleX(OH_Drawing_Font* cFont, float scaleX)
{
    Font* font = CastToFont(cFont);
    if (font == nullptr) {
        g_drawingErrorCode = OH_DRAWING_ERROR_INVALID_PARAMETER;
        return;
    }
    font->SetScaleX(scaleX);
}

float OH_Drawing_FontGetScaleX(const OH_Drawing_Font* cFont)
{
    const Font* font = CastToFont(cFont);
    if (font == nullptr) {
        g_drawingErrorCode = OH_DRAWING_ERROR_INVALID_PARAMETER;
        return -1.0f;
    }
    return font->GetScaleX();
}

void OH_Drawing_FontSetEmbeddedBitmaps(OH_Drawing_Font* cFont, bool isEmbeddedBitmaps)
{
    Font* font = CastToFont(cFont);
    if (font == nullptr) {
        g_drawingErrorCode = OH_DRAWING_ERROR_INVALID_PARAMETER;
        return;
    }
    font->SetEmbeddedBitmaps(isEmbeddedBitmaps);
}

bool OH_Drawing_FontIsEmbeddedBitmaps(const OH_Drawing_Font* cFont)
{
    const Font* font = CastToFont(cFont);
    if (font == nullptr) {
        g_drawingErrorCode = OH_DRAWING_ERROR_INVALID_PARAMETER;
        return false;
    }
    return font->IsEmbeddedBitmaps();
}

void OH_Drawing_FontDestroy(OH_Drawing_Font* cFont)
{
    if (!cFont) {
        return;
    }
    delete CastToFont(cFont);
}

float OH_Drawing_FontGetMetrics(OH_Drawing_Font* cFont, OH_Drawing_Font_Metrics* cFontMetrics)
{
    float ret = -1;
    Font* font = CastToFont(cFont);
    if (font == nullptr || cFontMetrics == nullptr) {
        g_drawingErrorCode = OH_DRAWING_ERROR_INVALID_PARAMETER;
        return ret;
    }
    FontMetrics metrics;
    ret = font->GetMetrics(&metrics);

    cFontMetrics->top = metrics.fTop;
    cFontMetrics->ascent = metrics.fAscent;
    cFontMetrics->descent = metrics.fDescent;
    cFontMetrics->leading = metrics.fLeading;
    cFontMetrics->bottom = metrics.fBottom;
    return ret;
}