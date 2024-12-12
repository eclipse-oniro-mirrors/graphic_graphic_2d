/*
 * Copyright (C) 2023 Huawei Device Co., Ltd.
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

#include "drawing_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "drawing_bitmap.h"
#include "drawing_brush.h"
#include "drawing_canvas.h"
#include "drawing_color.h"
#include "drawing_font_collection.h"
#include "drawing_path.h"
#include "drawing_pen.h"
#include "drawing_point.h"
#include "drawing_rect.h"
#include "drawing_shadow_layer.h"
#include "drawing_text_declaration.h"
#include "drawing_text_line.h"
#include "drawing_text_lineTypography.h"
#include "drawing_text_typography.h"
#include "drawing_types.h"
#include "get_object.h"
#include "rosen_text/typography.h"
#include "rosen_text/typography_create.h"

#include "draw/brush.h"

namespace OHOS::Rosen::Drawing {
void NativeDrawingBitmapTest(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return;
    }
    // initialize
    g_data = data;
    g_size = size;
    g_pos = 0;

    uint32_t width = GetObject<uint32_t>() % DATA_MAX_RANDOM;
    uint32_t height = GetObject<uint32_t>() % DATA_MAX_RANDOM;
    OH_Drawing_Bitmap* bitmap = OH_Drawing_BitmapCreate();
    OH_Drawing_BitmapFormat bitmapFormat { GetObject<OH_Drawing_ColorFormat>(), GetObject<OH_Drawing_AlphaFormat>() };
    OH_Drawing_BitmapBuild(bitmap, width, height, &bitmapFormat);
    OH_Drawing_BitmapDestroy(bitmap);
}

void NativeDrawingBrushTest(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return;
    }
    // initialize
    g_data = data;
    g_size = size;
    g_pos = 0;

    uint32_t red = GetObject<uint32_t>() % DATA_MAX_RANDOM;
    uint32_t gree = GetObject<uint32_t>() % DATA_MAX_RANDOM;
    uint32_t blue = GetObject<uint32_t>() % DATA_MAX_RANDOM;
    uint32_t alpha = GetObject<uint32_t>() % DATA_MAX_RANDOM;
    OH_Drawing_Brush* brush = OH_Drawing_BrushCreate();
    OH_Drawing_BrushSetAntiAlias(brush, false);
    OH_Drawing_BrushIsAntiAlias(brush);
    OH_Drawing_BrushSetColor(brush, OH_Drawing_ColorSetArgb(alpha, red, gree, blue));
    OH_Drawing_BrushGetColor(brush);
    OH_Drawing_BrushDestroy(brush);
}

void NativeDrawingCanvasBitmapTest(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return;
    }
    // initialize
    g_data = data;
    g_size = size;
    g_pos = 0;

    OH_Drawing_Canvas* canvas = OH_Drawing_CanvasCreate();
    OH_Drawing_Bitmap* bitmap = OH_Drawing_BitmapCreate();
    OH_Drawing_CanvasBind(canvas, bitmap);
    OH_Drawing_CanvasDestroy(canvas);
    OH_Drawing_BitmapDestroy(bitmap);
}

void NativeDrawingCanvasPenTest(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return;
    }
    // initialize
    g_data = data;
    g_size = size;
    g_pos = 0;

    OH_Drawing_Canvas* canvas = OH_Drawing_CanvasCreate();
    OH_Drawing_Pen* pen = OH_Drawing_PenCreate();
    OH_Drawing_CanvasAttachPen(canvas, pen);
    OH_Drawing_CanvasDetachPen(canvas);
    OH_Drawing_CanvasDestroy(canvas);
    OH_Drawing_PenDestroy(pen);
}

void NativeDrawingCanvasBrushTest(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return;
    }
    // initialize
    g_data = data;
    g_size = size;
    g_pos = 0;

    OH_Drawing_Canvas* canvas = OH_Drawing_CanvasCreate();
    OH_Drawing_Brush* brush = OH_Drawing_BrushCreate();
    OH_Drawing_CanvasAttachBrush(canvas, brush);
    OH_Drawing_CanvasDetachBrush(canvas);
    OH_Drawing_CanvasDestroy(canvas);
    OH_Drawing_BrushDestroy(brush);
}

void NativeDrawingCanvasDrawLineTest(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return;
    }
    // initialize
    g_data = data;
    g_size = size;
    g_pos = 0;

    uint32_t x1 = GetObject<uint32_t>() % DATA_MAX_RANDOM;
    uint32_t y1 = GetObject<uint32_t>() % DATA_MAX_RANDOM;
    uint32_t x2 = GetObject<uint32_t>() % DATA_MAX_RANDOM;
    uint32_t y2 = GetObject<uint32_t>() % DATA_MAX_RANDOM;
    OH_Drawing_Canvas* canvas = OH_Drawing_CanvasCreate();
    OH_Drawing_CanvasDrawLine(canvas, x1, y1, x2, y2);
    OH_Drawing_CanvasDestroy(canvas);
}

void NativeDrawingCanvasDrawPathTest(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return;
    }
    // initialize
    g_data = data;
    g_size = size;
    g_pos = 0;

    OH_Drawing_Canvas* canvas = OH_Drawing_CanvasCreate();
    OH_Drawing_Path* path = OH_Drawing_PathCreate();
    OH_Drawing_CanvasDrawPath(canvas, path);
    OH_Drawing_CanvasSave(canvas);
    OH_Drawing_CanvasRestore(canvas);
    OH_Drawing_CanvasDestroy(canvas);
    OH_Drawing_PathDestroy(path);
}

void NativeDrawingCanvasClearTest(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return;
    }
    // initialize
    g_data = data;
    g_size = size;
    g_pos = 0;

    uint32_t color = GetObject<uint32_t>() % DATA_MAX_RANDOM;
    OH_Drawing_Canvas* canvas = OH_Drawing_CanvasCreate();
    OH_Drawing_CanvasClear(canvas, color);
    OH_Drawing_CanvasDestroy(canvas);
}

void NativeDrawingColorTest(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return;
    }
    // initialize
    g_data = data;
    g_size = size;
    g_pos = 0;

    uint32_t color = GetObject<uint32_t>() % DATA_MAX_RANDOM;
    OH_Drawing_Brush* brush = OH_Drawing_BrushCreate();
    OH_Drawing_BrushSetAntiAlias(brush, GetObject<bool>());
    OH_Drawing_BrushIsAntiAlias(brush);
    OH_Drawing_BrushSetColor(brush, color);
    OH_Drawing_BrushGetColor(brush);
    OH_Drawing_BrushDestroy(brush);
}

void OHDrawingFontCollectionTest(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return;
    }
    // initialize
    g_data = data;
    g_size = size;
    g_pos = 0;

    OH_Drawing_FontCollection* fontCollection = OH_Drawing_CreateFontCollection();
    OH_Drawing_DestroyFontCollection(fontCollection);
}

void NativeDrawingPathMoveToTest(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return;
    }
    // initialize
    g_data = data;
    g_size = size;
    g_pos = 0;

    uint32_t x = GetObject<uint32_t>() % DATA_MAX_RANDOM;
    uint32_t y = GetObject<uint32_t>() % DATA_MAX_RANDOM;
    OH_Drawing_Path* path = OH_Drawing_PathCreate();
    OH_Drawing_PathMoveTo(path, x, y);
    OH_Drawing_PathDestroy(path);
}

void NativeDrawingPathLineToTest(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return;
    }
    // initialize
    g_data = data;
    g_size = size;
    g_pos = 0;

    uint32_t x = GetObject<uint32_t>() % DATA_MAX_RANDOM;
    uint32_t y = GetObject<uint32_t>() % DATA_MAX_RANDOM;
    OH_Drawing_Path* path = OH_Drawing_PathCreate();
    OH_Drawing_PathLineTo(path, x, y);
    OH_Drawing_PathDestroy(path);
}

void NativeDrawingPathResetTest(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return;
    }
    // initialize
    g_data = data;
    g_size = size;
    g_pos = 0;

    uint32_t x = GetObject<uint32_t>() % DATA_MAX_RANDOM;
    uint32_t y = GetObject<uint32_t>() % DATA_MAX_RANDOM;
    OH_Drawing_Path* path = OH_Drawing_PathCreate();
    OH_Drawing_PathMoveTo(path, x, y);
    OH_Drawing_PathReset(path);
    OH_Drawing_PathDestroy(path);
}

void NativeDrawingPathArcToTest(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return;
    }
    // initialize
    g_data = data;
    g_size = size;
    g_pos = 0;

    uint32_t x1 = GetObject<uint32_t>() % DATA_MAX_RANDOM;
    uint32_t y1 = GetObject<uint32_t>() % DATA_MAX_RANDOM;
    uint32_t x2 = GetObject<uint32_t>() % DATA_MAX_RANDOM;
    uint32_t y2 = GetObject<uint32_t>() % DATA_MAX_RANDOM;
    uint32_t startDeg = GetObject<uint32_t>() % DATA_MAX_RANDOM;
    uint32_t sweepDeg = GetObject<uint32_t>() % DATA_MAX_RANDOM;
    OH_Drawing_Path* path = OH_Drawing_PathCreate();
    OH_Drawing_PathArcTo(path, x1, y1, x2, y2, startDeg, sweepDeg);
    OH_Drawing_PathDestroy(path);
}

void NativeDrawingPathQuadToTest(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return;
    }
    // initialize
    g_data = data;
    g_size = size;
    g_pos = 0;

    uint32_t ctrlX = GetObject<uint32_t>() % DATA_MAX_RANDOM;
    uint32_t ctrlY = GetObject<uint32_t>() % DATA_MAX_RANDOM;
    uint32_t endX = GetObject<uint32_t>() % DATA_MAX_RANDOM;
    uint32_t endY = GetObject<uint32_t>() % DATA_MAX_RANDOM;
    OH_Drawing_Path* path = OH_Drawing_PathCreate();
    OH_Drawing_PathQuadTo(path, ctrlX, ctrlY, endX, endY);
    OH_Drawing_PathDestroy(path);
}

void NativeDrawingPathCubicToTest(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return;
    }
    // initialize
    g_data = data;
    g_size = size;
    g_pos = 0;

    uint32_t ctrlX1 = GetObject<uint32_t>() % DATA_MAX_RANDOM;
    uint32_t ctrlY1 = GetObject<uint32_t>() % DATA_MAX_RANDOM;
    uint32_t ctrlX2 = GetObject<uint32_t>() % DATA_MAX_RANDOM;
    uint32_t ctrlY2 = GetObject<uint32_t>() % DATA_MAX_RANDOM;
    uint32_t endX = GetObject<uint32_t>() % DATA_MAX_RANDOM;
    uint32_t endY = GetObject<uint32_t>() % DATA_MAX_RANDOM;
    OH_Drawing_Path* path = OH_Drawing_PathCreate();
    OH_Drawing_PathCubicTo(path, ctrlX1, ctrlY1, ctrlX2, ctrlY2, endX, endY);
    OH_Drawing_PathDestroy(path);
}

void NativeDrawingPathCloseTest(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return;
    }
    // initialize
    g_data = data;
    g_size = size;
    g_pos = 0;

    uint32_t x = GetObject<uint32_t>() % DATA_MAX_RANDOM;
    uint32_t y = GetObject<uint32_t>() % DATA_MAX_RANDOM;
    OH_Drawing_Path* path = OH_Drawing_PathCreate();
    OH_Drawing_PathLineTo(path, x, y);
    OH_Drawing_PathClose(path);
    OH_Drawing_PathDestroy(path);
}

void OHDrawingTextLineArray(OH_Drawing_Array* linesArray, const uint8_t* data, size_t size)
{
    g_data = data;
    g_size = size;
    g_pos = 0;
    size_t linesSize = OH_Drawing_GetDrawingArraySize(linesArray);
    OH_Drawing_GetTextLineByIndex(nullptr, linesSize - 1);
    OH_Drawing_TextLine* line = OH_Drawing_GetTextLineByIndex(linesArray, linesSize - 1);
    OH_Drawing_TextLineGetGlyphCount(nullptr);
    OH_Drawing_TextLineGetGlyphCount(line);
    size_t start = 0, end = 1;
    OH_Drawing_TextLineGetTextRange(nullptr, &start, &end);
    OH_Drawing_TextLineGetTextRange(line, &start, &end);
    OH_Drawing_TextLineGetGlyphRuns(nullptr);
    OH_Drawing_Array* runs = OH_Drawing_TextLineGetGlyphRuns(line);
    OH_Drawing_GetRunByIndex(runs, 0);
    OH_Drawing_GetRunByIndex(nullptr, GetObject<size_t>() % DATA_MAX_RANDOM);
    OH_Drawing_GetDrawingArraySize(nullptr);
    OH_Drawing_GetDrawingArraySize(runs);
    OH_Drawing_DestroyRuns(runs);
    OH_Drawing_TextLinePaint(
        nullptr, nullptr, GetObject<uint32_t>() % DATA_MAX_RANDOM, GetObject<uint32_t>() % DATA_MAX_RANDOM);
    auto canvas = OH_Drawing_CanvasCreate();
    OH_Drawing_TextLinePaint(
        line, canvas, GetObject<uint32_t>() % DATA_MAX_RANDOM, GetObject<uint32_t>() % DATA_MAX_RANDOM);
    OH_Drawing_CanvasDestroy(canvas);
    double ascent = 0.0, descent = 0.0, leading = 0.0;
    OH_Drawing_TextLineGetTypographicBounds(nullptr, &ascent, &descent, &leading);
    OH_Drawing_TextLineGetTypographicBounds(line, &ascent, &descent, &leading);
    OH_Drawing_TextLineGetImageBounds(nullptr);
    OH_Drawing_RectDestroy(OH_Drawing_TextLineGetImageBounds(line));
    OH_Drawing_TextLineGetTrailingSpaceWidth(nullptr);
    OH_Drawing_TextLineGetTrailingSpaceWidth(line);
    const char* ellipsis = "...";
    OH_Drawing_TextLineCreateTruncatedLine(nullptr, DATA_MAX_LAYOUT_WIDTH, 0, ellipsis);
    OH_Drawing_TextLine* truncatedLine =
        OH_Drawing_TextLineCreateTruncatedLine(line, DATA_MAX_LAYOUT_WIDTH, 0, ellipsis);
    OH_Drawing_DestroyTextLine(truncatedLine);
    uint32_t pointX = GetObject<uint32_t>() % DATA_MAX_RANDOM;
    uint32_t pointY = GetObject<uint32_t>() % DATA_MAX_RANDOM;
    OH_Drawing_Point* point = OH_Drawing_PointCreate(pointX, pointY);
    int32_t index = OH_Drawing_TextLineGetStringIndexForPosition(line, point);
    int32_t index1 = OH_Drawing_TextLineGetStringIndexForPosition(nullptr, point);
    OH_Drawing_PointDestroy(point);
    OH_Drawing_TextLineGetOffsetForStringIndex(line, index);
    OH_Drawing_TextLineGetOffsetForStringIndex(nullptr, index1);
    OH_Drawing_TextLineEnumerateCaretOffsets(line, [](double, int, bool) { return false; });
    OH_Drawing_TextLineEnumerateCaretOffsets(line, nullptr);
    OH_Drawing_TextLineGetAlignmentOffset(line, GetObject<uint32_t>() % DATA_MAX_RANDOM, DATA_MAX_LAYOUT_WIDTH);
    OH_Drawing_TextLineGetAlignmentOffset(nullptr, GetObject<uint32_t>() % DATA_MAX_RANDOM, DATA_MAX_LAYOUT_WIDTH);
    OH_Drawing_DestroyTextLine(line);
}

void OHDrawTextLineTest(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return;
    }
    g_data = data;
    g_size = size;
    g_pos = 0;

    uint32_t width = GetObject<uint32_t>() % DATA_MAX_RANDOM;
    uint32_t red = GetObject<uint32_t>() % DATA_MAX_RANDOM;
    uint32_t gree = GetObject<uint32_t>() % DATA_MAX_RANDOM;
    uint32_t blue = GetObject<uint32_t>() % DATA_MAX_RANDOM;
    uint32_t alpha = GetObject<uint32_t>() % DATA_MAX_RANDOM;
    uint32_t fontSize = GetObject<uint32_t>() % DATA_MAX_RANDOM;
    OH_Drawing_TypographyStyle* typoStyle = OH_Drawing_CreateTypographyStyle();
    OH_Drawing_TextStyle* txtStyle = OH_Drawing_CreateTextStyle();
    OH_Drawing_FontCollection* fontCollection = OH_Drawing_CreateFontCollection();
    OH_Drawing_TypographyCreate* handler = OH_Drawing_CreateTypographyHandler(typoStyle, fontCollection);
    OH_Drawing_DestroyFontCollection(fontCollection);
    OH_Drawing_SetTextStyleFontWeight(txtStyle, width);
    OH_Drawing_TypographyHandlerPopTextStyle(handler);
    OH_Drawing_SetTextStyleFontWeight(txtStyle, FONT_WEIGHT_400);
    OH_Drawing_SetTextStyleColor(txtStyle, OH_Drawing_ColorSetArgb(alpha, red, gree, blue));
    OH_Drawing_SetTextStyleFontSize(txtStyle, fontSize);
    OH_Drawing_SetTextStyleBaseLine(txtStyle, TEXT_BASELINE_ALPHABETIC);
    const char* fontFamilies[] = { "Roboto" };
    OH_Drawing_SetTextStyleFontFamilies(txtStyle, 1, fontFamilies);
    OH_Drawing_TypographyHandlerPushTextStyle(handler, txtStyle);
    std::string text = "Hello World 测试文本";
    OH_Drawing_TypographyHandlerAddText(handler, text.c_str());
    OH_Drawing_Typography* typography = OH_Drawing_CreateTypography(handler);
    OH_Drawing_TypographyLayout(typography, DATA_MAX_LAYOUT_WIDTH);
    OH_Drawing_TypographyGetTextLines(nullptr);
    OH_Drawing_Array* linesArray = OH_Drawing_TypographyGetTextLines(typography);
    OHDrawingTextLineArray(linesArray, data, size);
    OH_Drawing_DestroyTypography(typography);
    OH_Drawing_DestroyTypographyHandler(handler);
    OH_Drawing_DestroyTypographyStyle(typoStyle);
    OH_Drawing_DestroyTextStyle(txtStyle);
    OH_Drawing_DestroyTextLines(linesArray);
}

void OHDrawingLineTypographyTest(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return;
    }
    // initialize
    g_data = data;
    g_size = size;
    g_pos = 0;

    uint32_t red = GetObject<uint32_t>() % DATA_MAX_RANDOM;
    uint32_t gree = GetObject<uint32_t>() % DATA_MAX_RANDOM;
    uint32_t blue = GetObject<uint32_t>() % DATA_MAX_RANDOM;
    uint32_t alpha = GetObject<uint32_t>() % DATA_MAX_RANDOM;
    OH_Drawing_TypographyStyle* typographStyle = OH_Drawing_CreateTypographyStyle();
    OH_Drawing_TextStyle* textStyle = OH_Drawing_CreateTextStyle();
    OH_Drawing_FontCollection* fontCollection = OH_Drawing_CreateFontCollection();
    OH_Drawing_TypographyCreate* createHandler = OH_Drawing_CreateTypographyHandler(typographStyle, fontCollection);
    OH_Drawing_DestroyFontCollection(fontCollection);
    OH_Drawing_SetTextStyleColor(textStyle, OH_Drawing_ColorSetArgb(alpha, red, gree, blue));
    OH_Drawing_SetTextStyleFontSize(textStyle, DATA_MAX_ENUM_FONTSIZE);
    OH_Drawing_SetTextStyleFontWeight(textStyle, FONT_WEIGHT_400);
    OH_Drawing_SetTextStyleBaseLine(textStyle, TEXT_BASELINE_ALPHABETIC);
    const char* fontFamilies[] = { "Roboto" };
    OH_Drawing_SetTextStyleFontFamilies(textStyle, 1, fontFamilies);
    OH_Drawing_TypographyHandlerPushTextStyle(createHandler, textStyle);
    std::string text = "Hello \t 中国 测 World \n !@#$%^&*~(){}[] 123 4567890 - = ,. < >、/Drawing testlp ";
    text += "试 Drawing \n\n   \u231A \u513B \u00A9\uFE0F aaa "
            "clp11⌚😀😁🤣👨‍🔬👩‍👩‍👧‍👦👭مرحبا中国 测 "
            "World测试文本";
    OH_Drawing_TypographyHandlerAddText(createHandler, text.c_str());
    OH_Drawing_TypographyGetTextLines(nullptr);
    OH_Drawing_LineTypography* lineTypography = OH_Drawing_CreateLineTypography(createHandler);
    OH_Drawing_CreateLineTypography(nullptr);
    if (lineTypography == nullptr) {
        return;
    }
    size_t startIndex = GetObject<size_t>() % DATA_MAX_RANDOM;
    auto count = OH_Drawing_LineTypographyGetLineBreak(lineTypography, startIndex, DATA_MAX_LAYOUT_WIDTH);
    OH_Drawing_TextLine* line = OH_Drawing_LineTypographyCreateLine(lineTypography, startIndex, count);
    OH_Drawing_DestroyTextLine(line);

    OH_Drawing_DestroyLineTypography(lineTypography);
    OH_Drawing_DestroyTypographyHandler(createHandler);
    OH_Drawing_DestroyTypographyStyle(typographStyle);
    OH_Drawing_DestroyTextStyle(textStyle);
}

void NativeDrawingPenTest(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return;
    }
    // initialize
    g_data = data;
    g_size = size;
    g_pos = 0;

    uint32_t red = GetObject<uint32_t>() % DATA_MAX_RANDOM;
    uint32_t gree = GetObject<uint32_t>() % DATA_MAX_RANDOM;
    uint32_t blue = GetObject<uint32_t>() % DATA_MAX_RANDOM;
    uint32_t alpha = GetObject<uint32_t>() % DATA_MAX_RANDOM;
    uint32_t width = GetObject<uint32_t>() % DATA_MAX_RANDOM;
    uint32_t miter = GetObject<uint32_t>() % DATA_MAX_RANDOM;
    OH_Drawing_Pen* pen = OH_Drawing_PenCreate();
    OH_Drawing_PenSetAntiAlias(pen, true);
    OH_Drawing_PenIsAntiAlias(pen);
    OH_Drawing_PenSetColor(pen, OH_Drawing_ColorSetArgb(alpha, red, gree, blue));
    OH_Drawing_PenGetColor(pen);
    OH_Drawing_PenSetWidth(pen, width);
    OH_Drawing_PenGetWidth(pen);
    OH_Drawing_PenSetMiterLimit(pen, miter);
    OH_Drawing_PenGetMiterLimit(pen);
    OH_Drawing_PenSetCap(pen, OH_Drawing_PenLineCapStyle::LINE_SQUARE_CAP);
    OH_Drawing_PenGetCap(pen);
    OH_Drawing_PenSetJoin(pen, OH_Drawing_PenLineJoinStyle::LINE_ROUND_JOIN);
    OH_Drawing_PenGetJoin(pen);
    OH_Drawing_PenDestroy(pen);
}

void NativeDrawingShadowLayerTest(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return;
    }
    // initialize
    g_data = data;
    g_size = size;
    g_pos = 0;

    uint32_t blurRadius = GetObject<uint32_t>() % DATA_MAX_RANDOM;
    uint32_t x = GetObject<uint32_t>() % DATA_MAX_RANDOM;
    uint32_t y = GetObject<uint32_t>() % DATA_MAX_RANDOM;
    uint32_t color = GetObject<uint32_t>() % DATA_MAX_RANDOM;
    OH_Drawing_ShadowLayer* shadowLayer = OH_Drawing_ShadowLayerCreate(blurRadius, x, y, color);
    OH_Drawing_Pen* pen = OH_Drawing_PenCreate();
    OH_Drawing_Brush* brush = OH_Drawing_BrushCreate();
    OH_Drawing_BrushSetShadowLayer(brush, shadowLayer);
    OH_Drawing_PenSetShadowLayer(pen, shadowLayer);
    OH_Drawing_ShadowLayerDestroy(shadowLayer);
    OH_Drawing_PenDestroy(pen);
    OH_Drawing_BrushDestroy(brush);
}

void NativeDrawingTextStyleDecorationTest(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return;
    }
    // initialize
    g_data = data;
    g_size = size;
    g_pos = 0;

    OH_Drawing_TextStyle* txtStyle = OH_Drawing_CreateTextStyle();
    if (txtStyle == nullptr) {
        return;
    }
    uint32_t decorationA = GetObject<uint32_t>() % DATA_MAX_RANDOM;
    uint32_t decorationB = GetObject<uint32_t>() % DATA_MAX_RANDOM;
    OH_Drawing_AddTextStyleDecoration(txtStyle, decorationA);
    OH_Drawing_AddTextStyleDecoration(txtStyle, decorationB);
    OH_Drawing_RemoveTextStyleDecoration(txtStyle, decorationA);
    OH_Drawing_RemoveTextStyleDecoration(txtStyle, decorationB);
    OH_Drawing_DestroyTextStyle(txtStyle);
}

void OHDrawingTextTabTest(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return;
    }
    // initialize
    g_data = data;
    g_size = size;
    g_pos = 0;

    uint32_t location = GetObject<uint32_t>() % DATA_MAX_RANDOM;
    OH_Drawing_TypographyStyle* typoStyle = OH_Drawing_CreateTypographyStyle();
    OH_Drawing_TextTab* tab = OH_Drawing_CreateTextTab(OH_Drawing_TextAlign::TEXT_ALIGN_LEFT, location);
    OH_Drawing_GetTextTabAlignment(tab);
    OH_Drawing_GetTextTabLocation(tab);
    OH_Drawing_SetTypographyTextTab(typoStyle, tab);
    OH_Drawing_DestroyTypographyStyle(typoStyle);
    OH_Drawing_DestroyTextTab(tab);
}
void OHDrawingCreateSharedFontCollectionTest(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return;
    }
    // initialize
    g_data = data;
    g_size = size;
    g_pos = 0;

    // initialize
    OH_Drawing_DisableFontCollectionFallback(nullptr);
    OH_Drawing_DestroyFontCollection(nullptr);
    OH_Drawing_DisableFontCollectionSystemFont(nullptr);
    OH_Drawing_FontCollection* fontCollection = OH_Drawing_CreateSharedFontCollection();
    OH_Drawing_DisableFontCollectionFallback(fontCollection);
    OH_Drawing_DisableFontCollectionSystemFont(fontCollection);
    OH_Drawing_ClearFontCaches(fontCollection);
    OH_Drawing_ClearFontCaches(nullptr);
    OH_Drawing_DestroyFontCollection(fontCollection);
}

void OHDrawingCreateFontCollectionGlobalInstanceTest(const uint8_t* data, size_t size)
{
    if (data == nullptr) {
        return;
    }
    // initialize
    g_data = data;
    g_size = size;
    g_pos = 0;

    // initialize
    OH_Drawing_FontCollection* fontCollection = OH_Drawing_GetFontCollectionGlobalInstance();
    OH_Drawing_DisableFontCollectionFallback(fontCollection);
    OH_Drawing_DisableFontCollectionSystemFont(fontCollection);
    OH_Drawing_ClearFontCaches(fontCollection);
    OH_Drawing_ClearFontCaches(nullptr);
}
} // namespace OHOS::Rosen::Drawing

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    OHOS::Rosen::Drawing::NativeDrawingBitmapTest(data, size);
    OHOS::Rosen::Drawing::NativeDrawingBrushTest(data, size);
    OHOS::Rosen::Drawing::NativeDrawingCanvasBitmapTest(data, size);
    OHOS::Rosen::Drawing::NativeDrawingCanvasPenTest(data, size);
    OHOS::Rosen::Drawing::NativeDrawingCanvasBrushTest(data, size);
    OHOS::Rosen::Drawing::NativeDrawingCanvasDrawLineTest(data, size);
    OHOS::Rosen::Drawing::NativeDrawingCanvasDrawPathTest(data, size);
    OHOS::Rosen::Drawing::NativeDrawingCanvasClearTest(data, size);
    OHOS::Rosen::Drawing::NativeDrawingColorTest(data, size);
    OHOS::Rosen::Drawing::OHDrawingFontCollectionTest(data, size);
    OHOS::Rosen::Drawing::NativeDrawingPathMoveToTest(data, size);
    OHOS::Rosen::Drawing::NativeDrawingPathLineToTest(data, size);
    OHOS::Rosen::Drawing::NativeDrawingPathResetTest(data, size);
    OHOS::Rosen::Drawing::NativeDrawingPathArcToTest(data, size);
    OHOS::Rosen::Drawing::NativeDrawingPathQuadToTest(data, size);
    OHOS::Rosen::Drawing::NativeDrawingPathCubicToTest(data, size);
    OHOS::Rosen::Drawing::NativeDrawingPathCloseTest(data, size);
    OHOS::Rosen::Drawing::OHDrawTextLineTest(data, size);
    OHOS::Rosen::Drawing::OHDrawingLineTypographyTest(data, size);
    OHOS::Rosen::Drawing::NativeDrawingPenTest(data, size);
    OHOS::Rosen::Drawing::NativeDrawingShadowLayerTest(data, size);
    OHOS::Rosen::Drawing::NativeDrawingTextStyleDecorationTest(data, size);
    OHOS::Rosen::Drawing::OHDrawingTextTabTest(data, size);
    OHOS::Rosen::Drawing::OHDrawingCreateSharedFontCollectionTest(data, size);
    return 0;
}
