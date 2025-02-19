/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "../../dtk_test_ext.h"
#include <string>
#include "text/font.h"
#include "text/font_mgr.h"
#include "text/font_style_set.h"
#include "text/font_style.h"
#include "text/typeface.h"
#include <sstream>

namespace OHOS {
namespace Rosen {

static Drawing::Font MakeFont1(Drawing::Font& font,
    std::shared_ptr<Drawing::Typeface> typeface, float size, float scalex, float skewx)
{
    font.SetTypeface(typeface);
    font.SetSize(size);
    font.SetScaleX(scalex);
    font.SetSkewX(skewx);
    auto font1 = Drawing::Font(font.GetTypeface(), font.GetSize(), font.GetScaleX(), font.GetSkewX());
    font.SetSubpixel(false);
    font1.SetSubpixel(false);

    return font1;
}

static std::string g_text1 = "DDGR ddgr 鸿蒙 !@#%￥^&*;：，。";
static std::string g_text2 = "-_=+()123`.---~|{}【】,./?、？<>《》";
static std::string g_text3 = "\xE2\x99\x88\xE2\x99\x8A\xE2\x99\x88\xE2\x99\x8C\xE2\x99\x8D\xE2\x99\x8D";
static std::string g_text = g_text1 + g_text2 + g_text3;

static void DrawTexts(std::vector<std::string>& texts, Drawing::Font& font,
                      Drawing::Font& font1, TestPlaybackCanvas* playbackCanvas)
{
    int line = 200;
    int interval1 = 100;
    int interval2 = 200;
    int interval3 = 300;
    int interval4 = 400;

    for (auto text : texts) {
        std::shared_ptr<Drawing::TextBlob> textBlob = Drawing::TextBlob::MakeFromText(text.c_str(), text.size(), font);
        std::shared_ptr<Drawing::TextBlob> textinfo = Drawing::TextBlob::MakeFromText(text.c_str(), text.size(), font1);
        Drawing::Brush brush;
        playbackCanvas->AttachBrush(brush);
        playbackCanvas->DrawTextBlob(textBlob.get(), interval2, line);
        playbackCanvas->DrawTextBlob(textinfo.get(), interval2, line + interval1);
        playbackCanvas->DetachBrush();
        Drawing::Pen pen;
        playbackCanvas->AttachPen(pen);
        playbackCanvas->DrawTextBlob(textBlob.get(), interval2, line + interval2);
        playbackCanvas->DrawTextBlob(textBlob.get(), interval2, line + interval3);
        playbackCanvas->DetachPen();
        line += interval4;
    }
}

// 对应用例 font_font_3292
DEF_DTK(font_font_4, TestLevel::L2, 292)
{
    // 创建typeface
    std::shared_ptr<Drawing::FontMgr> fontMgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string familyName = "HMOS Color Emoji";
    std::shared_ptr<Drawing::FontStyleSet> fontStyleSet(fontMgr->MatchFamily(familyName.c_str()));
    auto typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->CreateTypeface(0));
    
    // 设置fontsize到LinearMetrics的属性
    auto font = Drawing::Font();
    auto font1 = MakeFont1(font, typeface, 0, 1.f, 1.f);
    font.SetBaselineSnap(false);
    font1.SetBaselineSnap(font.IsBaselineSnap());
    font.SetEdging(Drawing::FontEdging::SUBPIXEL_ANTI_ALIAS);
    font1.SetEdging(font.GetEdging());
    font.SetHinting(Drawing::FontHinting::NORMAL);
    font1.SetHinting(font.GetHinting());
    font.SetForceAutoHinting(false);
    font1.SetForceAutoHinting(font.IsForceAutoHinting());
    font.SetEmbeddedBitmaps(false);
    font1.SetEmbeddedBitmaps(font.IsEmbeddedBitmaps());
    font.SetEmbolden(true);
    font1.SetEmbolden(font.IsEmbolden());
    font.SetLinearMetrics(false);
    font1.SetLinearMetrics(font.IsLinearMetrics());

    // font操作接口，如果涉及，获取返回值赋值给text4，并将text4加入vector容器
    Drawing::Rect bounds;
    auto scalar = font.MeasureText(g_text.c_str(), g_text.size(), Drawing::TextEncoding::UTF16, &bounds);
    std::string text4 = "MeasureTextWidths = " + std::to_string(scalar);
    std::vector<std::string> texts = {g_text1, g_text2, g_text3, text4};
    DrawTexts(texts, font, font1, playbackCanvas_);
}

// 对应用例 font_font_3293
DEF_DTK(font_font_4, TestLevel::L2, 293)
{
    // 创建typeface
    std::shared_ptr<Drawing::FontMgr> fontMgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string familyName = "HMOS Color Emoji";
    std::shared_ptr<Drawing::FontStyleSet> fontStyleSet(fontMgr->MatchFamily(familyName.c_str()));
    auto typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->CreateTypeface(0));
    
    // 设置fontsize到LinearMetrics的属性
    auto font = Drawing::Font();
    auto font1 = MakeFont1(font, typeface, 27.13f, 1.f, -30.f);
    font.SetBaselineSnap(true);
    font1.SetBaselineSnap(font.IsBaselineSnap());
    font.SetHinting(Drawing::FontHinting::FULL);
    font1.SetHinting(font.GetHinting());
    font.SetForceAutoHinting(true);
    font1.SetForceAutoHinting(font.IsForceAutoHinting());
    font.SetEmbeddedBitmaps(true);
    font1.SetEmbeddedBitmaps(font.IsEmbeddedBitmaps());
    font.SetEmbolden(true);
    font1.SetEmbolden(font.IsEmbolden());
    font.SetLinearMetrics(true);
    font1.SetLinearMetrics(font.IsLinearMetrics());

    // font操作接口，如果涉及，获取返回值赋值给text4，并将text4加入vector容器
    Drawing::Rect bounds;
    auto scalar = font.MeasureText(g_text.c_str(), g_text.size(), Drawing::TextEncoding::UTF8, &bounds);
    std::string text4 = "MeasureTextWidths = " + std::to_string(scalar);
    std::vector<std::string> texts = {g_text1, g_text2, g_text3, text4};
    DrawTexts(texts, font, font1, playbackCanvas_);
}

// 对应用例 font_font_3294
DEF_DTK(font_font_4, TestLevel::L2, 294)
{
    // 创建typeface
    std::shared_ptr<Drawing::FontMgr> fontMgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string familyName = "HMOS Color Emoji";
    std::shared_ptr<Drawing::FontStyleSet> fontStyleSet(fontMgr->MatchFamily(familyName.c_str()));
    auto typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->CreateTypeface(0));
    
    // 设置fontsize到LinearMetrics的属性
    auto font = Drawing::Font();
    auto font1 = MakeFont1(font, typeface, 27.13f, 1.f, -30.f);
    font.SetEdging(Drawing::FontEdging::ALIAS);
    font1.SetEdging(font.GetEdging());
    font.SetHinting(Drawing::FontHinting::SLIGHT);
    font1.SetHinting(font.GetHinting());

    // font操作接口，如果涉及，获取返回值赋值给text4，并将text4加入vector容器
    int glyphCount = font.CountText(g_text.c_str(), g_text.length(), Drawing::TextEncoding::UTF8);
    uint16_t glyphs[glyphCount];
    int count = font.TextToGlyphs(g_text.c_str(), g_text.length(), Drawing::TextEncoding::GLYPH_ID,
        glyphs, glyphCount + 1);
    std::string text4 = "GlyphsCount = " + std::to_string(count);
    std::vector<std::string> texts = {g_text1, g_text2, g_text3, text4};
    DrawTexts(texts, font, font1, playbackCanvas_);
}

// 对应用例 font_font_3295
DEF_DTK(font_font_4, TestLevel::L2, 295)
{
    // 创建typeface
    std::shared_ptr<Drawing::FontMgr> fontMgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string familyName = "HMOS Color Emoji";
    std::shared_ptr<Drawing::FontStyleSet> fontStyleSet(fontMgr->MatchFamily(familyName.c_str()));
    auto typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->CreateTypeface(0));
    
    // 设置fontsize到LinearMetrics的属性
    auto font = Drawing::Font();
    auto font1 = MakeFont1(font, typeface, 27.13f, 30.f, 30.f);
    font.SetHinting(Drawing::FontHinting::FULL);
    font1.SetHinting(font.GetHinting());
    font.SetEmbolden(false);
    font1.SetEmbolden(font.IsEmbolden());

    // font操作接口，如果涉及，获取返回值赋值给text4，并将text4加入vector容器
    Drawing::Rect bounds;
    auto scalar = font.MeasureText(g_text.c_str(), g_text.size(), Drawing::TextEncoding::UTF32, &bounds);
    std::string text4 = "MeasureTextWidths = " + std::to_string(scalar);
    std::vector<std::string> texts = {g_text1, g_text2, g_text3, text4};
    DrawTexts(texts, font, font1, playbackCanvas_);
}

// 对应用例 font_font_3296
DEF_DTK(font_font_4, TestLevel::L2, 296)
{
    // 创建typeface
    std::shared_ptr<Drawing::FontMgr> fontMgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string familyName = "HMOS Color Emoji";
    std::shared_ptr<Drawing::FontStyleSet> fontStyleSet(fontMgr->MatchFamily(familyName.c_str()));
    auto typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->CreateTypeface(0));
    
    // 设置fontsize到LinearMetrics的属性
    auto font = Drawing::Font();
    auto font1 = MakeFont1(font, typeface, 71.f, -30.f, -30.f);
    font.SetBaselineSnap(true);
    font1.SetBaselineSnap(font.IsBaselineSnap());
    font.SetEdging(Drawing::FontEdging::ALIAS);
    font1.SetEdging(font.GetEdging());
    font.SetHinting(Drawing::FontHinting::SLIGHT);
    font1.SetHinting(font.GetHinting());
    font.SetForceAutoHinting(true);
    font1.SetForceAutoHinting(font.IsForceAutoHinting());
    font.SetEmbeddedBitmaps(true);
    font1.SetEmbeddedBitmaps(font.IsEmbeddedBitmaps());
    font.SetLinearMetrics(true);
    font1.SetLinearMetrics(font.IsLinearMetrics());

    // font操作接口，如果涉及，获取返回值赋值给text4，并将text4加入vector容器
    auto glyphsCount = font.CountText(g_text.c_str(), g_text.length(), Drawing::TextEncoding::GLYPH_ID);
    std::string text4 = "glyphsCount = " + std::to_string(glyphsCount);
    std::vector<std::string> texts = {g_text1, g_text2, g_text3, text4};
    DrawTexts(texts, font, font1, playbackCanvas_);
}

// 对应用例 font_font_3297
DEF_DTK(font_font_4, TestLevel::L2, 297)
{
    // 创建typeface
    std::shared_ptr<Drawing::FontMgr> fontMgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string familyName = "HMOS Color Emoji";
    std::shared_ptr<Drawing::FontStyleSet> fontStyleSet(fontMgr->MatchFamily(familyName.c_str()));
    auto typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->CreateTypeface(0));
    
    // 设置fontsize到LinearMetrics的属性
    auto font = Drawing::Font();
    auto font1 = MakeFont1(font, typeface, 71.f, 30.f, -1.f);
    font.SetBaselineSnap(true);
    font1.SetBaselineSnap(font.IsBaselineSnap());
    font.SetEdging(Drawing::FontEdging::ANTI_ALIAS);
    font1.SetEdging(font.GetEdging());
    font.SetHinting(Drawing::FontHinting::NORMAL);
    font1.SetHinting(font.GetHinting());
    font.SetForceAutoHinting(true);
    font1.SetForceAutoHinting(font.IsForceAutoHinting());
    font.SetEmbeddedBitmaps(true);
    font1.SetEmbeddedBitmaps(font.IsEmbeddedBitmaps());
    font.SetEmbolden(true);
    font1.SetEmbolden(font.IsEmbolden());
    font.SetLinearMetrics(true);
    font1.SetLinearMetrics(font.IsLinearMetrics());

    // font操作接口，如果涉及，获取返回值赋值给text4，并将text4加入vector容器
    int glyphCount = font.CountText(g_text.c_str(), g_text.length(), Drawing::TextEncoding::UTF8);
    uint16_t glyphs[glyphCount + 1];
    int count = font.TextToGlyphs(g_text.c_str(), g_text.length(), Drawing::TextEncoding::GLYPH_ID,
        glyphs, glyphCount + 1);
    std::string text4 = "GlyphsCount = " + std::to_string(count);
    std::vector<std::string> texts = {g_text1, g_text2, g_text3, text4};
    DrawTexts(texts, font, font1, playbackCanvas_);
}

// 对应用例 font_font_3298
DEF_DTK(font_font_4, TestLevel::L2, 298)
{
    // 创建typeface
    std::shared_ptr<Drawing::FontMgr> fontMgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string familyName = "HMOS Color Emoji";
    std::shared_ptr<Drawing::FontStyleSet> fontStyleSet(fontMgr->MatchFamily(familyName.c_str()));
    auto typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->CreateTypeface(0));
    
    // 设置fontsize到LinearMetrics的属性
    auto font = Drawing::Font();
    auto font1 = MakeFont1(font, typeface, 71.f, 30.f, -1.f);
    font.SetBaselineSnap(false);
    font1.SetBaselineSnap(font.IsBaselineSnap());
    font.SetEdging(Drawing::FontEdging::ALIAS);
    font1.SetEdging(font.GetEdging());
    font.SetForceAutoHinting(false);
    font1.SetForceAutoHinting(font.IsForceAutoHinting());
    font.SetEmbeddedBitmaps(false);
    font1.SetEmbeddedBitmaps(font.IsEmbeddedBitmaps());
    font.SetEmbolden(false);
    font1.SetEmbolden(font.IsEmbolden());
    font.SetLinearMetrics(false);
    font1.SetLinearMetrics(font.IsLinearMetrics());

    // font操作接口，如果涉及，获取返回值赋值给text4，并将text4加入vector容器
    Drawing::Rect bounds;
    auto scalar = font.MeasureText(g_text.c_str(), g_text.size(), Drawing::TextEncoding::GLYPH_ID, &bounds);
    std::string text4 = "MeasureTextWidths = " + std::to_string(scalar);
    std::vector<std::string> texts = {g_text1, g_text2, g_text3, text4};
    DrawTexts(texts, font, font1, playbackCanvas_);
}

// 对应用例 font_font_3299
DEF_DTK(font_font_4, TestLevel::L2, 299)
{
    // 创建typeface
    std::shared_ptr<Drawing::FontMgr> fontMgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string familyName = "HMOS Color Emoji";
    std::shared_ptr<Drawing::FontStyleSet> fontStyleSet(fontMgr->MatchFamily(familyName.c_str()));
    auto typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->CreateTypeface(0));
    
    // 设置fontsize到LinearMetrics的属性
    auto font = Drawing::Font();
    auto font1 = MakeFont1(font, typeface, 71.f, 30.f, -1.f);
    font.SetEdging(Drawing::FontEdging::SUBPIXEL_ANTI_ALIAS);
    font1.SetEdging(font.GetEdging());
    font.SetHinting(Drawing::FontHinting::NONE);
    font1.SetHinting(font.GetHinting());

    // font操作接口，如果涉及，获取返回值赋值给text4，并将text4加入vector容器
    std::vector<std::string> texts = {g_text1, g_text2, g_text3};
    DrawTexts(texts, font, font1, playbackCanvas_);
}

// 对应用例 font_font_3300
DEF_DTK(font_font_4, TestLevel::L2, 300)
{
    // 创建typeface
    std::shared_ptr<Drawing::FontMgr> fontMgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string familyName = "HMOS Color Emoji";
    std::shared_ptr<Drawing::FontStyleSet> fontStyleSet(fontMgr->MatchFamily(familyName.c_str()));
    auto typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->CreateTypeface(0));
    
    // 设置fontsize到LinearMetrics的属性
    auto font = Drawing::Font();
    auto font1 = MakeFont1(font, typeface, 500.f, -30.f, -0.5f);
    font.SetBaselineSnap(true);
    font1.SetBaselineSnap(font.IsBaselineSnap());
    font.SetHinting(Drawing::FontHinting::SLIGHT);
    font1.SetHinting(font.GetHinting());
    font.SetForceAutoHinting(true);
    font1.SetForceAutoHinting(font.IsForceAutoHinting());
    font.SetEmbeddedBitmaps(true);
    font1.SetEmbeddedBitmaps(font.IsEmbeddedBitmaps());
    font.SetEmbolden(true);
    font1.SetEmbolden(font.IsEmbolden());
    font.SetLinearMetrics(true);
    font1.SetLinearMetrics(font.IsLinearMetrics());

    // font操作接口，如果涉及，获取返回值赋值给text4，并将text4加入vector容器
    Drawing::FontMetrics metrics;
    auto SpaceLine = font.GetMetrics(&metrics);
    std::string text4 = "Recommended spaceing between lines = " + std::to_string(SpaceLine);
    std::vector<std::string> texts = {g_text1, g_text2, g_text3, text4};
    DrawTexts(texts, font, font1, playbackCanvas_);
}

// 对应用例 font_font_3301
DEF_DTK(font_font_4, TestLevel::L2, 301)
{
    // 创建typeface
    std::shared_ptr<Drawing::FontMgr> fontMgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string familyName = "HMOS Color Emoji";
    std::shared_ptr<Drawing::FontStyleSet> fontStyleSet(fontMgr->MatchFamily(familyName.c_str()));
    auto typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->CreateTypeface(0));
    
    // 设置fontsize到LinearMetrics的属性
    auto font = Drawing::Font();
    auto font1 = MakeFont1(font, typeface, 500.f, -30.f, -0.5f);
    font.SetBaselineSnap(false);
    font1.SetBaselineSnap(font.IsBaselineSnap());
    font.SetEdging(Drawing::FontEdging::SUBPIXEL_ANTI_ALIAS);
    font1.SetEdging(font.GetEdging());
    font.SetHinting(Drawing::FontHinting::FULL);
    font1.SetHinting(font.GetHinting());
    font.SetForceAutoHinting(false);
    font1.SetForceAutoHinting(font.IsForceAutoHinting());
    font.SetEmbeddedBitmaps(false);
    font1.SetEmbeddedBitmaps(font.IsEmbeddedBitmaps());
    font.SetEmbolden(false);
    font1.SetEmbolden(font.IsEmbolden());
    font.SetLinearMetrics(false);
    font1.SetLinearMetrics(font.IsLinearMetrics());

    // font操作接口，如果涉及，获取返回值赋值给text4，并将text4加入vector容器
    int glyphCount = font.CountText(g_text.c_str(), g_text.length(), Drawing::TextEncoding::UTF8);
    uint16_t glyphs[glyphCount - 1];
    int count = font.TextToGlyphs(g_text.c_str(), g_text.length(), Drawing::TextEncoding::GLYPH_ID, glyphs, glyphCount);
    std::string text4 = "GlyphsCount = " + std::to_string(count);
    std::vector<std::string> texts = {g_text1, g_text2, g_text3, text4};
    DrawTexts(texts, font, font1, playbackCanvas_);
}

// 对应用例 font_font_3302
DEF_DTK(font_font_4, TestLevel::L2, 302)
{
    // 创建typeface
    std::shared_ptr<Drawing::FontMgr> fontMgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string familyName = "HMOS Color Emoji";
    std::shared_ptr<Drawing::FontStyleSet> fontStyleSet(fontMgr->MatchFamily(familyName.c_str()));
    auto typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->CreateTypeface(0));
    
    // 设置fontsize到LinearMetrics的属性
    auto font = Drawing::Font();
    auto font1 = MakeFont1(font, typeface, 500.f, -30.f, -0.5f);
    font.SetEdging(Drawing::FontEdging::ANTI_ALIAS);
    font1.SetEdging(font.GetEdging());
    font.SetHinting(Drawing::FontHinting::NONE);
    font1.SetHinting(font.GetHinting());

    // font操作接口，如果涉及，获取返回值赋值给text4，并将text4加入vector容器
    auto scalar = font.MeasureSingleCharacter(0xEEEEE);
    std::string text4 = "Recommended spaceing between lines = " + std::to_string(scalar);
    std::vector<std::string> texts = {g_text1, g_text2, g_text3, text4};
    DrawTexts(texts, font, font1, playbackCanvas_);
}

// 对应用例 font_font_3303
DEF_DTK(font_font_4, TestLevel::L2, 303)
{
    // 创建typeface
    std::shared_ptr<Drawing::FontMgr> fontMgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string familyName = "HMOS Color Emoji";
    std::shared_ptr<Drawing::FontStyleSet> fontStyleSet(fontMgr->MatchFamily(familyName.c_str()));
    auto typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->CreateTypeface(0));
    
    // 设置fontsize到LinearMetrics的属性
    auto font = Drawing::Font();
    auto font1 = MakeFont1(font, typeface, 500.f, -1.f, -1.f);
    font.SetBaselineSnap(false);
    font1.SetBaselineSnap(font.IsBaselineSnap());
    font.SetEdging(Drawing::FontEdging::ANTI_ALIAS);
    font1.SetEdging(font.GetEdging());
    font.SetHinting(Drawing::FontHinting::NORMAL);
    font1.SetHinting(font.GetHinting());
    font.SetForceAutoHinting(false);
    font1.SetForceAutoHinting(font.IsForceAutoHinting());
    font.SetEmbeddedBitmaps(false);
    font1.SetEmbeddedBitmaps(font.IsEmbeddedBitmaps());
    font.SetEmbolden(true);
    font1.SetEmbolden(font.IsEmbolden());
    font.SetLinearMetrics(false);
    font1.SetLinearMetrics(font.IsLinearMetrics());

    // font操作接口，如果涉及，获取返回值赋值给text4，并将text4加入vector容器
    int glyphCount = font.CountText(g_text.c_str(), g_text.length(), Drawing::TextEncoding::UTF16);
    float widths[glyphCount];
    uint16_t glyphs[glyphCount];
    font.TextToGlyphs(g_text.c_str(), g_text.length(), Drawing::TextEncoding::UTF8, glyphs, glyphCount);
    font.GetWidths(glyphs, glyphCount, widths);
    std::string text4 = "GetWidths = " + std::to_string(widths[0]);
    std::vector<std::string> texts = {g_text1, g_text2, g_text3, text4};
    DrawTexts(texts, font, font1, playbackCanvas_);
}

// 对应用例 font_font_3304
DEF_DTK(font_font_4, TestLevel::L2, 304)
{
    // 创建typeface
    std::shared_ptr<Drawing::FontMgr> fontMgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string familyName = "HMOS Color Emoji";
    std::shared_ptr<Drawing::FontStyleSet> fontStyleSet(fontMgr->MatchFamily(familyName.c_str()));
    auto typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->MatchStyle({
        Drawing::FontStyle::INVISIBLE_WEIGHT,
        Drawing::FontStyle::ULTRA_CONDENSED_WIDTH,
        Drawing::FontStyle::OBLIQUE_SLANT}));
    
    // 设置fontsize到LinearMetrics的属性
    auto font = Drawing::Font();
    auto font1 = MakeFont1(font, typeface, -50.f, -1.f, 0);
    font.SetBaselineSnap(false);
    font1.SetBaselineSnap(font.IsBaselineSnap());
    font.SetEdging(Drawing::FontEdging::ANTI_ALIAS);
    font1.SetEdging(font.GetEdging());
    font.SetHinting(Drawing::FontHinting::FULL);
    font1.SetHinting(font.GetHinting());
    font.SetForceAutoHinting(false);
    font1.SetForceAutoHinting(font.IsForceAutoHinting());
    font.SetEmbeddedBitmaps(false);
    font1.SetEmbeddedBitmaps(font.IsEmbeddedBitmaps());
    font.SetEmbolden(false);
    font1.SetEmbolden(font.IsEmbolden());
    font.SetLinearMetrics(false);
    font1.SetLinearMetrics(font.IsLinearMetrics());

    // font操作接口，如果涉及，获取返回值赋值给text4，并将text4加入vector容器
    int glyphCount = font.CountText(g_text.c_str(), g_text.length(), Drawing::TextEncoding::UTF8);
    uint16_t glyphs[glyphCount];
    int count = font.TextToGlyphs(g_text.c_str(), g_text.length(), Drawing::TextEncoding::GLYPH_ID,
        glyphs, glyphCount + 1);
    std::string text4 = "GlyphsCount = " + std::to_string(count);
    std::vector<std::string> texts = {g_text1, g_text2, g_text3, text4};
    DrawTexts(texts, font, font1, playbackCanvas_);
}

// 对应用例 font_font_3305
DEF_DTK(font_font_4, TestLevel::L2, 305)
{
    // 创建typeface
    std::shared_ptr<Drawing::FontMgr> fontMgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string familyName = "HMOS Color Emoji";
    std::shared_ptr<Drawing::FontStyleSet> fontStyleSet(fontMgr->MatchFamily(familyName.c_str()));
    auto typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->MatchStyle({
        Drawing::FontStyle::INVISIBLE_WEIGHT,
        Drawing::FontStyle::ULTRA_CONDENSED_WIDTH,
        Drawing::FontStyle::OBLIQUE_SLANT}));
    
    // 设置fontsize到LinearMetrics的属性
    auto font = Drawing::Font();
    auto font1 = MakeFont1(font, typeface, -50.f, -1.f, 0);
    font.SetEdging(Drawing::FontEdging::ALIAS);
    font1.SetEdging(font.GetEdging());
    font.SetHinting(Drawing::FontHinting::NONE);
    font1.SetHinting(font.GetHinting());

    // font操作接口，如果涉及，获取返回值赋值给text4，并将text4加入vector容器
    Drawing::Rect bounds;
    auto scalar = font.MeasureText(g_text.c_str(), g_text.size(), Drawing::TextEncoding::UTF8, &bounds);
    std::string text4 = "MeasureTextWidths = " + std::to_string(scalar);
    std::vector<std::string> texts = {g_text1, g_text2, g_text3, text4};
    DrawTexts(texts, font, font1, playbackCanvas_);
}

// 对应用例 font_font_3306
DEF_DTK(font_font_4, TestLevel::L2, 306)
{
    // 创建typeface
    std::shared_ptr<Drawing::FontMgr> fontMgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string familyName = "HMOS Color Emoji";
    std::shared_ptr<Drawing::FontStyleSet> fontStyleSet(fontMgr->MatchFamily(familyName.c_str()));
    auto typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->MatchStyle({
        Drawing::FontStyle::INVISIBLE_WEIGHT,
        Drawing::FontStyle::ULTRA_CONDENSED_WIDTH,
        Drawing::FontStyle::OBLIQUE_SLANT}));
    
    // 设置fontsize到LinearMetrics的属性
    auto font = Drawing::Font();
    auto font1 = MakeFont1(font, typeface, -50.f, -0.5f, -0.5f);
    font.SetEdging(Drawing::FontEdging::SUBPIXEL_ANTI_ALIAS);
    font1.SetEdging(font.GetEdging());
    font.SetHinting(Drawing::FontHinting::SLIGHT);
    font1.SetHinting(font.GetHinting());

    // font操作接口，如果涉及，获取返回值赋值给text4，并将text4加入vector容器
    Drawing::Rect bounds;
    auto scalar = font.MeasureText(g_text.c_str(), g_text.size(), Drawing::TextEncoding::UTF8, &bounds);
    std::string text4 = "MeasureTextWidths = " + std::to_string(scalar);
    std::vector<std::string> texts = {g_text1, g_text2, g_text3, text4};
    DrawTexts(texts, font, font1, playbackCanvas_);
}

// 对应用例 font_font_3307
DEF_DTK(font_font_4, TestLevel::L2, 307)
{
    // 创建typeface
    std::shared_ptr<Drawing::FontMgr> fontMgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string familyName = "HMOS Color Emoji";
    std::shared_ptr<Drawing::FontStyleSet> fontStyleSet(fontMgr->MatchFamily(familyName.c_str()));
    auto typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->MatchStyle({
        Drawing::FontStyle::INVISIBLE_WEIGHT,
        Drawing::FontStyle::ULTRA_CONDENSED_WIDTH,
        Drawing::FontStyle::OBLIQUE_SLANT}));
    
    // 设置fontsize到LinearMetrics的属性
    auto font = Drawing::Font();
    auto font1 = MakeFont1(font, typeface, -31.f, -0.5f, 0.7f);
    font.SetBaselineSnap(true);
    font1.SetBaselineSnap(font.IsBaselineSnap());
    font.SetEdging(Drawing::FontEdging::ANTI_ALIAS);
    font1.SetEdging(font.GetEdging());
    font.SetHinting(Drawing::FontHinting::SLIGHT);
    font1.SetHinting(font.GetHinting());
    font.SetForceAutoHinting(true);
    font1.SetForceAutoHinting(font.IsForceAutoHinting());
    font.SetEmbeddedBitmaps(true);
    font1.SetEmbeddedBitmaps(font.IsEmbeddedBitmaps());
    font.SetEmbolden(true);
    font1.SetEmbolden(font.IsEmbolden());
    font.SetLinearMetrics(true);
    font1.SetLinearMetrics(font.IsLinearMetrics());

    // font操作接口，如果涉及，获取返回值赋值给text4，并将text4加入vector容器
    Drawing::Rect bounds;
    auto scalar = font.MeasureText(g_text.c_str(), g_text.size(), Drawing::TextEncoding::UTF16, &bounds);
    std::string text4 = "MeasureTextWidths = " + std::to_string(scalar);
    std::vector<std::string> texts = {g_text1, g_text2, g_text3, text4};
    DrawTexts(texts, font, font1, playbackCanvas_);
}

// 对应用例 font_font_3308
DEF_DTK(font_font_4, TestLevel::L2, 308)
{
    // 创建typeface
    std::shared_ptr<Drawing::FontMgr> fontMgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string familyName = "HMOS Color Emoji";
    std::shared_ptr<Drawing::FontStyleSet> fontStyleSet(fontMgr->MatchFamily(familyName.c_str()));
    auto typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->MatchStyle({
        Drawing::FontStyle::INVISIBLE_WEIGHT,
        Drawing::FontStyle::ULTRA_CONDENSED_WIDTH,
        Drawing::FontStyle::OBLIQUE_SLANT}));
    
    // 设置fontsize到LinearMetrics的属性
    auto font = Drawing::Font();
    auto font1 = MakeFont1(font, typeface, -31.f, -0.5f, 0.7f);
    font.SetEdging(Drawing::FontEdging::SUBPIXEL_ANTI_ALIAS);
    font1.SetEdging(font.GetEdging());

    // font操作接口，如果涉及，获取返回值赋值给text4，并将text4加入vector容器
    int glyphCount = font.CountText(g_text.c_str(), g_text.length(), Drawing::TextEncoding::UTF8);
    uint16_t glyphs[glyphCount + 1];
    int count = font.TextToGlyphs(g_text.c_str(), g_text.length(), Drawing::TextEncoding::GLYPH_ID,
        glyphs, glyphCount + 1);
    std::string text4 = "GlyphsCount = " + std::to_string(count);
    std::vector<std::string> texts = {g_text1, g_text2, g_text3, text4};
    DrawTexts(texts, font, font1, playbackCanvas_);
}

// 对应用例 font_font_3309
DEF_DTK(font_font_4, TestLevel::L2, 309)
{
    // 创建typeface
    std::shared_ptr<Drawing::FontMgr> fontMgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string familyName = "HMOS Color Emoji";
    std::shared_ptr<Drawing::FontStyleSet> fontStyleSet(fontMgr->MatchFamily(familyName.c_str()));
    auto typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->MatchStyle({
        Drawing::FontStyle::INVISIBLE_WEIGHT,
        Drawing::FontStyle::ULTRA_CONDENSED_WIDTH,
        Drawing::FontStyle::OBLIQUE_SLANT}));
    
    // 设置fontsize到LinearMetrics的属性
    auto font = Drawing::Font();
    auto font1 = MakeFont1(font, typeface, -31.f, 0, 0);
    font.SetBaselineSnap(true);
    font1.SetBaselineSnap(font.IsBaselineSnap());
    font.SetHinting(Drawing::FontHinting::NORMAL);
    font1.SetHinting(font.GetHinting());
    font.SetForceAutoHinting(true);
    font1.SetForceAutoHinting(font.IsForceAutoHinting());
    font.SetEmbeddedBitmaps(true);
    font1.SetEmbeddedBitmaps(font.IsEmbeddedBitmaps());
    font.SetEmbolden(true);
    font1.SetEmbolden(font.IsEmbolden());
    font.SetLinearMetrics(true);
    font1.SetLinearMetrics(font.IsLinearMetrics());

    // font操作接口，如果涉及，获取返回值赋值给text4，并将text4加入vector容器
    int glyphCount = font.CountText(g_text.c_str(), g_text.length(), Drawing::TextEncoding::UTF8);
    uint16_t glyphs[glyphCount - 1];
    int count = font.TextToGlyphs(g_text.c_str(), g_text.length(), Drawing::TextEncoding::GLYPH_ID,
        glyphs, glyphCount + 1);
    std::string text4 = "GlyphsCount = " + std::to_string(count);
    std::vector<std::string> texts = {g_text1, g_text2, g_text3, text4};
    DrawTexts(texts, font, font1, playbackCanvas_);
}

// 对应用例 font_font_3310
DEF_DTK(font_font_4, TestLevel::L2, 310)
{
    // 创建typeface
    std::shared_ptr<Drawing::FontMgr> fontMgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string familyName = "HMOS Color Emoji";
    std::shared_ptr<Drawing::FontStyleSet> fontStyleSet(fontMgr->MatchFamily(familyName.c_str()));
    auto typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->MatchStyle({
        Drawing::FontStyle::INVISIBLE_WEIGHT,
        Drawing::FontStyle::ULTRA_CONDENSED_WIDTH,
        Drawing::FontStyle::OBLIQUE_SLANT}));
    
    // 设置fontsize到LinearMetrics的属性
    auto font = Drawing::Font();
    auto font1 = MakeFont1(font, typeface, -15.34f, 0, 1.f);
    font.SetBaselineSnap(true);
    font1.SetBaselineSnap(font.IsBaselineSnap());
    font.SetHinting(Drawing::FontHinting::NONE);
    font1.SetHinting(font.GetHinting());
    font.SetForceAutoHinting(true);
    font1.SetForceAutoHinting(font.IsForceAutoHinting());
    font.SetEmbeddedBitmaps(true);
    font1.SetEmbeddedBitmaps(font.IsEmbeddedBitmaps());
    font.SetEmbolden(true);
    font1.SetEmbolden(font.IsEmbolden());
    font.SetLinearMetrics(true);
    font1.SetLinearMetrics(font.IsLinearMetrics());

    // font操作接口，如果涉及，获取返回值赋值给text4，并将text4加入vector容器
    int glyphCount = font.CountText(g_text.c_str(), g_text.length(), Drawing::TextEncoding::UTF8);
    uint16_t glyphs[glyphCount - 1];
    int count = font.TextToGlyphs(g_text.c_str(), g_text.length(), Drawing::TextEncoding::GLYPH_ID, glyphs, glyphCount);
    std::string text4 = "GlyphsCount = " + std::to_string(count);
    std::vector<std::string> texts = {g_text1, g_text2, g_text3, text4};
    DrawTexts(texts, font, font1, playbackCanvas_);
}

// 对应用例 font_font_3311
DEF_DTK(font_font_4, TestLevel::L2, 311)
{
    // 创建typeface
    std::shared_ptr<Drawing::FontMgr> fontMgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string familyName = "HMOS Color Emoji";
    std::shared_ptr<Drawing::FontStyleSet> fontStyleSet(fontMgr->MatchFamily(familyName.c_str()));
    auto typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->MatchStyle({
        Drawing::FontStyle::INVISIBLE_WEIGHT,
        Drawing::FontStyle::ULTRA_CONDENSED_WIDTH,
        Drawing::FontStyle::OBLIQUE_SLANT}));
    
    // 设置fontsize到LinearMetrics的属性
    auto font = Drawing::Font();
    auto font1 = MakeFont1(font, typeface, -15.34f, 0, 1.f);
    font.SetBaselineSnap(false);
    font1.SetBaselineSnap(font.IsBaselineSnap());
    font.SetEdging(Drawing::FontEdging::SUBPIXEL_ANTI_ALIAS);
    font1.SetEdging(font.GetEdging());
    font.SetHinting(Drawing::FontHinting::NORMAL);
    font1.SetHinting(font.GetHinting());
    font.SetForceAutoHinting(false);
    font1.SetForceAutoHinting(font.IsForceAutoHinting());
    font.SetEmbeddedBitmaps(false);
    font1.SetEmbeddedBitmaps(font.IsEmbeddedBitmaps());
    font.SetEmbolden(false);
    font1.SetEmbolden(font.IsEmbolden());
    font.SetLinearMetrics(false);
    font1.SetLinearMetrics(font.IsLinearMetrics());

    // font操作接口，如果涉及，获取返回值赋值给text4，并将text4加入vector容器
    Drawing::Rect bounds;
    auto scalar = font.MeasureText(g_text.c_str(), g_text.size(), Drawing::TextEncoding::UTF32, &bounds);
    std::string text4 = "MeasureTextWidths = " + std::to_string(scalar);
    std::vector<std::string> texts = {g_text1, g_text2, g_text3, text4};
    DrawTexts(texts, font, font1, playbackCanvas_);
}

// 对应用例 font_font_3312
DEF_DTK(font_font_4, TestLevel::L2, 312)
{
    // 创建typeface
    std::shared_ptr<Drawing::FontMgr> fontMgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string familyName = "HMOS Color Emoji";
    std::shared_ptr<Drawing::FontStyleSet> fontStyleSet(fontMgr->MatchFamily(familyName.c_str()));
    auto typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->MatchStyle({
        Drawing::FontStyle::INVISIBLE_WEIGHT,
        Drawing::FontStyle::ULTRA_CONDENSED_WIDTH,
        Drawing::FontStyle::OBLIQUE_SLANT}));
    
    // 设置fontsize到LinearMetrics的属性
    auto font = Drawing::Font();
    auto font1 = MakeFont1(font, typeface, -15.34f, 0.7f, 0.7f);
    font.SetBaselineSnap(false);
    font1.SetBaselineSnap(font.IsBaselineSnap());
    font.SetEdging(Drawing::FontEdging::ALIAS);
    font1.SetEdging(font.GetEdging());
    font.SetHinting(Drawing::FontHinting::FULL);
    font1.SetHinting(font.GetHinting());
    font.SetForceAutoHinting(false);
    font1.SetForceAutoHinting(font.IsForceAutoHinting());
    font.SetEmbeddedBitmaps(false);
    font1.SetEmbeddedBitmaps(font.IsEmbeddedBitmaps());
    font.SetEmbolden(false);
    font1.SetEmbolden(font.IsEmbolden());
    font.SetLinearMetrics(false);
    font1.SetLinearMetrics(font.IsLinearMetrics());

    // font操作接口，如果涉及，获取返回值赋值给text4，并将text4加入vector容器
    Drawing::FontMetrics metrics;
    auto SpaceLine = font.GetMetrics(&metrics);
    std::string text4 = "Recommended spaceing between lines = " + std::to_string(SpaceLine);
    std::vector<std::string> texts = {g_text1, g_text2, g_text3, text4};
    DrawTexts(texts, font, font1, playbackCanvas_);
}

// 对应用例 font_font_3313
DEF_DTK(font_font_4, TestLevel::L2, 313)
{
    // 创建typeface
    std::shared_ptr<Drawing::FontMgr> fontMgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string familyName = "HMOS Color Emoji";
    std::shared_ptr<Drawing::FontStyleSet> fontStyleSet(fontMgr->MatchFamily(familyName.c_str()));
    auto typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->MatchStyle({
        Drawing::FontStyle::INVISIBLE_WEIGHT,
        Drawing::FontStyle::ULTRA_CONDENSED_WIDTH,
        Drawing::FontStyle::OBLIQUE_SLANT}));
    
    // 设置fontsize到LinearMetrics的属性
    auto font = Drawing::Font();
    auto font1 = MakeFont1(font, typeface, 0, 0.7f, 30.f);
    font.SetBaselineSnap(true);
    font1.SetBaselineSnap(font.IsBaselineSnap());
    font.SetEdging(Drawing::FontEdging::ANTI_ALIAS);
    font1.SetEdging(font.GetEdging());
    font.SetForceAutoHinting(true);
    font1.SetForceAutoHinting(font.IsForceAutoHinting());
    font.SetEmbeddedBitmaps(true);
    font1.SetEmbeddedBitmaps(font.IsEmbeddedBitmaps());
    font.SetEmbolden(true);
    font1.SetEmbolden(font.IsEmbolden());
    font.SetLinearMetrics(true);
    font1.SetLinearMetrics(font.IsLinearMetrics());

    // font操作接口，如果涉及，获取返回值赋值给text4，并将text4加入vector容器
    auto SpaceLine = font.GetMetrics(nullptr);
    std::string text4 = "Recommended spaceing between lines = " + std::to_string(SpaceLine);
    std::vector<std::string> texts = {g_text1, g_text2, g_text3, text4};
    DrawTexts(texts, font, font1, playbackCanvas_);
}

// 对应用例 font_font_3314
DEF_DTK(font_font_4, TestLevel::L2, 314)
{
    // 创建typeface
    std::shared_ptr<Drawing::FontMgr> fontMgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string familyName = "HMOS Color Emoji";
    std::shared_ptr<Drawing::FontStyleSet> fontStyleSet(fontMgr->MatchFamily(familyName.c_str()));
    auto typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->MatchStyle({
        Drawing::FontStyle::INVISIBLE_WEIGHT,
        Drawing::FontStyle::ULTRA_CONDENSED_WIDTH,
        Drawing::FontStyle::OBLIQUE_SLANT}));
    
    // 设置fontsize到LinearMetrics的属性
    auto font = Drawing::Font();
    auto font1 = MakeFont1(font, typeface, 0, 0.7f, 30.f);
    font.SetBaselineSnap(false);
    font1.SetBaselineSnap(font.IsBaselineSnap());
    font.SetEdging(Drawing::FontEdging::ALIAS);
    font1.SetEdging(font.GetEdging());
    font.SetHinting(Drawing::FontHinting::SLIGHT);
    font1.SetHinting(font.GetHinting());
    font.SetForceAutoHinting(false);
    font1.SetForceAutoHinting(font.IsForceAutoHinting());
    font.SetEmbeddedBitmaps(false);
    font1.SetEmbeddedBitmaps(font.IsEmbeddedBitmaps());
    font.SetEmbolden(false);
    font1.SetEmbolden(font.IsEmbolden());
    font.SetLinearMetrics(false);
    font1.SetLinearMetrics(font.IsLinearMetrics());

    // font操作接口，如果涉及，获取返回值赋值给text4，并将text4加入vector容器
    int glyphCount = font.CountText(g_text.c_str(), g_text.length(), Drawing::TextEncoding::UTF8);
    uint16_t glyphs[glyphCount - 1];
    int count = font.TextToGlyphs(g_text.c_str(), g_text.length(), Drawing::TextEncoding::GLYPH_ID,
        glyphs, glyphCount - 1);
    std::string text4 = "GlyphsCount = " + std::to_string(count);
    std::vector<std::string> texts = {g_text1, g_text2, g_text3, text4};
    DrawTexts(texts, font, font1, playbackCanvas_);
}

// 对应用例 font_font_3315
DEF_DTK(font_font_4, TestLevel::L2, 315)
{
    // 创建typeface
    std::shared_ptr<Drawing::FontMgr> fontMgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string familyName = "HMOS Color Emoji";
    std::shared_ptr<Drawing::FontStyleSet> fontStyleSet(fontMgr->MatchFamily(familyName.c_str()));
    auto typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->MatchStyle({
        Drawing::FontStyle::INVISIBLE_WEIGHT,
        Drawing::FontStyle::ULTRA_CONDENSED_WIDTH,
        Drawing::FontStyle::OBLIQUE_SLANT}));
    
    // 设置fontsize到LinearMetrics的属性
    auto font = Drawing::Font();
    auto font1 = MakeFont1(font, typeface, 0, 0.7f, 30.f);
    font.SetHinting(Drawing::FontHinting::FULL);
    font1.SetHinting(font.GetHinting());

    // font操作接口，如果涉及，获取返回值赋值给text4，并将text4加入vector容器
    Drawing::Rect bounds;
    auto scalar = font.MeasureText(g_text.c_str(), g_text.size(), Drawing::TextEncoding::GLYPH_ID, &bounds);
    std::string text4 = "MeasureTextWidths = " + std::to_string(scalar);
    std::vector<std::string> texts = {g_text1, g_text2, g_text3, text4};
    DrawTexts(texts, font, font1, playbackCanvas_);
}

// 对应用例 font_font_3316
DEF_DTK(font_font_4, TestLevel::L2, 316)
{
    // 创建typeface
    std::shared_ptr<Drawing::FontMgr> fontMgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string familyName = "HMOS Color Emoji";
    std::shared_ptr<Drawing::FontStyleSet> fontStyleSet(fontMgr->MatchFamily(familyName.c_str()));
    auto typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->MatchStyle({
        Drawing::FontStyle::INVISIBLE_WEIGHT,
        Drawing::FontStyle::ULTRA_CONDENSED_WIDTH,
        Drawing::FontStyle::OBLIQUE_SLANT}));
    
    // 设置fontsize到LinearMetrics的属性
    auto font = Drawing::Font();
    auto font1 = MakeFont1(font, typeface, 0, 1.f, 1.f);
    font.SetEdging(Drawing::FontEdging::ANTI_ALIAS);
    font1.SetEdging(font.GetEdging());
    font.SetEmbolden(false);
    font1.SetEmbolden(font.IsEmbolden());

    // font操作接口，如果涉及，获取返回值赋值给text4，并将text4加入vector容器
    auto glyphsCount = font.CountText(g_text.c_str(), g_text.length(), Drawing::TextEncoding::UTF16);
    std::string text4 = "glyphsCount = " + std::to_string(glyphsCount);
    std::vector<std::string> texts = {g_text1, g_text2, g_text3, text4};
    DrawTexts(texts, font, font1, playbackCanvas_);
}

// 对应用例 font_font_3317
DEF_DTK(font_font_4, TestLevel::L2, 317)
{
    // 创建typeface
    std::shared_ptr<Drawing::FontMgr> fontMgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string familyName = "HMOS Color Emoji";
    std::shared_ptr<Drawing::FontStyleSet> fontStyleSet(fontMgr->MatchFamily(familyName.c_str()));
    auto typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->MatchStyle({
        Drawing::FontStyle::INVISIBLE_WEIGHT,
        Drawing::FontStyle::ULTRA_CONDENSED_WIDTH,
        Drawing::FontStyle::OBLIQUE_SLANT}));
    
    // 设置fontsize到LinearMetrics的属性
    auto font = Drawing::Font();
    auto font1 = MakeFont1(font, typeface, 27.13f, 1.f, -30.f);
    font.SetBaselineSnap(true);
    font1.SetBaselineSnap(font.IsBaselineSnap());
    font.SetEdging(Drawing::FontEdging::ALIAS);
    font1.SetEdging(font.GetEdging());
    font.SetForceAutoHinting(true);
    font1.SetForceAutoHinting(font.IsForceAutoHinting());
    font.SetEmbeddedBitmaps(true);
    font1.SetEmbeddedBitmaps(font.IsEmbeddedBitmaps());
    font.SetEmbolden(true);
    font1.SetEmbolden(font.IsEmbolden());
    font.SetLinearMetrics(true);
    font1.SetLinearMetrics(font.IsLinearMetrics());

    // font操作接口，如果涉及，获取返回值赋值给text4，并将text4加入vector容器
    auto scalar = font.MeasureSingleCharacter(0x44);
    std::string text4 = "Recommended spaceing between lines = " + std::to_string(scalar);
    std::vector<std::string> texts = {g_text1, g_text2, g_text3, text4};
    DrawTexts(texts, font, font1, playbackCanvas_);
}

// 对应用例 font_font_3318
DEF_DTK(font_font_4, TestLevel::L2, 318)
{
    // 创建typeface
    std::shared_ptr<Drawing::FontMgr> fontMgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string familyName = "HMOS Color Emoji";
    std::shared_ptr<Drawing::FontStyleSet> fontStyleSet(fontMgr->MatchFamily(familyName.c_str()));
    auto typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->MatchStyle({
        Drawing::FontStyle::INVISIBLE_WEIGHT,
        Drawing::FontStyle::ULTRA_CONDENSED_WIDTH,
        Drawing::FontStyle::OBLIQUE_SLANT}));
    
    // 设置fontsize到LinearMetrics的属性
    auto font = Drawing::Font();
    auto font1 = MakeFont1(font, typeface, 27.13f, 1.f, -30.f);
    font.SetBaselineSnap(false);
    font1.SetBaselineSnap(font.IsBaselineSnap());
    font.SetEdging(Drawing::FontEdging::SUBPIXEL_ANTI_ALIAS);
    font1.SetEdging(font.GetEdging());
    font.SetHinting(Drawing::FontHinting::NONE);
    font1.SetHinting(font.GetHinting());
    font.SetForceAutoHinting(false);
    font1.SetForceAutoHinting(font.IsForceAutoHinting());
    font.SetEmbeddedBitmaps(false);
    font1.SetEmbeddedBitmaps(font.IsEmbeddedBitmaps());
    font.SetEmbolden(false);
    font1.SetEmbolden(font.IsEmbolden());
    font.SetLinearMetrics(false);
    font1.SetLinearMetrics(font.IsLinearMetrics());

    // font操作接口，如果涉及，获取返回值赋值给text4，并将text4加入vector容器
    int glyphCount = font.CountText(g_text.c_str(), g_text.length(), Drawing::TextEncoding::UTF16);
    float widths[glyphCount];
    uint16_t glyphs[glyphCount];
    font.TextToGlyphs(g_text.c_str(), g_text.length(), Drawing::TextEncoding::UTF8, glyphs, glyphCount);
    font.GetWidths(glyphs, glyphCount, widths);
    std::string text4 = "GetWidths = " + std::to_string(widths[0]);
    std::vector<std::string> texts = {g_text1, g_text2, g_text3, text4};
    DrawTexts(texts, font, font1, playbackCanvas_);
}

// 对应用例 font_font_3319
DEF_DTK(font_font_4, TestLevel::L2, 319)
{
    // 创建typeface
    std::shared_ptr<Drawing::FontMgr> fontMgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string familyName = "HMOS Color Emoji";
    std::shared_ptr<Drawing::FontStyleSet> fontStyleSet(fontMgr->MatchFamily(familyName.c_str()));
    auto typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->MatchStyle({
        Drawing::FontStyle::INVISIBLE_WEIGHT,
        Drawing::FontStyle::ULTRA_CONDENSED_WIDTH,
        Drawing::FontStyle::OBLIQUE_SLANT}));
    
    // 设置fontsize到LinearMetrics的属性
    auto font = Drawing::Font();
    auto font1 = MakeFont1(font, typeface, 27.13f, 1.f, -30.f);
    font.SetEdging(Drawing::FontEdging::ANTI_ALIAS);
    font1.SetEdging(font.GetEdging());
    font.SetHinting(Drawing::FontHinting::NORMAL);
    font1.SetHinting(font.GetHinting());

    // font操作接口，如果涉及，获取返回值赋值给text4，并将text4加入vector容器
    int glyphCount = font.CountText(g_text.c_str(), g_text.length(), Drawing::TextEncoding::UTF16);
    uint16_t glyphs[glyphCount - 1];
    int count = font.TextToGlyphs(g_text.c_str(), g_text.length(), Drawing::TextEncoding::GLYPH_ID,
        glyphs, glyphCount + 1);
    std::string text4 = "GlyphsCount = " + std::to_string(count);
    std::vector<std::string> texts = {g_text1, g_text2, g_text3, text4};
    DrawTexts(texts, font, font1, playbackCanvas_);
}

// 对应用例 font_font_3320
DEF_DTK(font_font_4, TestLevel::L2, 320)
{
    // 创建typeface
    std::shared_ptr<Drawing::FontMgr> fontMgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string familyName = "HMOS Color Emoji";
    std::shared_ptr<Drawing::FontStyleSet> fontStyleSet(fontMgr->MatchFamily(familyName.c_str()));
    auto typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->MatchStyle({
        Drawing::FontStyle::INVISIBLE_WEIGHT,
        Drawing::FontStyle::ULTRA_CONDENSED_WIDTH,
        Drawing::FontStyle::OBLIQUE_SLANT}));
    
    // 设置fontsize到LinearMetrics的属性
    auto font = Drawing::Font();
    auto font1 = MakeFont1(font, typeface, 27.13f, 30.f, 30.f);
    font.SetBaselineSnap(true);
    font1.SetBaselineSnap(font.IsBaselineSnap());
    font.SetEdging(Drawing::FontEdging::SUBPIXEL_ANTI_ALIAS);
    font1.SetEdging(font.GetEdging());
    font.SetHinting(Drawing::FontHinting::NONE);
    font1.SetHinting(font.GetHinting());
    font.SetForceAutoHinting(true);
    font1.SetForceAutoHinting(font.IsForceAutoHinting());
    font.SetEmbeddedBitmaps(true);
    font1.SetEmbeddedBitmaps(font.IsEmbeddedBitmaps());
    font.SetLinearMetrics(true);
    font1.SetLinearMetrics(font.IsLinearMetrics());

    // font操作接口，如果涉及，获取返回值赋值给text4，并将text4加入vector容器
    auto glyphsCount = font.CountText(g_text.c_str(), g_text.length(), Drawing::TextEncoding::UTF32);
    std::string text4 = "glyphsCount = " + std::to_string(glyphsCount);
    std::vector<std::string> texts = {g_text1, g_text2, g_text3, text4};
    DrawTexts(texts, font, font1, playbackCanvas_);
}

}
}
