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
#include "dtk_test_ext.h"
#include "text/font_types.h"
#include "text/text_blob_builder.h"
#include "text/font_mgr.h"
#include "text/font.h"
#include "recording/mem_allocator.h"
#include "text/font_style_set.h"
#include "text/rs_xform.h"
#include "utils/point.h"
#include "utils/rect.h"
#include "text/typeface.h"
#include "text/font_style.h"
#include <sstream>

namespace OHOS {
namespace Rosen {

static void DrawTextBlob(std::vector<std::string>& texts, std::shared_ptr<Drawing::TextBlob> textBlob,
                         Drawing::Font& font1, TestPlaybackCanvas* playbackCanvas)
{
    int line = 200;
    int interval1 = 100;
    int interval2 = 200;
    int interval3 = 300;
    int interval4 = 400;

    for (auto text : texts) {
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

// 用例 Font_Scene_Transform_0215
DEF_DTK(Font_Scene_Transform_12, TestLevel::L2, 215)
{
    // 1.创建typeface
    std::shared_ptr<Drawing::FontMgr> fontMgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string familyName = "HMOS Color Emoji";
    std::shared_ptr<Drawing::FontStyleSet> fontStyleSet(fontMgr->MatchFamily(familyName.c_str()));
    auto typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->MatchStyle({
        Drawing::FontStyle::INVISIBLE_WEIGHT,
        Drawing::FontStyle::ULTRA_CONDENSED_WIDTH,
        Drawing::FontStyle::Slant::OBLIQUE_SLANT}));
    // 2.组合typeface操作接口
    std::string str = "CPAL";
    reverse(str.begin(), str.end());
    uint32_t tagid = *(reinterpret_cast<uint32_t*>(const_cast<char*>(str.c_str())));
    std::string typefacestr = "GetTableSize = " + std::to_string(typeface->GetTableSize(tagid));
    // 3.组合Font类接口,如果是操作类有返回值的接口,获取接口返回值加入vector容器
    auto font = Drawing::Font(typeface, 50.f, 1.0f, 1.0f);
    font.SetSubpixel(false);
    font.SetBaselineSnap(true);
    auto font1 = Drawing::Font(typeface, 50.f, 1.0f, 1.0f);
    font1.SetSubpixel(font.IsSubpixel());
    font1.SetBaselineSnap(font.IsBaselineSnap());

    // 4.创建TextBlob
    std::string textInfo = "😊😂🤣😍😒💕😘😁👍🙌👌";
    std::shared_ptr<Drawing::TextBlob> textBlob = Drawing::TextBlob::MakeFromText(
        textInfo.c_str(), textInfo.size(), font1, Drawing::TextEncoding::UTF8);

    // 5.组合textBlob类接口,如果有返回值则获取上一步创建的textBlob返回值打印
    Drawing::Paint paint;
    paint.SetColor(0xFFFF0000);
    float boundsx[] = {1, 2, 3};
    int intercepts = textBlob->GetIntercepts(boundsx, nullptr, &paint);
    std::string text2 = "intercepts = " + std::to_string(intercepts);

    //6. 得到需要绘制的所有返回值text,全部适应固定的textBlob构造方式打印
    std::vector<std::string> texts = {typefacestr, text2};

    //7.调用ClipIRect截取(0,0,1000,1000)区域（缺省,默认INTERSECT、不抗锯齿）
    auto rect1 = Drawing::RectI(0, 0, 1000, 1000);
    playbackCanvas_->ClipIRect(rect1, Drawing::ClipOp::INTERSECT);

    //8.调用Scale,Rotate,ConcatMatrix
    playbackCanvas_->Rotate(45, 50, 50);
    playbackCanvas_->Translate(400, 600);

    //9.最终绘制
    DrawTextBlob(texts, textBlob, font1, playbackCanvas_);
}

// 用例 Font_Scene_Transform_0216
DEF_DTK(Font_Scene_Transform_12, TestLevel::L2, 216)
{
    // 1.创建typeface
    std::shared_ptr<Drawing::FontMgr> fontMgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string familyName = "HMOS Color Emoji";
    std::shared_ptr<Drawing::FontStyleSet> fontStyleSet(fontMgr->MatchFamily(familyName.c_str()));
    auto typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->MatchStyle({
        Drawing::FontStyle::INVISIBLE_WEIGHT,
        Drawing::FontStyle::ULTRA_CONDENSED_WIDTH,
        Drawing::FontStyle::Slant::OBLIQUE_SLANT}));
    // 2.组合typeface操作接口
    auto data = typeface->Serialize();
    uint32_t size = 10;
    typeface->SetSize(size);
    std::shared_ptr<Drawing::Typeface> typeface1 = Drawing::Typeface::Deserialize(data->GetData(), typeface->GetSize());
    // 3.组合Font类接口,如果是操作类有返回值的接口,获取接口返回值加入vector容器
    auto font = Drawing::Font(typeface1, 50.f, 1.0f, 1.0f);
    font.SetSubpixel(false);
    font.SetEmbolden(false);
    auto font1 = Drawing::Font(typeface1, 50.f, 1.0f, 1.0f);
    font1.SetSubpixel(font.IsSubpixel());
    font1.SetEmbolden(font.IsEmbolden());

    // 4.创建TextBlob
    std::string textInfo = "😊😂🤣😍😒💕😘😁👍🙌👌";
    std::shared_ptr<Drawing::TextBlob> textBlob = Drawing::TextBlob::MakeFromText(
        textInfo.c_str(), textInfo.size(), font1, Drawing::TextEncoding::UTF8);

    // 5.组合textBlob类接口,如果有返回值则获取上一步创建的textBlob返回值打印
    auto rect = textBlob->Bounds();
    playbackCanvas_->DrawRect(*rect);

    //6. 得到需要绘制的所有返回值text,全部适应固定的textBlob构造方式打印
    std::vector<std::string> texts = {};

    //7.调用ClipIRect截取(0,0,1000,1000)区域（缺省,默认INTERSECT、不抗锯齿）

    //8.调用Scale,Rotate,ConcatMatrix
    Drawing::Matrix matrix;
    playbackCanvas_->ConcatMatrix(matrix);

    //9.最终绘制
    DrawTextBlob(texts, textBlob, font1, playbackCanvas_);
}

// 用例 Font_Scene_Transform_0217
DEF_DTK(Font_Scene_Transform_12, TestLevel::L2, 217)
{
    // 1.创建typeface
    std::shared_ptr<Drawing::FontMgr> fontMgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string familyName = "HMOS Color Emoji";
    std::shared_ptr<Drawing::FontStyleSet> fontStyleSet(fontMgr->MatchFamily(familyName.c_str()));
    auto typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->MatchStyle({
        Drawing::FontStyle::INVISIBLE_WEIGHT,
        Drawing::FontStyle::ULTRA_CONDENSED_WIDTH,
        Drawing::FontStyle::Slant::OBLIQUE_SLANT}));
    // 2.组合typeface操作接口
    typeface->SetHash(100);
    std::string  typefacestr = "GetHash = " + std::to_string(typeface->GetHash());;
    // 3.组合Font类接口,如果是操作类有返回值的接口,获取接口返回值加入vector容器
    auto font1 = Drawing::Font(typeface, 50.f, 1.0f, 1.0f);
    font1.SetSubpixel(false);
    std::string text0 = "DDGR ddgr 鸿蒙 !@#￥%^&*; : , 。";
    auto scalar = font1.UnicharToGlyph(0x44);
    std::string text4 = "Glyphs = " + std::to_string(scalar);

    // 4.创建TextBlob
    std::string textInfo = "😊😂🤣😍😒💕😘😁👍🙌👌";
    std::shared_ptr<Drawing::TextBlob> textBlob = Drawing::TextBlob::MakeFromText(
        textInfo.c_str(), textInfo.size(), font1, Drawing::TextEncoding::UTF8);

    // 5.组合textBlob类接口,如果有返回值则获取上一步创建的textBlob返回值打印
    std::vector<Drawing::Point> points;
    Drawing::TextBlob::GetDrawingPointsForTextBlob(textBlob.get(), points);
    std::string text2 = "";
    for (int i = 0; i < points.size(); i++) {
        text2 += std::to_string(i) + "-- X：" + std::to_string(points[i].GetX())
                     + "Y：" + std::to_string(points[i].GetY());
    }

    //6. 得到需要绘制的所有返回值text,全部适应固定的textBlob构造方式打印
    std::vector<std::string> texts = {typefacestr, text2, text4};

    //7.调用ClipIRect截取(0,0,1000,1000)区域（缺省,默认INTERSECT、不抗锯齿）

    //8.调用Scale,Rotate,ConcatMatrix
    Drawing::Matrix matrix;
    playbackCanvas_->ConcatMatrix(matrix);
    playbackCanvas_->Scale(0.5, 0.5);

    //9.最终绘制
    DrawTextBlob(texts, textBlob, font1, playbackCanvas_);
}

// 用例 Font_Scene_Transform_0218
DEF_DTK(Font_Scene_Transform_12, TestLevel::L2, 218)
{
    // 1.创建typeface
    std::shared_ptr<Drawing::FontMgr> fontMgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string familyName = "HMOS Color Emoji";
    std::shared_ptr<Drawing::FontStyleSet> fontStyleSet(fontMgr->MatchFamily(familyName.c_str()));
    auto typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->MatchStyle({
        Drawing::FontStyle::INVISIBLE_WEIGHT,
        Drawing::FontStyle::ULTRA_CONDENSED_WIDTH,
        Drawing::FontStyle::Slant::OBLIQUE_SLANT}));
    // 2.组合typeface操作接口
    std::string typefacestr = "IsCustomTypeface = " + std::to_string(typeface->IsCustomTypeface());
    // 3.组合Font类接口,如果是操作类有返回值的接口,获取接口返回值加入vector容器
    auto font = Drawing::Font(typeface, 50.f, 1.0f, 1.0f);
    font.SetSubpixel(false);
    font.SetForceAutoHinting(false);
    auto font1 = Drawing::Font(typeface, 50.f, 1.0f, 1.0f);
    font1.SetSubpixel(font.IsSubpixel());
    font1.SetForceAutoHinting(font.IsForceAutoHinting());

    // 4.创建TextBlob
    std::string textInfo = "harmony_os";
    int cont = textInfo.size();
    Drawing::Point p[cont];
    for (int i = 0; i < cont; i++) {
        p[i].SetX(-100 + 50 * i);
        p[i].SetY(1000 - 50 * i);
    }
    std::shared_ptr<Drawing::TextBlob> textBlob = Drawing::TextBlob::MakeFromPosText(
        textInfo.c_str(), 10, p, font1, Drawing::TextEncoding::UTF8);

    // 5.组合textBlob类接口,如果有返回值则获取上一步创建的textBlob返回值打印
    std::string text = "harmony_os";
    std::vector<uint16_t> glyphid;
    Drawing::TextBlob::GetDrawingGlyphIDforTextBlob(textBlob.get(), glyphid);
    std::string text2 = "";
    for (int row = 0; row < text.size() && row < glyphid.size(); row++) {
        text2 += std::string(1, text[row]) + "：" + std::to_string(glyphid[row]);
    }

    //6. 得到需要绘制的所有返回值text,全部适应固定的textBlob构造方式打印
    std::vector<std::string> texts = {typefacestr, text2};

    //7.调用ClipIRect截取(0,0,1000,1000)区域（缺省,默认INTERSECT、不抗锯齿）
    auto rrect = Drawing::RoundRect(Drawing::Rect(0, 0, 1000, 1000), 52, 52);
    playbackCanvas_->ClipRoundRect(rrect);

    //8.调用Scale,Rotate,ConcatMatrix
    playbackCanvas_->Rotate(45, 50, 50);
    playbackCanvas_->Scale(0.5, 0.5);
    playbackCanvas_->Translate(400, 600);

    //9.最终绘制
    DrawTextBlob(texts, textBlob, font1, playbackCanvas_);
}

// 用例 Font_Scene_Transform_0219
DEF_DTK(Font_Scene_Transform_12, TestLevel::L2, 219)
{
    // 1.创建typeface
    std::shared_ptr<Drawing::FontMgr> fontMgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string familyName = "HMOS Color Emoji";
    std::shared_ptr<Drawing::FontStyleSet> fontStyleSet(fontMgr->MatchFamily(familyName.c_str()));
    auto typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->MatchStyle({
        Drawing::FontStyle::INVISIBLE_WEIGHT,
        Drawing::FontStyle::ULTRA_CONDENSED_WIDTH,
        Drawing::FontStyle::Slant::OBLIQUE_SLANT}));
    // 2.组合typeface操作接口
    auto familyNamex = typeface->GetFamilyName();
    std::string typefacestr = "GetFamilyName = " + familyNamex;
    // 3.组合Font类接口,如果是操作类有返回值的接口,获取接口返回值加入vector容器
    auto font = Drawing::Font(typeface, 50.f, 1.0f, 1.0f);
    font.SetSubpixel(false);
    font.SetScaleX(1);
    auto font1 = Drawing::Font(typeface, 50.f, font.GetScaleX(), 1.0f);
    font1.SetSubpixel(font.IsSubpixel());

    // 4.创建TextBlob
    std::string textInfo = "harmony_os";
    int cont = textInfo.size();
    Drawing::Point p[cont];
    for (int i = 0; i < cont; i++) {
        p[i].SetX(-100 + 50 * i);
        p[i].SetY(1000 - 50 * i);
    }
    std::shared_ptr<Drawing::TextBlob> textBlob = Drawing::TextBlob::MakeFromPosText(
        textInfo.c_str(), 10, p, font1, Drawing::TextEncoding::UTF8);

    // 5.组合textBlob类接口,如果有返回值则获取上一步创建的textBlob返回值打印
    std::string textinfo1 = "Deserialize @Hello World";
    Drawing::TextBlob::Context* Ctx = new (std::nothrow) Drawing::TextBlob::Context(typeface, false);
    auto data2 = textBlob->Serialize(Ctx);
    std::shared_ptr<Drawing::TextBlob> infoTextBlob2 =
        Drawing::TextBlob::Deserialize(data2->GetData(), data2->GetSize(), Ctx);

    //6. 得到需要绘制的所有返回值text,全部适应固定的textBlob构造方式打印
    std::vector<std::string> texts = {typefacestr};

    //7.调用ClipIRect截取(0,0,1000,1000)区域（缺省,默认INTERSECT、不抗锯齿）
    auto rect1 = Drawing::RectI(0, 0, 1000, 1000);
    playbackCanvas_->ClipIRect(rect1, Drawing::ClipOp::INTERSECT);

    //8.调用Scale,Rotate,ConcatMatrix
    Drawing::Matrix matrix;
    playbackCanvas_->ConcatMatrix(matrix);
    playbackCanvas_->Rotate(45, 50, 50);
    playbackCanvas_->Scale(0.5, 0.5);
    playbackCanvas_->Translate(400, 600);

    //9.最终绘制
    DrawTextBlob(texts, textBlob, font1, playbackCanvas_);
}

// 用例 Font_Scene_Transform_0220
DEF_DTK(Font_Scene_Transform_12, TestLevel::L2, 220)
{
    // 1.创建typeface
    std::shared_ptr<Drawing::FontMgr> fontMgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string familyName = "HMOS Color Emoji";
    std::shared_ptr<Drawing::FontStyleSet> fontStyleSet(fontMgr->MatchFamily(familyName.c_str()));
    auto typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->MatchStyle({
        Drawing::FontStyle::INVISIBLE_WEIGHT,
        Drawing::FontStyle::ULTRA_CONDENSED_WIDTH,
        Drawing::FontStyle::Slant::OBLIQUE_SLANT}));
    // 2.组合typeface操作接口
    auto data = typeface->Serialize();
    uint32_t size = 10;
    typeface->SetSize(size);
    std::shared_ptr<Drawing::Typeface> typeface1 = Drawing::Typeface::Deserialize(data->GetData(), typeface->GetSize());
    // 3.组合Font类接口,如果是操作类有返回值的接口,获取接口返回值加入vector容器
    auto font1 = Drawing::Font(typeface1, 50.f, 1.0f, 1.0f);
    font1.SetSubpixel(false);
    std::string text0 = "DDGR ddgr 鸿蒙 !@#￥%^&*; : , 。";
    int glyphCount = font1.CountText(text0.c_str(), text0.length(), Drawing::TextEncoding::UTF16);
    uint16_t glyphs[glyphCount - 1];
    int count = font1.TextToGlyphs(text0.c_str(), text0.length(), Drawing::TextEncoding::UTF16, glyphs, glyphCount + 1);
    std::string text4 = "TextToGlyphs = " + std::to_string(count);

    // 4.创建TextBlob
    std::string textInfo = "harmony_os";
    int cont = textInfo.size();
    Drawing::Point p[cont];
    for (int i = 0; i < cont; i++) {
        p[i].SetX(-100 + 50 * i);
        p[i].SetY(1000 - 50 * i);
    }
    std::shared_ptr<Drawing::TextBlob> textBlob = Drawing::TextBlob::MakeFromPosText(
        textInfo.c_str(), 10, p, font1, Drawing::TextEncoding::UTF8);

    // 5.组合textBlob类接口,如果有返回值则获取上一步创建的textBlob返回值打印
    auto rect = textBlob->Bounds();
    playbackCanvas_->DrawRect(*rect);

    //6. 得到需要绘制的所有返回值text,全部适应固定的textBlob构造方式打印
    std::vector<std::string> texts = {text4};

    //7.调用ClipIRect截取(0,0,1000,1000)区域（缺省,默认INTERSECT、不抗锯齿）
    auto rect1 = Drawing::RectI(0, 0, 1000, 1000);
    playbackCanvas_->ClipIRect(rect1, Drawing::ClipOp::INTERSECT);

    //8.调用Scale,Rotate,ConcatMatrix
    Drawing::Matrix matrix;
    playbackCanvas_->ConcatMatrix(matrix);
    playbackCanvas_->Rotate(45, 50, 50);
    playbackCanvas_->Translate(400, 600);

    //9.最终绘制
    DrawTextBlob(texts, textBlob, font1, playbackCanvas_);
}

// 用例 Font_Scene_Transform_0221
DEF_DTK(Font_Scene_Transform_12, TestLevel::L2, 221)
{
    // 1.创建typeface
    std::shared_ptr<Drawing::FontMgr> fontMgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string familyName = "HMOS Color Emoji";
    std::shared_ptr<Drawing::FontStyleSet> fontStyleSet(fontMgr->MatchFamily(familyName.c_str()));
    auto typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->MatchStyle({
        Drawing::FontStyle::INVISIBLE_WEIGHT,
        Drawing::FontStyle::ULTRA_CONDENSED_WIDTH,
        Drawing::FontStyle::Slant::OBLIQUE_SLANT}));
    // 2.组合typeface操作接口
    std::string typefacestr = "GetUnitsPerEm = " + std::to_string(typeface->GetUnitsPerEm());
    // 3.组合Font类接口,如果是操作类有返回值的接口,获取接口返回值加入vector容器
    auto font = Drawing::Font(typeface, 50.f, 1.0f, 1.0f);
    font.SetSubpixel(false);
    font.SetHinting(Drawing::FontHinting::NORMAL);
    auto font1 = Drawing::Font(typeface, 50.f, 1.0f, 1.0f);
    font1.SetSubpixel(font.IsSubpixel());
    font1.SetHinting(font.GetHinting());

    // 4.创建TextBlob
    std::string textInfo = "harmony_os";
    std::shared_ptr<Drawing::TextBlob> textBlob = Drawing::TextBlob::MakeFromString(
        textInfo.c_str(), font1, Drawing::TextEncoding::UTF8);

    // 5.组合textBlob类接口,如果有返回值则获取上一步创建的textBlob返回值打印
    std::string text = "harmony_os";
    std::vector<uint16_t> glyphid;
    Drawing::TextBlob::GetDrawingGlyphIDforTextBlob(textBlob.get(), glyphid);
    playbackCanvas_->Translate(200, 200);
    for (int row = 0; row < text.size() && row < glyphid.size(); row++) {
        auto path = Drawing::TextBlob::GetDrawingPathforTextBlob(glyphid[row], textBlob.get());
        playbackCanvas_->DrawPath(path);
        playbackCanvas_->Translate(0, 100);
    }

    //6. 得到需要绘制的所有返回值text,全部适应固定的textBlob构造方式打印
    std::vector<std::string> texts = {typefacestr};

    //7.调用ClipIRect截取(0,0,1000,1000)区域（缺省,默认INTERSECT、不抗锯齿）
    Drawing::Region region;
    region.SetRect(Drawing::RectI(100, 100, 500, 500));
    playbackCanvas_->ClipRegion(region);

    //8.调用Scale,Rotate,ConcatMatrix
    Drawing::Matrix matrix;
    playbackCanvas_->ConcatMatrix(matrix);
    playbackCanvas_->Rotate(45, 50, 50);
    playbackCanvas_->Scale(0.5, 0.5);

    //9.最终绘制
    DrawTextBlob(texts, textBlob, font1, playbackCanvas_);
}

// 用例 Font_Scene_Transform_0222
DEF_DTK(Font_Scene_Transform_12, TestLevel::L2, 222)
{
    // 1.创建typeface
    std::shared_ptr<Drawing::FontMgr> fontMgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string familyName = "HMOS Color Emoji";
    std::shared_ptr<Drawing::FontStyleSet> fontStyleSet(fontMgr->MatchFamily(familyName.c_str()));
    auto typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->MatchStyle({
        Drawing::FontStyle::INVISIBLE_WEIGHT,
        Drawing::FontStyle::ULTRA_CONDENSED_WIDTH,
        Drawing::FontStyle::Slant::OBLIQUE_SLANT}));
    // 2.组合typeface操作接口
    std::string typefacestr = "GetItalic = " + std::to_string(typeface->GetItalic());
    // 3.组合Font类接口,如果是操作类有返回值的接口,获取接口返回值加入vector容器
    auto font = Drawing::Font(typeface, 50.f, 1.0f, 1.0f);
    font.SetSubpixel(false);
    font.SetSkewX(1.0f);
    auto font1 = Drawing::Font(typeface, 50.f, font.GetSkewX(), 1.0f);
    font1.SetSubpixel(font.IsSubpixel());

    // 4.创建TextBlob
    std::string textInfo = "harmony_os";
    std::shared_ptr<Drawing::TextBlob> textBlob = Drawing::TextBlob::MakeFromString(
        textInfo.c_str(), font1, Drawing::TextEncoding::UTF8);

    // 5.组合textBlob类接口,如果有返回值则获取上一步创建的textBlob返回值打印
    std::string name1 = "HMOS Color Emoji";
    std::string textInfo1 = "😊😂🤣😍😒💕😘😁👍🙌👌";
    std::shared_ptr<Drawing::TextBlob> textBlob1 = Drawing::TextBlob::MakeFromText(textInfo1.c_str(),
                                                      textInfo1.size(), font1, Drawing::TextEncoding::UTF8);
    if (textBlob1->IsEmoji()) {
        playbackCanvas_->DrawBackground(0xFF0000FF);
    } else {
        playbackCanvas_->DrawBackground(0xFFFF0000);
    }

    //6. 得到需要绘制的所有返回值text,全部适应固定的textBlob构造方式打印
    std::vector<std::string> texts = {typefacestr};

    //7.调用ClipIRect截取(0,0,1000,1000)区域（缺省,默认INTERSECT、不抗锯齿）
    auto rect1 = Drawing::Rect(0, 0, 600, 600);
    playbackCanvas_->ClipRect(rect1);

    //8.调用Scale,Rotate,ConcatMatrix
    playbackCanvas_->Scale(0.5, 0.5);

    //9.最终绘制
    DrawTextBlob(texts, textBlob, font1, playbackCanvas_);
}

// 用例 Font_Scene_Transform_0223
DEF_DTK(Font_Scene_Transform_12, TestLevel::L2, 223)
{
    // 1.创建typeface
    std::shared_ptr<Drawing::FontMgr> fontMgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string familyName = "HMOS Color Emoji";
    std::shared_ptr<Drawing::FontStyleSet> fontStyleSet(fontMgr->MatchFamily(familyName.c_str()));
    auto typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->MatchStyle({
        Drawing::FontStyle::INVISIBLE_WEIGHT,
        Drawing::FontStyle::ULTRA_CONDENSED_WIDTH,
        Drawing::FontStyle::Slant::OBLIQUE_SLANT}));
    // 2.组合typeface操作接口
    auto familyNamex = typeface->GetFamilyName();
    std::string typefacestr = "GetFamilyName = " + familyNamex;
    // 3.组合Font类接口,如果是操作类有返回值的接口,获取接口返回值加入vector容器
    auto font1 = Drawing::Font(typeface, 50.f, 1.0f, 1.0f);
    font1.SetSubpixel(false);
    std::string text0 = "DDGR ddgr 鸿蒙 !@#￥%^&*; : , 。";
    Drawing::Rect bounds;
    auto scalar = font1.MeasureText(text0.c_str(), text0.length(), Drawing::TextEncoding::UTF32, &bounds);
    std::string text4 = "MeasureTextWidths = " + std::to_string(scalar);

    // 4.创建TextBlob
    std::string textInfo = "harmony_os";
    std::shared_ptr<Drawing::TextBlob> textBlob = Drawing::TextBlob::MakeFromString(
        textInfo.c_str(), font1, Drawing::TextEncoding::UTF8);

    // 5.组合textBlob类接口,如果有返回值则获取上一步创建的textBlob返回值打印
    std::string textinfo1 = "Deserialize @Hello World";
    Drawing::TextBlob::Context* Ctx = new (std::nothrow) Drawing::TextBlob::Context(typeface, false);
    auto data2 = textBlob->Serialize(Ctx);
    std::shared_ptr<Drawing::TextBlob> infoTextBlob2 =
        Drawing::TextBlob::Deserialize(data2->GetData(), data2->GetSize(), Ctx);

    //6. 得到需要绘制的所有返回值text,全部适应固定的textBlob构造方式打印
    std::vector<std::string> texts = {typefacestr, text4};

    //7.调用ClipIRect截取(0,0,1000,1000)区域（缺省,默认INTERSECT、不抗锯齿）
    auto rect1 = Drawing::Rect(0, 0, 600, 600);
    playbackCanvas_->ClipRect(rect1);

    //8.调用Scale,Rotate,ConcatMatrix
    Drawing::Matrix matrix;
    playbackCanvas_->ConcatMatrix(matrix);
    playbackCanvas_->Rotate(45, 50, 50);
    playbackCanvas_->Scale(0.5, 0.5);
    playbackCanvas_->Translate(400, 600);

    //9.最终绘制
    DrawTextBlob(texts, textBlob, font1, playbackCanvas_);
}

// 用例 Font_Scene_Transform_0224
DEF_DTK(Font_Scene_Transform_12, TestLevel::L2, 224)
{
    // 1.创建typeface
    std::shared_ptr<Drawing::FontMgr> fontMgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string familyName = "HMOS Color Emoji";
    std::shared_ptr<Drawing::FontStyleSet> fontStyleSet(fontMgr->MatchFamily(familyName.c_str()));
    auto typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->MatchStyle({
        Drawing::FontStyle::INVISIBLE_WEIGHT,
        Drawing::FontStyle::ULTRA_CONDENSED_WIDTH,
        Drawing::FontStyle::Slant::OBLIQUE_SLANT}));
    // 2.组合typeface操作接口
    std::string typefacestr = "GetUniqueID = " + std::to_string(typeface->GetUniqueID());
    // 3.组合Font类接口,如果是操作类有返回值的接口,获取接口返回值加入vector容器
    auto font = Drawing::Font(typeface, 50.f, 1.0f, 1.0f);
    font.SetSubpixel(false);
    font.SetEmbeddedBitmaps(true);
    auto font1 = Drawing::Font(typeface, 50.f, 1.0f, 1.0f);
    font1.SetSubpixel(font.IsSubpixel());
    font1.SetEmbeddedBitmaps(font.IsEmbeddedBitmaps());

    // 4.创建TextBlob
    std::string textInfo = "1111111111111111111111111111111111";
    int maxGlyphCount = font1.CountText(textInfo.c_str(), textInfo.size(), Drawing::TextEncoding::UTF8);
    Drawing::RSXform xform[maxGlyphCount];
    for (int i = 0; i < maxGlyphCount; ++i) {
        xform[i].cos_ = cos(10 * i) + 0.1 * i;
        xform[i].sin_ = sin(10 * i);
        xform[i].tx_ = 40 * i + 100;;
        xform[i].ty_ = 100;
    }
    std::shared_ptr<Drawing::TextBlob> textBlob = Drawing::TextBlob::MakeFromRSXform(
        textInfo.c_str(), textInfo.size(), &xform[0], font1, Drawing::TextEncoding::UTF8);

    // 5.组合textBlob类接口,如果有返回值则获取上一步创建的textBlob返回值打印
    std::vector<Drawing::Point> points;
    Drawing::TextBlob::GetDrawingPointsForTextBlob(textBlob.get(), points);
    std::string text2 = "";
    for (int i = 0; i < points.size(); i++) {
        text2 += std::to_string(i) + "-- X：" + std::to_string(points[i].GetX())
                     + "Y：" + std::to_string(points[i].GetY());
    }

    //6. 得到需要绘制的所有返回值text,全部适应固定的textBlob构造方式打印
    std::vector<std::string> texts = {typefacestr, text2};

    //7.调用ClipIRect截取(0,0,1000,1000)区域（缺省,默认INTERSECT、不抗锯齿）
    Drawing::Path path;
    path.AddOval({100, 100, 356, 356});
    playbackCanvas_->ClipPath(path);

    //8.调用Scale,Rotate,ConcatMatrix
    playbackCanvas_->Rotate(45, 50, 50);

    //9.最终绘制
    DrawTextBlob(texts, textBlob, font1, playbackCanvas_);
}

// 用例 Font_Scene_Transform_0225
DEF_DTK(Font_Scene_Transform_12, TestLevel::L2, 225)
{
    // 1.创建typeface
    std::shared_ptr<Drawing::FontMgr> fontMgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string familyName = "HMOS Color Emoji";
    std::shared_ptr<Drawing::FontStyleSet> fontStyleSet(fontMgr->MatchFamily(familyName.c_str()));
    auto typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->MatchStyle({
        Drawing::FontStyle::INVISIBLE_WEIGHT,
        Drawing::FontStyle::ULTRA_CONDENSED_WIDTH,
        Drawing::FontStyle::Slant::OBLIQUE_SLANT}));
    // 2.组合typeface操作接口
    std::string typefacestr = "GetUniqueID = " + std::to_string(typeface->GetUniqueID());
    // 3.组合Font类接口,如果是操作类有返回值的接口,获取接口返回值加入vector容器
    auto font = Drawing::Font(typeface, 50.f, 1.0f, 1.0f);
    font.SetSubpixel(false);
    font.SetLinearMetrics(false);
    auto font1 = Drawing::Font(typeface, 50.f, 1.0f, 1.0f);
    font1.SetSubpixel(font.IsSubpixel());
    font1.SetLinearMetrics(font.IsLinearMetrics());

    // 4.创建TextBlob
    std::string textInfo = "1111111111111111111111111111111111";
    int maxGlyphCount = font1.CountText(textInfo.c_str(), textInfo.size(), Drawing::TextEncoding::UTF8);
    Drawing::RSXform xform[maxGlyphCount];
    for (int i = 0; i < maxGlyphCount; ++i) {
        xform[i].cos_ = cos(10 * i) + 0.1 * i;
        xform[i].sin_ = sin(10 * i);
        xform[i].tx_ = 40 * i + 100;;
        xform[i].ty_ = 100;
    }
    std::shared_ptr<Drawing::TextBlob> textBlob = Drawing::TextBlob::MakeFromRSXform(
        textInfo.c_str(), textInfo.size(), &xform[0], font1, Drawing::TextEncoding::UTF8);

    // 5.组合textBlob类接口,如果有返回值则获取上一步创建的textBlob返回值打印
    Drawing::Paint paint;
    paint.SetColor(0xFFFF0000);
    float boundsx[] = {1, 2, 3};
    int intercepts = textBlob->GetIntercepts(boundsx, nullptr, &paint);
    std::string text2 = "intercepts = " + std::to_string(intercepts);

    //6. 得到需要绘制的所有返回值text,全部适应固定的textBlob构造方式打印
    std::vector<std::string> texts = {typefacestr, text2};

    //7.调用ClipIRect截取(0,0,1000,1000)区域（缺省,默认INTERSECT、不抗锯齿）
    Drawing::Path path;
    path.AddOval({100, 100, 356, 356});
    playbackCanvas_->ClipPath(path);

    //8.调用Scale,Rotate,ConcatMatrix
    playbackCanvas_->Scale(0.5, 0.5);
    playbackCanvas_->Translate(400, 600);

    //9.最终绘制
    DrawTextBlob(texts, textBlob, font1, playbackCanvas_);
}

// 用例 Font_Scene_Transform_0227
DEF_DTK(Font_Scene_Transform_12, TestLevel::L2, 227)
{
    // 1.创建typeface
    std::shared_ptr<Drawing::FontMgr> fontMgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::shared_ptr<Drawing::FontStyleSet> fontStyleSet(fontMgr->CreateStyleSet(0));
    auto typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->CreateTypeface(0));
    // 2.组合typeface操作接口
    std::string typefacestr = "GetItalic = " + std::to_string(typeface->GetItalic());
    // 3.组合Font类接口,如果是操作类有返回值的接口,获取接口返回值加入vector容器
    auto font = Drawing::Font(typeface, 50.f, 1.0f, 1.0f);
    font.SetSubpixel(false);
    font.SetEdging(Drawing::FontEdging::ANTI_ALIAS);
    auto font1 = Drawing::Font(typeface, 50.f, 1.0f, 1.0f);
    font1.SetSubpixel(font.IsSubpixel());
    font1.SetEdging(font.GetEdging());

    // 4.创建TextBlob
    Drawing::TextBlobBuilder builder;
    auto buffer = builder.AllocRunPos(font1, 20, nullptr);
    for (int i = 0; i < 20; i++) {
        buffer.glyphs[i] = font1.UnicharToGlyph(0x9088);
        buffer.pos[i * 2] = 50.f * i;
        buffer.pos[i * 2 + 1] = 0;
    }
    std::shared_ptr<Drawing::TextBlob> textBlob = builder.Make();

    // 5.组合textBlob类接口,如果有返回值则获取上一步创建的textBlob返回值打印
    std::vector<Drawing::Point> points;
    Drawing::TextBlob::GetDrawingPointsForTextBlob(textBlob.get(), points);
    std::string text2 = "";
    for (int i = 0; i < points.size(); i++) {
        text2 += std::to_string(i) + "-- X：" + std::to_string(points[i].GetX())
                     + "Y：" + std::to_string(points[i].GetY());
    }

    //6. 得到需要绘制的所有返回值text,全部适应固定的textBlob构造方式打印
    std::vector<std::string> texts = {typefacestr, text2};

    //7.调用ClipIRect截取(0,0,1000,1000)区域（缺省,默认INTERSECT、不抗锯齿）
    Drawing::Region region;
    region.SetRect(Drawing::RectI(100, 100, 500, 500));
    playbackCanvas_->ClipRegion(region);

    //8.调用Scale,Rotate,ConcatMatrix
    playbackCanvas_->Rotate(45, 50, 50);
    playbackCanvas_->Translate(400, 600);

    //9.最终绘制
    DrawTextBlob(texts, textBlob, font1, playbackCanvas_);
}

// 用例 Font_Scene_Transform_0228
DEF_DTK(Font_Scene_Transform_12, TestLevel::L2, 228)
{
    // 1.创建typeface
    std::shared_ptr<Drawing::FontMgr> fontMgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::shared_ptr<Drawing::FontStyleSet> fontStyleSet(fontMgr->CreateStyleSet(0));
    auto typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->CreateTypeface(0));
    // 2.组合typeface操作接口
    std::string typefacestr = "GetUniqueID = " + std::to_string(typeface->GetUniqueID());
    // 3.组合Font类接口,如果是操作类有返回值的接口,获取接口返回值加入vector容器
    auto font = Drawing::Font(typeface, 50.f, 1.0f, 1.0f);
    font.SetSubpixel(false);
    font.SetSize(100.f);
    auto font1 = Drawing::Font(typeface, font.GetSize(), 1.0f, 1.0f);
    font1.SetSubpixel(font.IsSubpixel());

    // 4.创建TextBlob
    Drawing::TextBlobBuilder builder;
    auto buffer = builder.AllocRunPos(font1, 20, nullptr);
    for (int i = 0; i < 20; i++) {
        buffer.glyphs[i] = font1.UnicharToGlyph(0x9088);
        buffer.pos[i * 2] = 50.f * i;
        buffer.pos[i * 2 + 1] = 0;
    }
    std::shared_ptr<Drawing::TextBlob> textBlob = builder.Make();

    // 5.组合textBlob类接口,如果有返回值则获取上一步创建的textBlob返回值打印
    auto rect = textBlob->Bounds();
    playbackCanvas_->DrawRect(*rect);

    //6. 得到需要绘制的所有返回值text,全部适应固定的textBlob构造方式打印
    std::vector<std::string> texts = {typefacestr};

    //7.调用ClipIRect截取(0,0,1000,1000)区域（缺省,默认INTERSECT、不抗锯齿）
    Drawing::Path path;
    path.AddOval({100, 100, 356, 356});
    playbackCanvas_->ClipPath(path);

    //8.调用Scale,Rotate,ConcatMatrix
    Drawing::Matrix matrix;
    playbackCanvas_->ConcatMatrix(matrix);
    playbackCanvas_->Scale(0.5, 0.5);
    playbackCanvas_->Translate(400, 600);

    //9.最终绘制
    DrawTextBlob(texts, textBlob, font1, playbackCanvas_);
}

// 用例 Font_Scene_Transform_0229
DEF_DTK(Font_Scene_Transform_12, TestLevel::L2, 229)
{
    // 1.创建typeface
    std::shared_ptr<Drawing::FontMgr> fontMgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::shared_ptr<Drawing::FontStyleSet> fontStyleSet(fontMgr->CreateStyleSet(0));
    auto typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->CreateTypeface(0));
    // 2.组合typeface操作接口
    std::string typefacestr = "GetItalic = " + std::to_string(typeface->GetItalic());
    // 3.组合Font类接口,如果是操作类有返回值的接口,获取接口返回值加入vector容器
    auto font1 = Drawing::Font(typeface, 50.f, 1.0f, 1.0f);
    font1.SetSubpixel(false);
    std::string text0 = "DDGR ddgr 鸿蒙 !@#￥%^&*; : , 。";
    int glyphCount = font1.CountText(text0.c_str(), text0.length(), Drawing::TextEncoding::UTF8);
    float widths[glyphCount];
    uint16_t glyphs[glyphCount];
    font1.TextToGlyphs(text0.c_str(), text0.length(), Drawing::TextEncoding::UTF8, glyphs, glyphCount);
    font1.GetWidths(glyphs, glyphCount, widths);
    std::string text4 = "Getwidths = " + std::to_string(widths[0]);

    // 4.创建TextBlob
    Drawing::TextBlobBuilder builder;
    auto buffer = builder.AllocRunPos(font1, 20, nullptr);
    for (int i = 0; i < 20; i++) {
        buffer.glyphs[i] = font1.UnicharToGlyph(0x9088);
        buffer.pos[i * 2] = 50.f * i;
        buffer.pos[i * 2 + 1] = 0;
    }
    std::shared_ptr<Drawing::TextBlob> textBlob = builder.Make();

    // 5.组合textBlob类接口,如果有返回值则获取上一步创建的textBlob返回值打印
    std::string textinfo1 = "Deserialize @Hello World";
    Drawing::TextBlob::Context* Ctx = new (std::nothrow) Drawing::TextBlob::Context(typeface, false);
    auto data2 = textBlob->Serialize(Ctx);
    std::shared_ptr<Drawing::TextBlob> infoTextBlob2 =
        Drawing::TextBlob::Deserialize(data2->GetData(), data2->GetSize(), Ctx);

    //6. 得到需要绘制的所有返回值text,全部适应固定的textBlob构造方式打印
    std::vector<std::string> texts = {typefacestr, text4};

    //7.调用ClipIRect截取(0,0,1000,1000)区域（缺省,默认INTERSECT、不抗锯齿）
    Drawing::Path path;
    path.AddOval({100, 100, 356, 356});
    playbackCanvas_->ClipPath(path);

    //8.调用Scale,Rotate,ConcatMatrix
    playbackCanvas_->Scale(0.5, 0.5);
    playbackCanvas_->Translate(400, 600);

    //9.最终绘制
    DrawTextBlob(texts, textBlob, font1, playbackCanvas_);
}

// 用例 Font_Scene_Transform_0230
DEF_DTK(Font_Scene_Transform_12, TestLevel::L2, 230)
{
    // 1.创建typeface
    std::shared_ptr<Drawing::FontMgr> fontMgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::shared_ptr<Drawing::FontStyleSet> fontStyleSet(fontMgr->CreateStyleSet(0));
    auto typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->CreateTypeface(0));
    // 2.组合typeface操作接口
    auto data = typeface->Serialize();
    uint32_t size = 10;
    typeface->SetSize(size);
    std::shared_ptr<Drawing::Typeface> typeface1 = Drawing::Typeface::Deserialize(data->GetData(), typeface->GetSize());
    // 3.组合Font类接口,如果是操作类有返回值的接口,获取接口返回值加入vector容器
    auto font = Drawing::Font(typeface1, 50.f, 1.0f, 1.0f);
    font.SetSubpixel(false);
    font.SetBaselineSnap(true);
    auto font1 = Drawing::Font(typeface1, 50.f, 1.0f, 1.0f);
    font1.SetSubpixel(font.IsSubpixel());
    font1.SetBaselineSnap(font.IsBaselineSnap());

    // 4.创建TextBlob
    Drawing::TextBlobBuilder builder;
    auto buffer = builder.AllocRunRSXform(font1, 20);
    for (int i = 0; i < 20; i++) {
        buffer.glyphs[i] = font1.UnicharToGlyph(0x30);
        buffer.pos[i * 4] = cos(i * 18);
        buffer.pos[i * 4 + 1] = sin(18 * i);
        buffer.pos[i * 4 + 2] = 100;
        buffer.pos[i * 4 + 3] = 100;
    }
    std::shared_ptr<Drawing::TextBlob> textBlob = builder.Make();

    // 5.组合textBlob类接口,如果有返回值则获取上一步创建的textBlob返回值打印
    Drawing::Paint paint;
    paint.SetColor(0xFFFF0000);
    float boundsx[] = {1, 2, 3};
    int intercepts = textBlob->GetIntercepts(boundsx, nullptr, &paint);
    std::string text2 = "intercepts = " + std::to_string(intercepts);

    //6. 得到需要绘制的所有返回值text,全部适应固定的textBlob构造方式打印
    std::vector<std::string> texts = {text2};

    //7.调用ClipIRect截取(0,0,1000,1000)区域（缺省,默认INTERSECT、不抗锯齿）
    auto rrect = Drawing::RoundRect(Drawing::Rect(0, 0, 1000, 1000), 52, 52);
    playbackCanvas_->ClipRoundRect(rrect);

    //8.调用Scale,Rotate,ConcatMatrix
    Drawing::Matrix matrix;
    playbackCanvas_->ConcatMatrix(matrix);
    playbackCanvas_->Translate(400, 600);

    //9.最终绘制
    DrawTextBlob(texts, textBlob, font1, playbackCanvas_);
}

// 用例 Font_Scene_Transform_0231
DEF_DTK(Font_Scene_Transform_12, TestLevel::L2, 231)
{
    // 1.创建typeface
    std::shared_ptr<Drawing::FontMgr> fontMgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::shared_ptr<Drawing::FontStyleSet> fontStyleSet(fontMgr->CreateStyleSet(0));
    auto typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->CreateTypeface(0));
    // 2.组合typeface操作接口
    std::string typefacestr = "GetUnitsPerEm = " + std::to_string(typeface->GetUnitsPerEm());
    // 3.组合Font类接口,如果是操作类有返回值的接口,获取接口返回值加入vector容器
    auto font = Drawing::Font(typeface, 50.f, 1.0f, 1.0f);
    font.SetSubpixel(false);
    font.SetEmbolden(false);
    auto font1 = Drawing::Font(typeface, 50.f, 1.0f, 1.0f);
    font1.SetSubpixel(font.IsSubpixel());
    font1.SetEmbolden(font.IsEmbolden());

    // 4.创建TextBlob
    Drawing::TextBlobBuilder builder;
    auto buffer = builder.AllocRunRSXform(font1, 20);
    for (int i = 0; i < 20; i++) {
        buffer.glyphs[i] = font1.UnicharToGlyph(0x30);
        buffer.pos[i * 4] = cos(i * 18);
        buffer.pos[i * 4 + 1] = sin(18 * i);
        buffer.pos[i * 4 + 2] = 100;
        buffer.pos[i * 4 + 3] = 100;
    }
    std::shared_ptr<Drawing::TextBlob> textBlob = builder.Make();

    // 5.组合textBlob类接口,如果有返回值则获取上一步创建的textBlob返回值打印
    std::string textinfo1 = "Deserialize @Hello World";
    Drawing::TextBlob::Context* Ctx = new (std::nothrow) Drawing::TextBlob::Context(typeface, false);
    auto data2 = textBlob->Serialize(Ctx);
    std::shared_ptr<Drawing::TextBlob> infoTextBlob2 =
        Drawing::TextBlob::Deserialize(data2->GetData(), data2->GetSize(), Ctx);

    //6. 得到需要绘制的所有返回值text,全部适应固定的textBlob构造方式打印
    std::vector<std::string> texts = {typefacestr};

    //7.调用ClipIRect截取(0,0,1000,1000)区域（缺省,默认INTERSECT、不抗锯齿）
    auto rrect = Drawing::RoundRect(Drawing::Rect(0, 0, 1000, 1000), 52, 52);
    playbackCanvas_->ClipRoundRect(rrect);

    //8.调用Scale,Rotate,ConcatMatrix
    playbackCanvas_->Scale(0.5, 0.5);

    //9.最终绘制
    DrawTextBlob(texts, textBlob, font1, playbackCanvas_);
}

// 用例 Font_Scene_Transform_0232
DEF_DTK(Font_Scene_Transform_12, TestLevel::L2, 232)
{
    // 1.创建typeface
    std::shared_ptr<Drawing::FontMgr> fontMgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::shared_ptr<Drawing::FontStyleSet> fontStyleSet(fontMgr->CreateStyleSet(0));
    auto typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->CreateTypeface(0));
    // 2.组合typeface操作接口
    std::string typefacestr = "GetUniqueID = " + std::to_string(typeface->GetUniqueID());
    // 3.组合Font类接口,如果是操作类有返回值的接口,获取接口返回值加入vector容器
    auto font1 = Drawing::Font(typeface, 50.f, 1.0f, 1.0f);
    font1.SetSubpixel(false);
    std::string text0 = "DDGR ddgr 鸿蒙 !@#￥%^&*; : , 。";
    auto scalar = font1.UnicharToGlyph(0x44);
    std::string text4 = "Glyphs = " + std::to_string(scalar);

    // 4.创建TextBlob
    Drawing::TextBlobBuilder builder;
    auto buffer = builder.AllocRunRSXform(font1, 20);
    for (int i = 0; i < 20; i++) {
        buffer.glyphs[i] = font1.UnicharToGlyph(0x30);
        buffer.pos[i * 4] = cos(i * 18);
        buffer.pos[i * 4 + 1] = sin(18 * i);
        buffer.pos[i * 4 + 2] = 100;
        buffer.pos[i * 4 + 3] = 100;
    }
    std::shared_ptr<Drawing::TextBlob> textBlob = builder.Make();

    // 5.组合textBlob类接口,如果有返回值则获取上一步创建的textBlob返回值打印
    std::string name1 = "HMOS Color Emoji";
    std::string textInfo1 = "😊😂🤣😍😒💕😘😁👍🙌👌";
    std::shared_ptr<Drawing::TextBlob> textBlob1 = Drawing::TextBlob::MakeFromText(textInfo1.c_str(),
                                                      textInfo1.size(), font1, Drawing::TextEncoding::UTF8);
    if (textBlob1->IsEmoji()) {
        playbackCanvas_->DrawBackground(0xFF0000FF);
    } else {
        playbackCanvas_->DrawBackground(0xFFFF0000);
    }

    //6. 得到需要绘制的所有返回值text,全部适应固定的textBlob构造方式打印
    std::vector<std::string> texts = {typefacestr, text4};

    //7.调用ClipIRect截取(0,0,1000,1000)区域（缺省,默认INTERSECT、不抗锯齿）
    auto rrect = Drawing::RoundRect(Drawing::Rect(0, 0, 1000, 1000), 52, 52);
    playbackCanvas_->ClipRoundRect(rrect);

    //8.调用Scale,Rotate,ConcatMatrix
    Drawing::Matrix matrix;
    playbackCanvas_->ConcatMatrix(matrix);
    playbackCanvas_->Rotate(45, 50, 50);
    playbackCanvas_->Translate(400, 600);

    //9.最终绘制
    DrawTextBlob(texts, textBlob, font1, playbackCanvas_);
}

}
}
