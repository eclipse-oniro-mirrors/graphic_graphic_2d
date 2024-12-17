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
#include "../../rs_demo_test_ext.h"
#include "text/font.h"
#include "text/font_mgr.h"
#include "text/font_style_set.h"
#include "text/text_blob_builder.h"
#include "text/typeface.h"

/*
测试类：textblobbuilder
测试接口：allocrunrsxform
测试内容：
1、对接口入参字体样式、需生成textblob字符个数进行参数组合创建buffer。
2、对buffer里每个元素设置glyphsID并进行排版。
3、通过make接口创建textblob，并调用drawtextblob接口将内容绘制在画布上。
*/

namespace OHOS {
namespace Rosen {

void DrawText(Drawing::TextBlobBuilder& builder, TestPlaybackCanvas* playbackCanvas)
{
    Drawing::Brush brush;
    Drawing::Pen pen;

    int line2 = 2000;
    int line8 = 800;
    int interval2 = 200;

    playbackCanvas->AttachBrush(brush);
    std::shared_ptr<Drawing::TextBlob> infoTextBlob1 = builder.Make();
    playbackCanvas->DrawTextBlob(infoTextBlob1.get(), interval2, line8);
    playbackCanvas->DetachBrush();

    playbackCanvas->AttachPen(pen);
    playbackCanvas->DrawTextBlob(infoTextBlob1.get(), interval2, line2);
    playbackCanvas->DetachPen();
}

//对应用例allocrunrsxform_3001
DEF_RSDEMO(textblobbuilder_allocrunrsxform, TestLevel::L1, 1)
{

    std::shared_ptr<Drawing::FontMgr> font_mgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string name = "HarmonyOS Sans SC";
    std::shared_ptr<Drawing::FontStyle> fontStyleSet(font_mgr->MatchFamily(name.c_str()));
    auto typeface = Drawing::Typeface::MakeDefault();
    typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->CreateTypeface(0));
    auto font = Drawing::Font();
    font.SetTypeface(typeface);
    font.SetSize(50.f);
    Drawing::TextBlobBuilder builder;
    auto buffer = builder.AllocRunRSXform(font, 20);
    for (int i = 0; i < 20; i++) {
        buffer.glyphs[i] = font.UnicharToGlyph(0X30);
        buffer.pos[i * 4] = i+1;
        buffer.pos[i * 4 + 1] =  0;
        buffer.pos[i * 4 + 2] =  100;
        buffer.pos[i * 4 + 3] =  100;
    }
    DrawText(builder, playbackCanvas_);
}

//对应用例allocrunrsxform_3002
DEF_RSDEMO(textblobbuilder_allocrunrsxform, TestLevel::L1, 2)
{
    Drawing::Brush brush;
    Drawing::Pen pen;
    playbackCanvas_->AttachBrush(brush);
    std::shared_ptr<Drawing::FontMgr> font_mgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string name = "HarmonyOS Sans SC";
    std::shared_ptr<Drawing::FontStyle> fontStyleSet(font_mgr->MatchFamily(name.c_str()));
    auto typeface = Drawing::Typeface::MakeDefault();
    typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->CreateTypeface(0));
    auto font = Drawing::Font();
    font.SetTypeface(typeface);
    font.SetSize(50.f);
    Drawing::TextBlobBuilder builder;
    auto buffer = builder.AllocRunRSXform(font, 20);
    for (int i = 0; i < 20; i++) {
        buffer.glyphs[i] = font.UnicharToGlyph(0X30);
        buffer.pos[i * 4] = cos(i*18);
        buffer.pos[i * 4 + 1] = sin(18*i);
        buffer.pos[i * 4 + 2] = 100;
        buffer.pos[i * 4 + 3] = 100;
    }
    DrawText(builder, playbackCanvas_);
}

//对应用例allocrunrsxform_3003
DEF_RSDEMO(textblobbuilder_allocrunrsxform, TestLevel::L1, 3)
{
    Drawing::Brush brush;
    Drawing::Pen pen;
    playbackCanvas_->AttachBrush(brush);
    std::shared_ptr<Drawing::FontMgr> font_mgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string name = "HarmonyOS Sans SC";
    std::shared_ptr<Drawing::FontStyle> fontStyleSet(font_mgr->MatchFamily(name.c_str()));
    auto typeface = Drawing::Typeface::MakeDefault();
    typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->CreateTypeface(0));
    auto font = Drawing::Font();
    font.SetTypeface(typeface);
    font.SetSize(50.f);
    Drawing::TextBlobBuilder builder;
    auto buffer = builder.AllocRunRSXform(font, 20);
    for (int i = 0; i < 20; i++) {
        buffer.glyphs[i] = font.UnicharToGlyph(0X30);
        buffer.pos[i * 4] = 1;
        buffer.pos[i * 4 + 1] =  0;
        buffer.pos[i * 4 + 2] =  50*i;
        buffer.pos[i * 4 + 3] =  0;
    }
    DrawText(builder, playbackCanvas_);
}

//对应用例allocrunrsxform_3004
DEF_RSDEMO(textblobbuilder_allocrunrsxform, TestLevel::L1, 4)
{
    Drawing::Brush brush;
    Drawing::Pen pen;
    playbackCanvas_->AttachBrush(brush);
    std::shared_ptr<Drawing::FontMgr> font_mgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string name = "HarmonyOS Sans SC";
    std::shared_ptr<Drawing::FontStyle> fontStyleSet(font_mgr->MatchFamily(name.c_str()));
    auto typeface = Drawing::Typeface::MakeDefault();
    typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->CreateTypeface(0));
    auto font = Drawing::Font();
    font.SetTypeface(typeface);
    font.SetSize(50.f);
    Drawing::TextBlobBuilder builder;
    auto buffer = builder.AllocRunRSXform(font, 20);
    for (int i = 0; i < 20; i++) {
        buffer.glyphs[i] = font.UnicharToGlyph(0X30);
        buffer.pos[i * 4] = cos(10 * i) + 0.1 * i;
        buffer.pos[i * 4 + 1] = sin(10 * i);
        buffer.pos[i * 4 + 2] =  20*i;
        buffer.pos[i * 4 + 3] =  -10*i;
    }
    DrawText(builder, playbackCanvas_);
}

//对应用例allocrunrsxform_3005
DEF_RSDEMO(textblobbuilder_allocrunrsxform, TestLevel::L1, 5)
{
    Drawing::Brush brush;
    Drawing::Pen pen;
    playbackCanvas_->AttachBrush(brush);
    std::shared_ptr<Drawing::FontMgr> font_mgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string name = "HarmonyOS Sans SC";
    std::shared_ptr<Drawing::FontStyle> fontStyleSet(font_mgr->MatchFamily(name.c_str()));
    auto typeface = Drawing::Typeface::MakeDefault();
    typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->CreateTypeface(0));
    auto font = Drawing::Font();
    font.SetTypeface(typeface);
    font.SetSize(50.f);
    Drawing::TextBlobBuilder builder;
    auto buffer = builder.AllocRunRSXform(font, 20);
    for (int i = 0; i < 20; i++) {
        buffer.glyphs[i] = font.UnicharToGlyph(0X9088);
        buffer.pos[i * 4] = i+1;
        buffer.pos[i * 4 + 1] =  0;
        buffer.pos[i * 4 + 2] =  100;
        buffer.pos[i * 4 + 3] =  100;
    }
    DrawText(builder, playbackCanvas_);
}

//对应用例allocrunrsxform_3006
DEF_RSDEMO(textblobbuilder_allocrunrsxform, TestLevel::L1, 6)
{
    Drawing::Brush brush;
    Drawing::Pen pen;
    playbackCanvas_->AttachBrush(brush);
    std::shared_ptr<Drawing::FontMgr> font_mgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string name = "HarmonyOS Sans SC";
    std::shared_ptr<Drawing::FontStyle> fontStyleSet(font_mgr->MatchFamily(name.c_str()));
    auto typeface = Drawing::Typeface::MakeDefault();
    typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->CreateTypeface(0));
    auto font = Drawing::Font();
    font.SetTypeface(typeface);
    font.SetSize(50.f);
    Drawing::TextBlobBuilder builder;
    auto buffer = builder.AllocRunRSXform(font, 20);
    for (int i = 0; i < 20; i++) {
        buffer.glyphs[i] = font.UnicharToGlyph(0X9088);
        buffer.pos[i * 4] = cos(i*18);
        buffer.pos[i * 4 + 1] = sin(18*i);
        buffer.pos[i * 4 + 2] = 100;
        buffer.pos[i * 4 + 3] = 100;
    }
    DrawText(builder, playbackCanvas_);
}

//对应用例allocrunrsxform_3007
DEF_RSDEMO(textblobbuilder_allocrunrsxform, TestLevel::L1, 7)
{
    Drawing::Brush brush;
    Drawing::Pen pen;
    playbackCanvas_->AttachBrush(brush);
    std::shared_ptr<Drawing::FontMgr> font_mgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string name = "HarmonyOS Sans SC";
    std::shared_ptr<Drawing::FontStyle> fontStyleSet(font_mgr->MatchFamily(name.c_str()));
    auto typeface = Drawing::Typeface::MakeDefault();
    typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->CreateTypeface(0));
    auto font = Drawing::Font();
    font.SetTypeface(typeface);
    font.SetSize(50.f);
    Drawing::TextBlobBuilder builder;
    auto buffer = builder.AllocRunRSXform(font, 20);
    for (int i = 0; i < 20; i++) {
        buffer.glyphs[i] = font.UnicharToGlyph(0X9088);
        buffer.pos[i * 4] = 1;
        buffer.pos[i * 4 + 1] =  0;
        buffer.pos[i * 4 + 2] =  50*i;
        buffer.pos[i * 4 + 3] =  0;
    }
    DrawText(builder, playbackCanvas_);
}

//对应用例allocrunrsxform_3008
DEF_RSDEMO(textblobbuilder_allocrunrsxform, TestLevel::L1, 8)
{
    Drawing::Brush brush;
    Drawing::Pen pen;
    playbackCanvas_->AttachBrush(brush);
    std::shared_ptr<Drawing::FontMgr> font_mgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string name = "HarmonyOS Sans SC";
    std::shared_ptr<Drawing::FontStyle> fontStyleSet(font_mgr->MatchFamily(name.c_str()));
    auto typeface = Drawing::Typeface::MakeDefault();
    typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->CreateTypeface(0));
    auto font = Drawing::Font();
    font.SetTypeface(typeface);
    font.SetSize(50.f);
    Drawing::TextBlobBuilder builder;
    auto buffer = builder.AllocRunRSXform(font, 20);
    for (int i = 0; i < 20; i++) {
        buffer.glyphs[i] = font.UnicharToGlyph(0X9088);
        buffer.pos[i * 4] = cos(10 * i) + 0.1 * i;
        buffer.pos[i * 4 + 1] = sin(10 * i);
        buffer.pos[i * 4 + 2] =  20*i;
        buffer.pos[i * 4 + 3] =  -10*i;
    }
    DrawText(builder, playbackCanvas_);
}

//对应用例allocrunrsxform_3009
DEF_RSDEMO(textblobbuilder_allocrunrsxform, TestLevel::L1, 9)
{
    Drawing::Brush brush;
    Drawing::Pen pen;
    playbackCanvas_->AttachBrush(brush);
    std::shared_ptr<Drawing::FontMgr> font_mgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string name = "HarmonyOS Sans SC";
    std::shared_ptr<Drawing::FontStyle> fontStyleSet(font_mgr->MatchFamily(name.c_str()));
    auto typeface = Drawing::Typeface::MakeDefault();
    typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->CreateTypeface(0));
    auto font = Drawing::Font();
    font.SetTypeface(typeface);
    font.SetSize(50.f);
    Drawing::TextBlobBuilder builder;
    auto buffer = builder.AllocRunRSXform(font, 20);
    for (int i = 0; i < 20; i++) {
        buffer.glyphs[i] = font.UnicharToGlyph(0X00AE);
        buffer.pos[i * 4] = i+1;
        buffer.pos[i * 4 + 1] =  0;
        buffer.pos[i * 4 + 2] =  100;
        buffer.pos[i * 4 + 3] =  100;
    }
    DrawText(builder, playbackCanvas_);
}

//对应用例allocrunrsxform_3010
DEF_RSDEMO(textblobbuilder_allocrunrsxform, TestLevel::L1, 10)
{
    Drawing::Brush brush;
    Drawing::Pen pen;
    playbackCanvas_->AttachBrush(brush);
    std::shared_ptr<Drawing::FontMgr> font_mgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string name = "HarmonyOS Sans SC";
    std::shared_ptr<Drawing::FontStyle> fontStyleSet(font_mgr->MatchFamily(name.c_str()));
    auto typeface = Drawing::Typeface::MakeDefault();
    typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->CreateTypeface(0));
    auto font = Drawing::Font();
    font.SetTypeface(typeface);
    font.SetSize(50.f);
    Drawing::TextBlobBuilder builder;
    auto buffer = builder.AllocRunRSXform(font, 20);
    for (int i = 0; i < 20; i++) {
        buffer.glyphs[i] = font.UnicharToGlyph(0X00AE);
        buffer.pos[i * 4] = cos(i*18);
        buffer.pos[i * 4 + 1] = sin(18*i);
        buffer.pos[i * 4 + 2] = 100;
        buffer.pos[i * 4 + 3] = 100;
    }
    DrawText(builder, playbackCanvas_);
}

//对应用例allocrunrsxform_3011
DEF_RSDEMO(textblobbuilder_allocrunrsxform, TestLevel::L1, 11)
{
    Drawing::Brush brush;
    Drawing::Pen pen;
    playbackCanvas_->AttachBrush(brush);
    std::shared_ptr<Drawing::FontMgr> font_mgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string name = "HarmonyOS Sans SC";
    std::shared_ptr<Drawing::FontStyle> fontStyleSet(font_mgr->MatchFamily(name.c_str()));
    auto typeface = Drawing::Typeface::MakeDefault();
    typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->CreateTypeface(0));
    auto font = Drawing::Font();
    font.SetTypeface(typeface);
    font.SetSize(50.f);
    Drawing::TextBlobBuilder builder;
    auto buffer = builder.AllocRunRSXform(font, 20);
    for (int i = 0; i < 20; i++) {
        buffer.glyphs[i] = font.UnicharToGlyph(0X00AE);
        buffer.pos[i * 4] = 1;
        buffer.pos[i * 4 + 1] =  0;
        buffer.pos[i * 4 + 2] =  50*i;
        buffer.pos[i * 4 + 3] =  0;
    }
    DrawText(builder, playbackCanvas_);
}

//对应用例allocrunrsxform_3012
DEF_RSDEMO(textblobbuilder_allocrunrsxform, TestLevel::L1, 12)
{
    Drawing::Brush brush;
    Drawing::Pen pen;
    playbackCanvas_->AttachBrush(brush);
    std::shared_ptr<Drawing::FontMgr> font_mgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string name = "HarmonyOS Sans SC";
    std::shared_ptr<Drawing::FontStyle> fontStyleSet(font_mgr->MatchFamily(name.c_str()));
    auto typeface = Drawing::Typeface::MakeDefault();
    typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->CreateTypeface(0));
    auto font = Drawing::Font();
    font.SetTypeface(typeface);
    font.SetSize(50.f);
    Drawing::TextBlobBuilder builder;
    auto buffer = builder.AllocRunRSXform(font, 20);
    for (int i = 0; i < 20; i++) {
        buffer.glyphs[i] = font.UnicharToGlyph(0X00AE);
        buffer.pos[i * 4] = cos(10 * i) + 0.1 * i;
        buffer.pos[i * 4 + 1] = sin(10 * i);
        buffer.pos[i * 4 + 2] =  20*i;
        buffer.pos[i * 4 + 3] =  -10*i;
    }
    DrawText(builder, playbackCanvas_);
}

//对应用例allocrunrsxform_3013
DEF_RSDEMO(textblobbuilder_allocrunrsxform, TestLevel::L1, 13)
{
    Drawing::Brush brush;
    Drawing::Pen pen;
    playbackCanvas_->AttachBrush(brush);
    std::shared_ptr<Drawing::FontMgr> font_mgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string name = "HarmonyOS Sans SC";
    std::shared_ptr<Drawing::FontStyle> fontStyleSet(font_mgr->MatchFamily(name.c_str()));
    auto typeface = Drawing::Typeface::MakeDefault();
    typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->CreateTypeface(0));
    auto font = Drawing::Font();
    font.SetTypeface(typeface);
    font.SetSize(50.f);
    Drawing::TextBlobBuilder builder;
    auto buffer = builder.AllocRunRSXform(font, 10);
    for (int i = 0; i < 10; i++) {
        buffer.glyphs[i] = font.UnicharToGlyph(0X30);
        buffer.pos[i * 4] = i+1;
        buffer.pos[i * 4 + 1] =  0;
        buffer.pos[i * 4 + 2] =  100;
        buffer.pos[i * 4 + 3] =  100;
    }
    DrawText(builder, playbackCanvas_);
}

//对应用例allocrunrsxform_3014
DEF_RSDEMO(textblobbuilder_allocrunrsxform, TestLevel::L1, 14)
{
    Drawing::Brush brush;
    Drawing::Pen pen;
    playbackCanvas_->AttachBrush(brush);
    std::shared_ptr<Drawing::FontMgr> font_mgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string name = "HarmonyOS Sans SC";
    std::shared_ptr<Drawing::FontStyle> fontStyleSet(font_mgr->MatchFamily(name.c_str()));
    auto typeface = Drawing::Typeface::MakeDefault();
    typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->CreateTypeface(0));
    auto font = Drawing::Font();
    font.SetTypeface(typeface);
    font.SetSize(50.f);
    Drawing::TextBlobBuilder builder;
    auto buffer = builder.AllocRunRSXform(font, 10);
    for (int i = 0; i < 10; i++) {
        buffer.glyphs[i] = font.UnicharToGlyph(0X30);
        buffer.pos[i * 4] = cos(i*18);
        buffer.pos[i * 4 + 1] = sin(18*i);
        buffer.pos[i * 4 + 2] = 100;
        buffer.pos[i * 4 + 3] = 100;
    }
    DrawText(builder, playbackCanvas_);
}

//对应用例allocrunrsxform_3015
DEF_RSDEMO(textblobbuilder_allocrunrsxform, TestLevel::L1, 15)
{
    Drawing::Brush brush;
    Drawing::Pen pen;
    playbackCanvas_->AttachBrush(brush);
    std::shared_ptr<Drawing::FontMgr> font_mgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string name = "HarmonyOS Sans SC";
    std::shared_ptr<Drawing::FontStyle> fontStyleSet(font_mgr->MatchFamily(name.c_str()));
    auto typeface = Drawing::Typeface::MakeDefault();
    typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->CreateTypeface(0));
    auto font = Drawing::Font();
    font.SetTypeface(typeface);
    font.SetSize(50.f);
    Drawing::TextBlobBuilder builder;
    auto buffer = builder.AllocRunRSXform(font, 10);
    for (int i = 0; i < 10; i++) {
        buffer.glyphs[i] = font.UnicharToGlyph(0X30);
        buffer.pos[i * 4] = 1;
        buffer.pos[i * 4 + 1] =  0;
        buffer.pos[i * 4 + 2] =  50*i;
        buffer.pos[i * 4 + 3] =  0;
    }
    DrawText(builder, playbackCanvas_);
}

//对应用例allocrunrsxform_3016
DEF_RSDEMO(textblobbuilder_allocrunrsxform, TestLevel::L1, 16)
{
    Drawing::Brush brush;
    Drawing::Pen pen;
    playbackCanvas_->AttachBrush(brush);
    std::shared_ptr<Drawing::FontMgr> font_mgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string name = "HarmonyOS Sans SC";
    std::shared_ptr<Drawing::FontStyle> fontStyleSet(font_mgr->MatchFamily(name.c_str()));
    auto typeface = Drawing::Typeface::MakeDefault();
    typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->CreateTypeface(0));
    auto font = Drawing::Font();
    font.SetTypeface(typeface);
    font.SetSize(50.f);
    Drawing::TextBlobBuilder builder;
    auto buffer = builder.AllocRunRSXform(font, 10);
    for (int i = 0; i < 10; i++) {
        buffer.glyphs[i] = font.UnicharToGlyph(0X30);
        buffer.pos[i * 4] = cos(10 * i) + 0.1 * i;
        buffer.pos[i * 4 + 1] = sin(10 * i);
        buffer.pos[i * 4 + 2] =  20*i;
        buffer.pos[i * 4 + 3] =  -10*i;
    }
    DrawText(builder, playbackCanvas_);
}

//对应用例allocrunrsxform_3017
DEF_RSDEMO(textblobbuilder_allocrunrsxform, TestLevel::L1, 17)
{
    Drawing::Brush brush;
    Drawing::Pen pen;
    playbackCanvas_->AttachBrush(brush);
    std::shared_ptr<Drawing::FontMgr> font_mgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string name = "HarmonyOS Sans SC";
    std::shared_ptr<Drawing::FontStyle> fontStyleSet(font_mgr->MatchFamily(name.c_str()));
    auto typeface = Drawing::Typeface::MakeDefault();
    typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->CreateTypeface(0));
    auto font = Drawing::Font();
    font.SetTypeface(typeface);
    font.SetSize(50.f);
    Drawing::TextBlobBuilder builder;
    auto buffer = builder.AllocRunRSXform(font, 10);
    for (int i = 0; i < 10; i++) {
        buffer.glyphs[i] = font.UnicharToGlyph(0X9088);
        buffer.pos[i * 4] = i+1;
        buffer.pos[i * 4 + 1] =  0;
        buffer.pos[i * 4 + 2] =  100;
        buffer.pos[i * 4 + 3] =  100;
    }
    DrawText(builder, playbackCanvas_);
}

//对应用例allocrunrsxform_3018
DEF_RSDEMO(textblobbuilder_allocrunrsxform, TestLevel::L1, 18)
{
    Drawing::Brush brush;
    Drawing::Pen pen;
    playbackCanvas_->AttachBrush(brush);
    std::shared_ptr<Drawing::FontMgr> font_mgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string name = "HarmonyOS Sans SC";
    std::shared_ptr<Drawing::FontStyle> fontStyleSet(font_mgr->MatchFamily(name.c_str()));
    auto typeface = Drawing::Typeface::MakeDefault();
    typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->CreateTypeface(0));
    auto font = Drawing::Font();
    font.SetTypeface(typeface);
    font.SetSize(50.f);
    Drawing::TextBlobBuilder builder;
    auto buffer = builder.AllocRunRSXform(font, 10);
    for (int i = 0; i < 10; i++) {
        buffer.glyphs[i] = font.UnicharToGlyph(0X9088);
        buffer.pos[i * 4] = cos(i*18);
        buffer.pos[i * 4 + 1] = sin(18*i);
        buffer.pos[i * 4 + 2] = 100;
        buffer.pos[i * 4 + 3] = 100;
    }
    DrawText(builder, playbackCanvas_);
}

//对应用例allocrunrsxform_3019
DEF_RSDEMO(textblobbuilder_allocrunrsxform, TestLevel::L1, 19)
{
    Drawing::Brush brush;
    Drawing::Pen pen;
    playbackCanvas_->AttachBrush(brush);
    std::shared_ptr<Drawing::FontMgr> font_mgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string name = "HarmonyOS Sans SC";
    std::shared_ptr<Drawing::FontStyle> fontStyleSet(font_mgr->MatchFamily(name.c_str()));
    auto typeface = Drawing::Typeface::MakeDefault();
    typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->CreateTypeface(0));
    auto font = Drawing::Font();
    font.SetTypeface(typeface);
    font.SetSize(50.f);
    Drawing::TextBlobBuilder builder;
    auto buffer = builder.AllocRunRSXform(font, 10);
    for (int i = 0; i < 10; i++) {
        buffer.glyphs[i] = font.UnicharToGlyph(0X9088);
        buffer.pos[i * 4] = 1;
        buffer.pos[i * 4 + 1] =  0;
        buffer.pos[i * 4 + 2] =  50*i;
        buffer.pos[i * 4 + 3] =  0;
    }
    DrawText(builder, playbackCanvas_);
}

//对应用例allocrunrsxform_3020
DEF_RSDEMO(textblobbuilder_allocrunrsxform, TestLevel::L1, 20)
{
    Drawing::Brush brush;
    Drawing::Pen pen;
    playbackCanvas_->AttachBrush(brush);
    std::shared_ptr<Drawing::FontMgr> font_mgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string name = "HarmonyOS Sans SC";
    std::shared_ptr<Drawing::FontStyle> fontStyleSet(font_mgr->MatchFamily(name.c_str()));
    auto typeface = Drawing::Typeface::MakeDefault();
    typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->CreateTypeface(0));
    auto font = Drawing::Font();
    font.SetTypeface(typeface);
    font.SetSize(50.f);
    Drawing::TextBlobBuilder builder;
    auto buffer = builder.AllocRunRSXform(font, 10);
    for (int i = 0; i < 10; i++) {
        buffer.glyphs[i] = font.UnicharToGlyph(0X9088);
        buffer.pos[i * 4] = cos(10 * i) + 0.1 * i;
        buffer.pos[i * 4 + 1] = sin(10 * i);
        buffer.pos[i * 4 + 2] =  20*i;
        buffer.pos[i * 4 + 3] =  -10*i;
    }
    DrawText(builder, playbackCanvas_);
}

//对应用例allocrunrsxform_3021
DEF_RSDEMO(textblobbuilder_allocrunrsxform, TestLevel::L1, 21)
{
    Drawing::Brush brush;
    Drawing::Pen pen;
    playbackCanvas_->AttachBrush(brush);
    std::shared_ptr<Drawing::FontMgr> font_mgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string name = "HarmonyOS Sans SC";
    std::shared_ptr<Drawing::FontStyle> fontStyleSet(font_mgr->MatchFamily(name.c_str()));
    auto typeface = Drawing::Typeface::MakeDefault();
    typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->CreateTypeface(0));
    auto font = Drawing::Font();
    font.SetTypeface(typeface);
    font.SetSize(50.f);
    Drawing::TextBlobBuilder builder;
    auto buffer = builder.AllocRunRSXform(font, 10);
    for (int i = 0; i < 10; i++) {
        buffer.glyphs[i] = font.UnicharToGlyph(0X00AE);
        buffer.pos[i * 4] = i+1;
        buffer.pos[i * 4 + 1] =  0;
        buffer.pos[i * 4 + 2] =  100;
        buffer.pos[i * 4 + 3] =  100;
    }
    DrawText(builder, playbackCanvas_);
}

//对应用例allocrunrsxform_3022
DEF_RSDEMO(textblobbuilder_allocrunrsxform, TestLevel::L1, 22)
{
    Drawing::Brush brush;
    Drawing::Pen pen;
    playbackCanvas_->AttachBrush(brush);
    std::shared_ptr<Drawing::FontMgr> font_mgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string name = "HarmonyOS Sans SC";
    std::shared_ptr<Drawing::FontStyle> fontStyleSet(font_mgr->MatchFamily(name.c_str()));
    auto typeface = Drawing::Typeface::MakeDefault();
    typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->CreateTypeface(0));
    auto font = Drawing::Font();
    font.SetTypeface(typeface);
    font.SetSize(50.f);
    Drawing::TextBlobBuilder builder;
    auto buffer = builder.AllocRunRSXform(font, 10);
    for (int i = 0; i < 10; i++) {
        buffer.glyphs[i] = font.UnicharToGlyph(0X00AE);
        buffer.pos[i * 4] = cos(i*18);
        buffer.pos[i * 4 + 1] = sin(18*i);
        buffer.pos[i * 4 + 2] = 100;
        buffer.pos[i * 4 + 3] = 100;
    }
    DrawText(builder, playbackCanvas_);
}

//对应用例allocrunrsxform_3023
DEF_RSDEMO(textblobbuilder_allocrunrsxform, TestLevel::L1, 23)
{
    Drawing::Brush brush;
    Drawing::Pen pen;
    playbackCanvas_->AttachBrush(brush);
    std::shared_ptr<Drawing::FontMgr> font_mgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string name = "HarmonyOS Sans SC";
    std::shared_ptr<Drawing::FontStyle> fontStyleSet(font_mgr->MatchFamily(name.c_str()));
    auto typeface = Drawing::Typeface::MakeDefault();
    typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->CreateTypeface(0));
    auto font = Drawing::Font();
    font.SetTypeface(typeface);
    font.SetSize(50.f);
    Drawing::TextBlobBuilder builder;
    auto buffer = builder.AllocRunRSXform(font, 10);
    for (int i = 0; i < 10; i++) {
        buffer.glyphs[i] = font.UnicharToGlyph(0X00AE);
        buffer.pos[i * 4] = 1;
        buffer.pos[i * 4 + 1] =  0;
        buffer.pos[i * 4 + 2] =  50*i;
        buffer.pos[i * 4 + 3] =  0;
    }
    DrawText(builder, playbackCanvas_);
}

//对应用例allocrunrsxform_3024
DEF_RSDEMO(textblobbuilder_allocrunrsxform, TestLevel::L1, 24)
{
    Drawing::Brush brush;
    Drawing::Pen pen;
    playbackCanvas_->AttachBrush(brush);
    std::shared_ptr<Drawing::FontMgr> font_mgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string name = "HarmonyOS Sans SC";
    std::shared_ptr<Drawing::FontStyle> fontStyleSet(font_mgr->MatchFamily(name.c_str()));
    auto typeface = Drawing::Typeface::MakeDefault();
    typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->CreateTypeface(0));
    auto font = Drawing::Font();
    font.SetTypeface(typeface);
    font.SetSize(50.f);
    Drawing::TextBlobBuilder builder;
    auto buffer = builder.AllocRunRSXform(font, 10);
    for (int i = 0; i < 10; i++) {
        buffer.glyphs[i] = font.UnicharToGlyph(0X00AE);
        buffer.pos[i * 4] = cos(10 * i) + 0.1 * i;
        buffer.pos[i * 4 + 1] = sin(10 * i);
        buffer.pos[i * 4 + 2] =  20*i;
        buffer.pos[i * 4 + 3] =  -10*i;
    }
    DrawText(builder, playbackCanvas_);
}

//对应用例allocrunrsxform_3025
DEF_RSDEMO(textblobbuilder_allocrunrsxform, TestLevel::L1, 25)
{
    Drawing::Brush brush;
    Drawing::Pen pen;
    playbackCanvas_->AttachBrush(brush);
    std::shared_ptr<Drawing::FontMgr> font_mgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string name = "HarmonyOS Sans SC";
    std::shared_ptr<Drawing::FontStyle> fontStyleSet(font_mgr->MatchFamily(name.c_str()));
    auto typeface = Drawing::Typeface::MakeDefault();
    typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->CreateTypeface(0));
    auto font = Drawing::Font();
    font.SetTypeface(typeface);
    font.SetSize(50.f);
    Drawing::TextBlobBuilder builder;
    auto buffer = builder.AllocRunRSXform(font, 0);
    for (int i = 0; i < 0; i++) {
        buffer.glyphs[i] = font.UnicharToGlyph(0X30);
        buffer.pos[i * 4] = i+1;
        buffer.pos[i * 4 + 1] =  0;
        buffer.pos[i * 4 + 2] =  100;
        buffer.pos[i * 4 + 3] =  100;
    }
    DrawText(builder, playbackCanvas_);
}

//对应用例allocrunrsxform_3026
DEF_RSDEMO(textblobbuilder_allocrunrsxform, TestLevel::L1, 26)
{
    Drawing::Brush brush;
    Drawing::Pen pen;
    playbackCanvas_->AttachBrush(brush);
    std::shared_ptr<Drawing::FontMgr> font_mgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string name = "HarmonyOS Sans SC";
    std::shared_ptr<Drawing::FontStyle> fontStyleSet(font_mgr->MatchFamily(name.c_str()));
    auto typeface = Drawing::Typeface::MakeDefault();
    typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->CreateTypeface(0));
    auto font = Drawing::Font();
    font.SetTypeface(typeface);
    font.SetSize(50.f);
    Drawing::TextBlobBuilder builder;
    auto buffer = builder.AllocRunRSXform(font, 0);
    for (int i = 0; i < 0; i++) {
        buffer.glyphs[i] = font.UnicharToGlyph(0X30);
        buffer.pos[i * 4] = cos(i*18);
        buffer.pos[i * 4 + 1] = sin(18*i);
        buffer.pos[i * 4 + 2] = 100;
        buffer.pos[i * 4 + 3] = 100;
    }
    DrawText(builder, playbackCanvas_);
}

//对应用例allocrunrsxform_3027
DEF_RSDEMO(textblobbuilder_allocrunrsxform, TestLevel::L1, 27)
{
    Drawing::Brush brush;
    Drawing::Pen pen;
    playbackCanvas_->AttachBrush(brush);
    std::shared_ptr<Drawing::FontMgr> font_mgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string name = "HarmonyOS Sans SC";
    std::shared_ptr<Drawing::FontStyle> fontStyleSet(font_mgr->MatchFamily(name.c_str()));
    auto typeface = Drawing::Typeface::MakeDefault();
    typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->CreateTypeface(0));
    auto font = Drawing::Font();
    font.SetTypeface(typeface);
    font.SetSize(50.f);
    Drawing::TextBlobBuilder builder;
    auto buffer = builder.AllocRunRSXform(font, 0);
    for (int i = 0; i < 0; i++) {
        buffer.glyphs[i] = font.UnicharToGlyph(0X30);
        buffer.pos[i * 4] = 1;
        buffer.pos[i * 4 + 1] =  0;
        buffer.pos[i * 4 + 2] =  50*i;
        buffer.pos[i * 4 + 3] =  0;
    }
    DrawText(builder, playbackCanvas_);
}

//对应用例allocrunrsxform_3028
DEF_RSDEMO(textblobbuilder_allocrunrsxform, TestLevel::L1, 28)
{
    Drawing::Brush brush;
    Drawing::Pen pen;
    playbackCanvas_->AttachBrush(brush);
    std::shared_ptr<Drawing::FontMgr> font_mgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string name = "HarmonyOS Sans SC";
    std::shared_ptr<Drawing::FontStyle> fontStyleSet(font_mgr->MatchFamily(name.c_str()));
    auto typeface = Drawing::Typeface::MakeDefault();
    typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->CreateTypeface(0));
    auto font = Drawing::Font();
    font.SetTypeface(typeface);
    font.SetSize(50.f);
    Drawing::TextBlobBuilder builder;
    auto buffer = builder.AllocRunRSXform(font, 0);
    for (int i = 0; i < 0; i++) {
        buffer.glyphs[i] = font.UnicharToGlyph(0X30);
        buffer.pos[i * 4] = cos(10 * i) + 0.1 * i;
        buffer.pos[i * 4 + 1] = sin(10 * i);
        buffer.pos[i * 4 + 2] =  20*i;
        buffer.pos[i * 4 + 3] =  -10*i;
    }
    DrawText(builder, playbackCanvas_);
}

//对应用例allocrunrsxform_3029
DEF_RSDEMO(textblobbuilder_allocrunrsxform, TestLevel::L1, 29)
{
    Drawing::Brush brush;
    Drawing::Pen pen;
    playbackCanvas_->AttachBrush(brush);
    std::shared_ptr<Drawing::FontMgr> font_mgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string name = "HarmonyOS Sans SC";
    std::shared_ptr<Drawing::FontStyle> fontStyleSet(font_mgr->MatchFamily(name.c_str()));
    auto typeface = Drawing::Typeface::MakeDefault();
    typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->CreateTypeface(0));
    auto font = Drawing::Font();
    font.SetTypeface(typeface);
    font.SetSize(50.f);
    Drawing::TextBlobBuilder builder;
    auto buffer = builder.AllocRunRSXform(font, 0);
    for (int i = 0; i < 0; i++) {
        buffer.glyphs[i] = font.UnicharToGlyph(0X9088);
        buffer.pos[i * 4] = i+1;
        buffer.pos[i * 4 + 1] =  0;
        buffer.pos[i * 4 + 2] =  100;
        buffer.pos[i * 4 + 3] =  100;
    }
    DrawText(builder, playbackCanvas_);
}

//对应用例allocrunrsxform_3030
DEF_RSDEMO(textblobbuilder_allocrunrsxform, TestLevel::L1, 30)
{
    Drawing::Brush brush;
    Drawing::Pen pen;
    playbackCanvas_->AttachBrush(brush);
    std::shared_ptr<Drawing::FontMgr> font_mgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string name = "HarmonyOS Sans SC";
    std::shared_ptr<Drawing::FontStyle> fontStyleSet(font_mgr->MatchFamily(name.c_str()));
    auto typeface = Drawing::Typeface::MakeDefault();
    typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->CreateTypeface(0));
    auto font = Drawing::Font();
    font.SetTypeface(typeface);
    font.SetSize(50.f);
    Drawing::TextBlobBuilder builder;
    auto buffer = builder.AllocRunRSXform(font, 0);
    for (int i = 0; i < 0; i++) {
        buffer.glyphs[i] = font.UnicharToGlyph(0X9088);
        buffer.pos[i * 4] = cos(i*18);
        buffer.pos[i * 4 + 1] = sin(18*i);
        buffer.pos[i * 4 + 2] = 100;
        buffer.pos[i * 4 + 3] = 100;
    }
    DrawText(builder, playbackCanvas_);
}

//对应用例allocrunrsxform_3031
DEF_RSDEMO(textblobbuilder_allocrunrsxform, TestLevel::L1, 31)
{
    Drawing::Brush brush;
    Drawing::Pen pen;
    playbackCanvas_->AttachBrush(brush);
    std::shared_ptr<Drawing::FontMgr> font_mgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string name = "HarmonyOS Sans SC";
    std::shared_ptr<Drawing::FontStyle> fontStyleSet(font_mgr->MatchFamily(name.c_str()));
    auto typeface = Drawing::Typeface::MakeDefault();
    typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->CreateTypeface(0));
    auto font = Drawing::Font();
    font.SetTypeface(typeface);
    font.SetSize(50.f);
    Drawing::TextBlobBuilder builder;
    auto buffer = builder.AllocRunRSXform(font, 0);
    for (int i = 0; i < 0; i++) {
        buffer.glyphs[i] = font.UnicharToGlyph(0X9088);
        buffer.pos[i * 4] = 1;
        buffer.pos[i * 4 + 1] =  0;
        buffer.pos[i * 4 + 2] =  50*i;
        buffer.pos[i * 4 + 3] =  0;
    }
    DrawText(builder, playbackCanvas_);
}

//对应用例allocrunrsxform_3032
DEF_RSDEMO(textblobbuilder_allocrunrsxform, TestLevel::L1, 32)
{
    Drawing::Brush brush;
    Drawing::Pen pen;
    playbackCanvas_->AttachBrush(brush);
    std::shared_ptr<Drawing::FontMgr> font_mgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string name = "HarmonyOS Sans SC";
    std::shared_ptr<Drawing::FontStyle> fontStyleSet(font_mgr->MatchFamily(name.c_str()));
    auto typeface = Drawing::Typeface::MakeDefault();
    typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->CreateTypeface(0));
    auto font = Drawing::Font();
    font.SetTypeface(typeface);
    font.SetSize(50.f);
    Drawing::TextBlobBuilder builder;
    auto buffer = builder.AllocRunRSXform(font, 0);
    for (int i = 0; i < 0; i++) {
        buffer.glyphs[i] = font.UnicharToGlyph(0X9088);
        buffer.pos[i * 4] = cos(10 * i) + 0.1 * i;
        buffer.pos[i * 4 + 1] = sin(10 * i);
        buffer.pos[i * 4 + 2] =  20*i;
        buffer.pos[i * 4 + 3] =  -10*i;
    }
    DrawText(builder, playbackCanvas_);
}

//对应用例allocrunrsxform_3033
DEF_RSDEMO(textblobbuilder_allocrunrsxform, TestLevel::L1, 33)
{
    Drawing::Brush brush;
    Drawing::Pen pen;
    playbackCanvas_->AttachBrush(brush);
    std::shared_ptr<Drawing::FontMgr> font_mgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string name = "HarmonyOS Sans SC";
    std::shared_ptr<Drawing::FontStyle> fontStyleSet(font_mgr->MatchFamily(name.c_str()));
    auto typeface = Drawing::Typeface::MakeDefault();
    typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->CreateTypeface(0));
    auto font = Drawing::Font();
    font.SetTypeface(typeface);
    font.SetSize(50.f);
    Drawing::TextBlobBuilder builder;
    auto buffer = builder.AllocRunRSXform(font, 0);
    for (int i = 0; i < 0; i++) {
        buffer.glyphs[i] = font.UnicharToGlyph(0X00AE);
        buffer.pos[i * 4] = i+1;
        buffer.pos[i * 4 + 1] =  0;
        buffer.pos[i * 4 + 2] =  100;
        buffer.pos[i * 4 + 3] =  100;
    }
    DrawText(builder, playbackCanvas_);
}

//对应用例allocrunrsxform_3034
DEF_RSDEMO(textblobbuilder_allocrunrsxform, TestLevel::L1, 34)
{
    Drawing::Brush brush;
    Drawing::Pen pen;
    playbackCanvas_->AttachBrush(brush);
    std::shared_ptr<Drawing::FontMgr> font_mgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string name = "HarmonyOS Sans SC";
    std::shared_ptr<Drawing::FontStyle> fontStyleSet(font_mgr->MatchFamily(name.c_str()));
    auto typeface = Drawing::Typeface::MakeDefault();
    typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->CreateTypeface(0));
    auto font = Drawing::Font();
    font.SetTypeface(typeface);
    font.SetSize(50.f);
    Drawing::TextBlobBuilder builder;
    auto buffer = builder.AllocRunRSXform(font, 0);
    for (int i = 0; i < 0; i++) {
        buffer.glyphs[i] = font.UnicharToGlyph(0X00AE);
        buffer.pos[i * 4] = cos(i*18);
        buffer.pos[i * 4 + 1] = sin(18*i);
        buffer.pos[i * 4 + 2] = 100;
        buffer.pos[i * 4 + 3] = 100;
    }
    DrawText(builder, playbackCanvas_);
}

//对应用例allocrunrsxform_3035
DEF_RSDEMO(textblobbuilder_allocrunrsxform, TestLevel::L1, 35)
{
    Drawing::Brush brush;
    Drawing::Pen pen;
    playbackCanvas_->AttachBrush(brush);
    std::shared_ptr<Drawing::FontMgr> font_mgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string name = "HarmonyOS Sans SC";
    std::shared_ptr<Drawing::FontStyle> fontStyleSet(font_mgr->MatchFamily(name.c_str()));
    auto typeface = Drawing::Typeface::MakeDefault();
    typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->CreateTypeface(0));
    auto font = Drawing::Font();
    font.SetTypeface(typeface);
    font.SetSize(50.f);
    Drawing::TextBlobBuilder builder;
    auto buffer = builder.AllocRunRSXform(font, 0);
    for (int i = 0; i < 0; i++) {
        buffer.glyphs[i] = font.UnicharToGlyph(0X00AE);
        buffer.pos[i * 4] = 1;
        buffer.pos[i * 4 + 1] =  0;
        buffer.pos[i * 4 + 2] =  50*i;
        buffer.pos[i * 4 + 3] =  0;
    }
    DrawText(builder, playbackCanvas_);
}

//对应用例allocrunrsxform_3036
DEF_RSDEMO(textblobbuilder_allocrunrsxform, TestLevel::L1, 36)
{
    Drawing::Brush brush;
    Drawing::Pen pen;
    playbackCanvas_->AttachBrush(brush);
    std::shared_ptr<Drawing::FontMgr> font_mgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string name = "HarmonyOS Sans SC";
    std::shared_ptr<Drawing::FontStyle> fontStyleSet(font_mgr->MatchFamily(name.c_str()));
    auto typeface = Drawing::Typeface::MakeDefault();
    typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->CreateTypeface(0));
    auto font = Drawing::Font();
    font.SetTypeface(typeface);
    font.SetSize(50.f);
    Drawing::TextBlobBuilder builder;
    auto buffer = builder.AllocRunRSXform(font, 0);
    for (int i = 0; i < 0; i++) {
        buffer.glyphs[i] = font.UnicharToGlyph(0X00AE);
        buffer.pos[i * 4] = cos(10 * i) + 0.1 * i;
        buffer.pos[i * 4 + 1] = sin(10 * i);
        buffer.pos[i * 4 + 2] =  20*i;
        buffer.pos[i * 4 + 3] =  -10*i;
    }
    DrawText(builder, playbackCanvas_);
}

//对应用例allocrunrsxform_3037
DEF_RSDEMO(textblobbuilder_allocrunrsxform, TestLevel::L1, 37)
{
    Drawing::Brush brush;
    Drawing::Pen pen;
    playbackCanvas_->AttachBrush(brush);
    std::shared_ptr<Drawing::FontMgr> font_mgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string name = "HarmonyOS Sans SC";
    std::shared_ptr<Drawing::FontStyle> fontStyleSet(font_mgr->MatchFamily(name.c_str()));
    auto typeface = Drawing::Typeface::MakeDefault();
    typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->CreateTypeface(0));
    auto font = Drawing::Font();
    font.SetTypeface(typeface);
    font.SetSize(50.f);
    Drawing::TextBlobBuilder builder;
    auto buffer = builder.AllocRunRSXform(font, -1);
    for (int i = 0; i < 10; i++) {
        buffer.glyphs[i] = font.UnicharToGlyph(0X30);
        buffer.pos[i * 4] = i+1;
        buffer.pos[i * 4 + 1] =  0;
        buffer.pos[i * 4 + 2] =  100;
        buffer.pos[i * 4 + 3] =  100;
    }
    DrawText(builder, playbackCanvas_);
}

//对应用例allocrunrsxform_3038
DEF_RSDEMO(textblobbuilder_allocrunrsxform, TestLevel::L1, 38)
{
    Drawing::Brush brush;
    Drawing::Pen pen;
    playbackCanvas_->AttachBrush(brush);
    std::shared_ptr<Drawing::FontMgr> font_mgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string name = "HarmonyOS Sans SC";
    std::shared_ptr<Drawing::FontStyle> fontStyleSet(font_mgr->MatchFamily(name.c_str()));
    auto typeface = Drawing::Typeface::MakeDefault();
    typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->CreateTypeface(0));
    auto font = Drawing::Font();
    font.SetTypeface(typeface);
    font.SetSize(50.f);
    Drawing::TextBlobBuilder builder;
    auto buffer = builder.AllocRunRSXform(font, -1);
    for (int i = 0; i < 10; i++) {
        buffer.glyphs[i] = font.UnicharToGlyph(0X30);
        buffer.pos[i * 4] = cos(i*18);
        buffer.pos[i * 4 + 1] = sin(18*i);
        buffer.pos[i * 4 + 2] = 100;
        buffer.pos[i * 4 + 3] = 100;
    }
    DrawText(builder, playbackCanvas_);
}

//对应用例allocrunrsxform_3039
DEF_RSDEMO(textblobbuilder_allocrunrsxform, TestLevel::L1, 39)
{
    Drawing::Brush brush;
    Drawing::Pen pen;
    playbackCanvas_->AttachBrush(brush);
    std::shared_ptr<Drawing::FontMgr> font_mgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string name = "HarmonyOS Sans SC";
    std::shared_ptr<Drawing::FontStyle> fontStyleSet(font_mgr->MatchFamily(name.c_str()));
    auto typeface = Drawing::Typeface::MakeDefault();
    typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->CreateTypeface(0));
    auto font = Drawing::Font();
    font.SetTypeface(typeface);
    font.SetSize(50.f);
    Drawing::TextBlobBuilder builder;
    auto buffer = builder.AllocRunRSXform(font, -1);
    for (int i = 0; i < 10; i++) {
        buffer.glyphs[i] = font.UnicharToGlyph(0X30);
        buffer.pos[i * 4] = 1;
        buffer.pos[i * 4 + 1] =  0;
        buffer.pos[i * 4 + 2] =  50*i;
        buffer.pos[i * 4 + 3] =  0;
    }
    DrawText(builder, playbackCanvas_);
}

//对应用例allocrunrsxform_3040
DEF_RSDEMO(textblobbuilder_allocrunrsxform, TestLevel::L1, 40)
{
    Drawing::Brush brush;
    Drawing::Pen pen;
    playbackCanvas_->AttachBrush(brush);
    std::shared_ptr<Drawing::FontMgr> font_mgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string name = "HarmonyOS Sans SC";
    std::shared_ptr<Drawing::FontStyle> fontStyleSet(font_mgr->MatchFamily(name.c_str()));
    auto typeface = Drawing::Typeface::MakeDefault();
    typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->CreateTypeface(0));
    auto font = Drawing::Font();
    font.SetTypeface(typeface);
    font.SetSize(50.f);
    Drawing::TextBlobBuilder builder;
    auto buffer = builder.AllocRunRSXform(font, -1);
    for (int i = 0; i < 10; i++) {
        buffer.glyphs[i] = font.UnicharToGlyph(0X30);
        buffer.pos[i * 4] = cos(10 * i) + 0.1 * i;
        buffer.pos[i * 4 + 1] = sin(10 * i);
        buffer.pos[i * 4 + 2] =  20*i;
        buffer.pos[i * 4 + 3] =  -10*i;
    }
    DrawText(builder, playbackCanvas_);
}

//对应用例allocrunrsxform_3041
DEF_RSDEMO(textblobbuilder_allocrunrsxform, TestLevel::L1, 41)
{
    Drawing::Brush brush;
    Drawing::Pen pen;
    playbackCanvas_->AttachBrush(brush);
    std::shared_ptr<Drawing::FontMgr> font_mgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string name = "HarmonyOS Sans SC";
    std::shared_ptr<Drawing::FontStyle> fontStyleSet(font_mgr->MatchFamily(name.c_str()));
    auto typeface = Drawing::Typeface::MakeDefault();
    typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->CreateTypeface(0));
    auto font = Drawing::Font();
    font.SetTypeface(typeface);
    font.SetSize(50.f);
    Drawing::TextBlobBuilder builder;
    auto buffer = builder.AllocRunRSXform(font, -1);
    for (int i = 0; i < 10; i++) {
        buffer.glyphs[i] = font.UnicharToGlyph(0X9088);
        buffer.pos[i * 4] = i+1;
        buffer.pos[i * 4 + 1] =  0;
        buffer.pos[i * 4 + 2] =  100;
        buffer.pos[i * 4 + 3] =  100;
    }
    DrawText(builder, playbackCanvas_);
}

//对应用例allocrunrsxform_3042
DEF_RSDEMO(textblobbuilder_allocrunrsxform, TestLevel::L1, 42)
{
    Drawing::Brush brush;
    Drawing::Pen pen;
    playbackCanvas_->AttachBrush(brush);
    std::shared_ptr<Drawing::FontMgr> font_mgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string name = "HarmonyOS Sans SC";
    std::shared_ptr<Drawing::FontStyle> fontStyleSet(font_mgr->MatchFamily(name.c_str()));
    auto typeface = Drawing::Typeface::MakeDefault();
    typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->CreateTypeface(0));
    auto font = Drawing::Font();
    font.SetTypeface(typeface);
    font.SetSize(50.f);
    Drawing::TextBlobBuilder builder;
    auto buffer = builder.AllocRunRSXform(font, -1);
    for (int i = 0; i < 10; i++) {
        buffer.glyphs[i] = font.UnicharToGlyph(0X9088);
        buffer.pos[i * 4] = cos(i*18);
        buffer.pos[i * 4 + 1] = sin(18*i);
        buffer.pos[i * 4 + 2] = 100;
        buffer.pos[i * 4 + 3] = 100;
    }
    DrawText(builder, playbackCanvas_);
}

//对应用例allocrunrsxform_3043
DEF_RSDEMO(textblobbuilder_allocrunrsxform, TestLevel::L1, 43)
{
    Drawing::Brush brush;
    Drawing::Pen pen;
    playbackCanvas_->AttachBrush(brush);
    std::shared_ptr<Drawing::FontMgr> font_mgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string name = "HarmonyOS Sans SC";
    std::shared_ptr<Drawing::FontStyle> fontStyleSet(font_mgr->MatchFamily(name.c_str()));
    auto typeface = Drawing::Typeface::MakeDefault();
    typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->CreateTypeface(0));
    auto font = Drawing::Font();
    font.SetTypeface(typeface);
    font.SetSize(50.f);
    Drawing::TextBlobBuilder builder;
    auto buffer = builder.AllocRunRSXform(font, -1);
    for (int i = 0; i < 10; i++) {
        buffer.glyphs[i] = font.UnicharToGlyph(0X9088);
        buffer.pos[i * 4] = 1;
        buffer.pos[i * 4 + 1] =  0;
        buffer.pos[i * 4 + 2] =  50*i;
        buffer.pos[i * 4 + 3] =  0;
    }
    DrawText(builder, playbackCanvas_);
}

//对应用例allocrunrsxform_3044
DEF_RSDEMO(textblobbuilder_allocrunrsxform, TestLevel::L1, 44)
{
    Drawing::Brush brush;
    Drawing::Pen pen;
    playbackCanvas_->AttachBrush(brush);
    std::shared_ptr<Drawing::FontMgr> font_mgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string name = "HarmonyOS Sans SC";
    std::shared_ptr<Drawing::FontStyle> fontStyleSet(font_mgr->MatchFamily(name.c_str()));
    auto typeface = Drawing::Typeface::MakeDefault();
    typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->CreateTypeface(0));
    auto font = Drawing::Font();
    font.SetTypeface(typeface);
    font.SetSize(50.f);
    Drawing::TextBlobBuilder builder;
    auto buffer = builder.AllocRunRSXform(font, -1);
    for (int i = 0; i < 10; i++) {
        buffer.glyphs[i] = font.UnicharToGlyph(0X9088);
        buffer.pos[i * 4] = cos(10 * i) + 0.1 * i;
        buffer.pos[i * 4 + 1] = sin(10 * i);
        buffer.pos[i * 4 + 2] =  20*i;
        buffer.pos[i * 4 + 3] =  -10*i;
    }
    DrawText(builder, playbackCanvas_);
}

//对应用例allocrunrsxform_3045
DEF_RSDEMO(textblobbuilder_allocrunrsxform, TestLevel::L1, 45)
{
    Drawing::Brush brush;
    Drawing::Pen pen;
    playbackCanvas_->AttachBrush(brush);
    std::shared_ptr<Drawing::FontMgr> font_mgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string name = "HarmonyOS Sans SC";
    std::shared_ptr<Drawing::FontStyle> fontStyleSet(font_mgr->MatchFamily(name.c_str()));
    auto typeface = Drawing::Typeface::MakeDefault();
    typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->CreateTypeface(0));
    auto font = Drawing::Font();
    font.SetTypeface(typeface);
    font.SetSize(50.f);
    Drawing::TextBlobBuilder builder;
    auto buffer = builder.AllocRunRSXform(font, -1);
    for (int i = 0; i < 10; i++) {
        buffer.glyphs[i] = font.UnicharToGlyph(0X00AE);
        buffer.pos[i * 4] = i+1;
        buffer.pos[i * 4 + 1] =  0;
        buffer.pos[i * 4 + 2] =  100;
        buffer.pos[i * 4 + 3] =  100;
    }
    DrawText(builder, playbackCanvas_);
}

//对应用例allocrunrsxform_3046
DEF_RSDEMO(textblobbuilder_allocrunrsxform, TestLevel::L1, 46)
{
    Drawing::Brush brush;
    Drawing::Pen pen;
    playbackCanvas_->AttachBrush(brush);
    std::shared_ptr<Drawing::FontMgr> font_mgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string name = "HarmonyOS Sans SC";
    std::shared_ptr<Drawing::FontStyle> fontStyleSet(font_mgr->MatchFamily(name.c_str()));
    auto typeface = Drawing::Typeface::MakeDefault();
    typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->CreateTypeface(0));
    auto font = Drawing::Font();
    font.SetTypeface(typeface);
    font.SetSize(50.f);
    Drawing::TextBlobBuilder builder;
    auto buffer = builder.AllocRunRSXform(font, -1);
    for (int i = 0; i < -1; i++) {
        buffer.glyphs[i] = font.UnicharToGlyph(0X00AE);
        buffer.pos[i * 4] = cos(i*18);
        buffer.pos[i * 4 + 1] = sin(18*i);
        buffer.pos[i * 4 + 2] = 100;
        buffer.pos[i * 4 + 3] = 100;
    }
    DrawText(builder, playbackCanvas_);
}

//对应用例allocrunrsxform_3047
DEF_RSDEMO(textblobbuilder_allocrunrsxform, TestLevel::L1, 47)
{
    Drawing::Brush brush;
    Drawing::Pen pen;
    playbackCanvas_->AttachBrush(brush);
    std::shared_ptr<Drawing::FontMgr> font_mgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string name = "HarmonyOS Sans SC";
    std::shared_ptr<Drawing::FontStyle> fontStyleSet(font_mgr->MatchFamily(name.c_str()));
    auto typeface = Drawing::Typeface::MakeDefault();
    typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->CreateTypeface(0));
    auto font = Drawing::Font();
    font.SetTypeface(typeface);
    font.SetSize(50.f);
    Drawing::TextBlobBuilder builder;
    auto buffer = builder.AllocRunRSXform(font, -1);
    for (int i = 0; i < 10; i++) {
        buffer.glyphs[i] = font.UnicharToGlyph(0X00AE);
        buffer.pos[i * 4] = 1;
        buffer.pos[i * 4 + 1] =  0;
        buffer.pos[i * 4 + 2] =  50*i;
        buffer.pos[i * 4 + 3] =  0;
    }
    DrawText(builder, playbackCanvas_);
}

//对应用例allocrunrsxform_3048
DEF_RSDEMO(textblobbuilder_allocrunrsxform, TestLevel::L1, 48)
{
    Drawing::Brush brush;
    Drawing::Pen pen;
    playbackCanvas_->AttachBrush(brush);
    std::shared_ptr<Drawing::FontMgr> font_mgr(Drawing::FontMgr::CreateDefaultFontMgr());
    std::string name = "HarmonyOS Sans SC";
    std::shared_ptr<Drawing::FontStyle> fontStyleSet(font_mgr->MatchFamily(name.c_str()));
    auto typeface = Drawing::Typeface::MakeDefault();
    typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->CreateTypeface(0));
    auto font = Drawing::Font();
    font.SetTypeface(typeface);
    font.SetSize(50.f);
    Drawing::TextBlobBuilder builder;
    auto buffer = builder.AllocRunRSXform(font, -1);
    for (int i = 0; i < 10; i++) {
        buffer.glyphs[i] = font.UnicharToGlyph(0X00AE);
        buffer.pos[i * 4] = cos(10 * i) + 0.1 * i;
        buffer.pos[i * 4 + 1] = sin(10 * i);
        buffer.pos[i * 4 + 2] =  20*i;
        buffer.pos[i * 4 + 3] =  -10*i;
    }
    DrawText(builder, playbackCanvas_);
}

}
}
