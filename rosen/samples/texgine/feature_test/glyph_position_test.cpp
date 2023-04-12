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

#include <sstream>

#include <texgine/dynamic_file_font_provider.h>
#include <texgine/system_font_provider.h>
#include <texgine/typography_builder.h>

#include "feature_test_framework.h"
#include "text_define.h"

using namespace OHOS::Rosen::TextEngine;

namespace {
struct GlyphPosition {
    double x_ = 0;
    double y_ = 5;
    TypographyStyle ys_;
} datas[] {
    { .x_ = -5,  .y_ = -5 },
    { .x_ = -5,  .y_ = 15 },
    { .x_ = 5,   .y_ = -5 },
    { .x_ = -5,  .y_ = 85 },
    { .x_ = 155, .y_ = -5 },
    { .x_ = 155, .y_ = 15 },
    { .x_ = 155, .y_ = 85 },
    { .x_ = 96,  .y_ = 8 },
    { .x_ = 100, .y_ = 8 },
    { .x_ = 137, .y_ = 15 },
    { .x_ = 96,  .y_ = 8, .ys_ = { .align_ = TextAlign::CENTER, }, },
    { .x_ = 100, .y_ = 8, .ys_ = { .align_ = TextAlign::CENTER, }, },
    { .x_ = 123, .y_ = 70, .ys_ = { .align_ = TextAlign::CENTER, }, },
    { .x_ = 22,  .y_ = 70, .ys_ = { .align_ = TextAlign::CENTER, }, },
    { .x_ = 46,  .y_ = 70, },
    { .x_ = 52,  .y_ = 70, },
    { .x_ = 55,  .y_ = 70, },
    { .x_ = 52,  .y_ = 67, },
};

constexpr auto text = "hello world hello world 你好世界 你好世界， hello openharmony, hello openharmony, 你好鸿蒙";

class GlyphPositionTest : public TestFeature {
public:
    GlyphPositionTest() : TestFeature("GlyphPositionTest")
    {
    }

    void Layout()
    {
        TextStyle xs;
        xs.fontFamilies_ = {"Segoe UI Emoji"};
        xs.fontSize_ = 14;

        for (auto &data : datas) {
            auto dfprovider = DynamicFileFontProvider::Create();
            dfprovider->LoadFont("Segoe UI Emoji", RESOURCE_PATH_PREFIX "seguiemj.ttf");
            auto fps = FontProviders::Create();
            fps->AppendFontProvider(dfprovider);
            fps->AppendFontProvider(SystemFontProvider::GetInstance());

            auto builder = TypographyBuilder::Create(data.ys_, std::move(fps));

            builder->PushStyle(xs);
            builder->AppendSpan(text);
            builder->PopStyle();

            std::string emojiText = Woman Skin1 ZWJ RedHeart ZWJ Man Skin0;
            builder->PushStyle(xs);
            builder->AppendSpan(emojiText);
            builder->PopStyle();

            auto onPaint = [data](const struct TypographyData &tyData, TexgineCanvas &canvas, double x, double y) {
                auto &typography = tyData.typography;
                typography->Paint(canvas, x, y);
                TexginePaint paint;
                paint.SetAntiAlias(true);
                paint.SetColor(0x7F00FF00);
                paint.SetStrokeWidth(5);
                canvas.DrawLine(x + data.x_ - 10, y + data.y_, x + data.x_ + 10, y + data.y_, paint);
                canvas.DrawLine(x + data.x_, y + data.y_ - 10, x + data.x_, y + data.y_ + 10, paint);
                paint.SetColor(0xFF00FF);
                paint.SetAlpha(255 * 0.3);
                canvas.Save();
                canvas.Translate(x, y);
                auto ia = typography->GetGlyphIndexByCoordinate(data.x_, data.y_);
                auto rects = typography->GetTextRectsByBoundary(Boundary{ia.index_, ia.index_ + 1},
                    TextRectHeightStyle::COVER_TOP_AND_BOTTOM, TextRectWidthStyle::TIGHT);
                if (rects.size()) {
                    canvas.DrawRect(rects.back().rect_, paint);
                }
                canvas.Restore();
            };

            std::stringstream ss;
            ss << "(" << data.x_ << ", " << data.y_ << ")";
            if (data.ys_.align_ == TextAlign::CENTER) {
                ss << " align(center)";
            }

            auto typography = builder->Build();
            typography->Layout(150);
            typographies_.push_back({
                .typography = typography,
                .comment = ss.str(),
                .onPaint = onPaint,
            });
        }
    }
} g_test;
} // namespace
