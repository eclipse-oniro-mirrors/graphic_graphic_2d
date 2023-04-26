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

#include <texgine/dynamic_file_font_provider.h>
#include <texgine/system_font_provider.h>
#include <texgine/typography_builder.h>

#include "feature_test_framework.h"
#include "text_define.h"

using namespace OHOS::Rosen::TextEngine;

namespace {
#define FAMILY1 WOMAN SKIN1 ZWJ RED_HEART ZWJ MAN SKIN0
#define FAMILY2 PERSON SKIN4 ZWJ RED_HEART ZWJ MAN ZWJ PERSON SKIN2
#define ROLE1 PERSON SKIN3 ZWJ AIRPLANE
#define ROLE2 PERSON SKIN1 ZWJ LAPTOP
#define GENERED1 BOUNCING_BALL SKIN2 ZWJ WOMAN_SPORT_VARIANT EMOJI_VARIANT
#define GENERED2 LIFTING_WEIGHTS SKIN0 ZWJ MAN_SPORT_VARIANT EMOJI_VARIANT
#define HAIR1 MAN SKIN2 ZWJ HAIR_BALD
#define HAIR2 PERSON SKIN4 ZWJ HAIR_CURLY
#define OTHER1 RED_HEART ZWJ "\U0001F525"
#define OTHER2 FLAG EMOJI_VARIANT ZWJ TRANSGENDER EMOJI_VARIANT

struct Emoji {
    TextStyle style = { .fontSize_ = 32 };
    std::string emoji;
    std::string title;
} g_emojis[] = {
    {
        .emoji = WATCH,
        .title = "watch",
    },
    {
        .emoji = FAST_FORWARD_BUTTON,
        .title = "fast forward button",
    },
    {
        .emoji = ALART_CLOCK,
        .title = "alart clock",
    },
    {
        .emoji = UMBRELLA,
        .title = "umbrella",
    },
    {
        .emoji = RED_CIRCLE,
        .title = "red circle",
    },
    {
        .emoji = BLACK_LARGE_SQUARE,
        .title = "black large square",
    },
    {
        .emoji = CURLY_LOOP,
        .title = "curly loop",
    },
    {
        .emoji = PLUS,
        .title = "plus",
    },
    {
        .emoji = SNOWMAN,
        .title = "snowman",
    },
    {
        .emoji = VOLTAGE,
        .title = "voltage",
    },
    {
        .emoji = COPYRIGHT,
        .title = "copyright",
    },
    {
        .emoji = REGISTERED,
        .title = "registered",
    },
    {
        .emoji = DOUBLE_EXCLAMATION_MARK,
        .title = "double exclamation mark",
    },
    {
        .emoji = EXCLAMATION_QUESTION_MARK,
        .title = "exclamation question mark",
    },
    {
        .emoji = WAVY_DASH,
        .title = "wavy dash",
    },
    {
        .emoji = LEFT_ARROW,
        .title = "left arrow",
    },
    {
        .emoji = RED_HEART,
        .title = "red heart",
    },
    {
        .emoji = PENCIL,
        .title = "pencil",
    },
    {
        .emoji = AIRPLANE,
        .title = "airplan",
    },
    {
        .emoji = ATOM,
        .title = "atom",
    },
    {
        .emoji = RED_DRAGON,
        .title = "red dragon",
    },
    {
        .emoji = JOKER,
        .title = "joker",
    },
    {
        .emoji = CYCLONE,
        .title = "cyclone",
    },
    {
        .emoji = NEW_MOON_FACE,
        .title = "new moon face",
    },
    {
        .emoji = CAT,
        .title = "cat",
    },
    {
        .emoji = DOG,
        .title = "dog",
    },
    {
        .emoji = BOY,
        .title = "boy",
    },
};

class EmojiTest : public TestFeature {
public:
    EmojiTest() : TestFeature("EmojiTest")
    {
    }

    void Layout()
    {
        for (auto &emoji : g_emojis) {
            TypographyStyle tystyle;
            auto dfProvider = DynamicFileFontProvider::Create();
            dfProvider->LoadFont("Segoe UI Emoji", RESOURCE_PATH_PREFIX "seguiemj.ttf");
            auto fps = FontProviders::Create();
            fps->AppendFontProvider(dfProvider);
            fps->AppendFontProvider(SystemFontProvider::GetInstance());
            auto builder = TypographyBuilder::Create(tystyle, std::move(fps));

            emoji.style.fontFamilies_ = {"Segoe UI Emoji"};
            builder->PushStyle(emoji.style);
            builder->AppendSpan(emoji.emoji);
            builder->PopStyle();

            auto typography = builder->Build();
            double widthLimit = 100;
            typography->Layout(widthLimit);
            typographies_.push_back({ .typography = typography, .comment = emoji.title });
        }
    }
} g_test;
} // namespace
