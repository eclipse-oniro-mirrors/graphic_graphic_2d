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

#include <texgine/any_span.h>
#include <texgine/system_font_provider.h>
#include <texgine/typography_builder.h>
#include <texgine/utils/memory_usage_scope.h>

#include "feature_test_framework.h"
#include "my_any_span.h"

using namespace OHOS::Rosen::TextEngine;

namespace {
struct Res {
    std::string textContent_ = "";
    uint32_t color_ = 0x00000000;
};

std::vector<Res> shortRes = {
    {
        .textContent_ = "提示：十翅+堡堡分享桶=？",
        .color_ = 0xffffff00,
    },
};

std::vector<Res> longRes = {
    {
        .textContent_ = "【损友阿乐的投喂】",
        .color_ = 0xff00ff00,
    },
    {
        .textContent_ = "休息天也要和朋友们一起云享受生活！损友阿乐拎着美味出现了！来猜今天阿乐带来什么美味套餐？",
        .color_ = 0xffffff00,
    },
    {
        .textContent_ = "提示：十翅+堡堡分享桶=？",
        .color_ = 0xffff00ff,
    },
    {
        .textContent_ = "答案：十翅堡堡分享桶，疫情期间注意防护哦",
        .color_ = 0xff0000ff,
    },
    {
        .textContent_ = "【损友阿乐的投喂】",
        .color_ = 0xff00ff00,
    },
    {
        .textContent_ = "休息天也要和朋友们一起云享受生活！损友阿乐拎着美味出现了！来猜今天阿乐带来什么美味套餐？",
        .color_ = 0xffffff00,
    },
    {
        .textContent_ = "提示：十翅+堡堡分享桶=？",
        .color_ = 0xff0000ff,
    },
    {
        .textContent_ = "答案：十翅堡堡分享桶，疫情期间注意防护哦",
        .color_ = 0xff0000ff,
    }
};

std::vector<Res> manyImageRes = {
    { .textContent_ = "同行多个", },
    { .color_ = 0xffff0000, },
    { .color_ = 0xffffff00, },
    { .color_ = 0xff0000ff, },
    { .color_ = 0xff00ff00, },
    { .textContent_ = "同行多个", },
    { .color_ = 0xffff0000, },
    { .color_ = 0xffffff00, },
    { .color_ = 0xff0000ff, },
    { .color_ = 0xff00ff00, },
};

struct Info {
    std::vector<Res> res_;
    TextStyle textStyle_ = {};
    double imageHeight_ = 20.0;
    TypographyStyle tpStyle_;
    TextRectHeightStyle heightStyle_ = TextRectHeightStyle::TIGHT;
    TextRectWidthStyle widthStyle_ = TextRectWidthStyle::TIGHT;
    int widthLimit_ = 500;
    std::string title_ = "";
    bool rect = false;
} infos[] = {
    {
        .res_ = shortRes,
        .title_ = "default",
    },
    {
        .res_ = shortRes,
        .textStyle_ = { .fontSize_ = 32, },
        .imageHeight_ = 32,
        .title_ = "fontSize: 32, imageHeight: 32",
    },
    {
        .res_ = longRes,
        .imageHeight_ = 16,
        .title_ = "多行显示",
    },
    {
        .res_ = manyImageRes,
        .imageHeight_ = 16,
        .title_ = "同行多个",
    },
    {
        .res_ = longRes,
        .imageHeight_ = 16,
        .tpStyle_ = { .maxLines_ = 2 },
        .title_ = "maxLines: 2",
    },
    {
        .res_ = longRes,
        .imageHeight_ = 16,
        .tpStyle_ = { .maxLines_ = 2, .ellipsis_ = u"***" },
        .title_ = "maxLines: 2, ellipsis: '***'",
    },
    {
        .res_ = shortRes,
        .tpStyle_ = {
            .lineStyle_ = { .only_ = true },
        },
        .title_ = "RectHeightStyle: Tight, RectWidthStyle: Tight",
        .rect = true,
    },
    {
        .res_ = shortRes,
        .tpStyle_ = {
            .lineStyle_ = { .only_ = true },
        },
        .heightStyle_ = TextRectHeightStyle::COVER_TOP_AND_BOTTOM,
        .title_ = "RectHeightStyle: MaxHeight, RectWidthStyle: Tight",
        .rect = true,
    },
    {
        .res_ = longRes,
        .imageHeight_ = 16,
        .tpStyle_ = {
            .lineStyle_ = { .only_ = true },
        },
        .title_ = "RectHeightStyle: Tight, RectWidthStyle: Tight",
        .rect = true,
    },
    {
        .res_ = longRes,
        .imageHeight_ = 16,
        .tpStyle_ = {
            .lineStyle_ = { .only_ = true },
        },
        .widthStyle_ = TextRectWidthStyle::MAX_WIDTH,
        .title_ = "RectHeightStyle: Tight, RectWidthStyle: MaxWidth",
        .rect = true,
    }
};

class MixTest : public TestFeature {
public:
    MixTest() : TestFeature("MixTest")
    {
    }

    void Layout()
    {
        for (auto &info : infos) {
            auto builder = TypographyBuilder::Create(info.tpStyle_);

            for (auto &res : info.res_) {
                if (res.color_ != 0x00000000) {
                    builder->AppendSpan(std::make_shared<MyAnySpan>(
                        20, info.imageHeight_,
                        AnySpanAlignment::ABOVE_BASELINE,
                        TextBaseline::ALPHABETIC,
                        0, res.color_));
                }
                if (!res.textContent_.empty()) {
                    builder->PushStyle(info.textStyle_);
                    builder->AppendSpan(res.textContent_);
                }
            }

            auto typography = builder->Build();
            typography->Layout(info.widthLimit_);
            typographies_.push_back({
                .typography = typography,
                .needRainbowChar = info.rect,
            });
        }
    }
} g_test;
} // namespace
