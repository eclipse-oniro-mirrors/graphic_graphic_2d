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
#include "text/font.h"
#include "recording/mem_allocator.h"
#include "text/font_mgr.h"
#include "text/font_style_set.h"
#include "text/rs_xform.h"
#include "utils/point.h"
#include "utils/rect.h"
#include "text/typeface.h"

/*
测试类：FontStyleSet
测试接口：Count
测试内容：对接口取返回值，并构造typeface字体格式，并指定在font上，最终通过drawtextblob接口将Count的值以文字形式绘制在画布上
*/

namespace OHOS {
namespace Rosen {

static void DrawFontStylesetCount(std::shared_ptr<Drawing::FontMgr> font_mgr,
    std::string name, TestPlaybackCanvas* playbackCanvas)
{
    std::shared_ptr<Drawing::FontStyleSet> fontStyleSet(
        name.empty()
            ? font_mgr->CreateStyleSet(0)
            : font_mgr->MatchFamily(name.c_str())
    );
    int fontStyleCount = fontStyleSet->Count();

    auto typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->CreateTypeface(0));
    auto font = Drawing::Font(typeface, 50.f, 1.0f, 0.f);
    std::string text1 = "DDGR ddgr 鸿蒙 !@#%￥^&*;：，。";
    std::string text2 = "-_=+()123`.---~|{}【】,./?、？<>《》";
    std::string text3 = "\xE2\x99\x88\xE2\x99\x8A\xE2\x99\x88\xE2\x99\x8C\xE2\x99\x8D\xE2\x99\x8D";
    std::string text4 = "fontStyleCount = " + std::to_string(fontStyleCount);
    std::string texts[] = { text1, text2, text3, text4 };
    int interval = 200;
    int line = 200;
    for (auto text : texts) {
        std::shared_ptr<Drawing::TextBlob> textBlob = Drawing::TextBlob::MakeFromText(text.c_str(), text.size(), font);
        Drawing::Brush brush;
        playbackCanvas->AttachBrush(brush);
        playbackCanvas->DrawTextBlob(textBlob.get(), interval, line);
        line += interval;
        playbackCanvas->DetachBrush();
        Drawing::Pen pen;
        playbackCanvas->AttachPen(pen);
        playbackCanvas->DrawTextBlob(textBlob.get(), interval, line);
        line += interval;
        playbackCanvas->DetachPen();
    }
}

//对应用例 FontStyleSet_Count_3001
DEF_DTK(fontstyleset_count, TestLevel::L1, 1)
{
    DrawFontStylesetCount(Drawing::FontMgr::CreateDefaultFontMgr(), "HarmonyOS Sans", playbackCanvas_);
}

//对应用例 FontStyleSet_Count_3002
DEF_DTK(fontstyleset_count, TestLevel::L1, 2)
{
    DrawFontStylesetCount(Drawing::FontMgr::CreateDefaultFontMgr(), "", playbackCanvas_);
}

//对应用例 FontStyleSet_Count_3003
DEF_DTK(fontstyleset_count, TestLevel::L1, 3)
{
    DrawFontStylesetCount(Drawing::FontMgr::CreateDynamicFontMgr(), "HarmonyOS Sans", playbackCanvas_);
}

//对应用例 FontStyleSet_Count_3004
DEF_DTK(fontstyleset_count, TestLevel::L1, 4)
{
    DrawFontStylesetCount(Drawing::FontMgr::CreateDynamicFontMgr(), "", playbackCanvas_);
}

}
}