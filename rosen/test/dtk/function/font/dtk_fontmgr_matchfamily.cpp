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
#include "text/font.h"
#include "recording/mem_allocator.h"
#include "text/font_mgr.h"
#include "text/font_style_set.h"
#include "text/rs_xform.h"
#include "utils/point.h"
#include "utils/rect.h"
#include "text/typeface.h"

/*
测试类：FontMgr
测试接口：MatchFamily
测试内容：对接口入参familyName取string类型字符串，构造typeface字体格式，并指定在font上，最终通过drawtextblob接口将text内容绘制在画布上
*/
namespace OHOS {
namespace Rosen {

void CommonMatchFamily(TestPlaybackCanvas* playbackCanvas,
                       std::shared_ptr<Drawing::FontMgr> fontMgr,
                       std::string familyName)
{
    if (familyName == "get") {
        fontMgr->GetFamilyName(0, familyName);
    }

    std::shared_ptr<Drawing::FontStyleSet> fontStyleSet(fontMgr->MatchFamily(familyName.c_str()));
    auto typeface = std::shared_ptr<Drawing::Typeface>(fontStyleSet->CreateTypeface(0));
    
    auto font = Drawing::Font(typeface, 50.f, 1.0f, 0.f);
    std::string text1 = "DDGR ddgr 鸿蒙 !@#%￥^&*;：，。";
    std::string text2 = "-_=+()123`.---~|{}【】,./?、？<>《》";
    std::string text3 = "\xE2\x99\x88\xE2\x99\x8A\xE2\x99\x88\xE2\x99\x8C\xE2\x99\x8D\xE2\x99\x8D";
    std::string texts[] = {text1, text2, text3};
    int line = 200;
    int interval2 = 200;
    for (auto text : texts) {
        std::shared_ptr<Drawing::TextBlob> textBlob = Drawing::TextBlob::MakeFromText(text.c_str(), text.size(), font);
        Drawing::Brush brush;
        playbackCanvas->AttachBrush(brush);
        playbackCanvas->DrawTextBlob(textBlob.get(), interval2, line);
        line += interval2;
        playbackCanvas->DetachBrush();
        Drawing::Pen pen;
        playbackCanvas->AttachPen(pen);
        playbackCanvas->DrawTextBlob(textBlob.get(), interval2, line);
        line += interval2;
        playbackCanvas->DetachPen();
    }
}
//对应用例 FontMgr_MatchFamily_3001
DEF_DTK(fontmgr_matchfamily, TestLevel::L1, 1)
{
    std::shared_ptr<Drawing::FontMgr> fontMgr(Drawing::FontMgr::CreateDefaultFontMgr());
    CommonMatchFamily(playbackCanvas_, fontMgr, "abcd");
}

//对应用例 FontMgr_MatchFamily_3002
DEF_DTK(fontmgr_matchfamily, TestLevel::L1, 2)
{
    std::shared_ptr<Drawing::FontMgr> fontMgr(Drawing::FontMgr::CreateDynamicFontMgr());
    CommonMatchFamily(playbackCanvas_, fontMgr, "");
}

//对应用例 FontMgr_MatchFamily_3003
DEF_DTK(fontmgr_matchfamily, TestLevel::L1, 3)
{
    std::shared_ptr<Drawing::FontMgr> fontMgr(Drawing::FontMgr::CreateDefaultFontMgr());
    CommonMatchFamily(playbackCanvas_, fontMgr, "");
}

//对应用例 FontMgr_MatchFamily_3004
DEF_DTK(fontmgr_matchfamily, TestLevel::L1, 4)
{
    std::shared_ptr<Drawing::FontMgr> fontMgr(Drawing::FontMgr::CreateDefaultFontMgr());
    CommonMatchFamily(playbackCanvas_, fontMgr, "HMOS Color Emoji");
}

//对应用例 FontMgr_MatchFamily_3005
DEF_DTK(fontmgr_matchfamily, TestLevel::L1, 5)
{
    std::shared_ptr<Drawing::FontMgr> fontMgr(Drawing::FontMgr::CreateDynamicFontMgr());
    CommonMatchFamily(playbackCanvas_, fontMgr, "abcd");
}

//对应用例 FontMgr_MatchFamily_3006
DEF_DTK(fontmgr_matchfamily, TestLevel::L1, 6)
{
    std::shared_ptr<Drawing::FontMgr> fontMgr(Drawing::FontMgr::CreateDynamicFontMgr());
    CommonMatchFamily(playbackCanvas_, fontMgr, "get");
}

//对应用例 FontMgr_MatchFamily_3007
DEF_DTK(fontmgr_matchfamily, TestLevel::L1, 7)
{
    std::shared_ptr<Drawing::FontMgr> fontMgr(Drawing::FontMgr::CreateDynamicFontMgr());
    CommonMatchFamily(playbackCanvas_, fontMgr, "HMOS Color Emoji");
}

//对应用例 FontMgr_MatchFamily_3008
DEF_DTK(fontmgr_matchfamily, TestLevel::L1, 8)
{
    std::shared_ptr<Drawing::FontMgr> fontMgr(Drawing::FontMgr::CreateDefaultFontMgr());
    CommonMatchFamily(playbackCanvas_, fontMgr, "get");
}

}
}
