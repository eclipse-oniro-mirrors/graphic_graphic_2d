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

#include "gtest/gtest.h"
#include "txt/text_style.h"
#include "symbol_engine/hm_symbol_run.h"
#include "symbol_engine/hm_symbol_txt.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Rosen {
namespace SPText {
static const float MIN_VALUE = 1e-6;
class OHHmSymbolRunTest : public testing::Test {
public:
    static bool AnimationFunc(const std::shared_ptr<TextEngine::SymbolAnimationConfig>& symbolAnimationConfig);
};

bool OHHmSymbolRunTest::AnimationFunc(const std::shared_ptr<TextEngine::SymbolAnimationConfig>& symbolAnimationConfig)
{
    return true;
}

/*
 * @tc.name: DrawSymbol001
 * @tc.desc: test DrawSymbol with one Glyph
 * @tc.type: FUNC
 */
HWTEST_F(OHHmSymbolRunTest, DrawSymbol001, TestSize.Level1)
{
    std::shared_ptr<RSCanvas> rsCanvas = std::make_shared<RSCanvas>();
    RSPoint paint_ = {100, 100}; // 1, 1 is the offset
    const char* str = "A";
    Drawing::Font font;
    auto textblob = Drawing::TextBlob::MakeFromText(str, strlen(str), font, Drawing::TextEncoding::UTF8);
    HMSymbolTxt symbolTxt;
    std::function<bool(const std::shared_ptr<OHOS::Rosen::TextEngine::SymbolAnimationConfig>&)>
        animationFunc = nullptr;
    HMSymbolRun hmSymbolRun = HMSymbolRun(0, symbolTxt, textblob, animationFunc);
    hmSymbolRun.DrawSymbol(rsCanvas.get(), paint_);

    // test rsCanvas is nullptr
    hmSymbolRun.DrawSymbol(nullptr, paint_);

    textblob = nullptr; // test textblob is bullptr
    HMSymbolRun hmSymbolRun1 = HMSymbolRun(1, symbolTxt, textblob, animationFunc);
    hmSymbolRun1.DrawSymbol(rsCanvas.get(), paint_);

    // test rsCanvas is nullptr, textblob is nullptr
    hmSymbolRun1.DrawSymbol(nullptr, paint_);
}

/*
 * @tc.name: DrawSymbol002
 * @tc.desc: test DrawSymbol with Glyphs
 * @tc.type: FUNC
 */
HWTEST_F(OHHmSymbolRunTest, DrawSymbol002, TestSize.Level1)
{
    std::shared_ptr<RSCanvas> rsCanvas = std::make_shared<RSCanvas>();
    RSPoint paint_ = {100, 100}; // 100, 100 is the offset
    const char* str = "Test multiple glyphs";
    Drawing::Font font;
    auto textblob = Drawing::TextBlob::MakeFromText(str, strlen(str), font, Drawing::TextEncoding::UTF8);
    HMSymbolTxt symbolTxt;
    std::function<bool(const std::shared_ptr<OHOS::Rosen::TextEngine::SymbolAnimationConfig>&)>
        animationFunc = nullptr;
    HMSymbolRun hmSymbolRun = HMSymbolRun(0, symbolTxt, textblob, animationFunc);
    hmSymbolRun.DrawSymbol(rsCanvas.get(), paint_);
}

/*
 * @tc.name: DrawSymbol003
 * @tc.desc: test DrawSymbol with animation
 * @tc.type: FUNC
 */
HWTEST_F(OHHmSymbolRunTest, DrawSymbol003, TestSize.Level1)
{
    std::shared_ptr<RSCanvas> rsCanvas = std::make_shared<RSCanvas>();
    RSPoint paint_ = {100, 100}; // 100, 100 is the offset
    const char* str = "A";
    Drawing::Font font;
    auto textblob = Drawing::TextBlob::MakeFromText(str, strlen(str), font, Drawing::TextEncoding::UTF8);
    HMSymbolTxt symbolTxt;
    symbolTxt.SetAnimationStart(true);
    // test bounce animation
    symbolTxt.SetSymbolEffect(RSEffectStrategy::BOUNCE);
    std::function<bool(const std::shared_ptr<OHOS::Rosen::TextEngine::SymbolAnimationConfig>&)>
        animationFunc = nullptr;
    HMSymbolRun hmSymbolRun = HMSymbolRun(0, symbolTxt, textblob, animationFunc);
    hmSymbolRun.DrawSymbol(rsCanvas.get(), paint_);
    EXPECT_TRUE(symbolTxt.GetEffectStrategy() == RSEffectStrategy::BOUNCE);

    // test pulse aimation
    symbolTxt.SetSymbolEffect(RSEffectStrategy::PULSE);
    HMSymbolRun hmSymbolRun1 = HMSymbolRun(1, symbolTxt, textblob, animationFunc);
    hmSymbolRun1.DrawSymbol(rsCanvas.get(), paint_);
    EXPECT_TRUE(symbolTxt.GetEffectStrategy() == RSEffectStrategy::PULSE);
}

/*
 * @tc.name: SetSymbolRenderColor001
 * @tc.desc: test SetSymbolRenderColor with renderMode
 * @tc.type: FUNC
 */
HWTEST_F(OHHmSymbolRunTest, SetSymbolRenderColor001, TestSize.Level1)
{
    // step 1: Simulation input
    RSSColor color1 = {1.0, 255, 0, 0}; // the 1.0 is alpha, 255, 0, 0 is RGB
    RSSColor color2 = {1.0, 0, 255, 0}; // the 1.0 is alpha, 255, 0, 0 is RGB
    std::vector<RSSColor> colors = {color1, color2};
    RSRenderGroup group1;
    RSRenderGroup group2;
    RSSymbolLayers symbolInfo;
    symbolInfo.renderGroups.push_back(group1);
    symbolInfo.renderGroups.push_back(group2);
    const char* str = "A";
    Drawing::Font font;
    auto textblob = Drawing::TextBlob::MakeFromText(str, strlen(str), font, Drawing::TextEncoding::UTF8);
    HMSymbolTxt symbolTxt;
    std::function<bool(const std::shared_ptr<OHOS::Rosen::TextEngine::SymbolAnimationConfig>&)>
        animationFunc = nullptr;
    HMSymbolRun hmSymbolRun = HMSymbolRun(0, symbolTxt, textblob, animationFunc);

    // step 2: Import different RenderingStrategy to test the color result.
    RSSymbolRenderingStrategy renderMode = RSSymbolRenderingStrategy::SINGLE;
    hmSymbolRun.SetSymbolRenderColor(renderMode, colors, symbolInfo);
    bool check = false;
    if (color1.r == symbolInfo.renderGroups[0].color.r &&
        color1.g == symbolInfo.renderGroups[0].color.g &&
        color1.b == symbolInfo.renderGroups[0].color.b) {
        check = true;
    }
    EXPECT_EQ(check, true);

    renderMode = RSSymbolRenderingStrategy::MULTIPLE_OPACITY;
    hmSymbolRun.SetSymbolRenderColor(renderMode, colors, symbolInfo);
    bool check1 = false;
    if (color1.r == symbolInfo.renderGroups[0].color.r &&
        color1.g == symbolInfo.renderGroups[0].color.g &&
        color1.b == symbolInfo.renderGroups[0].color.b) {
        check1 = true;
    }
    EXPECT_EQ(check1, true);

    renderMode = RSSymbolRenderingStrategy::MULTIPLE_COLOR;
    hmSymbolRun.SetSymbolRenderColor(renderMode, colors, symbolInfo);
    bool check2 = false;
    if (color2.r == symbolInfo.renderGroups[1].color.r &&
        color2.g == symbolInfo.renderGroups[1].color.g &&
        color2.b == symbolInfo.renderGroups[1].color.b) {
        check2 = true;
    }
    EXPECT_EQ(check2, true);
}

/*
 * @tc.name: SetSymbolRenderColor002
 * @tc.desc: test SetSymbolRenderColor with renderMode
 * @tc.type: FUNC
 */
HWTEST_F(OHHmSymbolRunTest, SetSymbolRenderColor002, TestSize.Level1)
{
    std::vector<RSSColor> colors = {};
    RSSColor color = {1.0, 0, 255, 0}; // the 1.0 is alpha, 255, 0, 0 is RGB
    RSRenderGroup group1;
    group1.color = color;
    RSSymbolLayers symbolInfo;
    symbolInfo.renderGroups.push_back(group1);
    const char* str = "A";
    Drawing::Font font;
    auto textblob = Drawing::TextBlob::MakeFromText(str, strlen(str), font, Drawing::TextEncoding::UTF8);
    HMSymbolTxt symbolTxt;
    std::function<bool(const std::shared_ptr<OHOS::Rosen::TextEngine::SymbolAnimationConfig>&)>
        animationFunc = nullptr;
    HMSymbolRun hmSymbolRun = HMSymbolRun(0, symbolTxt, textblob, animationFunc);

    // step 2: Import different RenderingStrategy to test the color result.
    RSSymbolRenderingStrategy renderMode = RSSymbolRenderingStrategy::SINGLE;
    hmSymbolRun.SetSymbolRenderColor(renderMode, colors, symbolInfo);
    bool check = false;
    if (abs(color.a - symbolInfo.renderGroups[0].color.a) < MIN_VALUE &&
        color.r == symbolInfo.renderGroups[0].color.r &&
        color.g == symbolInfo.renderGroups[0].color.g &&
        color.b == symbolInfo.renderGroups[0].color.b) {
        check = true;
    }
    EXPECT_EQ(check, true);
}

/*
 * @tc.name: SymbolAnimation001
 * @tc.desc: test SymbolAnimation with glyphId
 * @tc.type: FUNC
 */
HWTEST_F(OHHmSymbolRunTest, SymbolAnimation001, TestSize.Level1)
{
    uint16_t glyphId = 3; // 3 is an existing GlyphID
    std::pair<float, float> offset = {100, 100}; // 100, 100 is the offset
    const char* str = "A";
    Drawing::Font font;
    auto textblob = Drawing::TextBlob::MakeFromText(str, strlen(str), font, Drawing::TextEncoding::UTF8);
    HMSymbolTxt symbolTxt;
    RSHMSymbolData symbol;
    std::function<bool(const std::shared_ptr<OHOS::Rosen::TextEngine::SymbolAnimationConfig>&)>
        animationFunc = nullptr;
    HMSymbolRun hmSymbolRun = HMSymbolRun(0, symbolTxt, textblob, animationFunc);
    bool check = false;
    check = hmSymbolRun.SymbolAnimation(symbol, glyphId, offset);
    EXPECT_TRUE(check == false);
}

/*
 * @tc.name: GetAnimationGroups001
 * @tc.desc: test GetAnimationGroups with glyphId
 * @tc.type: FUNC
 */
HWTEST_F(OHHmSymbolRunTest, GetAnimationGroups001, TestSize.Level1)
{
    uint16_t glyphId = 3; // 3 is an existing GlyphID
    RSEffectStrategy effectStrategy = RSEffectStrategy::BOUNCE;
    RSAnimationSetting animationOut;
    const char* str = "A";
    Drawing::Font font;
    auto textblob = Drawing::TextBlob::MakeFromText(str, strlen(str), font, Drawing::TextEncoding::UTF8);
    HMSymbolTxt symbolTxt;
    std::function<bool(const std::shared_ptr<OHOS::Rosen::TextEngine::SymbolAnimationConfig>&)>
        animationFunc = nullptr;
    HMSymbolRun hmSymbolRun = HMSymbolRun(0, symbolTxt, textblob, animationFunc);
    bool flag = hmSymbolRun.GetAnimationGroups(glyphId, effectStrategy, animationOut);
    EXPECT_TRUE(flag);
}

/*
 * @tc.name: GetAnimationGroups002
 * @tc.desc: test GetAnimationGroups with pulse animation
 * @tc.type: FUNC
 */
HWTEST_F(OHHmSymbolRunTest, GetAnimationGroups002, TestSize.Level1)
{
    uint16_t glyphId = 3; // 3 is an existing GlyphID
    RSEffectStrategy effectStrategy = RSEffectStrategy::PULSE;
    RSAnimationSetting animationOut;
    const char* str = "A";
    Drawing::Font font;
    auto textblob = Drawing::TextBlob::MakeFromText(str, strlen(str), font, Drawing::TextEncoding::UTF8);
    HMSymbolTxt symbolTxt;
    std::function<bool(const std::shared_ptr<OHOS::Rosen::TextEngine::SymbolAnimationConfig>&)>
        animationFunc = nullptr;
    HMSymbolRun hmSymbolRun = HMSymbolRun(0, symbolTxt, textblob, animationFunc);
    bool flag = hmSymbolRun.GetAnimationGroups(glyphId, effectStrategy, animationOut);
    EXPECT_TRUE(flag == false);
}

/*
 * @tc.name: GetSymbolLayers001
 * @tc.desc: test GetSymbolLayers with glyphId
 * @tc.type: FUNC
 */
HWTEST_F(OHHmSymbolRunTest, GetSymbolLayers001, TestSize.Level1)
{
    // step 1: init data
    uint16_t glyphId = 3; // 3 is an existing GlyphID
    RSSColor color = {1.0, 255, 0, 0}; // the 1.0 is alpha, 255, 0, 0 is RGB
    HMSymbolTxt symbolTxt;
    symbolTxt.SetRenderColor(color);
    auto symbolLayer = HMSymbolRun::GetSymbolLayers(glyphId, symbolTxt);
    EXPECT_TRUE(symbolLayer.symbolGlyphId == glyphId);

    if (!symbolLayer.renderGroups.empty()) {
        auto layerColor = symbolLayer.renderGroups[0].color;
        EXPECT_TRUE(layerColor.r == color.r); // the default color is {1.0, 0, 0, 0}
    }
}

/*
 * @tc.name: SetRenderColor001
 * @tc.desc: test SetRenderColor with colorList
 * @tc.type: FUNC
 */
HWTEST_F(OHHmSymbolRunTest, SetRenderColor001, TestSize.Level1)
{
    const char* str = "A";
    Drawing::Font font;
    auto textblob = Drawing::TextBlob::MakeFromText(str, strlen(str), font, Drawing::TextEncoding::UTF8);
    HMSymbolTxt symbolTxt;
    std::function<bool(const std::shared_ptr<OHOS::Rosen::TextEngine::SymbolAnimationConfig>&)>
        animationFunc = nullptr;
    HMSymbolRun hmSymbolRun = HMSymbolRun(0, symbolTxt, textblob, animationFunc);
    RSSColor color1 = {1.0, 255, 0, 0}; // the 1.0 is alpha, 255, 0, 0 is RGB
    RSSColor color2 = {1.0, 0, 0, 0}; // the 1.0 is alpha, 0, 0, 0 is RGB
    std::vector<RSSColor> rsscolors1 = {color1};
    std::vector<RSSColor> rsscolors2 = {color1, color2};

    hmSymbolRun.SetRenderColor(rsscolors1);
    auto ret1 = hmSymbolRun.symbolTxt_.GetRenderColor();
    EXPECT_EQ(ret1.size(), 1);
    hmSymbolRun.SetRenderColor(rsscolors2);
    auto ret2 = hmSymbolRun.symbolTxt_.GetRenderColor();
    EXPECT_EQ(ret2.size(), 2);
}

/*
 * @tc.name: SetRenderMode001
 * @tc.desc: test SetRenderMode with renderMode
 * @tc.type: FUNC
 */
HWTEST_F(OHHmSymbolRunTest, SetRenderMode001, TestSize.Level1)
{
    const char* str = "A";
    Drawing::Font font;
    auto textblob = Drawing::TextBlob::MakeFromText(str, strlen(str), font, Drawing::TextEncoding::UTF8);
    HMSymbolTxt symbolTxt;
    std::function<bool(const std::shared_ptr<OHOS::Rosen::TextEngine::SymbolAnimationConfig>&)>
        animationFunc = nullptr;
    HMSymbolRun hmSymbolRun = HMSymbolRun(0, symbolTxt, textblob, animationFunc);
    hmSymbolRun.SetRenderMode(Drawing::DrawingSymbolRenderingStrategy::SINGLE);
    EXPECT_EQ(hmSymbolRun.symbolTxt_.GetRenderMode(), Drawing::DrawingSymbolRenderingStrategy::SINGLE);

    hmSymbolRun.SetRenderMode(Drawing::DrawingSymbolRenderingStrategy::MULTIPLE_COLOR);
    EXPECT_EQ(hmSymbolRun.symbolTxt_.GetRenderMode(), Drawing::DrawingSymbolRenderingStrategy::MULTIPLE_COLOR);

    hmSymbolRun.SetRenderMode(Drawing::DrawingSymbolRenderingStrategy::MULTIPLE_OPACITY);
    EXPECT_EQ(hmSymbolRun.symbolTxt_.GetRenderMode(), Drawing::DrawingSymbolRenderingStrategy::MULTIPLE_OPACITY);
}

/*
 * @tc.name: SetSymbolEffect001
 * @tc.desc: test SetSymbolEffect with symbolEffect
 * @tc.type: FUNC
 */
HWTEST_F(OHHmSymbolRunTest, SetSymbolEffect001, TestSize.Level1)
{
    const char* str = "A";
    Drawing::Font font;
    auto textblob = Drawing::TextBlob::MakeFromText(str, strlen(str), font, Drawing::TextEncoding::UTF8);
    HMSymbolTxt symbolTxt;
    std::function<bool(const std::shared_ptr<OHOS::Rosen::TextEngine::SymbolAnimationConfig>&)>
        animationFunc = nullptr;
    HMSymbolRun hmSymbolRun = HMSymbolRun(0, symbolTxt, textblob, animationFunc);

    hmSymbolRun.SetSymbolEffect(Drawing::DrawingEffectStrategy::NONE);
    EXPECT_EQ(hmSymbolRun.symbolTxt_.GetEffectStrategy(), Drawing::DrawingEffectStrategy::NONE);

    hmSymbolRun.SetSymbolEffect(Drawing::DrawingEffectStrategy::SCALE);
    EXPECT_EQ(hmSymbolRun.symbolTxt_.GetEffectStrategy(), Drawing::DrawingEffectStrategy::SCALE);

    hmSymbolRun.SetSymbolEffect(Drawing::DrawingEffectStrategy::VARIABLE_COLOR);
    EXPECT_EQ(hmSymbolRun.symbolTxt_.GetEffectStrategy(), Drawing::DrawingEffectStrategy::VARIABLE_COLOR);

    hmSymbolRun.SetSymbolEffect(Drawing::DrawingEffectStrategy::APPEAR);
    EXPECT_EQ(hmSymbolRun.symbolTxt_.GetEffectStrategy(), Drawing::DrawingEffectStrategy::APPEAR);

    hmSymbolRun.SetSymbolEffect(Drawing::DrawingEffectStrategy::DISAPPEAR);
    EXPECT_EQ(hmSymbolRun.symbolTxt_.GetEffectStrategy(), Drawing::DrawingEffectStrategy::DISAPPEAR);

    hmSymbolRun.SetSymbolEffect(Drawing::DrawingEffectStrategy::BOUNCE);
    EXPECT_EQ(hmSymbolRun.symbolTxt_.GetEffectStrategy(), Drawing::DrawingEffectStrategy::BOUNCE);

    hmSymbolRun.SetSymbolEffect(Drawing::DrawingEffectStrategy::PULSE);
    EXPECT_EQ(hmSymbolRun.symbolTxt_.GetEffectStrategy(), Drawing::DrawingEffectStrategy::PULSE);

    hmSymbolRun.SetSymbolEffect(Drawing::DrawingEffectStrategy::REPLACE_APPEAR);
    EXPECT_EQ(hmSymbolRun.symbolTxt_.GetEffectStrategy(), Drawing::DrawingEffectStrategy::REPLACE_APPEAR);
}

/*
 * @tc.name: SetAnimationMode001
 * @tc.desc: test SetAnimationMode with animationMode
 * @tc.type: FUNC
 */
HWTEST_F(OHHmSymbolRunTest, SetAnimationMode001, TestSize.Level1)
{
    const char* str = "A";
    Drawing::Font font;
    auto textblob = Drawing::TextBlob::MakeFromText(str, strlen(str), font, Drawing::TextEncoding::UTF8);
    HMSymbolTxt symbolTxt;
    std::function<bool(const std::shared_ptr<OHOS::Rosen::TextEngine::SymbolAnimationConfig>&)>
        animationFunc = nullptr;
    HMSymbolRun hmSymbolRun = HMSymbolRun(0, symbolTxt, textblob, animationFunc);
    hmSymbolRun.SetAnimationMode(0); // the 0 is the wholeSymbol or cumulative effect
    EXPECT_EQ(hmSymbolRun.symbolTxt_.GetAnimationMode(), 0);

    hmSymbolRun.SetAnimationMode(1); // the 1 is the byLayer or iteratuve effect
    EXPECT_EQ(hmSymbolRun.symbolTxt_.GetAnimationMode(), 1);

    hmSymbolRun.SetAnimationMode(500); // 500 is test Boundary Value
    EXPECT_EQ(hmSymbolRun.symbolTxt_.GetAnimationMode(), 1);
}

/*
 * @tc.name: SetAnimationStart001
 * @tc.desc: test SetAnimationStart with animationStart
 * @tc.type: FUNC
 */
HWTEST_F(OHHmSymbolRunTest, SetAnimationStart001, TestSize.Level1)
{
    const char* str = "A";
    Drawing::Font font;
    auto textblob = Drawing::TextBlob::MakeFromText(str, strlen(str), font, Drawing::TextEncoding::UTF8);
    HMSymbolTxt symbolTxt;
    std::function<bool(const std::shared_ptr<OHOS::Rosen::TextEngine::SymbolAnimationConfig>&)>
        animationFunc = nullptr;
    HMSymbolRun hmSymbolRun = HMSymbolRun(0, symbolTxt, textblob, animationFunc);
    EXPECT_EQ(hmSymbolRun.symbolTxt_.GetAnimationStart(), false);
    hmSymbolRun.SetAnimationStart(true);
    EXPECT_EQ(hmSymbolRun.symbolTxt_.GetAnimationStart(), true);
}


/*
 * @tc.name: SetCommonSubType001
 * @tc.desc: test SetCommonSubType with commonSubType
 * @tc.type: FUNC
 */
HWTEST_F(OHHmSymbolRunTest, SetCommonSubType001, TestSize.Level1)
{
    const char* str = "A";
    Drawing::Font font;
    auto textblob = Drawing::TextBlob::MakeFromText(str, strlen(str), font, Drawing::TextEncoding::UTF8);
    HMSymbolTxt symbolTxt;
    std::function<bool(const std::shared_ptr<OHOS::Rosen::TextEngine::SymbolAnimationConfig>&)>
        animationFunc = nullptr;
    HMSymbolRun hmSymbolRun = HMSymbolRun(0, symbolTxt, textblob, animationFunc);
    hmSymbolRun.SetCommonSubType(Drawing::DrawingCommonSubType::DOWN);
    EXPECT_EQ(hmSymbolRun.symbolTxt_.GetCommonSubType(), Drawing::DrawingCommonSubType::DOWN);

    hmSymbolRun.SetCommonSubType(Drawing::DrawingCommonSubType::UP);
    EXPECT_EQ(hmSymbolRun.symbolTxt_.GetCommonSubType(), Drawing::DrawingCommonSubType::UP);
}

/*
 * @tc.name: SetTextBlob001
 * @tc.desc: test SetTextBlob with textBlob
 * @tc.type: FUNC
 */
HWTEST_F(OHHmSymbolRunTest, SetTextBlob001, TestSize.Level1)
{
    Drawing::Font font;
    const char* str1 = "A";
    auto textblob1 = Drawing::TextBlob::MakeFromText(str1, strlen(str1), font, Drawing::TextEncoding::UTF8);
    HMSymbolTxt symbolTxt;
    std::function<bool(const std::shared_ptr<OHOS::Rosen::TextEngine::SymbolAnimationConfig>&)>
        animationFunc = nullptr;
    HMSymbolRun hmSymbolRun = HMSymbolRun(0, symbolTxt, textblob1, animationFunc);

    EXPECT_NE(hmSymbolRun.textBlob_, nullptr);
    hmSymbolRun.SetTextBlob(nullptr);
    EXPECT_NE(hmSymbolRun.textBlob_, nullptr);

    //glyphId1:"A", glyphId2:"A"
    //glyphId1.size() == 1,glyphId2.size() == 1,glyphId1[0] == glyphId2[0]
    const char* str2 = "A";
    auto textblob2 = Drawing::TextBlob::MakeFromText(str2, strlen(str2), font, Drawing::TextEncoding::UTF8);
    hmSymbolRun.currentAnimationHasPlayed_ = true;
    hmSymbolRun.SetTextBlob(textblob2);
    EXPECT_TRUE(hmSymbolRun.currentAnimationHasPlayed_);

    //glyphId1:"A", glyphId2:"B"
    //glyphId1.size() == 1,glyphId2.size() == 1,glyphId1[0] != glyphId2[0]
    const char* str3 = "B";
    auto textblob3 = Drawing::TextBlob::MakeFromText(str3, strlen(str3), font, Drawing::TextEncoding::UTF8);
    hmSymbolRun.SetTextBlob(textblob3);
    EXPECT_FALSE(hmSymbolRun.currentAnimationHasPlayed_);

    //glyphId1:"B", glyphId2:"BA"
    //glyphId1.size() == 1,glyphId2.size() != 1,glyphId1[0] == glyphId2[0]
    const char* str4 = "BA";
    auto textblob4 = Drawing::TextBlob::MakeFromText(str4, strlen(str4), font, Drawing::TextEncoding::UTF8);
    hmSymbolRun.currentAnimationHasPlayed_ = true;
    hmSymbolRun.SetTextBlob(textblob4);
    EXPECT_FALSE(hmSymbolRun.currentAnimationHasPlayed_);

    //glyphId1:"BA", glyphId2:"A"
    //glyphId1.size() != 1,glyphId2.size() == 1,glyphId1[0] != glyphId2[0]
    hmSymbolRun.currentAnimationHasPlayed_ = true;
    hmSymbolRun.SetTextBlob(textblob2);
    EXPECT_FALSE(hmSymbolRun.currentAnimationHasPlayed_);

    //glyphId1:"A", glyphId2:"BA"
    //glyphId1.size() == 1,glyphId2.size() != 1,glyphId1[0] != glyphId2[0]
    hmSymbolRun.currentAnimationHasPlayed_ = true;
    hmSymbolRun.SetTextBlob(textblob4);
    EXPECT_FALSE(hmSymbolRun.currentAnimationHasPlayed_);

    //glyphId1:"BA", glyphId2:"AB"
    //glyphId1.size() != 1,glyphId2.size() != 1,glyphId1[0] != glyphId2[0]
    const char* str5 = "AB";
    auto textblob5 = Drawing::TextBlob::MakeFromText(str5, strlen(str5), font, Drawing::TextEncoding::UTF8);
    hmSymbolRun.currentAnimationHasPlayed_ = true;
    hmSymbolRun.SetTextBlob(textblob5);
    EXPECT_FALSE(hmSymbolRun.currentAnimationHasPlayed_);

    //glyphId1:"AB", glyphId2:"AC"
    //glyphId1.size() != 1,glyphId2.size() != 1,glyphId1[0] == glyphId2[0]
    const char* str6 = "AC";
    auto textblob6 = Drawing::TextBlob::MakeFromText(str6, strlen(str6), font, Drawing::TextEncoding::UTF8);
    hmSymbolRun.currentAnimationHasPlayed_ = true;
    hmSymbolRun.SetTextBlob(textblob6);
    EXPECT_FALSE(hmSymbolRun.currentAnimationHasPlayed_);

    //glyphId1:"AC", glyphId2:"B"
    //glyphId1.size() != 1,glyphId2.size() == 1,glyphId1[0] != glyphId2[0]
    hmSymbolRun.currentAnimationHasPlayed_ = true;
    hmSymbolRun.SetTextBlob(textblob3);
    EXPECT_FALSE(hmSymbolRun.currentAnimationHasPlayed_);
}

/*
 * @tc.name: SetAnimation001
 * @tc.desc: test SetAnimation with animationFunc
 * @tc.type: FUNC
 */
HWTEST_F(OHHmSymbolRunTest, SetAnimation001, TestSize.Level1)
{
    const char* str = "A";
    Drawing::Font font;
    auto textblob = Drawing::TextBlob::MakeFromText(str, strlen(str), font, Drawing::TextEncoding::UTF8);
    std::function<bool(const std::shared_ptr<OHOS::Rosen::TextEngine::SymbolAnimationConfig>&)>
        animationFunc = nullptr;
    HMSymbolTxt symbolTxt;
    HMSymbolRun hmSymbolRun = HMSymbolRun(0, symbolTxt, textblob, animationFunc);
    EXPECT_EQ(hmSymbolRun.animationFunc_, nullptr);
    hmSymbolRun.SetAnimation(AnimationFunc);
    EXPECT_NE(hmSymbolRun.animationFunc_, nullptr);
    hmSymbolRun.SetAnimation(animationFunc);
    EXPECT_NE(hmSymbolRun.animationFunc_, nullptr);
}
} // namespace SPText
} // namespace Rosen
} // namespace OHOS