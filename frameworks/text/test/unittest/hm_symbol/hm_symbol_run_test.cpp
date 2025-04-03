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
class OHHmSymbolRunTest : public testing::Test {};


/*
 * @tc.name: DrawSymbol001
 * @tc.desc: test DrawSymbol with one Glyph
 * @tc.type: FUNC
 */
HWTEST_F(OHHmSymbolRunTest, DrawSymbol001, TestSize.Level1)
{
    std::shared_ptr<RSCanvas> rsCanvas = std::make_shared<RSCanvas>();
    RSPoint paint_ = {100, 100}; // 100, 100 is the offset
    HMSymbolTxt symbolTxt;
    std::function<bool(const std::shared_ptr<TextEngine::SymbolAnimationConfig>&)> animationFunc =
        [](const std::shared_ptr<TextEngine::SymbolAnimationConfig>& symbolAnimationConfig) {
            return true;
        };
    HMSymbolRun hmSymbolRun = HMSymbolRun(0, symbolTxt, nullptr, animationFunc);

    // test rsCanvas is nullptr, textblob is nullptr
    hmSymbolRun.DrawSymbol(nullptr, paint_);
    EXPECT_FALSE(hmSymbolRun.currentAnimationHasPlayed_);

    // test rsCanvas isn't nullptr, textblob is nullptr
    hmSymbolRun.DrawSymbol(rsCanvas.get(), paint_);
    EXPECT_FALSE(hmSymbolRun.currentAnimationHasPlayed_);

    const char* str = "A"; // "A" is one Glyph
    Drawing::Font font;
    auto textblob = Drawing::TextBlob::MakeFromText(str, strlen(str), font, Drawing::TextEncoding::UTF8);
    HMSymbolRun hmSymbolRun1 = HMSymbolRun(1, symbolTxt, textblob, animationFunc);

    // test rsCanvas is nullptr, textblob isn't nullptr
    hmSymbolRun1.DrawSymbol(nullptr, paint_);
    EXPECT_FALSE(hmSymbolRun1.currentAnimationHasPlayed_);

    // test rsCanvas isn't nullptr, textblob isn't nullptr
    hmSymbolRun1.DrawSymbol(rsCanvas.get(), paint_);
    EXPECT_FALSE(hmSymbolRun1.currentAnimationHasPlayed_);
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
    const char* str = "Test multiple glyphs"; // "Test multiple glyphs" is Glyphs
    Drawing::Font font;
    auto textblob = Drawing::TextBlob::MakeFromText(str, strlen(str), font, Drawing::TextEncoding::UTF8);
    HMSymbolTxt symbolTxt;
    std::function<bool(const std::shared_ptr<TextEngine::SymbolAnimationConfig>&)> animationFunc =
        [](const std::shared_ptr<TextEngine::SymbolAnimationConfig>& symbolAnimationConfig) {
            return true;
        };

    HMSymbolRun hmSymbolRun = HMSymbolRun(0, symbolTxt, textblob, animationFunc);

    EXPECT_FALSE(hmSymbolRun.currentAnimationHasPlayed_);
    hmSymbolRun.DrawSymbol(rsCanvas.get(), paint_);
    EXPECT_FALSE(hmSymbolRun.currentAnimationHasPlayed_);
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
    std::function<bool(const std::shared_ptr<TextEngine::SymbolAnimationConfig>&)> animationFunc =
        [](const std::shared_ptr<TextEngine::SymbolAnimationConfig>& symbolAnimationConfig) {
            return true;
        };
    HMSymbolRun hmSymbolRun = HMSymbolRun(0, symbolTxt, textblob, animationFunc);
    // test bounce animation
    hmSymbolRun.SetAnimationStart(true);
    hmSymbolRun.SetSymbolEffect(RSEffectStrategy::BOUNCE);

    EXPECT_FALSE(hmSymbolRun.currentAnimationHasPlayed_);
    hmSymbolRun.DrawSymbol(rsCanvas.get(), paint_);
    EXPECT_TRUE(hmSymbolRun.currentAnimationHasPlayed_);

    // test appear animation
    hmSymbolRun.SetSymbolEffect(RSEffectStrategy::APPEAR);
    EXPECT_FALSE(hmSymbolRun.currentAnimationHasPlayed_);
    hmSymbolRun.DrawSymbol(rsCanvas.get(), paint_);
    EXPECT_TRUE(hmSymbolRun.currentAnimationHasPlayed_);

    // test pulse aimation, this glyph not support, result is false
    hmSymbolRun.SetSymbolEffect(RSEffectStrategy::PULSE);
    EXPECT_FALSE(hmSymbolRun.currentAnimationHasPlayed_);
    hmSymbolRun.DrawSymbol(rsCanvas.get(), paint_);
    EXPECT_FALSE(hmSymbolRun.currentAnimationHasPlayed_);
}

/*
 * @tc.name: SetSymbolRenderColor001
 * @tc.desc: test SetSymbolRenderColor with multi colors
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
 * @tc.desc: test SetSymbolRenderColor with one color
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
    hmSymbolRun.UpdateSymbolLayersGroups(glyphId);
    check = hmSymbolRun.SymbolAnimation(symbol, offset);
    EXPECT_FALSE(check);
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
    hmSymbolRun.UpdateSymbolLayersGroups(glyphId);
    bool flag = hmSymbolRun.GetAnimationGroups(effectStrategy, animationOut);
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
    hmSymbolRun.UpdateSymbolLayersGroups(glyphId);
    bool flag = hmSymbolRun.GetAnimationGroups(effectStrategy, animationOut);
    EXPECT_FALSE(flag);
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
    std::shared_ptr<RSTextBlob> textBlob = nullptr;
    std::function<bool(const std::shared_ptr<TextEngine::SymbolAnimationConfig>&)> animationFunc = nullptr;
    HMSymbolRun hmSymbolRun = HMSymbolRun(0, symbolTxt, textBlob, animationFunc);
    auto symbolLayer = hmSymbolRun.GetSymbolLayers(glyphId, symbolTxt);
    EXPECT_TRUE(symbolLayer.renderGroups.empty());

    hmSymbolRun.UpdateSymbolLayersGroups(glyphId);
    symbolLayer = hmSymbolRun.GetSymbolLayers(glyphId, symbolTxt);
    EXPECT_EQ(symbolLayer.symbolGlyphId, glyphId);

    if (!symbolLayer.renderGroups.empty()) {
        auto layerColor = symbolLayer.renderGroups[0].color;
        EXPECT_EQ(layerColor.r, color.r); // the default color is {1.0, 0, 0, 0}
    }
}

/*
 * @tc.name: SetRenderColor001
 * @tc.desc: test SetRenderColor with colorList
 * @tc.type: FUNC
 */
HWTEST_F(OHHmSymbolRunTest, SetRenderColor001, TestSize.Level1)
{
    std::shared_ptr<RSCanvas> rsCanvas = std::make_shared<RSCanvas>();
    RSPoint paint_ = {100, 100}; // 100, 100 is the offset
    const char* str = "A";
    Drawing::Font font;
    auto textblob = Drawing::TextBlob::MakeFromText(str, strlen(str), font, Drawing::TextEncoding::UTF8);
    HMSymbolTxt symbolTxt;
    std::function<bool(const std::shared_ptr<TextEngine::SymbolAnimationConfig>&)> animationFunc =
        [](const std::shared_ptr<TextEngine::SymbolAnimationConfig>& symbolAnimationConfig) {
            return true;
        };
    HMSymbolRun hmSymbolRun = HMSymbolRun(0, symbolTxt, textblob, animationFunc);
    RSSColor color1 = {1.0, 255, 0, 0}; // the 1.0 is alpha, 255, 0, 0 is RGB
    RSSColor color2 = {1.0, 0, 0, 0}; // the 1.0 is alpha, 0, 0, 0 is RGB
    std::vector<RSSColor> rsscolors1 = {color1};
    std::vector<RSSColor> rsscolors2 = {color1, color2};

    hmSymbolRun.SetAnimationStart(true);
    hmSymbolRun.SetSymbolEffect(RSEffectStrategy::BOUNCE);

    EXPECT_FALSE(hmSymbolRun.currentAnimationHasPlayed_);
    hmSymbolRun.DrawSymbol(rsCanvas.get(), paint_);
    EXPECT_TRUE(hmSymbolRun.currentAnimationHasPlayed_);

    hmSymbolRun.SetRenderColor(rsscolors1);
    EXPECT_TRUE(hmSymbolRun.currentAnimationHasPlayed_);
    auto ret1 = hmSymbolRun.symbolTxt_.GetRenderColor();
    EXPECT_EQ(ret1.size(), 1);

    hmSymbolRun.SetRenderColor(rsscolors2);
    EXPECT_TRUE(hmSymbolRun.currentAnimationHasPlayed_);
    auto ret2 = hmSymbolRun.symbolTxt_.GetRenderColor();
    EXPECT_EQ(ret2.size(), 2);
}

/*
 * @tc.name: SetRenderMode001
 * @tc.desc: test SetRenderMode with SINGLE
 * @tc.type: FUNC
 */
HWTEST_F(OHHmSymbolRunTest, SetRenderMode001, TestSize.Level1)
{
    std::shared_ptr<RSCanvas> rsCanvas = std::make_shared<RSCanvas>();
    RSPoint paint_ = {100, 100}; // 100, 100 is the offset
    const char* str = "A";
    Drawing::Font font;
    auto textblob = Drawing::TextBlob::MakeFromText(str, strlen(str), font, Drawing::TextEncoding::UTF8);
    HMSymbolTxt symbolTxt;
    std::function<bool(const std::shared_ptr<TextEngine::SymbolAnimationConfig>&)> animationFunc =
        [](const std::shared_ptr<TextEngine::SymbolAnimationConfig>& symbolAnimationConfig) {
            return true;
        };
    HMSymbolRun hmSymbolRun = HMSymbolRun(0, symbolTxt, textblob, animationFunc);
    hmSymbolRun.SetAnimationStart(true);
    hmSymbolRun.SetSymbolEffect(RSEffectStrategy::BOUNCE);

    hmSymbolRun.currentAnimationHasPlayed_ = true;
    hmSymbolRun.SetRenderMode(Drawing::DrawingSymbolRenderingStrategy::SINGLE);
    EXPECT_EQ(hmSymbolRun.symbolTxt_.GetRenderMode(), Drawing::DrawingSymbolRenderingStrategy::SINGLE);
    EXPECT_TRUE(hmSymbolRun.currentAnimationHasPlayed_);
}

/*
 * @tc.name: SetRenderMode002
 * @tc.desc: test SetRenderMode with MULTIPLE_COLOR
 * @tc.type: FUNC
 */
HWTEST_F(OHHmSymbolRunTest, SetRenderMode002, TestSize.Level1)
{
    std::shared_ptr<RSCanvas> rsCanvas = std::make_shared<RSCanvas>();
    RSPoint paint_ = {100, 100}; // 100, 100 is the offset
    const char* str = "A";
    Drawing::Font font;
    auto textblob = Drawing::TextBlob::MakeFromText(str, strlen(str), font, Drawing::TextEncoding::UTF8);
    HMSymbolTxt symbolTxt;
    std::function<bool(const std::shared_ptr<TextEngine::SymbolAnimationConfig>&)> animationFunc =
        [](const std::shared_ptr<TextEngine::SymbolAnimationConfig>& symbolAnimationConfig) {
            return true;
        };
    HMSymbolRun hmSymbolRun = HMSymbolRun(0, symbolTxt, textblob, animationFunc);
    hmSymbolRun.SetAnimationStart(true);
    hmSymbolRun.SetSymbolEffect(RSEffectStrategy::BOUNCE);

    hmSymbolRun.currentAnimationHasPlayed_ = true;
    hmSymbolRun.SetRenderMode(Drawing::DrawingSymbolRenderingStrategy::MULTIPLE_COLOR);
    EXPECT_EQ(hmSymbolRun.symbolTxt_.GetRenderMode(), Drawing::DrawingSymbolRenderingStrategy::MULTIPLE_COLOR);
    EXPECT_TRUE(hmSymbolRun.currentAnimationHasPlayed_);
}

/*
 * @tc.name: SetRenderMode003
 * @tc.desc: test SetRenderMode with MULTIPLE_OPACITY
 * @tc.type: FUNC
 */
HWTEST_F(OHHmSymbolRunTest, SetRenderMode003, TestSize.Level1)
{
    std::shared_ptr<RSCanvas> rsCanvas = std::make_shared<RSCanvas>();
    RSPoint paint_ = {100, 100}; // 100, 100 is the offset
    const char* str = "A";
    Drawing::Font font;
    auto textblob = Drawing::TextBlob::MakeFromText(str, strlen(str), font, Drawing::TextEncoding::UTF8);
    HMSymbolTxt symbolTxt;
    std::function<bool(const std::shared_ptr<TextEngine::SymbolAnimationConfig>&)> animationFunc =
        [](const std::shared_ptr<TextEngine::SymbolAnimationConfig>& symbolAnimationConfig) {
            return true;
        };
    HMSymbolRun hmSymbolRun = HMSymbolRun(0, symbolTxt, textblob, animationFunc);
    hmSymbolRun.SetAnimationStart(true);
    hmSymbolRun.SetSymbolEffect(RSEffectStrategy::BOUNCE);

    hmSymbolRun.currentAnimationHasPlayed_ = true;
    hmSymbolRun.SetRenderMode(Drawing::DrawingSymbolRenderingStrategy::MULTIPLE_OPACITY);
    EXPECT_EQ(hmSymbolRun.symbolTxt_.GetRenderMode(), Drawing::DrawingSymbolRenderingStrategy::MULTIPLE_OPACITY);
    EXPECT_TRUE(hmSymbolRun.currentAnimationHasPlayed_);
}

/*
 * @tc.name: SetSymbolEffect001
 * @tc.desc: test SetSymbolEffect with DrawingEffectStrategy::NONE
 * @tc.type: FUNC
 */
HWTEST_F(OHHmSymbolRunTest, SetSymbolEffect001, TestSize.Level1)
{
    std::shared_ptr<RSCanvas> rsCanvas = std::make_shared<RSCanvas>();
    RSPoint paint_ = {100, 100}; // 100, 100 is the offset
    const char* str = "A";
    Drawing::Font font;
    auto textblob = Drawing::TextBlob::MakeFromText(str, strlen(str), font, Drawing::TextEncoding::UTF8);
    HMSymbolTxt symbolTxt;
    std::function<bool(const std::shared_ptr<TextEngine::SymbolAnimationConfig>&)> animationFunc =
        [](const std::shared_ptr<TextEngine::SymbolAnimationConfig>& symbolAnimationConfig) {
            return true;
        };
    HMSymbolRun hmSymbolRun = HMSymbolRun(0, symbolTxt, textblob, animationFunc);
    hmSymbolRun.SetAnimationStart(true);
    hmSymbolRun.currentAnimationHasPlayed_ = true;

    hmSymbolRun.SetSymbolEffect(Drawing::DrawingEffectStrategy::NONE);
    EXPECT_EQ(hmSymbolRun.symbolTxt_.GetEffectStrategy(), Drawing::DrawingEffectStrategy::NONE);
    EXPECT_FALSE(hmSymbolRun.currentAnimationHasPlayed_);
    hmSymbolRun.DrawSymbol(rsCanvas.get(), paint_);
    EXPECT_FALSE(hmSymbolRun.currentAnimationHasPlayed_);
}

/*
 * @tc.name: SetSymbolEffect002
 * @tc.desc: test SetSymbolEffect with DrawingEffectStrategy::SCALE
 * @tc.type: FUNC
 */
HWTEST_F(OHHmSymbolRunTest, SetSymbolEffect002, TestSize.Level1)
{
    std::shared_ptr<RSCanvas> rsCanvas = std::make_shared<RSCanvas>();
    RSPoint paint_ = {100, 100}; // 100, 100 is the offset
    const char* str = "A";
    Drawing::Font font;
    auto textblob = Drawing::TextBlob::MakeFromText(str, strlen(str), font, Drawing::TextEncoding::UTF8);
    HMSymbolTxt symbolTxt;
    std::function<bool(const std::shared_ptr<TextEngine::SymbolAnimationConfig>&)> animationFunc =
        [](const std::shared_ptr<TextEngine::SymbolAnimationConfig>& symbolAnimationConfig) {
            return true;
        };
    HMSymbolRun hmSymbolRun = HMSymbolRun(0, symbolTxt, textblob, animationFunc);
    hmSymbolRun.SetAnimationStart(true);
    hmSymbolRun.currentAnimationHasPlayed_ = true;

    hmSymbolRun.SetSymbolEffect(Drawing::DrawingEffectStrategy::SCALE);
    EXPECT_EQ(hmSymbolRun.symbolTxt_.GetEffectStrategy(), Drawing::DrawingEffectStrategy::SCALE);
    EXPECT_FALSE(hmSymbolRun.currentAnimationHasPlayed_);
    hmSymbolRun.DrawSymbol(rsCanvas.get(), paint_);
    EXPECT_TRUE(hmSymbolRun.currentAnimationHasPlayed_);
}

/*
 * @tc.name: SetSymbolEffect003
 * @tc.desc: test SetSymbolEffect with DrawingEffectStrategy::VARIABLE_COLOR
 * @tc.type: FUNC
 */
HWTEST_F(OHHmSymbolRunTest, SetSymbolEffect003, TestSize.Level1)
{
    std::shared_ptr<RSCanvas> rsCanvas = std::make_shared<RSCanvas>();
    RSPoint paint_ = {100, 100}; // 100, 100 is the offset
    const char* str = "A";
    Drawing::Font font;
    auto textblob = Drawing::TextBlob::MakeFromText(str, strlen(str), font, Drawing::TextEncoding::UTF8);
    HMSymbolTxt symbolTxt;
    std::function<bool(const std::shared_ptr<TextEngine::SymbolAnimationConfig>&)> animationFunc =
        [](const std::shared_ptr<TextEngine::SymbolAnimationConfig>& symbolAnimationConfig) {
            return true;
        };
    HMSymbolRun hmSymbolRun = HMSymbolRun(0, symbolTxt, textblob, animationFunc);
    hmSymbolRun.SetAnimationStart(true);
    hmSymbolRun.currentAnimationHasPlayed_ = true;

    hmSymbolRun.SetSymbolEffect(Drawing::DrawingEffectStrategy::VARIABLE_COLOR);
    EXPECT_EQ(hmSymbolRun.symbolTxt_.GetEffectStrategy(), Drawing::DrawingEffectStrategy::VARIABLE_COLOR);
    EXPECT_FALSE(hmSymbolRun.currentAnimationHasPlayed_);
    hmSymbolRun.DrawSymbol(rsCanvas.get(), paint_);
    EXPECT_TRUE(hmSymbolRun.currentAnimationHasPlayed_);
}

/*
 * @tc.name: SetSymbolEffect004
 * @tc.desc: test SetSymbolEffect with DrawingEffectStrategy::APPEAR
 * @tc.type: FUNC
 */
HWTEST_F(OHHmSymbolRunTest, SetSymbolEffect004, TestSize.Level1)
{
    std::shared_ptr<RSCanvas> rsCanvas = std::make_shared<RSCanvas>();
    RSPoint paint_ = {100, 100}; // 100, 100 is the offset
    const char* str = "A";
    Drawing::Font font;
    auto textblob = Drawing::TextBlob::MakeFromText(str, strlen(str), font, Drawing::TextEncoding::UTF8);
    HMSymbolTxt symbolTxt;
    std::function<bool(const std::shared_ptr<TextEngine::SymbolAnimationConfig>&)> animationFunc =
        [](const std::shared_ptr<TextEngine::SymbolAnimationConfig>& symbolAnimationConfig) {
            return true;
        };
    HMSymbolRun hmSymbolRun = HMSymbolRun(0, symbolTxt, textblob, animationFunc);
    hmSymbolRun.SetAnimationStart(true);
    hmSymbolRun.currentAnimationHasPlayed_ = true;

    hmSymbolRun.SetSymbolEffect(Drawing::DrawingEffectStrategy::APPEAR);
    EXPECT_EQ(hmSymbolRun.symbolTxt_.GetEffectStrategy(), Drawing::DrawingEffectStrategy::APPEAR);
    EXPECT_FALSE(hmSymbolRun.currentAnimationHasPlayed_);
    hmSymbolRun.DrawSymbol(rsCanvas.get(), paint_);
    EXPECT_TRUE(hmSymbolRun.currentAnimationHasPlayed_);
}

/*
 * @tc.name: SetSymbolEffect005
 * @tc.desc: test SetSymbolEffect with different DrawingEffectStrategy::DISAPPEAR
 * @tc.type: FUNC
 */
HWTEST_F(OHHmSymbolRunTest, SetSymbolEffect005, TestSize.Level1)
{
    std::shared_ptr<RSCanvas> rsCanvas = std::make_shared<RSCanvas>();
    RSPoint paint_ = {100, 100}; // 100, 100 is the offset
    const char* str = "A";
    Drawing::Font font;
    auto textblob = Drawing::TextBlob::MakeFromText(str, strlen(str), font, Drawing::TextEncoding::UTF8);
    HMSymbolTxt symbolTxt;
    std::function<bool(const std::shared_ptr<TextEngine::SymbolAnimationConfig>&)> animationFunc =
        [](const std::shared_ptr<TextEngine::SymbolAnimationConfig>& symbolAnimationConfig) {
            return true;
        };
    HMSymbolRun hmSymbolRun = HMSymbolRun(0, symbolTxt, textblob, animationFunc);
    hmSymbolRun.SetAnimationStart(true);
    hmSymbolRun.currentAnimationHasPlayed_ = true;

    hmSymbolRun.SetSymbolEffect(Drawing::DrawingEffectStrategy::DISAPPEAR);
    EXPECT_EQ(hmSymbolRun.symbolTxt_.GetEffectStrategy(), Drawing::DrawingEffectStrategy::DISAPPEAR);
    EXPECT_FALSE(hmSymbolRun.currentAnimationHasPlayed_);
    hmSymbolRun.DrawSymbol(rsCanvas.get(), paint_);
    EXPECT_TRUE(hmSymbolRun.currentAnimationHasPlayed_);
}

/*
 * @tc.name: SetSymbolEffect006
 * @tc.desc: test SetSymbolEffect with different DrawingEffectStrategy::BOUNCE
 * @tc.type: FUNC
 */
HWTEST_F(OHHmSymbolRunTest, SetSymbolEffect006, TestSize.Level1)
{
    std::shared_ptr<RSCanvas> rsCanvas = std::make_shared<RSCanvas>();
    RSPoint paint_ = {100, 100}; // 100, 100 is the offset
    const char* str = "A";
    Drawing::Font font;
    auto textblob = Drawing::TextBlob::MakeFromText(str, strlen(str), font, Drawing::TextEncoding::UTF8);
    HMSymbolTxt symbolTxt;
    std::function<bool(const std::shared_ptr<TextEngine::SymbolAnimationConfig>&)> animationFunc =
        [](const std::shared_ptr<TextEngine::SymbolAnimationConfig>& symbolAnimationConfig) {
            return true;
        };
    HMSymbolRun hmSymbolRun = HMSymbolRun(0, symbolTxt, textblob, animationFunc);
    hmSymbolRun.SetAnimationStart(true);
    hmSymbolRun.currentAnimationHasPlayed_ = true;

    hmSymbolRun.SetSymbolEffect(Drawing::DrawingEffectStrategy::BOUNCE);
    EXPECT_EQ(hmSymbolRun.symbolTxt_.GetEffectStrategy(), Drawing::DrawingEffectStrategy::BOUNCE);
    EXPECT_FALSE(hmSymbolRun.currentAnimationHasPlayed_);
    hmSymbolRun.DrawSymbol(rsCanvas.get(), paint_);
    EXPECT_TRUE(hmSymbolRun.currentAnimationHasPlayed_);
}

/*
 * @tc.name: SetSymbolEffect007
 * @tc.desc: test SetSymbolEffect with different DrawingEffectStrategy::PULSE
 * @tc.type: FUNC
 */
HWTEST_F(OHHmSymbolRunTest, SetSymbolEffect007, TestSize.Level1)
{
    std::shared_ptr<RSCanvas> rsCanvas = std::make_shared<RSCanvas>();
    RSPoint paint_ = {100, 100}; // 100, 100 is the offset
    const char* str = "A";
    Drawing::Font font;
    auto textblob = Drawing::TextBlob::MakeFromText(str, strlen(str), font, Drawing::TextEncoding::UTF8);
    HMSymbolTxt symbolTxt;
    std::function<bool(const std::shared_ptr<TextEngine::SymbolAnimationConfig>&)> animationFunc =
        [](const std::shared_ptr<TextEngine::SymbolAnimationConfig>& symbolAnimationConfig) {
            return true;
        };
    HMSymbolRun hmSymbolRun = HMSymbolRun(0, symbolTxt, textblob, animationFunc);
    hmSymbolRun.SetAnimationStart(true);
    hmSymbolRun.currentAnimationHasPlayed_ = true;

    hmSymbolRun.SetSymbolEffect(Drawing::DrawingEffectStrategy::PULSE);
    EXPECT_EQ(hmSymbolRun.symbolTxt_.GetEffectStrategy(), Drawing::DrawingEffectStrategy::PULSE);
    EXPECT_FALSE(hmSymbolRun.currentAnimationHasPlayed_);
    hmSymbolRun.DrawSymbol(rsCanvas.get(), paint_);
    EXPECT_FALSE(hmSymbolRun.currentAnimationHasPlayed_);
}

/*
 * @tc.name: SetSymbolEffect008
 * @tc.desc: test SetSymbolEffect with different DrawingEffectStrategy::REPLACE_APPEAR
 * @tc.type: FUNC
 */
HWTEST_F(OHHmSymbolRunTest, SetSymbolEffect008, TestSize.Level1)
{
    std::shared_ptr<RSCanvas> rsCanvas = std::make_shared<RSCanvas>();
    RSPoint paint_ = {100, 100}; // 100, 100 is the offset
    const char* str = "A";
    Drawing::Font font;
    auto textblob = Drawing::TextBlob::MakeFromText(str, strlen(str), font, Drawing::TextEncoding::UTF8);
    HMSymbolTxt symbolTxt;
    std::function<bool(const std::shared_ptr<TextEngine::SymbolAnimationConfig>&)> animationFunc =
        [](const std::shared_ptr<TextEngine::SymbolAnimationConfig>& symbolAnimationConfig) {
            return true;
        };
    HMSymbolRun hmSymbolRun = HMSymbolRun(0, symbolTxt, textblob, animationFunc);
    hmSymbolRun.SetAnimationStart(true);
    hmSymbolRun.currentAnimationHasPlayed_ = true;

    hmSymbolRun.SetSymbolEffect(Drawing::DrawingEffectStrategy::REPLACE_APPEAR);
    EXPECT_EQ(hmSymbolRun.symbolTxt_.GetEffectStrategy(), Drawing::DrawingEffectStrategy::REPLACE_APPEAR);
    EXPECT_FALSE(hmSymbolRun.currentAnimationHasPlayed_);
    hmSymbolRun.DrawSymbol(rsCanvas.get(), paint_);
    EXPECT_TRUE(hmSymbolRun.currentAnimationHasPlayed_);
}

/*
 * @tc.name: SetAnimationMode001
 * @tc.desc: test SetAnimationMode with animationMode
 * @tc.type: FUNC
 */
HWTEST_F(OHHmSymbolRunTest, SetAnimationMode001, TestSize.Level1)
{
    std::shared_ptr<RSCanvas> rsCanvas = std::make_shared<RSCanvas>();
    RSPoint paint_ = {100, 100}; // 100, 100 is the offset
    const char* str = "A";
    Drawing::Font font;
    auto textblob = Drawing::TextBlob::MakeFromText(str, strlen(str), font, Drawing::TextEncoding::UTF8);
    HMSymbolTxt symbolTxt;
    std::function<bool(const std::shared_ptr<TextEngine::SymbolAnimationConfig>&)> animationFunc =
        [](const std::shared_ptr<TextEngine::SymbolAnimationConfig>& symbolAnimationConfig) {
            return true;
        };
    HMSymbolRun hmSymbolRun = HMSymbolRun(0, symbolTxt, textblob, animationFunc);
    hmSymbolRun.SetAnimationStart(true);
    hmSymbolRun.SetSymbolEffect(RSEffectStrategy::VARIABLE_COLOR);

    EXPECT_FALSE(hmSymbolRun.currentAnimationHasPlayed_);
    hmSymbolRun.DrawSymbol(rsCanvas.get(), paint_);
    EXPECT_TRUE(hmSymbolRun.currentAnimationHasPlayed_);

    hmSymbolRun.SetAnimationMode(0); // the 0 is the wholeSymbol or cumulative effect
    EXPECT_EQ(hmSymbolRun.symbolTxt_.GetAnimationMode(), 0);
    EXPECT_FALSE(hmSymbolRun.currentAnimationHasPlayed_);
    hmSymbolRun.DrawSymbol(rsCanvas.get(), paint_);
    EXPECT_TRUE(hmSymbolRun.currentAnimationHasPlayed_);

    hmSymbolRun.SetAnimationMode(1); // the 1 is the byLayer or iteratuve effect
    EXPECT_EQ(hmSymbolRun.symbolTxt_.GetAnimationMode(), 1);
    EXPECT_FALSE(hmSymbolRun.currentAnimationHasPlayed_);
    hmSymbolRun.DrawSymbol(rsCanvas.get(), paint_);
    EXPECT_TRUE(hmSymbolRun.currentAnimationHasPlayed_);

    hmSymbolRun.SetAnimationMode(500); // 500 is test Boundary Value
    EXPECT_EQ(hmSymbolRun.symbolTxt_.GetAnimationMode(), 1);
    EXPECT_FALSE(hmSymbolRun.currentAnimationHasPlayed_);
    hmSymbolRun.DrawSymbol(rsCanvas.get(), paint_);
    EXPECT_TRUE(hmSymbolRun.currentAnimationHasPlayed_);
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
    EXPECT_FALSE(hmSymbolRun.symbolTxt_.GetAnimationStart());
    hmSymbolRun.SetAnimationStart(true);
    EXPECT_TRUE(hmSymbolRun.symbolTxt_.GetAnimationStart());
}

/*
 * @tc.name: SetCommonSubType001
 * @tc.desc: test SetCommonSubType with commonSubType::DOWN
 * @tc.type: FUNC
 */
HWTEST_F(OHHmSymbolRunTest, SetCommonSubType001, TestSize.Level1)
{
    std::shared_ptr<RSCanvas> rsCanvas = std::make_shared<RSCanvas>();
    RSPoint paint_ = {100, 100}; // 100, 100 is the offset
    const char* str = "A";
    Drawing::Font font;
    auto textblob = Drawing::TextBlob::MakeFromText(str, strlen(str), font, Drawing::TextEncoding::UTF8);
    HMSymbolTxt symbolTxt;
    std::function<bool(const std::shared_ptr<TextEngine::SymbolAnimationConfig>&)> animationFunc =
        [](const std::shared_ptr<TextEngine::SymbolAnimationConfig>& symbolAnimationConfig) {
            return true;
        };
    HMSymbolRun hmSymbolRun = HMSymbolRun(0, symbolTxt, textblob, animationFunc);
    hmSymbolRun.SetAnimationStart(true);
    hmSymbolRun.SetSymbolEffect(RSEffectStrategy::BOUNCE);

    EXPECT_FALSE(hmSymbolRun.currentAnimationHasPlayed_);
    hmSymbolRun.DrawSymbol(rsCanvas.get(), paint_);
    EXPECT_TRUE(hmSymbolRun.currentAnimationHasPlayed_);

    hmSymbolRun.SetCommonSubType(Drawing::DrawingCommonSubType::DOWN);
    EXPECT_EQ(hmSymbolRun.symbolTxt_.GetCommonSubType(), Drawing::DrawingCommonSubType::DOWN);
    EXPECT_FALSE(hmSymbolRun.currentAnimationHasPlayed_);
    hmSymbolRun.DrawSymbol(rsCanvas.get(), paint_);
    EXPECT_TRUE(hmSymbolRun.currentAnimationHasPlayed_);
}

/*
 * @tc.name: SetCommonSubType002
 * @tc.desc: test SetCommonSubType with commonSubType::UP
 * @tc.type: FUNC
 */
HWTEST_F(OHHmSymbolRunTest, SetCommonSubType002, TestSize.Level1)
{
    std::shared_ptr<RSCanvas> rsCanvas = std::make_shared<RSCanvas>();
    RSPoint paint_ = {100, 100}; // 100, 100 is the offset
    const char* str = "A";
    Drawing::Font font;
    auto textblob = Drawing::TextBlob::MakeFromText(str, strlen(str), font, Drawing::TextEncoding::UTF8);
    HMSymbolTxt symbolTxt;
    std::function<bool(const std::shared_ptr<TextEngine::SymbolAnimationConfig>&)> animationFunc =
        [](const std::shared_ptr<TextEngine::SymbolAnimationConfig>& symbolAnimationConfig) {
            return true;
        };
    HMSymbolRun hmSymbolRun = HMSymbolRun(0, symbolTxt, textblob, animationFunc);
    hmSymbolRun.SetAnimationStart(true);
    hmSymbolRun.SetSymbolEffect(RSEffectStrategy::BOUNCE);

    EXPECT_FALSE(hmSymbolRun.currentAnimationHasPlayed_);
    hmSymbolRun.DrawSymbol(rsCanvas.get(), paint_);
    EXPECT_TRUE(hmSymbolRun.currentAnimationHasPlayed_);

    hmSymbolRun.SetCommonSubType(Drawing::DrawingCommonSubType::UP);
    EXPECT_EQ(hmSymbolRun.symbolTxt_.GetCommonSubType(), Drawing::DrawingCommonSubType::UP);
    EXPECT_FALSE(hmSymbolRun.currentAnimationHasPlayed_);
    hmSymbolRun.DrawSymbol(rsCanvas.get(), paint_);
    EXPECT_TRUE(hmSymbolRun.currentAnimationHasPlayed_);
}

/*
 * @tc.name: SetTextBlob001
 * @tc.desc: test SetTextBlob with null textBlob
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
}

/*
 * @tc.name: SetTextBlob002
 * @tc.desc: test SetTextBlob with same content(before:"A",after:"A",Corresponding truth table: 111)
 * @tc.type: FUNC
 */
HWTEST_F(OHHmSymbolRunTest, SetTextBlob002, TestSize.Level1)
{
    Drawing::Font font;
    const char* str1 = "A";
    auto textblob1 = Drawing::TextBlob::MakeFromText(str1, strlen(str1), font, Drawing::TextEncoding::UTF8);
    HMSymbolTxt symbolTxt;
    std::function<bool(const std::shared_ptr<OHOS::Rosen::TextEngine::SymbolAnimationConfig>&)>
        animationFunc = nullptr;
    HMSymbolRun hmSymbolRun = HMSymbolRun(0, symbolTxt, textblob1, animationFunc);

    //glyphId1:"A", glyphId2:"A"
    //glyphId1.size() == 1,glyphId2.size() == 1,glyphId1[0] == glyphId2[0]
    const char* str2 = "A";
    auto textblob2 = Drawing::TextBlob::MakeFromText(str2, strlen(str2), font, Drawing::TextEncoding::UTF8);
    hmSymbolRun.currentAnimationHasPlayed_ = true;
    hmSymbolRun.SetTextBlob(textblob2);
    EXPECT_TRUE(hmSymbolRun.currentAnimationHasPlayed_);
}

/*
 * @tc.name: SetTextBlob003
 * @tc.desc: test SetTextBlob with different content(before:"A",after:"B",Corresponding truth table: 110)
 * @tc.type: FUNC
 */
HWTEST_F(OHHmSymbolRunTest, SetTextBlob003, TestSize.Level1)
{
    Drawing::Font font;
    const char* str1 = "A";
    auto textblob1 = Drawing::TextBlob::MakeFromText(str1, strlen(str1), font, Drawing::TextEncoding::UTF8);
    HMSymbolTxt symbolTxt;
    std::function<bool(const std::shared_ptr<OHOS::Rosen::TextEngine::SymbolAnimationConfig>&)>
        animationFunc = nullptr;
    HMSymbolRun hmSymbolRun = HMSymbolRun(0, symbolTxt, textblob1, animationFunc);

    //glyphId1:"A", glyphId2:"B"
    //glyphId1.size() == 1,glyphId2.size() == 1,glyphId1[0] != glyphId2[0]
    const char* str2 = "B";
    auto textblob2 = Drawing::TextBlob::MakeFromText(str2, strlen(str2), font, Drawing::TextEncoding::UTF8);
    hmSymbolRun.SetTextBlob(textblob2);
    EXPECT_FALSE(hmSymbolRun.currentAnimationHasPlayed_);
}

/*
 * @tc.name: SetTextBlob004
 * @tc.desc: test SetTextBlob with different content(before:"A",after:"AB",Corresponding truth table: 101)
 * @tc.type: FUNC
 */
HWTEST_F(OHHmSymbolRunTest, SetTextBlob004, TestSize.Level1)
{
    Drawing::Font font;
    const char* str1 = "A";
    auto textblob1 = Drawing::TextBlob::MakeFromText(str1, strlen(str1), font, Drawing::TextEncoding::UTF8);
    HMSymbolTxt symbolTxt;
    std::function<bool(const std::shared_ptr<OHOS::Rosen::TextEngine::SymbolAnimationConfig>&)>
        animationFunc = nullptr;
    HMSymbolRun hmSymbolRun = HMSymbolRun(0, symbolTxt, textblob1, animationFunc);

    //glyphId1:"A", glyphId2:"AB"
    //glyphId1.size() == 1,glyphId2.size() != 1,glyphId1[0] == glyphId2[0]
    const char* str2 = "AB";
    auto textblob2 = Drawing::TextBlob::MakeFromText(str2, strlen(str2), font, Drawing::TextEncoding::UTF8);
    hmSymbolRun.currentAnimationHasPlayed_ = true;
    hmSymbolRun.SetTextBlob(textblob2);
    EXPECT_FALSE(hmSymbolRun.currentAnimationHasPlayed_);
}

/*
 * @tc.name: SetTextBlob005
 * @tc.desc: test SetTextBlob with different content(before:"A",after:"BA",Corresponding truth table: 100)
 * @tc.type: FUNC
 */
HWTEST_F(OHHmSymbolRunTest, SetTextBlob005, TestSize.Level1)
{
    Drawing::Font font;
    const char* str1 = "A";
    auto textblob1 = Drawing::TextBlob::MakeFromText(str1, strlen(str1), font, Drawing::TextEncoding::UTF8);
    HMSymbolTxt symbolTxt;
    std::function<bool(const std::shared_ptr<OHOS::Rosen::TextEngine::SymbolAnimationConfig>&)>
        animationFunc = nullptr;
    HMSymbolRun hmSymbolRun = HMSymbolRun(0, symbolTxt, textblob1, animationFunc);

    //glyphId1:"A", glyphId2:"BA"
    //glyphId1.size() == 1,glyphId2.size() != 1,glyphId1[0] != glyphId2[0]
    const char* str2 = "BA";
    auto textblob2 = Drawing::TextBlob::MakeFromText(str2, strlen(str2), font, Drawing::TextEncoding::UTF8);
    hmSymbolRun.currentAnimationHasPlayed_ = true;
    hmSymbolRun.SetTextBlob(textblob2);
    EXPECT_FALSE(hmSymbolRun.currentAnimationHasPlayed_);
}

/*
 * @tc.name: SetTextBlob006
 * @tc.desc: test SetTextBlob with different content(before:"AB",after:"A",Corresponding truth table: 011)
 * @tc.type: FUNC
 */
HWTEST_F(OHHmSymbolRunTest, SetTextBlob006, TestSize.Level1)
{
    Drawing::Font font;
    const char* str1 = "AB";
    auto textblob1 = Drawing::TextBlob::MakeFromText(str1, strlen(str1), font, Drawing::TextEncoding::UTF8);
    HMSymbolTxt symbolTxt;
    std::function<bool(const std::shared_ptr<OHOS::Rosen::TextEngine::SymbolAnimationConfig>&)>
        animationFunc = nullptr;
    HMSymbolRun hmSymbolRun = HMSymbolRun(0, symbolTxt, textblob1, animationFunc);

    //glyphId1:"AB", glyphId2:"A"
    //glyphId1.size() != 1,glyphId2.size() == 1,glyphId1[0] == glyphId2[0]
    const char* str2 = "A";
    auto textblob2 = Drawing::TextBlob::MakeFromText(str2, strlen(str2), font, Drawing::TextEncoding::UTF8);
    hmSymbolRun.currentAnimationHasPlayed_ = true;
    hmSymbolRun.SetTextBlob(textblob2);
    EXPECT_FALSE(hmSymbolRun.currentAnimationHasPlayed_);
}

/*
 * @tc.name: SetTextBlob007
 * @tc.desc: test SetTextBlob with different content(before:"AB",after:"B",Corresponding truth table: 010)
 * @tc.type: FUNC
 */
HWTEST_F(OHHmSymbolRunTest, SetTextBlob007, TestSize.Level1)
{
    Drawing::Font font;
    const char* str1 = "AB";
    auto textblob1 = Drawing::TextBlob::MakeFromText(str1, strlen(str1), font, Drawing::TextEncoding::UTF8);
    HMSymbolTxt symbolTxt;
    std::function<bool(const std::shared_ptr<OHOS::Rosen::TextEngine::SymbolAnimationConfig>&)>
        animationFunc = nullptr;
    HMSymbolRun hmSymbolRun = HMSymbolRun(0, symbolTxt, textblob1, animationFunc);

    //glyphId1:"AB", glyphId2:"B"
    //glyphId1.size() != 1,glyphId2.size() == 1,glyphId1[0] != glyphId2[0]
    const char* str2 = "B";
    auto textblob2 = Drawing::TextBlob::MakeFromText(str2, strlen(str2), font, Drawing::TextEncoding::UTF8);
    hmSymbolRun.currentAnimationHasPlayed_ = true;
    hmSymbolRun.SetTextBlob(textblob2);
    EXPECT_FALSE(hmSymbolRun.currentAnimationHasPlayed_);
}

/*
 * @tc.name: SetTextBlob008
 * @tc.desc: test SetTextBlob with different content(before:"AB",after:"AC",Corresponding truth table: 001)
 * @tc.type: FUNC
 */
HWTEST_F(OHHmSymbolRunTest, SetTextBlob008, TestSize.Level1)
{
    Drawing::Font font;
    const char* str1 = "AB";
    auto textblob1 = Drawing::TextBlob::MakeFromText(str1, strlen(str1), font, Drawing::TextEncoding::UTF8);
    HMSymbolTxt symbolTxt;
    std::function<bool(const std::shared_ptr<OHOS::Rosen::TextEngine::SymbolAnimationConfig>&)>
        animationFunc = nullptr;
    HMSymbolRun hmSymbolRun = HMSymbolRun(0, symbolTxt, textblob1, animationFunc);

    //glyphId1:"AB", glyphId2:"AC"
    //glyphId1.size() != 1,glyphId2.size() != 1,glyphId1[0] == glyphId2[0]
    const char* str2 = "AC";
    auto textblob2 = Drawing::TextBlob::MakeFromText(str2, strlen(str2), font, Drawing::TextEncoding::UTF8);
    hmSymbolRun.currentAnimationHasPlayed_ = true;
    hmSymbolRun.SetTextBlob(textblob2);
    EXPECT_FALSE(hmSymbolRun.currentAnimationHasPlayed_);
}

/*
 * @tc.name: SetTextBlob009
 * @tc.desc: test SetTextBlob with different content(before:"AB",after:"BA",Corresponding truth table: 000)
 * @tc.type: FUNC
 */
HWTEST_F(OHHmSymbolRunTest, SetTextBlob009, TestSize.Level1)
{
    Drawing::Font font;
    const char* str1 = "AB";
    auto textblob1 = Drawing::TextBlob::MakeFromText(str1, strlen(str1), font, Drawing::TextEncoding::UTF8);
    HMSymbolTxt symbolTxt;
    std::function<bool(const std::shared_ptr<OHOS::Rosen::TextEngine::SymbolAnimationConfig>&)>
        animationFunc = nullptr;
    HMSymbolRun hmSymbolRun = HMSymbolRun(0, symbolTxt, textblob1, animationFunc);

    //glyphId1:"AB", glyphId2:"BA"
    //glyphId1.size() != 1,glyphId2.size() != 1,glyphId1[0] != glyphId2[0]
    const char* str2 = "BA";
    auto textblob2 = Drawing::TextBlob::MakeFromText(str2, strlen(str2), font, Drawing::TextEncoding::UTF8);
    hmSymbolRun.currentAnimationHasPlayed_ = true;
    hmSymbolRun.SetTextBlob(textblob2);
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

    std::function<bool(const std::shared_ptr<TextEngine::SymbolAnimationConfig>&)> animationFunc1 =
        [](const std::shared_ptr<TextEngine::SymbolAnimationConfig>& symbolAnimationConfig) {
            return true;
        };
    hmSymbolRun.SetAnimation(animationFunc1);
    EXPECT_NE(hmSymbolRun.animationFunc_, nullptr);
    hmSymbolRun.SetAnimation(animationFunc);
    EXPECT_NE(hmSymbolRun.animationFunc_, nullptr);
}

/*
 * @tc.name: UpdateSymbolLayersGroups001
 * @tc.desc: test UpdateSymbolLayersGroups
 * @tc.type: FUNC
 */
HWTEST_F(OHHmSymbolRunTest, UpdateSymbolLayersGroups001, TestSize.Level1)
{
    HMSymbolTxt symbolTxt;
    symbolTxt.SetSymbolType(SymbolType::SYSTEM);
    std::function<bool(const std::shared_ptr<OHOS::Rosen::TextEngine::SymbolAnimationConfig>&)>
        animationFunc = nullptr;
    std::shared_ptr<RSTextBlob> textBlob = nullptr;
    HMSymbolRun hmSymbolRun = HMSymbolRun(0, symbolTxt, textBlob, animationFunc);
    uint16_t glyphId = 3; // 3 is an existing GlyphID
    hmSymbolRun.UpdateSymbolLayersGroups(glyphId);
    EXPECT_EQ(hmSymbolRun.symbolLayersGroups_.symbolGlyphId, glyphId);

    glyphId = 0; // 0 is a nonexistent GlyphID
    HMSymbolRun hmSymbolRun1 = HMSymbolRun(0, symbolTxt, textBlob, animationFunc);
    hmSymbolRun1.UpdateSymbolLayersGroups(glyphId);
    EXPECT_TRUE(hmSymbolRun1.symbolLayersGroups_.renderModeGroups.empty());

    symbolTxt.SetSymbolType(SymbolType::CUSTOM);
    HMSymbolRun hmSymbolRun2 = HMSymbolRun(0, symbolTxt, textBlob, animationFunc);
    hmSymbolRun2.UpdateSymbolLayersGroups(glyphId);
    EXPECT_TRUE(hmSymbolRun2.symbolLayersGroups_.renderModeGroups.empty());
}

/*
 * @tc.name: SymbolUid001
 * @tc.desc: test GetSymbolUid and GetSymbolUid
 * @tc.type: FUNC
 */
HWTEST_F(OHHmSymbolRunTest, SymbolUid001, TestSize.Level1)
{
    HMSymbolRun hmSymbolRun = HMSymbolRun();
    EXPECT_EQ(hmSymbolRun.GetSymbolUid(), 0);
    hmSymbolRun.SetSymbolUid(100);
    EXPECT_EQ(hmSymbolRun.GetSymbolUid(), 100);
}

/*
 * @tc.name: SymbolTxt001
 * @tc.desc: test GetSymbolTxt and SetSymbolTxt
 * @tc.type: FUNC
 */
HWTEST_F(OHHmSymbolRunTest, SymbolTxt001, TestSize.Level1)
{
    HMSymbolRun hmSymbolRun = HMSymbolRun();

    //test get method
    HMSymbolTxt hmSymbolEmpty;
    HMSymbolTxt hmSymbolTxt = hmSymbolRun.GetSymbolTxt();
    EXPECT_EQ(hmSymbolEmpty, hmSymbolTxt);

    //test set method
    HMSymbolTxt hmSymbolTest;
    hmSymbolTest.SetRenderMode(Drawing::DrawingSymbolRenderingStrategy::MULTIPLE_COLOR);
    hmSymbolRun.SetSymbolTxt(hmSymbolTest);

    EXPECT_EQ(hmSymbolRun.GetSymbolTxt().GetRenderMode(), Drawing::DrawingSymbolRenderingStrategy::MULTIPLE_COLOR);
}

} // namespace SPText
} // namespace Rosen
} // namespace OHOS