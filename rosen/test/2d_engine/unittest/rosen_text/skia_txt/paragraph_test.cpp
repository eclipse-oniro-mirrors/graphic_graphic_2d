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
#include <cstddef>

#include "gtest/gtest.h"
#include "font_collection.h"
#include "modules/skparagraph/src/ParagraphImpl.h"
#include "ohos/init_data.h"
#include "paragraph_builder.h"
#include "paragraph_impl.h"
#include "paragraph_style.h"
#include "text_style.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::Rosen;
using namespace OHOS::Rosen::Drawing;
using namespace OHOS::Rosen::SPText;

namespace txt {
namespace skt = skia::textlayout;
class ParagraphTest : public testing::Test {
public:
    void SetUp() override;
    void TearDown() override;

    static bool AnimationFunc(const std::shared_ptr<TextEngine::SymbolAnimationConfig>& symbolAnimationConfig);
    static skia::textlayout::ParagraphImpl* GetParagraphSkiaImpl(const std::shared_ptr<Paragraph>& paragraph);
    static ParagraphImpl* GetParagraphImpl(const std::shared_ptr<Paragraph>& paragraph);

protected:
    std::shared_ptr<Paragraph> paragraph_;
    int layoutWidth_ = 50;
    std::u16string text_ = u"text";
};

void ParagraphTest::SetUp()
{
    SetHwIcuDirectory();
    ParagraphStyle paragraphStyle;
    std::shared_ptr<FontCollection> fontCollection = std::make_shared<FontCollection>();
    ASSERT_NE(fontCollection, nullptr);
    fontCollection->SetupDefaultFontManager();
    std::shared_ptr<ParagraphBuilder> paragraphBuilder = ParagraphBuilder::Create(paragraphStyle, fontCollection);
    ASSERT_NE(paragraphBuilder, nullptr);
    paragraphBuilder->AddText(text_);
    // 50 just for test
    PlaceholderRun placeholderRun(50, 50, PlaceholderAlignment::BASELINE, SPText::TextBaseline::ALPHABETIC, 0.0);
    paragraphBuilder->AddPlaceholder(placeholderRun);
    paragraph_ = paragraphBuilder->Build();
    ASSERT_NE(paragraph_, nullptr);
    // 50 just for test
    paragraph_->Layout(layoutWidth_);
    paragraph_->MeasureText();
}

void ParagraphTest::TearDown()
{
    paragraph_.reset();
}

ParagraphImpl* ParagraphTest::GetParagraphImpl(const std::shared_ptr<Paragraph>& paragraph)
{
    return static_cast<ParagraphImpl*>(paragraph.get());
}

skia::textlayout::ParagraphImpl* ParagraphTest::GetParagraphSkiaImpl(const std::shared_ptr<Paragraph>& paragraph)
{
    return static_cast<skia::textlayout::ParagraphImpl*>(GetParagraphImpl(paragraph)->paragraph_.get());
}

bool ParagraphTest::AnimationFunc(const std::shared_ptr<TextEngine::SymbolAnimationConfig>& symbolAnimationConfig)
{
    return true;
}

/*
 * @tc.name: ParagraphTest001
 * @tc.desc: test for GetMaxWidth
 * @tc.type: FUNC
 */
HWTEST_F(ParagraphTest, ParagraphTest001, TestSize.Level1)
{
    EXPECT_EQ(paragraph_->GetMaxWidth(), layoutWidth_);
    EXPECT_EQ(paragraph_->GetHeight(), 19);
    EXPECT_EQ(static_cast<int>(paragraph_->GetLongestLine()), 44);
    EXPECT_EQ(static_cast<int>(paragraph_->GetMinIntrinsicWidth()), 50);
    EXPECT_EQ(static_cast<int>(paragraph_->GetMaxIntrinsicWidth()), 78);
    EXPECT_EQ(static_cast<int>(paragraph_->GetAlphabeticBaseline()), 14);
    EXPECT_EQ(static_cast<int>(paragraph_->GetIdeographicBaseline()), 18);
    EXPECT_EQ(paragraph_->GetGlyphsBoundsTop(), -11);
    EXPECT_EQ(paragraph_->GetGlyphsBoundsBottom(), 1);
    EXPECT_EQ(paragraph_->GetGlyphsBoundsLeft(), 0);
    EXPECT_EQ(static_cast<int>(paragraph_->GetGlyphsBoundsRight()), 36);
    EXPECT_TRUE(paragraph_->DidExceedMaxLines());
    EXPECT_EQ(paragraph_->GetLineCount(), 1);
    EXPECT_EQ(paragraph_->GetUnresolvedGlyphsCount(), 0);
    EXPECT_EQ(paragraph_->GetRectsForRange(0, text_.size(), RectHeightStyle::MAX, RectWidthStyle::TIGHT).size(), 1);
    EXPECT_EQ(paragraph_->GetRectsForPlaceholders().size(), 0);
    EXPECT_EQ(paragraph_->GetGlyphPositionAtCoordinate(0.0, 0.0).affinity, OHOS::Rosen::SPText::Affinity::DOWNSTREAM);
    EXPECT_EQ(paragraph_->GetGlyphPositionAtCoordinate(0.0, 0.0).position, 0.0);
    EXPECT_EQ(paragraph_->GetWordBoundary(0).start, 0);
    EXPECT_EQ(paragraph_->GetActualTextRange(0, false).start, 0);
    EXPECT_EQ(paragraph_->GetActualTextRange(-1, false).start, 0);
    EXPECT_EQ(paragraph_->GetActualTextRange(paragraph_->GetLineCount(), false).start, 0);
    EXPECT_EQ(paragraph_->GetActualTextRange(paragraph_->GetLineCount(), false).end, 0);
    EXPECT_EQ(paragraph_->GetLineMetrics().size(), 1);
    EXPECT_EQ(static_cast<int>(paragraph_->GetLongestLineWithIndent()), 44);
}

/*
 * @tc.name: ParagraphTest002
 * @tc.desc: test for SetIndents
 * @tc.type: FUNC
 */
HWTEST_F(ParagraphTest, ParagraphTest002, TestSize.Level1)
{
    // 0.5 just for test
    std::vector<float> indents = { 0.5, 1 };
    paragraph_->SetIndents(indents);
    EXPECT_EQ(paragraph_->DetectIndents(0), 0.5);
    EXPECT_EQ(paragraph_->DetectIndents(indents.size()), 1);
}

/*
 * @tc.name: ParagraphTest003
 * @tc.desc: test for MarkDirty
 * @tc.type: FUNC
 */
HWTEST_F(ParagraphTest, ParagraphTest003, TestSize.Level1)
{
    paragraph_->MarkDirty();
    auto paragraphImpl = GetParagraphSkiaImpl(paragraph_);
    EXPECT_EQ(paragraphImpl->fState, skia::textlayout::kIndexed);
}

/*
 * @tc.name: ParagraphTest004
 * @tc.desc: test for UpdateFontSize
 * @tc.type: FUNC
 */
HWTEST_F(ParagraphTest, ParagraphTest004, TestSize.Level1)
{
    // 2 24.0 just for test
    paragraph_->UpdateFontSize(0, text_.size(), 24.0);
    auto paragraphImpl = GetParagraphSkiaImpl(paragraph_);
    ASSERT_GT(paragraphImpl->fTextStyles.size(), 0);
    EXPECT_EQ(paragraphImpl->fTextStyles.at(0).fStyle.getFontSize(), 24);
}

/*
 * @tc.name: ParagraphTest005
 * @tc.desc: test for Paint
 * @tc.type: FUNC
 */
HWTEST_F(ParagraphTest, ParagraphTest005, TestSize.Level1)
{
    SkCanvas skCanvas;
    // redundancy because it has been checked in setup
    ASSERT_NE(paragraph_, nullptr);
    paragraph_->Paint(&skCanvas, 0.0, 0.0);
    Canvas canvas;
    paragraph_->Paint(&canvas, 0.0, 0.0);
    Path path;
    paragraph_->Paint(&canvas, &path, 0.0, 0.0);
}

/*
 * @tc.name: ParagraphTest006
 * @tc.desc: test for GetLineMetricsAt
 * @tc.type: FUNC
 */
HWTEST_F(ParagraphTest, ParagraphTest006, TestSize.Level1)
{
    skia::textlayout::LineMetrics lineMetrics;
    auto metrics = paragraph_->MeasureText();
    ASSERT_TRUE(paragraph_->GetLineMetricsAt(0, &lineMetrics));
    EXPECT_EQ(lineMetrics.fAscent, -metrics.fAscent);
    EXPECT_EQ(lineMetrics.fDescent, metrics.fDescent);
}

/*
 * @tc.name: ParagraphTest007
 * @tc.desc: test for SetAnimation
 * @tc.type: FUNC
 */
HWTEST_F(ParagraphTest, ParagraphTest007, TestSize.Level1)
{
    std::function<bool(const std::shared_ptr<TextEngine::SymbolAnimationConfig>&)> animationFunc =
        ParagraphTest::AnimationFunc;
    paragraph_->SetAnimation(animationFunc);
    auto paragraphImpl = GetParagraphImpl(paragraph_);
    EXPECT_TRUE(paragraphImpl->animationFunc_(nullptr));
}

/*
 * @tc.name: ParagraphTest008
 * @tc.desc: test for SetParagraghId
 * @tc.type: FUNC
 */
HWTEST_F(ParagraphTest, ParagraphTest008, TestSize.Level1)
{
    paragraph_->SetParagraghId(1);
    auto paragraphImpl = GetParagraphImpl(paragraph_);
    EXPECT_EQ(paragraphImpl->id_, 1);
}

/*
 * @tc.name: ParagraphTest009
 * @tc.desc: test for GetFontMetricsResult
 * @tc.type: FUNC
 */
HWTEST_F(ParagraphTest, ParagraphTest009, TestSize.Level1)
{
    SPText::TextStyle textStyle;
    auto fontMetrics = paragraph_->GetFontMetricsResult(textStyle);
    EXPECT_EQ(static_cast<int>(fontMetrics.fTop), -14);
}

/*
 * @tc.name: ParagraphTest010
 * @tc.desc: test for GetLineFontMetrics
 * @tc.type: FUNC
 */
HWTEST_F(ParagraphTest, ParagraphTest010, TestSize.Level1)
{
    size_t charNumber = 1;
    std::vector<Drawing::FontMetrics> fontMetrics;
    ASSERT_TRUE(paragraph_->GetLineFontMetrics(1, charNumber, fontMetrics));
    ASSERT_GT(fontMetrics.size(), 0);
    auto metrics = paragraph_->MeasureText();
    EXPECT_EQ(metrics.fAscent, fontMetrics.at(0).fAscent);
    EXPECT_EQ(metrics.fDescent, fontMetrics.at(0).fDescent);
}

/*
 * @tc.name: ParagraphTest011
 * @tc.desc: test for CloneSelf
 * @tc.type: FUNC
 */
HWTEST_F(ParagraphTest, ParagraphTest011, TestSize.Level1)
{
    auto paragraphClone = paragraph_->CloneSelf();
    EXPECT_EQ(paragraphClone->GetHeight(), paragraph_->GetHeight());
    EXPECT_EQ(paragraphClone->GetMaxWidth(), paragraph_->GetMaxWidth());
    EXPECT_EQ(paragraphClone->GetMinIntrinsicWidth(), paragraph_->GetMinIntrinsicWidth());
    EXPECT_EQ(paragraphClone->GetGlyphsBoundsBottom(), paragraph_->GetGlyphsBoundsBottom());
    EXPECT_EQ(paragraphClone->GetGlyphsBoundsLeft(), paragraph_->GetGlyphsBoundsLeft());
    EXPECT_EQ(paragraphClone->GetLongestLine(), paragraph_->GetLongestLine());
    EXPECT_EQ(paragraphClone->GetLongestLineWithIndent(), paragraph_->GetLongestLineWithIndent());
}

/*
 * @tc.name: ParagraphTest012
 * @tc.desc: test for SkStyleToTextStyle
 * @tc.type: FUNC
 */
HWTEST_F(ParagraphTest, ParagraphTest012, TestSize.Level1)
{
    skt::TextStyle skStyle;
    skStyle.setBackgroundPaintID(-1);
    skStyle.addShadow(skia::textlayout::TextShadow());
    skStyle.setColor(0xFF0000FF);           // used for testing. Set the color to blue.
    skStyle.setDecorationColor(0xFF000000); // used for testing. Set the color to black.
    skStyle.setDecorationThicknessMultiplier(2.0f);
    skStyle.setFontFamilies({ SkString("sans-serif") });
    skStyle.setFontSize(12.0f);
    skStyle.setHeight(1.5f);
    SPText::TextStyle txt = paragraph_->SkStyleToTextStyle(skStyle);
    EXPECT_EQ(txt.color, skStyle.getColor());
    EXPECT_EQ(txt.decorationColor, skStyle.fDecoration.fColor);
    EXPECT_EQ(txt.decorationThicknessMultiplier, skStyle.fDecoration.fThicknessMultiplier);
    EXPECT_EQ(txt.fontSize, skStyle.getFontSize());
    EXPECT_EQ(txt.height, skStyle.getHeight());
    ASSERT_GT(txt.fontFamilies.size(), 0);
    EXPECT_EQ(txt.fontFamilies.back(), std::string(skStyle.fFontFamilies.back().c_str()));
}

/*
 * @tc.name: ParagraphTest013
 * @tc.desc: test for UpdateColor
 * @tc.type: FUNC
 */
HWTEST_F(ParagraphTest, ParagraphTest013, TestSize.Level1)
{
    RSColor color(255, 0, 0, 255);
    std::u16string text = u"text";
    paragraph_->UpdateColor(0, text.length(), color);
    auto paragraphImpl = GetParagraphImpl(paragraph_);
    for (auto p: paragraphImpl->paints_) {
        EXPECT_EQ(p.color, color);
    }
}

/*
 * @tc.name: ParagraphTest014
 * @tc.desc: test for SkStyleToTextStyle
 * @tc.type: FUNC
 */
HWTEST_F(ParagraphTest, ParagraphTest014, TestSize.Level1)
{
    auto metrics = paragraph_->GetLineMetrics();
    for (auto skLineMetrics : metrics) {
        for (const auto& [index, styleMetrics] : skLineMetrics.fLineMetrics) {
            OHOS::Rosen::SPText::TextStyle spTextStyle = paragraph_->SkStyleToTextStyle(*styleMetrics.text_style);
            EXPECT_EQ(spTextStyle.color, styleMetrics.text_style->fColor);
            EXPECT_EQ(spTextStyle.decorationColor, styleMetrics.text_style->fDecoration.fColor);
        }
    }
}

/*
 * @tc.name: ParagraphTest015
 * @tc.desc: test for text add hyphen
 * @tc.type: FUNC
 */
HWTEST_F(ParagraphTest, ParagraphTest015, TestSize.Level1)
{
    OHOS::Rosen::SPText::TextStyle style;
    style.fontSize = 50;
    ParagraphStyle paragraphStyle;
    paragraphStyle.maxLines = 10;
    paragraphStyle.locale = "en-gb";
    paragraphStyle.wordBreakType = OHOS::Rosen::SPText::WordBreakType::BREAK_HYPHEN;
    std::shared_ptr<FontCollection> fontCollection = std::make_shared<FontCollection>();
    ASSERT_NE(fontCollection, nullptr);
    fontCollection->SetupDefaultFontManager();
    std::shared_ptr<ParagraphBuilder> paragraphBuilder = ParagraphBuilder::Create(paragraphStyle, fontCollection);
    ASSERT_NE(paragraphBuilder, nullptr);
    std::u16string text = u"British English is the official language of the United Kingdom. It has some differences in "
                          u"spelling, pronunciation, and vocabulary compared to American English.";
    paragraphBuilder->PushStyle(style);
    paragraphBuilder->AddText(text);
    std::shared_ptr<Paragraph> paragraph = paragraphBuilder->Build();
    ASSERT_NE(paragraph, nullptr);
    paragraph->Layout(687);
    std::vector<std::unique_ptr<SPText::TextLineBase>> textLines = paragraph->GetTextLines();
    ASSERT_EQ(textLines.size(), 6);
    //expect lines 2,3,4 to have hyphenation breakpoints,
    //and the last charater of each line to have a hyphen glyphid of 800
    size_t breakArr[3] = {2, 3, 4};
    for (std::size_t i = 0; i < 3; i++) {
        ASSERT_NE(textLines.at(breakArr[i]), nullptr);
        std::vector<std::unique_ptr<SPText::Run>> runs = textLines.at(breakArr[i])->GetGlyphRuns();
        ASSERT_NE(runs.back(), nullptr);
        std::vector<uint16_t> glyphs = runs.back()->GetGlyphs();
        EXPECT_EQ(glyphs.back(), 800);
    }
}

/*
 * @tc.name: ParagraphTest016
 * @tc.desc: test for combin follow liga
 * @tc.type: FUNC
 */
HWTEST_F(ParagraphTest, ParagraphTest016, TestSize.Level1)
{
    OHOS::Rosen::SPText::TextStyle style;
    style.fontSize = 30;
    ParagraphStyle paragraphStyle;
    paragraphStyle.spTextStyle = style;
    std::shared_ptr<FontCollection> fontCollection = std::make_shared<FontCollection>();
    ASSERT_NE(fontCollection, nullptr);
    fontCollection->SetupDefaultFontManager();
    std::shared_ptr<ParagraphBuilder> paragraphBuilder = ParagraphBuilder::Create(paragraphStyle, fontCollection);
    ASSERT_NE(paragraphBuilder, nullptr);
    std::u16string text = u"brt゙゙";
    paragraphBuilder->PushStyle(style);
    paragraphBuilder->AddText(text);
    std::shared_ptr<Paragraph> paragraph = paragraphBuilder->Build();
    ASSERT_NE(paragraph, nullptr);
    paragraph->Layout(100);
    std::vector<std::unique_ptr<SPText::TextLineBase>> textLines = paragraph->GetTextLines();
    ASSERT_EQ(textLines.size(), 1);
    std::unique_ptr<SPText::TextLineBase>& textLine = textLines.at(0);
    std::vector<std::unique_ptr<SPText::Run>> runs = textLine->GetGlyphRuns();
    ASSERT_EQ(runs.size(), 2);
    // 'a' will hit HM Sans
    std::vector<uint16_t> glyphs1 = runs.at(0)->GetGlyphs();
    ASSERT_EQ(glyphs1.size(), 1);
    EXPECT_EQ(glyphs1.at(0), 217);
    // 'rt゙゙' will hit cjk
    std::vector<uint16_t> glyphs2 = runs.at(1)->GetGlyphs();
    ASSERT_EQ(glyphs2.size(), 4);
    EXPECT_EQ(glyphs2.at(0), 83);
    EXPECT_EQ(glyphs2.at(1), 85);
    EXPECT_EQ(glyphs2.at(2), 1546);
    EXPECT_EQ(glyphs2.at(3), 1546);
}
} // namespace txt