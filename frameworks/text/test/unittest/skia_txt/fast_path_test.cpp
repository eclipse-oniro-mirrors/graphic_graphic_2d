/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <limits>
#include <string>
#include <thread>
#include <vector>

#include "font_collection.h"
#include "gtest/gtest.h"
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
namespace {
// Wide enough to lay out a single line of short Chinese text; used for every
// geometry comparison so that both the fast path and the standard path see the
// exact same layout constraints.
constexpr double K_LAYOUT_WIDTH = 2048.0;
// A non-simplified-chinese locale disables the fast path in
// ParagraphImpl::isBlockStyleEligible, forcing the whole paragraph through the
// standard harfbuzz path. For CJK ideographs the glyph advance does not depend
// on the locale, so the reference paragraph is geometrically equivalent to the
// fast-path paragraph except for the shaping path taken.
constexpr const char* K_REFERENCE_LOCALE = "en-US";

std::shared_ptr<FontCollection> CreateFontCollection()
{
    auto fontCollection = std::make_shared<FontCollection>();
    fontCollection->SetupDefaultFontManager();
    return fontCollection;
}

std::shared_ptr<Paragraph> BuildParagraph(const std::shared_ptr<FontCollection>& fontCollection,
    const std::u16string& text, const ParagraphStyle& paragraphStyle, const SPText::TextStyle& textStyle)
{
    std::shared_ptr<ParagraphBuilder> builder = ParagraphBuilder::Create(paragraphStyle, fontCollection);
    if (builder == nullptr) {
        return nullptr;
    }
    builder->PushStyle(textStyle);
    builder->AddText(text);
    builder->Pop();
    return builder->Build();
}

// A paragraph with the default (empty) locale, i.e. the zh-Hans default that the
// adapter applies. Simplified chinese text shaped by this paragraph is eligible
// for the shaping fast path.
std::shared_ptr<Paragraph> BuildFastPathParagraph(const std::shared_ptr<FontCollection>& fontCollection,
    const std::u16string& text, const ParagraphStyle& paragraphStyle = ParagraphStyle(),
    const SPText::TextStyle& textStyle = SPText::TextStyle())
{
    return BuildParagraph(fontCollection, text, paragraphStyle, textStyle);
}

// The reference paragraph carries the same text and styles but a non-simplified
// locale on both the paragraph and the pushed style, so every block fails the
// fast path eligibility check and the text is shaped by harfbuzz only.
std::shared_ptr<Paragraph> BuildStandardPathParagraph(const std::shared_ptr<FontCollection>& fontCollection,
    const std::u16string& text, const ParagraphStyle& paragraphStyle = ParagraphStyle(),
    const SPText::TextStyle& textStyle = SPText::TextStyle())
{
    ParagraphStyle refPara = paragraphStyle;
    refPara.locale = K_REFERENCE_LOCALE;
    SPText::TextStyle refStyle = textStyle;
    refStyle.locale = K_REFERENCE_LOCALE;
    return BuildParagraph(fontCollection, text, refPara, refStyle);
}

// Lays out a paragraph and returns a snapshot of its geometry. The rectangle
// union and the sum of the rect widths are run-segmentation independent, so they
// stay comparable even when the fast path and the standard path group characters
// into a different number of runs.
struct GeometrySnapshot {
    double height = 0.0;
    double longestLine = 0.0;
    double maxIntrinsicWidth = 0.0;
    double minIntrinsicWidth = 0.0;
    double alphabeticBaseline = 0.0;
    double ideographicBaseline = 0.0;
    size_t lineCount = 0;
    int32_t unresolvedGlyphs = 0;
    SkRect rectUnion = SkRect::MakeEmpty();
    double rectWidthSum = 0.0;
};

GeometrySnapshot SnapshotGeometry(const std::shared_ptr<Paragraph>& paragraph, size_t textLength)
{
    GeometrySnapshot snapshot;
    snapshot.height = paragraph->GetHeight();
    snapshot.longestLine = paragraph->GetLongestLine();
    snapshot.maxIntrinsicWidth = paragraph->GetMaxIntrinsicWidth();
    snapshot.minIntrinsicWidth = paragraph->GetMinIntrinsicWidth();
    snapshot.alphabeticBaseline = paragraph->GetAlphabeticBaseline();
    snapshot.ideographicBaseline = paragraph->GetIdeographicBaseline();
    snapshot.lineCount = paragraph->GetLineCount();
    snapshot.unresolvedGlyphs = paragraph->GetUnresolvedGlyphsCount();
    std::vector<TextBox> boxes =
        paragraph->GetRectsForRange(0, textLength, RectHeightStyle::TIGHT, RectWidthStyle::TIGHT);
    for (const TextBox& box : boxes) {
        snapshot.rectUnion.join(box.rect);
        snapshot.rectWidthSum += box.rect.width();
    }
    return snapshot;
}

void ExpectGeometryConsistent(const char* what, const std::shared_ptr<Paragraph>& fast,
    const std::shared_ptr<Paragraph>& standard, const std::u16string& text)
{
    GeometrySnapshot fastSnap = SnapshotGeometry(fast, text.size());
    GeometrySnapshot stdSnap = SnapshotGeometry(standard, text.size());
    EXPECT_EQ(fastSnap.lineCount, stdSnap.lineCount) << what;
    EXPECT_EQ(fastSnap.unresolvedGlyphs, stdSnap.unresolvedGlyphs) << what;
    EXPECT_FLOAT_EQ(static_cast<float>(fastSnap.height), static_cast<float>(stdSnap.height)) << what;
    EXPECT_FLOAT_EQ(static_cast<float>(fastSnap.longestLine), static_cast<float>(stdSnap.longestLine)) << what;
    EXPECT_FLOAT_EQ(static_cast<float>(fastSnap.maxIntrinsicWidth),
        static_cast<float>(stdSnap.maxIntrinsicWidth)) << what;
    EXPECT_FLOAT_EQ(static_cast<float>(fastSnap.minIntrinsicWidth),
        static_cast<float>(stdSnap.minIntrinsicWidth)) << what;
    EXPECT_FLOAT_EQ(static_cast<float>(fastSnap.alphabeticBaseline),
        static_cast<float>(stdSnap.alphabeticBaseline)) << what;
    EXPECT_FLOAT_EQ(static_cast<float>(fastSnap.ideographicBaseline),
        static_cast<float>(stdSnap.ideographicBaseline)) << what;
    EXPECT_FLOAT_EQ(static_cast<float>(fastSnap.rectUnion.fLeft), static_cast<float>(stdSnap.rectUnion.fLeft)) << what;
    EXPECT_FLOAT_EQ(static_cast<float>(fastSnap.rectUnion.fTop), static_cast<float>(stdSnap.rectUnion.fTop)) << what;
    EXPECT_FLOAT_EQ(static_cast<float>(fastSnap.rectUnion.fRight),
        static_cast<float>(stdSnap.rectUnion.fRight)) << what;
    EXPECT_FLOAT_EQ(static_cast<float>(fastSnap.rectUnion.fBottom),
        static_cast<float>(stdSnap.rectUnion.fBottom)) << what;
    // The sum may accumulate the per-glyph floats in a different order when the
    // two paths group the runs differently, so allow a tiny rounding slack.
    EXPECT_NEAR(static_cast<float>(fastSnap.rectWidthSum), static_cast<float>(stdSnap.rectWidthSum), 0.01f) << what;
}

// Element-wise rectangle comparison. Only valid when both paragraphs went
// through the exact same shaping path (e.g. both fell back to the standard
// harfbuzz path), where the run segmentation is identical by construction.
void ExpectSameRects(const char* what, const std::shared_ptr<Paragraph>& first,
    const std::shared_ptr<Paragraph>& second, const std::u16string& text)
{
    std::vector<TextBox> firstBoxes =
        first->GetRectsForRange(0, text.size(), RectHeightStyle::TIGHT, RectWidthStyle::TIGHT);
    std::vector<TextBox> secondBoxes =
        second->GetRectsForRange(0, text.size(), RectHeightStyle::TIGHT, RectWidthStyle::TIGHT);
    ASSERT_EQ(firstBoxes.size(), secondBoxes.size()) << what;
    for (size_t i = 0; i < firstBoxes.size(); ++i) {
        EXPECT_FLOAT_EQ(firstBoxes[i].rect.fLeft, secondBoxes[i].rect.fLeft) << what;
        EXPECT_FLOAT_EQ(firstBoxes[i].rect.fTop, secondBoxes[i].rect.fTop) << what;
        EXPECT_FLOAT_EQ(firstBoxes[i].rect.fRight, secondBoxes[i].rect.fRight) << what;
        EXPECT_FLOAT_EQ(firstBoxes[i].rect.fBottom, secondBoxes[i].rect.fBottom) << what;
    }
}

// Sums the widths of the boxes covering the UTF-16 range [start, end). Used to
// compare the advance of a single run segment (digits, emoji, a bracket, ...)
// between the fast path and the standard path.
double RectRangeWidth(const std::shared_ptr<Paragraph>& paragraph, size_t start, size_t end)
{
    std::vector<TextBox> boxes = paragraph->GetRectsForRange(start, end, RectHeightStyle::TIGHT, RectWidthStyle::TIGHT);
    double width = 0.0;
    for (const TextBox& box : boxes) {
        width += box.rect.width();
    }
    return width;
}

// The rects returned by getRectsForRange must not overlap and must follow each
// other without gaps (single line text, LTR).
void ExpectNonOverlappingContiguous(const std::vector<TextBox>& boxes)
{
    for (size_t i = 1; i < boxes.size(); ++i) {
        EXPECT_LE(boxes[i - 1].rect.fRight,
            boxes[i].rect.fLeft + 0.01f) << "boxes " << (i - 1) << " and " << i << " overlap";
    }
}

skia::textlayout::ParagraphImpl* GetSkiaParagraph(const std::shared_ptr<Paragraph>& paragraph)
{
    return static_cast<skia::textlayout::ParagraphImpl*>(
        static_cast<ParagraphImpl*>(paragraph.get())->paragraph_.get());
}

std::vector<std::string> GetRunFamilyNames(const std::shared_ptr<Paragraph>& paragraph)
{
    std::vector<std::string> names;
    skia::textlayout::ParagraphImpl* impl = GetSkiaParagraph(paragraph);
    if (impl == nullptr) {
        return names;
    }
    for (const auto& run : impl->runs()) {
        std::shared_ptr<Typeface> typeface = run.font().GetTypeface();
        names.push_back(typeface == nullptr ? std::string() : typeface->GetFamilyName());
    }
    return names;
}

void ExpectFontMetricsEqual(const char* what, const Drawing::FontMetrics& first, const Drawing::FontMetrics& second)
{
    EXPECT_FLOAT_EQ(first.fTop, second.fTop) << what;
    EXPECT_FLOAT_EQ(first.fAscent, second.fAscent) << what;
    EXPECT_FLOAT_EQ(first.fDescent, second.fDescent) << what;
    EXPECT_FLOAT_EQ(first.fBottom, second.fBottom) << what;
    EXPECT_FLOAT_EQ(first.fLeading, second.fLeading) << what;
}

// Worker body of the ConcurrentLayout test: runs on the spawned threads, each
// building and laying out its own batch of paragraphs, and records a failure
// if any layout diverges from the baseline snapshot taken by the main thread.
void LayoutAndCheckParagraphBatch(const std::shared_ptr<FontCollection>& fontCollection, const std::u16string& text,
    size_t baselineLineCount, double baselineLongestLine, int32_t baselineUnresolved, int paragraphCount,
    std::atomic<bool>& failed)
{
    for (int i = 0; i < paragraphCount; ++i) {
        auto paragraph = BuildFastPathParagraph(fontCollection, text);
        if (paragraph == nullptr) {
            failed = true;
            return;
        }
        paragraph->Layout(K_LAYOUT_WIDTH);
        if (paragraph->GetLineCount() != baselineLineCount ||
            std::fabs(paragraph->GetLongestLine() - baselineLongestLine) > 0.01f ||
            paragraph->GetUnresolvedGlyphsCount() != baselineUnresolved) {
            failed = true;
        }
    }
}

} // namespace

class FastPathTest : public testing::Test {
public:
    void SetUp() override;
};

void FastPathTest::SetUp()
{
    SetHwIcuDirectory();
}

/*
 * @tc.name: FastPathPureChinese
 * @tc.desc: pure simplified chinese single-style text is laid out by the fast
 *           path and matches the standard path geometry.
 * @tc.type: FUNC
 */
HWTEST_F(FastPathTest, FastPathPureChinese, TestSize.Level0)
{
    const std::u16string text = u"中文排版测试文本";
    auto fontCollection = CreateFontCollection();
    auto fast = BuildFastPathParagraph(fontCollection, text);
    auto standard = BuildStandardPathParagraph(fontCollection, text);
    ASSERT_NE(fast, nullptr);
    ASSERT_NE(standard, nullptr);
    fast->Layout(K_LAYOUT_WIDTH);
    standard->Layout(K_LAYOUT_WIDTH);

    EXPECT_EQ(fast->GetUnresolvedGlyphsCount(), 0);
    ExpectGeometryConsistent("pure chinese", fast, standard, text);
}

/*
 * @tc.name: FastPathChineseWithEmoji
 * @tc.desc: mixed chinese and emoji text; the emoji segment is contiguous with
 *           the chinese segment and keeps the standard path advance.
 * @tc.type: FUNC
 */
HWTEST_F(FastPathTest, FastPathChineseWithEmoji, TestSize.Level0)
{
    // 中, 文, then U+1F600 (a surrogate pair), then 排, 版.
    const std::u16string text = u"中文😀排版";
    const size_t emojiStart = 2;
    const size_t emojiEnd = 4;
    auto fontCollection = CreateFontCollection();
    auto fast = BuildFastPathParagraph(fontCollection, text);
    auto standard = BuildStandardPathParagraph(fontCollection, text);
    ASSERT_NE(fast, nullptr);
    ASSERT_NE(standard, nullptr);
    fast->Layout(K_LAYOUT_WIDTH);
    standard->Layout(K_LAYOUT_WIDTH);

    EXPECT_EQ(fast->GetUnresolvedGlyphsCount(), 0);
    std::vector<TextBox> boxes = fast->GetRectsForRange(0, text.size(), RectHeightStyle::TIGHT, RectWidthStyle::TIGHT);
    ExpectNonOverlappingContiguous(boxes);
    // The emoji glyph must keep exactly the advance the standard path assigns it.
    EXPECT_FLOAT_EQ(static_cast<float>(RectRangeWidth(fast, emojiStart, emojiEnd)),
        static_cast<float>(RectRangeWidth(standard, emojiStart, emojiEnd)));
    ExpectGeometryConsistent("chinese with emoji", fast, standard, text);
}

/*
 * @tc.name: FastPathChineseWithDigits
 * @tc.desc: ASCII digits embedded in chinese text are shaped as their own
 *           segment (kASCIIDigits -> the default system font family) with the
 *           standard advance.
 * @tc.type: FUNC
 */
HWTEST_F(FastPathTest, FastPathChineseWithDigits, TestSize.Level0)
{
    const std::u16string text = u"共 128 项";
    const size_t digitStart = 2;
    const size_t digitEnd = 5;
    auto fontCollection = CreateFontCollection();
    auto fast = BuildFastPathParagraph(fontCollection, text);
    auto standard = BuildStandardPathParagraph(fontCollection, text);
    ASSERT_NE(fast, nullptr);
    ASSERT_NE(standard, nullptr);
    fast->Layout(K_LAYOUT_WIDTH);
    standard->Layout(K_LAYOUT_WIDTH);

    EXPECT_EQ(fast->GetUnresolvedGlyphsCount(), 0);
    EXPECT_FLOAT_EQ(static_cast<float>(RectRangeWidth(fast, digitStart, digitEnd)),
        static_cast<float>(RectRangeWidth(standard, digitStart, digitEnd)));
    ExpectGeometryConsistent("chinese with digits", fast, standard, text);
}

/*
 * @tc.name: FastPathWithNewline
 * @tc.desc: multi-line chinese text breaks at the hard newline and keeps the
 *           standard path line structure. (The latest commit keeps the .notdef
 *           advance of the control character to match harfbuzz, so the newline
 *           width is compared against the standard path instead of a hard zero.)
 * @tc.type: FUNC
 */
HWTEST_F(FastPathTest, FastPathWithNewline, TestSize.Level0)
{
    const std::u16string text = u"第一行中文\n第二行中文";
    auto fontCollection = CreateFontCollection();
    auto fast = BuildFastPathParagraph(fontCollection, text);
    auto standard = BuildStandardPathParagraph(fontCollection, text);
    ASSERT_NE(fast, nullptr);
    ASSERT_NE(standard, nullptr);
    fast->Layout(K_LAYOUT_WIDTH);
    standard->Layout(K_LAYOUT_WIDTH);

    EXPECT_EQ(fast->GetUnresolvedGlyphsCount(), 0);
    EXPECT_EQ(fast->GetLineCount(), 2u);
    ExpectGeometryConsistent("chinese with newline", fast, standard, text);
}

/*
 * @tc.name: FastPathWithSpace
 * @tc.desc: halfwidth spaces join the adjacent chinese segment and keep the
 *           standard total width.
 * @tc.type: FUNC
 */
HWTEST_F(FastPathTest, FastPathWithSpace, TestSize.Level0)
{
    const std::u16string text = u"中文 排版 测试";
    auto fontCollection = CreateFontCollection();
    auto fast = BuildFastPathParagraph(fontCollection, text);
    auto standard = BuildStandardPathParagraph(fontCollection, text);
    ASSERT_NE(fast, nullptr);
    ASSERT_NE(standard, nullptr);
    fast->Layout(K_LAYOUT_WIDTH);
    standard->Layout(K_LAYOUT_WIDTH);

    EXPECT_EQ(fast->GetUnresolvedGlyphsCount(), 0);
    ExpectGeometryConsistent("chinese with spaces", fast, standard, text);
}

/*
 * @tc.name: FastPathCJKExtRanges
 * @tc.desc: CJK Extension A, compatibility ideographs and fullwidth forms are
 *           part of the simplified-chinese fast path class and keep the
 *           standard path advances.
 * @tc.type: FUNC
 */
HWTEST_F(FastPathTest, FastPathCJKExtRanges, TestSize.Level0)
{
    // CJK Extension A endpoints (㐀 U+3400, 䶿 U+4DBF), CJK compatibility
    // ideographs (豈 U+F900 and U+FAD9, the last assigned codepoint of the
    // F900-FAFF block) and a fullwidth form (Ａ U+FF21). U+FAFF is deliberately
    // avoided: it is an unassigned (reserved) codepoint with no glyph in any
    // font, so it would always count as one unresolved glyph.
    const std::u16string text = u"\u3400\u4DBF\uF900\uFAD9\uFF21";
    auto fontCollection = CreateFontCollection();
    auto fast = BuildFastPathParagraph(fontCollection, text);
    auto standard = BuildStandardPathParagraph(fontCollection, text);
    ASSERT_NE(fast, nullptr);
    ASSERT_NE(standard, nullptr);
    fast->Layout(K_LAYOUT_WIDTH);
    standard->Layout(K_LAYOUT_WIDTH);

    EXPECT_EQ(fast->GetUnresolvedGlyphsCount(), 0);
    ExpectGeometryConsistent("cjk extension ranges", fast, standard, text);
}

/*
 * @tc.name: FastPathCustomFamily
 * @tc.desc: a user specified font family is tagged kCustom and shapes the text
 *           with that family, keeping the standard path geometry.
 * @tc.type: FUNC
 */
HWTEST_F(FastPathTest, FastPathCustomFamily, TestSize.Level0)
{
    const std::u16string text = u"中文排版";
    SPText::TextStyle style;
    auto fontCollection = CreateFontCollection();
    auto fast = BuildFastPathParagraph(fontCollection, text, ParagraphStyle(), style);
    auto standard = BuildStandardPathParagraph(fontCollection, text, ParagraphStyle(), style);
    ASSERT_NE(fast, nullptr);
    ASSERT_NE(standard, nullptr);
    fast->Layout(K_LAYOUT_WIDTH);
    standard->Layout(K_LAYOUT_WIDTH);

    EXPECT_EQ(fast->GetUnresolvedGlyphsCount(), 0);
    // The custom family tag shapes with the user-specified family, so the fast
    // path resolves exactly the family the standard path resolves.
    std::vector<std::string> fastFamilies = GetRunFamilyNames(fast);
    std::vector<std::string> standardFamilies = GetRunFamilyNames(standard);
    ASSERT_GE(fastFamilies.size(), 1u);
    EXPECT_EQ(fastFamilies, standardFamilies);
    ExpectGeometryConsistent("custom family", fast, standard, text);
}

/*
 * @tc.name: ConsistencyFastVsStandard
 * @tc.desc: the fast path and the standard path return the same width, height
 *           and rectangles for the same text.
 * @tc.type: FUNC
 */
HWTEST_F(FastPathTest, ConsistencyFastVsStandard, TestSize.Level0)
{
    const std::u16string text = u"快排与标准路径一致性验证";
    auto fontCollection = CreateFontCollection();
    auto fast = BuildFastPathParagraph(fontCollection, text);
    auto standard = BuildStandardPathParagraph(fontCollection, text);
    ASSERT_NE(fast, nullptr);
    ASSERT_NE(standard, nullptr);
    fast->Layout(K_LAYOUT_WIDTH);
    standard->Layout(K_LAYOUT_WIDTH);

    ExpectGeometryConsistent("fast vs standard", fast, standard, text);
}

/*
 * @tc.name: ConsistencyFakeBoldItalic
 * @tc.desc: fake bold and fake italic are applied the same way on both paths.
 * @tc.type: FUNC
 */
HWTEST_F(FastPathTest, ConsistencyFakeBoldItalic, TestSize.Level0)
{
    const std::u16string text = u"中文排版";
    SPText::TextStyle style;
    style.fontWeight = OHOS::Rosen::SPText::FontWeight::W700;
    style.fontStyle = OHOS::Rosen::SPText::FontStyle::ITALIC;
    auto fontCollection = CreateFontCollection();
    auto fast = BuildFastPathParagraph(fontCollection, text, ParagraphStyle(), style);
    auto standard = BuildStandardPathParagraph(fontCollection, text, ParagraphStyle(), style);
    ASSERT_NE(fast, nullptr);
    ASSERT_NE(standard, nullptr);
    fast->Layout(K_LAYOUT_WIDTH);
    standard->Layout(K_LAYOUT_WIDTH);

    EXPECT_EQ(fast->GetUnresolvedGlyphsCount(), 0);
    // The fast path run must carry the same italic skew as the standard path.
    skia::textlayout::ParagraphImpl* fastImpl = GetSkiaParagraph(fast);
    skia::textlayout::ParagraphImpl* stdImpl = GetSkiaParagraph(standard);
    ASSERT_NE(fastImpl, nullptr);
    ASSERT_NE(stdImpl, nullptr);
    EXPECT_GT(fastImpl->runs().size(), 0u);
    EXPECT_GT(stdImpl->runs().size(), 0u);
    EXPECT_FLOAT_EQ(fastImpl->runs()[0].font().GetSkewX(), stdImpl->runs()[0].font().GetSkewX());
    ExpectGeometryConsistent("fake bold italic", fast, standard, text);
}

/*
 * @tc.name: ConsistencyHeightMetrics
 * @tc.desc: heightOverride, halfLeading and baselineShift produce the same line
 *           height and baselines on both paths.
 * @tc.type: FUNC
 */
HWTEST_F(FastPathTest, ConsistencyHeightMetrics, TestSize.Level0)
{
    const std::u16string text = u"中文排版\n第二行";
    SPText::TextStyle style;
    style.heightOverride = true;
    style.height = 2.0;
    style.halfLeading = true;
    style.baseLineShift = 5.0;
    auto fontCollection = CreateFontCollection();
    auto fast = BuildFastPathParagraph(fontCollection, text, ParagraphStyle(), style);
    auto standard = BuildStandardPathParagraph(fontCollection, text, ParagraphStyle(), style);
    ASSERT_NE(fast, nullptr);
    ASSERT_NE(standard, nullptr);
    fast->Layout(K_LAYOUT_WIDTH);
    standard->Layout(K_LAYOUT_WIDTH);

    Drawing::FontMetrics fastMetrics = fast->MeasureText();
    Drawing::FontMetrics stdMetrics = standard->MeasureText();
    ExpectFontMetricsEqual("height metrics", fastMetrics, stdMetrics);
    EXPECT_FLOAT_EQ(static_cast<float>(fast->GetHeight()), static_cast<float>(standard->GetHeight()));
    EXPECT_FLOAT_EQ(
        static_cast<float>(fast->GetAlphabeticBaseline()), static_cast<float>(standard->GetAlphabeticBaseline()));
    EXPECT_FLOAT_EQ(
        static_cast<float>(fast->GetIdeographicBaseline()), static_cast<float>(standard->GetIdeographicBaseline()));
    EXPECT_EQ(fast->GetLineCount(), standard->GetLineCount());
}

/*
 * @tc.name: ConsistencyHinting
 * @tc.desc: both paths honor the paragraph hinting flag and stay consistent for
 *           every hinting configuration.
 * @tc.type: FUNC
 */
HWTEST_F(FastPathTest, ConsistencyHinting, TestSize.Level0)
{
    const std::u16string text = u"中文排版提示";
    auto fontCollection = CreateFontCollection();

    ParagraphStyle hintOn;
    hintOn.hintingIsOn = true;
    auto fastHintOn = BuildFastPathParagraph(fontCollection, text, hintOn);
    auto standardHintOn = BuildStandardPathParagraph(fontCollection, text, hintOn);
    ASSERT_NE(fastHintOn, nullptr);
    ASSERT_NE(standardHintOn, nullptr);
    fastHintOn->Layout(K_LAYOUT_WIDTH);
    standardHintOn->Layout(K_LAYOUT_WIDTH);
    ExpectGeometryConsistent("hinting on", fastHintOn, standardHintOn, text);

    ParagraphStyle hintOff;
    hintOff.hintingIsOn = false;
    auto fastHintOff = BuildFastPathParagraph(fontCollection, text, hintOff);
    auto standardHintOff = BuildStandardPathParagraph(fontCollection, text, hintOff);
    ASSERT_NE(fastHintOff, nullptr);
    ASSERT_NE(standardHintOff, nullptr);
    fastHintOff->Layout(K_LAYOUT_WIDTH);
    standardHintOff->Layout(K_LAYOUT_WIDTH);
    ExpectGeometryConsistent("hinting off", fastHintOff, standardHintOff, text);
}

/*
 * @tc.name: FallbackOpeningBracket
 * @tc.desc: CJK opening brackets are excluded from the fast path; the whole
 *           paragraph falls back to the standard path and the bracket keeps its
 *           fullwidth advance.
 * @tc.type: FUNC
 */
HWTEST_F(FastPathTest, FallbackOpeningBracket, TestSize.Level0)
{
    // 《 (index 0) and （ (index 4) are both in the excluded opening bracket list.
    const std::u16string text = u"《中文》（测试）";
    auto fontCollection = CreateFontCollection();
    auto fast = BuildFastPathParagraph(fontCollection, text);
    auto standard = BuildStandardPathParagraph(fontCollection, text);
    ASSERT_NE(fast, nullptr);
    ASSERT_NE(standard, nullptr);
    fast->Layout(K_LAYOUT_WIDTH);
    standard->Layout(K_LAYOUT_WIDTH);

    // Both excluded brackets must keep a fullwidth step (about one em).
    EXPECT_GT(RectRangeWidth(fast, 0, 1), 12.0);
    EXPECT_GT(RectRangeWidth(fast, 4, 5), 12.0);
    ExpectGeometryConsistent("opening bracket", fast, standard, text);
    ExpectSameRects("opening bracket", fast, standard, text);
}

/*
 * @tc.name: FallbackLatinLetter
 * @tc.desc: Latin letters and halfwidth punctuation are not in the fast path
 *           whitelist; the paragraph falls back to the standard path.
 * @tc.type: FUNC
 */
HWTEST_F(FastPathTest, FallbackLatinLetter, TestSize.Level0)
{
    const std::u16string text = u"中文abc排版";
    auto fontCollection = CreateFontCollection();
    auto fast = BuildFastPathParagraph(fontCollection, text);
    auto standard = BuildStandardPathParagraph(fontCollection, text);
    ASSERT_NE(fast, nullptr);
    ASSERT_NE(standard, nullptr);
    fast->Layout(K_LAYOUT_WIDTH);
    standard->Layout(K_LAYOUT_WIDTH);

    ExpectGeometryConsistent("latin letter", fast, standard, text);
    ExpectSameRects("latin letter", fast, standard, text);
}

/*
 * @tc.name: FallbackEmojiSequences
 * @tc.desc: combining marks, ZWJ sequences, skin tone modifiers and regional
 *           indicators need complex shaping and fall back to the standard path.
 * @tc.type: FUNC
 */
HWTEST_F(FastPathTest, FallbackEmojiSequences, TestSize.Level0)
{
    auto fontCollection = CreateFontCollection();
    const std::u16string texts[] = {
        u"中\u0301文",      // combining acute accent
        u"👨\u200D👩\u200D👧", // ZWJ family sequence
        u"👍🏽",              // skin tone modifier
        u"🇨🇳",              // regional indicator flag
    };
    for (const std::u16string& text : texts) {
        auto fast = BuildFastPathParagraph(fontCollection, text);
        auto standard = BuildStandardPathParagraph(fontCollection, text);
        ASSERT_NE(fast, nullptr);
        ASSERT_NE(standard, nullptr);
        fast->Layout(K_LAYOUT_WIDTH);
        standard->Layout(K_LAYOUT_WIDTH);

        ExpectGeometryConsistent("emoji sequence", fast, standard, text);
        ExpectSameRects("emoji sequence", fast, standard, text);
    }
}

/*
 * @tc.name: FallbackRTL
 * @tc.desc: RTL text has an odd bidi level and falls back to the standard path.
 * @tc.type: FUNC
 */
HWTEST_F(FastPathTest, FallbackRTL, TestSize.Level0)
{
    const std::u16string text = u"مرحبا بالعالم";
    auto fontCollection = CreateFontCollection();
    auto fast = BuildFastPathParagraph(fontCollection, text);
    auto standard = BuildStandardPathParagraph(fontCollection, text);
    ASSERT_NE(fast, nullptr);
    ASSERT_NE(standard, nullptr);
    fast->Layout(K_LAYOUT_WIDTH);
    standard->Layout(K_LAYOUT_WIDTH);

    ExpectGeometryConsistent("rtl", fast, standard, text);
    ExpectSameRects("rtl", fast, standard, text);
}

/*
 * @tc.name: FallbackMultiBidi
 * @tc.desc: text with more than one bidi region falls back to the standard path.
 * @tc.type: FUNC
 */
HWTEST_F(FastPathTest, FallbackMultiBidi, TestSize.Level0)
{
    const std::u16string text = u"中文 مرحبا English 排版";
    auto fontCollection = CreateFontCollection();
    auto fast = BuildFastPathParagraph(fontCollection, text);
    auto standard = BuildStandardPathParagraph(fontCollection, text);
    ASSERT_NE(fast, nullptr);
    ASSERT_NE(standard, nullptr);
    fast->Layout(K_LAYOUT_WIDTH);
    standard->Layout(K_LAYOUT_WIDTH);

    EXPECT_GE(fast->GetLineCount(), 1u);
    ExpectGeometryConsistent("multi bidi", fast, standard, text);
    ExpectSameRects("multi bidi", fast, standard, text);
}

/*
 * @tc.name: FallbackHantLocale
 * @tc.desc: a traditional-chinese locale disables the fast path and falls back
 *           to the standard path.
 * @tc.type: FUNC
 */
HWTEST_F(FastPathTest, FallbackHantLocale, TestSize.Level0)
{
    const std::u16string text = u"中文排版";
    ParagraphStyle paragraphStyle;
    paragraphStyle.locale = "zh-Hant-TW";
    SPText::TextStyle style;
    style.locale = "zh-Hant-TW";
    auto fontCollection = CreateFontCollection();
    auto fast = BuildFastPathParagraph(fontCollection, text, paragraphStyle, style);
    auto standard = BuildStandardPathParagraph(fontCollection, text, paragraphStyle, style);
    ASSERT_NE(fast, nullptr);
    ASSERT_NE(standard, nullptr);
    fast->Layout(K_LAYOUT_WIDTH);
    standard->Layout(K_LAYOUT_WIDTH);

    ExpectGeometryConsistent("hant locale", fast, standard, text);
    ExpectSameRects("hant locale", fast, standard, text);
}

/*
 * @tc.name: FallbackLetterSpacing
 * @tc.desc: non-zero letter spacing disables the fast path.
 * @tc.type: FUNC
 */
HWTEST_F(FastPathTest, FallbackLetterSpacing, TestSize.Level0)
{
    const std::u16string text = u"中文排版";
    SPText::TextStyle style;
    style.letterSpacing = 2.0;
    auto fontCollection = CreateFontCollection();
    auto fast = BuildFastPathParagraph(fontCollection, text, ParagraphStyle(), style);
    auto standard = BuildStandardPathParagraph(fontCollection, text, ParagraphStyle(), style);
    ASSERT_NE(fast, nullptr);
    ASSERT_NE(standard, nullptr);
    fast->Layout(K_LAYOUT_WIDTH);
    standard->Layout(K_LAYOUT_WIDTH);

    ExpectGeometryConsistent("letter spacing", fast, standard, text);
    ExpectSameRects("letter spacing", fast, standard, text);
}

/*
 * @tc.name: FallbackWordSpacing
 * @tc.desc: non-zero word spacing disables the fast path.
 * @tc.type: FUNC
 */
HWTEST_F(FastPathTest, FallbackWordSpacing, TestSize.Level0)
{
    const std::u16string text = u"中文 排版";
    SPText::TextStyle style;
    style.wordSpacing = 5.0;
    auto fontCollection = CreateFontCollection();
    auto fast = BuildFastPathParagraph(fontCollection, text, ParagraphStyle(), style);
    auto standard = BuildStandardPathParagraph(fontCollection, text, ParagraphStyle(), style);
    ASSERT_NE(fast, nullptr);
    ASSERT_NE(standard, nullptr);
    fast->Layout(K_LAYOUT_WIDTH);
    standard->Layout(K_LAYOUT_WIDTH);

    ExpectGeometryConsistent("word spacing", fast, standard, text);
    ExpectSameRects("word spacing", fast, standard, text);
}

/*
 * @tc.name: FallbackFontFeatures
 * @tc.desc: configured OpenType font features disable the fast path.
 * @tc.type: FUNC
 */
HWTEST_F(FastPathTest, FallbackFontFeatures, TestSize.Level0)
{
    const std::u16string text = u"中文排版";
    SPText::TextStyle style;
    style.fontFeatures.SetFeature("kern", 0);
    auto fontCollection = CreateFontCollection();
    auto fast = BuildFastPathParagraph(fontCollection, text, ParagraphStyle(), style);
    auto standard = BuildStandardPathParagraph(fontCollection, text, ParagraphStyle(), style);
    ASSERT_NE(fast, nullptr);
    ASSERT_NE(standard, nullptr);
    fast->Layout(K_LAYOUT_WIDTH);
    standard->Layout(K_LAYOUT_WIDTH);

    ExpectGeometryConsistent("font features", fast, standard, text);
    ExpectSameRects("font features", fast, standard, text);
}

/*
 * @tc.name: FallbackPriorityTypeface
 * @tc.desc: a priority typeface (custom symbol support) disables the fast path.
 * @tc.type: FUNC
 */
HWTEST_F(FastPathTest, FallbackPriorityTypeface, TestSize.Level0)
{
    const std::u16string text = u"中文排版";
    std::shared_ptr<Typeface> typeface = Typeface::MakeDefault();
    ASSERT_NE(typeface, nullptr);
    SPText::TextStyle style;
    style.SetFontTypefaces({ typeface });
    auto fontCollection = CreateFontCollection();
    auto fast = BuildFastPathParagraph(fontCollection, text, ParagraphStyle(), style);
    auto standard = BuildStandardPathParagraph(fontCollection, text, ParagraphStyle(), style);
    ASSERT_NE(fast, nullptr);
    ASSERT_NE(standard, nullptr);
    fast->Layout(K_LAYOUT_WIDTH);
    standard->Layout(K_LAYOUT_WIDTH);

    ExpectGeometryConsistent("priority typeface", fast, standard, text);
    ExpectSameRects("priority typeface", fast, standard, text);
}

/*
 * @tc.name: CustomFontExactMatch
 * @tc.desc: a font family that is not exactly the built-in simplified-chinese
 *           family name or "Sans-serif" is classified as a custom font (kCustom)
 *           and shaped with that family.
 * @tc.type: FUNC
 */
HWTEST_F(FastPathTest, CustomFontExactMatch, TestSize.Level0)
{
    const std::u16string text = u"中文排版";
    SPText::TextStyle style;
    // The requested family is the built-in simplified-chinese family name
    // without the SC suffix, so the exact-match rule (commit 9e885cc1cb) must
    // treat it as a custom family.
    auto fontCollection = CreateFontCollection();
    auto fast = BuildFastPathParagraph(fontCollection, text, ParagraphStyle(), style);
    auto standard = BuildStandardPathParagraph(fontCollection, text, ParagraphStyle(), style);
    ASSERT_NE(fast, nullptr);
    ASSERT_NE(standard, nullptr);
    fast->Layout(K_LAYOUT_WIDTH);
    standard->Layout(K_LAYOUT_WIDTH);

    EXPECT_EQ(fast->GetUnresolvedGlyphsCount(), 0);
    // kCustom shapes with the exact requested family, matching the standard
    // path; had it been tagged kSimplifiedChinese it would have used the SC
    // family instead and the resolved families would diverge.
    std::vector<std::string> fastFamilies = GetRunFamilyNames(fast);
    std::vector<std::string> standardFamilies = GetRunFamilyNames(standard);
    ASSERT_GE(fastFamilies.size(), 1u);
    EXPECT_EQ(fastFamilies, standardFamilies);
    ExpectGeometryConsistent("custom font exact match", fast, standard, text);
}

/*
 * @tc.name: FallbackUnresolvedGlyph
 * @tc.desc: text whose glyphs are not resolved by the fast path fonts falls
 *           back to the standard path without leaving unresolved glyph residue.
 * @tc.type: FUNC
 */
HWTEST_F(FastPathTest, FallbackUnresolvedGlyph, TestSize.Level0)
{
    // U+E000 is outside every fast path whitelist range, forcing the standard
    // path for the whole paragraph.
    const std::u16string text = u"中文\uE000";
    auto fontCollection = CreateFontCollection();
    auto fast = BuildFastPathParagraph(fontCollection, text);
    auto standard = BuildStandardPathParagraph(fontCollection, text);
    ASSERT_NE(fast, nullptr);
    ASSERT_NE(standard, nullptr);
    fast->Layout(K_LAYOUT_WIDTH);
    standard->Layout(K_LAYOUT_WIDTH);

    // The rollback must leave no fast-path residue: the paragraph reports
    // exactly the standard path's unresolved glyph count.
    EXPECT_EQ(fast->GetUnresolvedGlyphsCount(), standard->GetUnresolvedGlyphsCount());
    ExpectGeometryConsistent("unresolved glyph", fast, standard, text);
    ExpectSameRects("unresolved glyph", fast, standard, text);
}

/*
 * @tc.name: FallbackRollbackClean
 * @tc.desc: a paragraph whose tail contains an ineligible character is
 *           re-shaped entirely by the standard path; no fast path run or
 *           duplicate rectangle is left behind.
 * @tc.type: FUNC
 */
HWTEST_F(FastPathTest, FallbackRollbackClean, TestSize.Level0)
{
    // The first five characters are fast-path eligible, the trailing 'A' is not.
    const std::u16string text = u"中文排版测试A";
    auto fontCollection = CreateFontCollection();
    auto fast = BuildFastPathParagraph(fontCollection, text);
    auto standard = BuildStandardPathParagraph(fontCollection, text);
    ASSERT_NE(fast, nullptr);
    ASSERT_NE(standard, nullptr);
    fast->Layout(K_LAYOUT_WIDTH);
    standard->Layout(K_LAYOUT_WIDTH);

    std::vector<TextBox> boxes = fast->GetRectsForRange(0, text.size(), RectHeightStyle::TIGHT, RectWidthStyle::TIGHT);
    for (const TextBox& box : boxes) {
        EXPECT_LT(box.rect.fLeft, box.rect.fRight) << "zero or negative width rectangle";
    }
    ExpectNonOverlappingContiguous(boxes);
    // Both paragraphs went through the standard path, so the rectangles must be
    // identical one by one.
    ExpectSameRects("rollback clean", fast, standard, text);
}

/*
 * @tc.name: ConcurrentLayout
 * @tc.desc: concurrent build + layout of different paragraph objects is free of
 *           data races and yields stable, reproducible results.
 * @tc.type: FUNC
 */
HWTEST_F(FastPathTest, ConcurrentLayout, TestSize.Level0)
{
    constexpr int kThreadCount = 8;
    constexpr int kParagraphsPerThread = 5;
    const std::u16string text = u"中文并发排版测试0123456789";
    auto fontCollection = CreateFontCollection();

    auto fast = BuildFastPathParagraph(fontCollection, text);
    ASSERT_NE(fast, nullptr);
    fast->Layout(K_LAYOUT_WIDTH);
    size_t baselineLineCount = fast->GetLineCount();
    double baselineLongestLine = fast->GetLongestLine();
    int32_t baselineUnresolved = fast->GetUnresolvedGlyphsCount();

    std::atomic<bool> failed { false };
    std::vector<std::thread> threads;
    for (int t = 0; t < kThreadCount; ++t) {
        threads.emplace_back(
            [&fontCollection, &text, &baselineLineCount, &baselineLongestLine, &baselineUnresolved, &failed]() {
                LayoutAndCheckParagraphBatch(fontCollection, text, baselineLineCount, baselineLongestLine,
                    baselineUnresolved, kParagraphsPerThread, failed);
            });
    }
    for (std::thread& thread : threads) {
        thread.join();
    }
    EXPECT_FALSE(failed);
}

/*
 * @tc.name: MetricsWithoutCompression
 * @tc.desc: fonts without a compression config (fontScale == 0) keep their
 *           line height and ascent/descent identical to the standard path.
 * @tc.type: FUNC
 */
HWTEST_F(FastPathTest, MetricsWithoutCompression, TestSize.Level0)
{
    // The default simplified-chinese font family is not listed in
    // FONT_FAMILY_COMPRESSION_CONFIG, so its ScaleParam.fontScale is 0 and the
    // un-compressed metrics branch is taken.
    const std::u16string text = u"中文排版";
    auto fontCollection = CreateFontCollection();
    auto fast = BuildFastPathParagraph(fontCollection, text);
    auto standard = BuildStandardPathParagraph(fontCollection, text);
    ASSERT_NE(fast, nullptr);
    ASSERT_NE(standard, nullptr);
    fast->Layout(K_LAYOUT_WIDTH);
    standard->Layout(K_LAYOUT_WIDTH);

    Drawing::FontMetrics fastMetrics = fast->MeasureText();
    Drawing::FontMetrics stdMetrics = standard->MeasureText();
    ExpectFontMetricsEqual("metrics without compression", fastMetrics, stdMetrics);
    EXPECT_FLOAT_EQ(static_cast<float>(fast->GetHeight()), static_cast<float>(standard->GetHeight()));
    EXPECT_FLOAT_EQ(
        static_cast<float>(fast->GetAlphabeticBaseline()), static_cast<float>(standard->GetAlphabeticBaseline()));
    EXPECT_FLOAT_EQ(
        static_cast<float>(fast->GetIdeographicBaseline()), static_cast<float>(standard->GetIdeographicBaseline()));
}
} // namespace txt
