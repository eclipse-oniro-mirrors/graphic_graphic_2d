/*
 * Copyright (c) 2025-2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, Hardware
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "gtest/gtest.h"

#include "text/font.h"
#include "text/text_blob.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Rosen {
namespace Drawing {
class FontTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void FontTest::SetUpTestCase() {}
void FontTest::TearDownTestCase() {}
void FontTest::SetUp() {}
void FontTest::TearDown() {}

/**
 * @tc.name: FontMeasureTextWithBrushOrPenTest001
 * @tc.desc: 
 * @tc.type: FUNC
 * @tc.require:AR20250515745872
 * @tc.author:
 */
HWTEST_F(FontTest, FontMeasureTextWithBrushOrPenTest001, TestSize.Level1)
{
    Font font;
    std::shared_ptr<OHOS::Rosen::Drawing::Typeface> zhCnTypeface = Drawing::Typeface::MakeDefault();
    font.SetTypeface(zhCnTypeface);
    Brush brush;
    Pen pen;
    const char* text = "你好世界";
    auto textWidth = font.MeasureText(text, strlen(text), TextEncoding::UTF8, nullptr, &brush, &pen);
    EXPECT_EQ((int)textWidth, 0);
}

/**
 * @tc.name: FontGetWidthsBoundsTest001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:AR20250515745872
 * @tc.author:
 */
HWTEST_F(FontTest, FontGetWidthsBoundsTest001, TestSize.Level1)
{
    Font font;
    std::shared_ptr<OHOS::Rosen::Drawing::Typeface> zhCnTypeface = Drawing::Typeface::MakeDefault();
    font.SetTypeface(zhCnTypeface);
    Brush brush;
    Pen pen;
    float widths[50] = {0.0f};
    Rect* bounds = new Rect[50];
    font.GetWidthsBounds(nullptr, 0, widths, bounds, &brush, &pen);
    EXPECT_EQ((int)widths[0], 0);
    ASSERT_NE(bounds, nullptr);
    if (bounds != nullptr) {
        delete [] bounds;
        bounds = nullptr;
    }
}

/**
 * @tc.name: FontGetPosTest001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:AR20250515745872
 * @tc.author:
 */
HWTEST_F(FontTest, FontGetPosTest001, TestSize.Level1)
{
    Font font;
    std::shared_ptr<OHOS::Rosen::Drawing::Typeface> zhCnTypeface = Drawing::Typeface::MakeDefault();
    font.SetTypeface(zhCnTypeface);
    uint16_t glyphs[] = { 0, 0 };
    Point points[] = { {0, 0}, {0, 0} };
    font.GetPos(glyphs, 2, points, {10, 10}); // 2:count
    ASSERT_NE((int)points[0].GetX(), 0);
    ASSERT_NE((int)points[0].GetY(), 0);
}

/**
 * @tc.name: FontGetSpacingTest001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:AR20250515745872
 * @tc.author:
 */
HWTEST_F(FontTest, FontGetSpacingTest001, TestSize.Level1)
{
    Font font;
    std::shared_ptr<OHOS::Rosen::Drawing::Typeface> zhCnTypeface = Drawing::Typeface::MakeDefault();
    font.SetTypeface(zhCnTypeface);
    auto spacing = font.GetSpacing();
    ASSERT_NE((int)spacing, 0);
}

/**
 * @tc.name: FontUnicharToGlyphWithFeatures001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:ICG6L3
 * @tc.author:
 */
HWTEST_F(FontTest, FontUnicharToGlyphWithFeatures001, TestSize.Level1)
{
    Font font;
    const char* str = "a";
    const char* strEmpty = "";
    std::shared_ptr<Drawing::DrawingFontFeatures> features = std::make_shared<Drawing::DrawingFontFeatures>();
    uint16_t glyph = font.UnicharToGlyphWithFeatures(str, nullptr);
    ASSERT_EQ(glyph, 0);
    glyph = font.UnicharToGlyphWithFeatures(strEmpty, features);
    ASSERT_EQ(glyph, 0);
    std::shared_ptr<OHOS::Rosen::Drawing::Typeface> zhCnTypeface = Drawing::Typeface::MakeDefault();
    font.SetTypeface(zhCnTypeface);
    glyph = font.UnicharToGlyphWithFeatures(strEmpty, features);
    ASSERT_EQ(glyph, 0);
}

/**
 * @tc.name: MeasureSingleCharacterWithFeatures001
 * @tc.desc:
 * @tc.type: FUNC
 * @tc.require:ICG6L3
 * @tc.author:
 */
HWTEST_F(FontTest, MeasureSingleCharacterWithFeatures001, TestSize.Level1)
{
    Font font;
    const char* str = "a";
    float width = font.MeasureSingleCharacterWithFeatures(str, 0, nullptr);
    ASSERT_NE(width, 0);
    const char* strNoFallback = "\uE000";
    uint32_t unicodeNoFallback = 0xE000;
    width = font.MeasureSingleCharacterWithFeatures(strNoFallback, unicodeNoFallback, nullptr);
    ASSERT_EQ(width, 0);
}
} // namespace Drawing
} // namespace Rosen
} // namespace OHOS
