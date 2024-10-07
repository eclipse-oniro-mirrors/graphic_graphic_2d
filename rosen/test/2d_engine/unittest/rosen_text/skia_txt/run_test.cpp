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
#include "font_collection.h"
#include "paragraph_builder.h"
#include "paragraph_style.h"
#include "run_impl.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::Rosen;
using namespace OHOS::Rosen::Drawing;
using namespace OHOS::Rosen::SPText;

namespace txt {
class RunTest : public testing::Test {
public:
    void SetUp() override;
    void TearDown() override;

private:
    // 50 is the width of the layout, just for test
    int layoutWidth_ = 50;
    // this is the default font family name, just for test
    std::string familyName_ = { 0x48, 0x61, 0x72, 0x6d, 0x6f, 0x6e, 0x79, 0x4f, 0x53, 0x2d, 0x53, 0x61, 0x6e, 0x73 };

    std::shared_ptr<Paragraph> paragraph_;
    std::vector<std::unique_ptr<SPText::Run>> runs_;
};

void RunTest::SetUp()
{
    ParagraphStyle paragraphStyle;
    std::shared_ptr<FontCollection> fontCollection = std::make_shared<FontCollection>();
    ASSERT_NE(fontCollection, nullptr);
    fontCollection->SetupDefaultFontManager();
    std::shared_ptr<ParagraphBuilder> paragraphBuilder = ParagraphBuilder::Create(paragraphStyle, fontCollection);
    ASSERT_NE(paragraphBuilder, nullptr);
    std::u16string text = u"RunTest";
    paragraphBuilder->AddText(text);
    paragraph_ = paragraphBuilder->Build();
    ASSERT_NE(paragraph_, nullptr);
    paragraph_->Layout(layoutWidth_);
    auto textLineBases = paragraph_->GetTextLines();
    runs_ = textLineBases[0]->GetGlyphRuns();
}

void RunTest::TearDown()
{
    paragraph_.reset();
    runs_.clear();
}

/*
 * @tc.name: RunTest001
 * @tc.desc: test for GetFont
 * @tc.type: FUNC
 */
HWTEST_F(RunTest, RunTest001, TestSize.Level1)
{
    EXPECT_EQ(runs_.size(), 1);
    ASSERT_NE(runs_.at(0), nullptr);
    EXPECT_EQ(runs_[0]->GetFont().GetTypeface()->GetFamilyName(), familyName_);
}

/*
 * @tc.name: RunTest002
 * @tc.desc: test for GetGlyphCount
 * @tc.type: FUNC
 */
HWTEST_F(RunTest, RunTest002, TestSize.Level1)
{
    EXPECT_EQ(runs_.size(), 1);
    ASSERT_NE(runs_.at(0), nullptr);
    EXPECT_EQ(runs_[0]->GetGlyphCount(), 7);
}

/*
 * @tc.name: RunTest003
 * @tc.desc: test for GetGlyphs
 * @tc.type: FUNC
 */
HWTEST_F(RunTest, RunTest003, TestSize.Level1)
{
    EXPECT_EQ(runs_.size(), 1);
    ASSERT_NE(runs_.at(0), nullptr);
    auto glyphs = runs_[0]->GetGlyphs();
    EXPECT_NE(glyphs[0], 0);
}

/*
 * @tc.name: RunTest004
 * @tc.desc: test for GetPositions
 * @tc.type: FUNC
 */
HWTEST_F(RunTest, RunTest004, TestSize.Level1)
{
    EXPECT_EQ(runs_.size(), 1);
    ASSERT_NE(runs_.at(0), nullptr);
    EXPECT_EQ(runs_[0]->GetPositions().size(), 7);
    EXPECT_EQ(runs_[0]->GetPositions()[0].GetX(), 0);
}

/*
 * @tc.name: RunTest005
 * @tc.desc: test for GetOffsets
 * @tc.type: FUNC
 */
HWTEST_F(RunTest, RunTest005, TestSize.Level1)
{
    EXPECT_EQ(runs_.size(), 1);
    ASSERT_NE(runs_[0], nullptr);
    EXPECT_EQ(runs_[0]->GetOffsets().size(), 7);
    EXPECT_EQ(runs_[0]->GetOffsets()[0].GetX(), 0);
}

/*
 * @tc.name: RunTest006
 * @tc.desc: test for Paint
 * @tc.type: FUNC
 */
HWTEST_F(RunTest, RunTest006, TestSize.Level1)
{
    EXPECT_EQ(runs_.size(), 1);
    ASSERT_NE(runs_.at(0), nullptr);
    Canvas canvas;
    runs_.at(0)->Paint(&canvas, 0.0, 0.0);
    runs_.at(0)->Paint(nullptr, 0.0, 0.0);
}
} // namespace txt