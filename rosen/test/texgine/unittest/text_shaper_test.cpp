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

#include <gtest/gtest.h>

#include "font_collection.h"
#include "measurer.h"
#include "mock/mock_any_span.h"
#include "mock/mock_measurer.h"
#include "param_test_macros.h"
#include "texgine_exception.h"
#include "texgine/font_providers.h"
#include "texgine_text_blob.h"
#include "texgine_text_blob_builder.h"
#include "texgine/typography_types.h"
#include "text_shaper.h"
#include "typeface.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Rosen {
namespace TextEngine {
struct MockVars {
    std::vector<uint16_t> catchedBufferGlyphs_;
    std::vector<float> catchedBufferPos_;
    std::vector<std::string> catchedGenerateFontCollectionFamilies_;

    std::shared_ptr<TexgineTextBlob> retvalTextBlobBuilderMake_ = nullptr;
    std::shared_ptr<FontCollection> retvalGenerateFontCollection_ =
        std::make_shared<FontCollection>(std::vector<std::shared_ptr<VariantFontStyleSet>>{});
    std::unique_ptr<MockMeasurer> retvalMeasurerCreate_ = std::make_unique<MockMeasurer>();
} tsMockvars;

void InitTsMockVars(struct MockVars &&vars)
{
    tsMockvars = std::move(vars);
}

TexgineTextBlobBuilder::RunBuffer& TexgineTextBlobBuilder::AllocRunPos(const TexgineFont& font, int count)
{
    static TexgineTextBlobBuilder::RunBuffer buffer;
    tsMockvars.catchedBufferGlyphs_.resize(count);
    tsMockvars.catchedBufferPos_.resize(count * 2);
    buffer.glyphs_ = tsMockvars.catchedBufferGlyphs_.data();
    buffer.pos_ = tsMockvars.catchedBufferPos_.data();
    return buffer;
}

std::shared_ptr<TexgineTextBlob> TexgineTextBlobBuilder::Make()
{
    return tsMockvars.retvalTextBlobBuilderMake_;
}

std::shared_ptr<FontCollection> FontProviders::GenerateFontCollection(
    const std::vector<std::string> &families) const noexcept(true)
{
    tsMockvars.catchedGenerateFontCollectionFamilies_ = families;
    return tsMockvars.retvalGenerateFontCollection_;
}

std::unique_ptr<Measurer> Measurer::Create(const std::vector<uint16_t> &text,
    const FontCollection &fontCollection)
{
    return std::move(tsMockvars.retvalMeasurerCreate_);
}

struct TextSpanInfo {
    CharGroups cgs_ = CharGroups::CreateEmpty();
};

class ControllerForTest {
public:
    static std::shared_ptr<TextSpan> GenerateTextSpan(TextSpanInfo info)
    {
        auto ts = std::make_shared<TextSpan>();
        ts->cgs_ = info.cgs_;
        return ts;
    }
};

auto GenerateTextSpan(TextSpanInfo info)
{
    return ControllerForTest::GenerateTextSpan(info);
}

class TextShaperTest : public testing::TestWithParam<std::shared_ptr<TextSpan>> {
public:
    static void SetUpTestCase()
    {
        cgs1_.PushBack({ .glyphs_ = { {1, 1, 0, 0.1, 0.1}, {2, 1, 0, 0.2, 0.2} }, .visibleWidth_ = 2 });
        cgs2_.PushBack({ .glyphs_ = { {1, 1, 0, 0.1, 0.1} }, .visibleWidth_ = 1 });
        cgs2_.PushBack({ .glyphs_ = { {2, 1, 0, 0.2, 0.2} }, .visibleWidth_ = 1 });
    }

    static inline CharGroups cgs1_ = CharGroups::CreateEmpty();
    static inline CharGroups cgs2_ = CharGroups::CreateEmpty();
    static inline std::shared_ptr<TypographyStyle> ysNormal_ = std::make_shared<TypographyStyle>();
    static inline std::shared_ptr<TypographyStyle> ysNoProvider_ = std::make_shared<TypographyStyle>();
};

/**
 * @tc.name: DoShape1
 * @tc.desc: Verify the DoShape
 * @tc.type:FUNC
 */
HWTEST_F(TextShaperTest, DoShape1, TestSize.Level1)
{
    TextShaper shaper;
    auto fp = FontProviders::Create();
    std::shared_ptr<TextSpan> tsNullptr;
    auto tsNormal = TextSpan::MakeFromText("normal");
    ASSERT_EXCEPTION(ExceptionType::InvalidArgument, shaper.DoShape(tsNullptr, {}, {}, fp));
    ASSERT_EXCEPTION(ExceptionType::InvalidArgument, shaper.DoShape(tsNormal, {}, {}, nullptr));
}
} // namespace TextEngine
} // namespace Rosen
} // namespace OHOS
