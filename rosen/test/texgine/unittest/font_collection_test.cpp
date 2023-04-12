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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "font_collection.h"
#include "texgine_font_manager.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Rosen {
namespace TextEngine {
struct MockVars {
    int catchedSize_ = -1;
    bool hasRetval_ = false;
    int hasCount_ = 0;
    std::shared_ptr<TexgineFontManager> fontMgr_ = std::make_shared<TexgineFontManager>();
    std::shared_ptr<TexgineTypeface> SCRetvalTypeface_ = std::make_shared<TexgineTypeface>();
    std::shared_ptr<TexgineTypeface> styleRetvalTypeface_ = std::make_shared<TexgineTypeface>();
    std::vector<std::shared_ptr<VariantFontStyleSet>> fontStyleSets_;
    std::shared_ptr<Texgine::FontCollection> fontCollection_;
} fcMockvars;

std::shared_ptr<TexgineFontManager> TexgineFontManager::RefDefault()
{
    return fcMockvars.fontMgr_;
}

std::shared_ptr<TexgineTypeface> TexgineFontManager::MatchFamilyStyleCharacter(const char familyName[],
    TexgineFontStyle &style, const char *bcp47[], int bcp47Count, int32_t character)
{
    fcMockvars.catchedSize_ = bcp47Count;
    return fcMockvars.SCRetvalTypeface_;
}

std::shared_ptr<TexgineTypeface> VariantFontStyleSet::MatchStyle(std::shared_ptr<TexgineFontStyle> pattern)
{
    return fcMockvars.styleRetvalTypeface_;
}

bool Typeface::Has(uint32_t ch)
{
    fcMockvars.hasCount_++;
    return fcMockvars.hasRetval_;
}

std::vector<std::shared_ptr<VariantFontStyleSet>> CreateSets()
{
    std::vector<std::shared_ptr<VariantFontStyleSet>> sets;
    auto tfss = std::make_shared<TexgineFontStyleSet>(nullptr);
    sets.push_back(std::make_shared<VariantFontStyleSet>(tfss));
    return sets;
}

void InitFcMockVars(MockVars vars)
{
    fcMockvars = vars;
    fcMockvars.fontCollection_ = std::make_shared<FontCollection>(std::move(fcMockvars.fontStyleSets_));
}

class FontCollectionTest : public testing::Test {
};

// 过程测试
// 创建FontCollection对象
// 判定不抛出异常
HWTEST_F(FontCollectionTest, FontCollection, TestSize.Level1)
{
    InitFcMockVars({});
    EXPECT_NO_THROW(FontCollection fc(std::move(fcMockvars.fontStyleSets_)));
}

// 过程测试
// 调用GetTypefaceForChar函数，locale为空
// 调用GetTypefaceForChar函数
// 判定bcp47.size为0
// 判定返回值为非空指针, 调用Get返回的typeface与传入的相同
HWTEST_F(FontCollectionTest, GetTypefaceForChar1, TestSize.Level1)
{
    InitFcMockVars({});
    auto tf = fcMockvars.fontCollection_->GetTypefaceForChar('a', {}, "", "");
    EXPECT_NE(tf, nullptr);
    EXPECT_EQ(tf->Get(), fcMockvars.SCRetvalTypeface_);
    EXPECT_EQ(fcMockvars.catchedSize_, 0);
}

// 过程测试
// 控制RefDefault返回nullptr
// 调用GetTypefaceForChar函数
// 判定返回值为空指针
HWTEST_F(FontCollectionTest, GetTypefaceForChar2, TestSize.Level1)
{
    InitFcMockVars({.fontMgr_ = nullptr});
    EXPECT_EQ(fcMockvars.fontCollection_->GetTypefaceForChar('a', {}, "zh_CN", ""), nullptr);
    EXPECT_EQ(fcMockvars.catchedSize_, -1);
}

// 过程测试
// 控制matchFamilyStyleCharacter返回nullptr
// 调用GetTypefaceForChar函数
// 判定返回值为空指针
HWTEST_F(FontCollectionTest, GetTypefaceForChar3, TestSize.Level1)
{
    InitFcMockVars({.SCRetvalTypeface_ = nullptr});
    EXPECT_EQ(fcMockvars.fontCollection_->GetTypefaceForChar('a', {}, "", "zh_CN"), nullptr);
    EXPECT_NE(fcMockvars.catchedSize_, 0);
}

// 过程测试
// 调用两次GetTypefaceForChar函数
// 第一次判定返回非空指针，bcp47.size不为0
// 第二次判定返回非空指针，bcp47.size == -1
// 判定两次得到的typeface相同
HWTEST_F(FontCollectionTest, GetTypefaceForChar4, TestSize.Level1)
{
    InitFcMockVars({});
    auto tf1 = fcMockvars.fontCollection_->GetTypefaceForChar('a', {}, "", "zh_HK");
    EXPECT_NE(tf1, nullptr);
    EXPECT_NE(fcMockvars.catchedSize_, 0);
    InitFcMockVars({});
    auto tf2 = fcMockvars.fontCollection_->GetTypefaceForChar('a', {}, "", "zh_HK");
    EXPECT_NE(tf2, nullptr);
    EXPECT_EQ(fcMockvars.catchedSize_, -1);
    EXPECT_EQ(tf1->Get(), tf2->Get());
}

// 过程测试
// 控制matchStyle函数返回nullptr
// 调用GetTypefaceForChar函数
// 判定返回值为空指针
HWTEST_F(FontCollectionTest, GetTypefaceForChar5, TestSize.Level1)
{
    InitFcMockVars({.fontMgr_ = nullptr, .styleRetvalTypeface_ = nullptr, .fontStyleSets_ = CreateSets()});
    EXPECT_EQ(fcMockvars.fontCollection_->GetTypefaceForChar('a', {}, "", "en_US"), nullptr);
}

// 过程测试
// Has返回false
// 调用GetTypefaceForChar函数
// 判定返回值非空指针
HWTEST_F(FontCollectionTest, GetTypefaceForChar6, TestSize.Level1)
{
    InitFcMockVars({.fontMgr_ = nullptr, .fontStyleSets_ = CreateSets()});
    EXPECT_EQ(fcMockvars.fontCollection_->GetTypefaceForChar('a', {}, "", "en_US"), nullptr);
}

// 过程测试
// 控制Has返回值为true
// 创建对象时传入非空vector
// 调用两次GetTypefaceForChar函数
// 判定返回值为非空指针
// 判定Has调用两次
// 判定两次得到的SkTypeface相同
HWTEST_F(FontCollectionTest, GetTypefaceForChar7, TestSize.Level1)
{
    InitFcMockVars({.hasRetval_ = true, .fontMgr_ = nullptr, .fontStyleSets_ = CreateSets()});
    auto tf1 = fcMockvars.fontCollection_->GetTypefaceForChar('a', {}, "", "locale1");
    auto tf2 = fcMockvars.fontCollection_->GetTypefaceForChar('a', {}, "", "locale1");
    EXPECT_NE(tf1, nullptr);
    EXPECT_NE(tf2, nullptr);
    EXPECT_EQ(fcMockvars.hasCount_, 2);
    EXPECT_EQ(tf1->Get(), tf2->Get());
}
} // namespace TextEngine
} // namespace Rosen
} // namespace OHOS
