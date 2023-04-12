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

#include "param_test_macros.h"
#include "texgine_data.h"
#include "texgine_font_manager.h"
#include "texgine_stream.h"
#include "texgine/system_font_provider.h"
#include "texgine_typeface.h"
#include "variant_font_style_set.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Rosen {
namespace TextEngine {
struct MockVars {
    std::shared_ptr<TexgineFontStyleSet> fontStyleSet_ = TexgineFontStyleSet::CreateEmpty();
    std::shared_ptr<TexgineFontManager> fontMgr_ = std::make_shared<TexgineFontManager>();
} sfpMockvars;

void InitSfpMockVars(MockVars vars)
{
    sfpMockvars = std::move(vars);
}

std::shared_ptr<TexgineFontManager> TexgineFontManager::RefDefault()
{
    return sfpMockvars.fontMgr_;
}

std::shared_ptr<TexgineFontStyleSet> TexgineFontManager::MatchFamily(const char familyName[])
{
    return sfpMockvars.fontStyleSet_;
}

class SystemFontProviderTest : public testing::Test {
public:
    std::shared_ptr<SystemFontProvider> systemFontProvider = SystemFontProvider::GetInstance();
};

// 过程测试
// 调用GetInstance函数
// 判定返回值为非空指针
HWTEST_F(SystemFontProviderTest, GetInstance, TestSize.Level1)
{
    EXPECT_NE(SystemFontProvider::GetInstance(), nullptr);
}

// 异常测试
// 控制RefDefault函数返回空指针
// 调用MatchFamily函数
// 判定返回空指针
HWTEST_F(SystemFontProviderTest, MatchFamily1, TestSize.Level1)
{
    InitSfpMockVars({.fontMgr_ = nullptr});
    auto fss = systemFontProvider->MatchFamily("");
    EXPECT_EQ(fss, nullptr);
}

// 异常测试
// 控制MatchFamily函数返回空指针
// 调用MatchFamily函数
// 调用Get方法
// 判定返回空指针
HWTEST_F(SystemFontProviderTest, MatchFamily2, TestSize.Level1)
{
    InitSfpMockVars({.fontStyleSet_ = nullptr});
    auto fss = systemFontProvider->MatchFamily("");
    EXPECT_EQ(fss->TryToTexgineFontStyleSet(), nullptr);
}

// 逻辑测试
// 调用MatchFamily函数
// 判定返回非空指针
// 调用Get方法
// 判定返回非空指针
HWTEST_F(SystemFontProviderTest, MatchFamily3, TestSize.Level1)
{
    InitSfpMockVars({});
    auto fss = systemFontProvider->MatchFamily("");
    EXPECT_NE(fss, nullptr);
    EXPECT_NE(fss->TryToTexgineFontStyleSet()->Get(), nullptr);
}
} // namespace TextEngine
} // namespace Rosen
} // namespace OHOS
