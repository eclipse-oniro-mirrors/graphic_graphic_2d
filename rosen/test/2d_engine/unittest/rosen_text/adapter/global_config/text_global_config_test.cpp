/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "text_global_config.h"
#include "text/text_blob.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::Rosen::Drawing;
namespace OHOS::Rosen {
class TextGlobalConfigTest : public testing::Test {};

static uint32_t GetTextHighContrast()
{
    auto& instance = ProcessTextConstrast::Instance();
    return static_cast<uint32_t>(instance.GetTextContrast());
}

/*
 * @tc.name: TextGighContrastTest01
 * @tc.desc: test for text high contrast mode
 * @tc.type: FUNC
 */
HWTEST_F(TextGlobalConfigTest, TextGighContrastTest01, TestSize.Level1)
{
    auto result = TextGlobalConfig::SetTextHighContrast(TEXT_FOLLOW_SYSTEM_HIGH_CONTRAST);
    EXPECT_EQ(result, TEXT_SUCCESS);
    EXPECT_EQ(GetTextHighContrast(), TEXT_FOLLOW_SYSTEM_HIGH_CONTRAST);

    result = TextGlobalConfig::SetTextHighContrast(TEXT_APP_DISABLE_HIGH_CONTRAST);
    EXPECT_EQ(result, TEXT_SUCCESS);
    EXPECT_EQ(GetTextHighContrast(), TEXT_APP_DISABLE_HIGH_CONTRAST);

    result = TextGlobalConfig::SetTextHighContrast(TEXT_APP_ENABLE_HIGH_CONTRAST);
    EXPECT_EQ(result, TEXT_SUCCESS);
    EXPECT_EQ(GetTextHighContrast(), TEXT_APP_ENABLE_HIGH_CONTRAST);
}

/*
 * @tc.name: TextGighContrastTest02
 * @tc.desc: test for text high contrast mode（Invalid）
 * @tc.type: FUNC
 */
HWTEST_F(TextGlobalConfigTest, TextGighContrastTest02, TestSize.Level1)
{
    uint32_t preValue = GetTextHighContrast();
    auto result = TextGlobalConfig::SetTextHighContrast(TEXT_HIGH_CONTRAST_BUTT);
    EXPECT_EQ(result, TEXT_ERR_PARA_INVALID);
    EXPECT_EQ(GetTextHighContrast(), preValue);
}

} // namespace OHOS::Rosen