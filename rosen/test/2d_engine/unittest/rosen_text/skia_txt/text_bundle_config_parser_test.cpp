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

#define private public
#ifndef OHOS_TEXT_ENABLE
#define OHOS_TEXT_ENABLE
#endif
#include "txt/text_bundle_config_parser.h"
#undef private
#include "gtest/gtest.h"
#include "application_info.h"
#include "bundle_info.h"
#include "hap_module_info.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Rosen {
namespace SPText {
class TextBundleConfigParserTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    static inline std::string metaData;
};

void TextBundleConfigParserTest::SetUpTestCase()
{
    metaData = "text_bundle_config_parser_test";
}

void TextBundleConfigParserTest::TearDownTestCase() {}

/*
 * @tc.name: BundleManagerTest001
 * @tc.desc: test for GetAdapterTextHeight
 * @tc.type: FUNC
 */
HWTEST_F(TextBundleConfigParserTest, BundleManagerTest001, TestSize.Level1)
{
    EXPECT_FALSE(TextBundleConfigParser::GetInstance().IsAdapterTextHeightEnabled());
}

#ifdef OHOS_TEXT_ENABLE
/*
 * @tc.name: GetSystemAbilityManagerTest001
 * @tc.desc: test for GetSystemAbilityManager
 * @tc.type: FUNC
 */
HWTEST_F(TextBundleConfigParserTest, GetSystemAbilityManagerTest001, TestSize.Level1)
{
    EXPECT_EQ(TextBundleConfigParser::GetInstance().GetSystemAbilityManager(), nullptr);
}

/*
 * @tc.name: IsMetaDataExistInModuleTest001
 * @tc.desc: test for IsMetaDataExistInModule
 * @tc.type: FUNC
 */
HWTEST_F(TextBundleConfigParserTest, IsMetaDataExistInModuleTest001, TestSize.Level1)
{
    EXPECT_FALSE(TextBundleConfigParser::GetInstance().IsMetaDataExistInModule(metaData));
    EXPECT_FALSE(TextBundleConfigParser::GetInstance().IsMetaDataExistInModule(""));
}

/*
 * @tc.name: IsTargetApiVersionText001
 * @tc.desc: test for IsTargetApiVersion
 * @tc.type: FUNC
 */
HWTEST_F(TextBundleConfigParserTest, IsTargetApiVersionText001, TestSize.Level1)
{
    TextBundleConfigParser::GetInstance().initStatus_ = true;
    TextBundleConfigParser::GetInstance().targetApiVersionResult_ = SINCE_API16_VERSION;
    ASSERT_TRUE(TextBundleConfigParser::GetInstance().IsTargetApiVersion(SINCE_API16_VERSION));
    TextBundleConfigParser::GetInstance().initStatus_ = false;
}
#endif
} // namespace SPText
} // namespace Rosen
} // namespace OHOS