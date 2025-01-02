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
#include <test_header.h>

#include "xml_parser.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Rosen {
class HgmXmlParserTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    static constexpr char CONFIG[] = "/sys_prod/etc/graphic/hgm_policy_config.xml";
};

void HgmXmlParserTest::SetUpTestCase() {}
void HgmXmlParserTest::TearDownTestCase() {}
void HgmXmlParserTest::SetUp() {}
void HgmXmlParserTest::TearDown() {}

/**
 * @tc.name: LoadConfiguration
 * @tc.desc: Verify the result of LoadConfiguration function
 * @tc.type: FUNC
 * @tc.require: I7DMS1
 */
HWTEST_F(HgmXmlParserTest, LoadConfiguration, Function | SmallTest | Level1)
{
    std::unique_ptr<XMLParser> parser = std::make_unique<XMLParser>();

    PART("CaseDescription") {
        STEP("1. get an xml parser") {
            STEP_ASSERT_NE(parser, nullptr);
        }
        STEP("2. check the result of configuration") {
            int32_t load = parser->LoadConfiguration(CONFIG);
            STEP_ASSERT_GE(load, 0);
        }
    }
}

/**
 * @tc.name: Parse
 * @tc.desc: Verify the result of parsing functions
 * @tc.type: FUNC
 * @tc.require: I7DMS1
 */
HWTEST_F(HgmXmlParserTest, Parse, Function | SmallTest | Level1)
{
    std::unique_ptr<XMLParser> parser = std::make_unique<XMLParser>();
    parser->LoadConfiguration(CONFIG);
    parser->Parse();
    parser->GetParsedData();
}

/**
 * @tc.name: StringToVector001
 * @tc.desc: Verify the result of StringToVector001 functions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HgmXmlParserTest, StringToVector001, Function | SmallTest | Level1)
{
    std::unique_ptr<XMLParser> parser = std::make_unique<XMLParser>();
    std::string emptyInput = "";
    std::vector<uint32_t> result = parser->StringToVector(emptyInput);
    EXPECT_TRUE(result.empty());
}

/**
 * @tc.name: StringToVector002
 * @tc.desc: Verify the result of StringToVector002 functions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HgmXmlParserTest, StringToVector002, Function | SmallTest | Level1)
{
    std::unique_ptr<XMLParser> parser = std::make_unique<XMLParser>();
    std::string spacesBetweenNumbersInput = "1 2   3  45 ";
    std::vector<uint32_t> expected = {1, 2, 3, 45};
    std::vector<uint32_t> result = parser->StringToVector(spacesBetweenNumbersInput);
    EXPECT_EQ(expected, result);
}

/**
 * @tc.name: StringToVector003
 * @tc.desc: Verify the result of StringToVector003 functions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HgmXmlParserTest, StringToVector003, Function | SmallTest | Level1)
{
    std::unique_ptr<XMLParser> parser = std::make_unique<XMLParser>();
    std::string invalidInput = "abc";
    std::vector<uint32_t> result = parser->StringToVector(invalidInput);
    EXPECT_TRUE(result.empty());
}
} // namespace Rosen
} // namespace OHOS