/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include <regex>
#include "limit_number.h"
#include "parameters.h"

#include "touch_screen/touch_screen.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::Rosen {
class TouchScreenUnitTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;

private:
    bool IsFoldScreen();
    std::vector<std::string> Split(const std::string& str, const std::string& regex_str);
};

void TouchScreenUnitTest::SetUpTestCase() {}
void TouchScreenUnitTest::TearDownTestCase() {}
void TouchScreenUnitTest::SetUp() {}
void TouchScreenUnitTest::TearDown() {}

std::vector<std::string> TouchScreenUnitTest::Split(const std::string& str, const std::string& regex_str)
{
    std::regex regexz(regex_str);
    std::vector<std::string> list(
        std::sregex_token_iterator(str.begin(), str.end(), regexz, -1),
        std::sregex_token_iterator()
    );
    return list;
}

bool TouchScreenUnitTest::IsFoldScreen()
{
    const std::regex foldTypeRegex("^(\\d+)(,\\d+){3,}$");
    const std::string typeProp = "1";
    const std::string screenNums  = "2";
    const std::string delimiter = ",";
    const int foldTypePropSize = 4;
    auto foldTypeProp = system::GetParameter("const.window.foldscreen.type", "0,0,0,0");
    if (!std::regex_match(foldTypeProp, foldTypeRegex)) {
        return false;
    }
    auto foldTypeProps = Split(foldTypeProp, delimiter);
    if (foldTypeProps.size() < foldTypePropSize) {
        return false;
    }
    if (foldTypeProps[0].compare(typeProp) == 0 && foldTypeProps[1].compare(screenNums) == 0) {
        return true;
    }
    return false;
}

/*
 * @tc.name: InitTouchScreen_001
 * @tc.desc: Test InitTouchScreen
 * @tc.type: FUNC
 * @tc.require: issueI5ZK2I
 */
HWTEST_F(TouchScreenUnitTest, InitTouchScreen_001, TestSize.Level1)
{
    ASSERT_EQ(false, TOUCH_SCREEN->IsSetFeatureConfigHandleValid());
    TOUCH_SCREEN->InitTouchScreen();
    ASSERT_EQ(true, TOUCH_SCREEN->IsSetFeatureConfigHandleValid());
}

/*
 * @tc.name: SetFeatureConfig_001
 * @tc.desc: Test SetFeatureConfig
 * @tc.type: FUNC
 * @tc.require: issueI5ZK2I
 */
HWTEST_F(TouchScreenUnitTest, SetFeatureConfig_001, TestSize.Level1)
{
    TOUCH_SCREEN->InitTouchScreen();
    ASSERT_EQ(true, TOUCH_SCREEN->IsSetFeatureConfigHandleValid());

    int32_t feature = 12;
    const char* config = "0";
    if (IsFoldScreen()) {
        ASSERT_EQ(TOUCH_SCREEN->SetFeatureConfig(feature, config), 0);
    } else {
        ASSERT_LT(TOUCH_SCREEN->SetFeatureConfig(feature, config), 0);
    }
}

/*
 * @tc.name: SetFeatureConfig_002
 * @tc.desc: Test SetFeatureConfig
 * @tc.type: FUNC
 * @tc.require: issueI5ZK2I
 */
HWTEST_F(TouchScreenUnitTest, SetFeatureConfig_002, TestSize.Level1)
{
    TOUCH_SCREEN->InitTouchScreen();
    ASSERT_EQ(true, TOUCH_SCREEN->IsSetFeatureConfigHandleValid());

    int32_t feature = 12;
    const char* config = "1";
    if (IsFoldScreen()) {
        ASSERT_EQ(TOUCH_SCREEN->SetFeatureConfig(feature, config), 0);
    } else {
        ASSERT_LT(TOUCH_SCREEN->SetFeatureConfig(feature, config), 0);
    }
}

/*
 * @tc.name: SetFeatureConfig_003
 * @tc.desc: Test SetFeatureConfig
 * @tc.type: FUNC
 * @tc.require: issueI5ZK2I
 */
HWTEST_F(TouchScreenUnitTest, SetFeatureConfig_003, TestSize.Level1)
{
    TOUCH_SCREEN->InitTouchScreen();
    ASSERT_EQ(true, TOUCH_SCREEN->IsSetFeatureConfigHandleValid());

    int32_t feature = 12;
    const char* config = "-1";
    ASSERT_LT(TOUCH_SCREEN->SetFeatureConfig(feature, config), 0);
}

/*
 * @tc.name: SetFeatureConfig_004
 * @tc.desc: Test SetFeatureConfig
 * @tc.type: FUNC
 * @tc.require: issueIB39L8
 */
HWTEST_F(TouchScreenUnitTest, SetFeatureConfig_004, TestSize.Level1)
{
    TOUCH_SCREEN->InitTouchScreen();
    ASSERT_EQ(true, TOUCH_SCREEN->IsSetAftConfigHandleValid());

    const char* config = "version:3+main";
    ASSERT_EQ(TOUCH_SCREEN->SetAftConfig(config), 0);
}

}