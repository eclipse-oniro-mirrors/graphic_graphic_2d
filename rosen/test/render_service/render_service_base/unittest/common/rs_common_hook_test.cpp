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

#include "common/rs_common_hook.h"
using namespace testing;
using namespace testing::ext;

namespace OHOS::Rosen {
class RsCommonHookTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void RsCommonHookTest::SetUpTestCase() {}
void RsCommonHookTest::TearDownTestCase() {}
void RsCommonHookTest::SetUp() {}
void RsCommonHookTest::TearDown() {}

/**
 * @tc.name: OnStartNewAnimationTest1
 * @tc.desc: test results of OnStartNewAnimationTest1
 * @tc.type:FUNC
 * @tc.require: issuesIA96Q3
 */
HWTEST_F(RsCommonHookTest, OnStartNewAnimationTest1, TestSize.Level1)
{
    std::string result;
    auto callback = [&result](const std::string& componentName) { result = componentName; };
    RsCommonHook::Instance().RegisterStartNewAnimationListener(callback);
    std::string componentName = "SWIPER_FLING";
    RsCommonHook::Instance().OnStartNewAnimation(componentName);
    ASSERT_EQ(result, componentName);
}

/**
 * @tc.name: OnStartNewAnimationTest2
 * @tc.desc: test results of OnStartNewAnimationTest2
 * @tc.type:FUNC
 * @tc.require: issuesIA96Q3
 */
HWTEST_F(RsCommonHookTest, OnStartNewAnimationTest2, TestSize.Level1)
{
    std::string result;
    auto callback = [&result](const std::string& componentName) { result = componentName; };
    RsCommonHook::Instance().RegisterStartNewAnimationListener(nullptr);
    std::string componentName = "SWIPER_FLING";
    RsCommonHook::Instance().OnStartNewAnimation(componentName);
    ASSERT_NE(result, componentName);
}

/**
 * @tc.name: SetComponentPowerFpsFuncTest
 * @tc.desc: test results of SetComponentPowerFpsFuncTest
 * @tc.type:FUNC
 * @tc.require: issuesIA96Q3
 */
HWTEST_F(RsCommonHookTest, SetComponentPowerFpsFuncTest, TestSize.Level1)
{
    auto callback = [](FrameRateRange &range) {};
    RsCommonHook::Instance().SetComponentPowerFpsFunc(callback);
}

/**
 * @tc.name: GetComponentPowerFpsTest
 * @tc.desc: test results of GetComponentPowerFpsTest
 * @tc.type:FUNC
 * @tc.require: issuesIA96Q3
 */
HWTEST_F(RsCommonHookTest, GetComponentPowerFpsTest, TestSize.Level1)
{
    auto callback = [](FrameRateRange &range) {
        range.preferred_ = RANGE_MAX_REFRESHRATE;
    };
    RsCommonHook::Instance().SetComponentPowerFpsFunc(callback);
    FrameRateRange range;
    RsCommonHook::Instance().GetComponentPowerFps(range);
    ASSERT_EQ(range.preferred_, RANGE_MAX_REFRESHRATE);
}

} // namespace OHOS::Rosen