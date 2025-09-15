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
    RsCommonHook::Instance().RegisterStartNewAnimationListener(nullptr);
    std::string componentName = "SWIPER_FLING";
    RsCommonHook::Instance().OnStartNewAnimation(componentName);
    ASSERT_EQ(RsCommonHook::Instance().startNewAniamtionFunc_, nullptr);
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

/**
 * @tc.name: SetAdaptiveColorGamutEnableTest
 * @tc.desc: Verify the SetAdaptiveColorGamutEnableTest and IsAdaptiveColorGamutEnabled
 * @tc.type:FUNC
 * @tc.require: issuesIC82H3
 */
HWTEST_F(RsCommonHookTest, SetAdaptiveColorGamutEnableTest, TestSize.Level1)
{
    RsCommonHook::Instance().SetAdaptiveColorGamutEnable(true);
    ASSERT_EQ(RsCommonHook::Instance().IsAdaptiveColorGamutEnabled(), true);
    RsCommonHook::Instance().SetAdaptiveColorGamutEnable(false);
    ASSERT_EQ(RsCommonHook::Instance().IsAdaptiveColorGamutEnabled(), false);
}

/**
 * @tc.name: SetAndGetBundleNameTest
 * @tc.desc: test results of SetTvPlayerBundleName and GetTvPlayerBundleName
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RsCommonHookTest, SetAndGetBundleNameTest, TestSize.Level1)
{
    const std::string testBundleName = "com.example.tvplayer";
    RsCommonHook::Instance().SetTvPlayerBundleName(testBundleName);
    auto result = RsCommonHook::Instance().GetTvPlayerBundleName();
    EXPECT_EQ(result, testBundleName);
}

/**
 * @tc.name: SetFilterUnderHwcConfigByAppTest
 * @tc.desc: test results of SetFilterUnderHwcConfigByApp and GetFilterUnderHwcConfigByApp
 * @tc.type:FUNC
 * @tc.require: issuesICKNNB
 */
HWTEST_F(RsCommonHookTest, SetAndGetFilterUnderHwcConfigByAppTest, TestSize.Level1)
{
    const std::string collaborationBundleName = "com.example.devicecollaboration";
    auto result = RsCommonHook::Instance().GetFilterUnderHwcConfigByApp(collaborationBundleName);
    EXPECT_EQ(result, "");
    RsCommonHook::Instance().SetFilterUnderHwcConfigByApp(collaborationBundleName, "1");
    auto result1 = RsCommonHook::Instance().GetFilterUnderHwcConfigByApp(collaborationBundleName);
    EXPECT_EQ(result1, "1");
}

/**
 * @tc.name: SetAndGetOverlappedHwcNodeInAppEnabledConfig
 * @tc.desc: test results of SetOverlappedHwcNodeInAppEnabledConfig and GetOverlappedHwcNodeInAppEnabledConfig
 * @tc.type:FUNC
 * @tc.require: issuesICKNNB
 */
HWTEST_F(RsCommonHookTest, SetAndGetOverlappedHwcNodeInAppEnabledConfig, TestSize.Level1)
{
    const std::string testBundleName1 = "com.example.app1";
    const std::string testBundleName2 = "com.example.app2";
    RsCommonHook::Instance().SetOverlappedHwcNodeInAppEnabledConfig(testBundleName1, "1");
    auto result1 = RsCommonHook::Instance().GetOverlappedHwcNodeInAppEnabledConfig(testBundleName1);
    EXPECT_EQ(result1, "1");
    auto result2 = RsCommonHook::Instance().GetOverlappedHwcNodeInAppEnabledConfig(testBundleName2);
    EXPECT_EQ(result2, "");
}

/**
 * @tc.name: SetAndGetImageEnhancePidListTest
 * @tc.desc: test results of SetImageEnhancePidList and GetImageEnhancePidList
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RsCommonHookTest, SetAndGetImageEnhancePidListTest, TestSize.Level1)
{
    std::unordered_set<pid_t> testImageEnhancePidList = {};
    RsCommonHook::Instance().SetImageEnhancePidList(testImageEnhancePidList);
    auto result1 = RsCommonHook::Instance().GetImageEnhancePidList();
    EXPECT_EQ(result1, testImageEnhancePidList);
    pid_t pid1 = 1;
    testImageEnhancePidList.insert(pid1);
    RsCommonHook::Instance().SetImageEnhancePidList(testImageEnhancePidList);
    auto result2 = RsCommonHook::Instance().GetImageEnhancePidList();
    EXPECT_EQ(result2, testImageEnhancePidList);
    pid_t pid2 = 2;
    testImageEnhancePidList.insert(pid2);
    RsCommonHook::Instance().SetImageEnhancePidList(testImageEnhancePidList);
    auto result3 = RsCommonHook::Instance().GetImageEnhancePidList();
    EXPECT_EQ(result3, testImageEnhancePidList);
}
} // namespace OHOS::Rosen