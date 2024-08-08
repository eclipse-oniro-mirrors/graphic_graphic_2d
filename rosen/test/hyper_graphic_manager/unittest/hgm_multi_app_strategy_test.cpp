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

#include <gtest/gtest.h>
#include <limits>
#include <test_header.h>

#include "hgm_core.h"
#include "hgm_frame_rate_manager.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Rosen {
namespace {
    constexpr int32_t nodeIdOffset = 32;
    const std::string settingStrategyName = "99";
    const std::string otherPkgName = "com.pkg.other";
    const std::string defaultPidStr = "0";

    constexpr int32_t fps0 = 10;
    constexpr int32_t downFps0 = 90;
    constexpr int32_t pid0 = 10010;
    const std::string strategyName0 = "110";
    const std::string pkgName0 = "com.app10";
    constexpr int32_t appType0 = 20010;

    constexpr int32_t fps1 = 15;
    constexpr int32_t downFps1 = 120;
    constexpr int32_t pid1 = 10015;
    const std::string strategyName1 = "115";
    const std::string pkgName1 = "com.app15";
    constexpr int32_t appType1 = 20015;
}

struct PkgParam {
    std::string pkgName;
    int32_t fps;
    pid_t pid;
    std::shared_ptr<RSRenderFrameRateLinker> linker;
};

class HgmMultiAppStrategyTest : public testing::Test {
public:
    static void SetUpTestCase() {}
    static void TearDownTestCase() {}
    void SetUp();
    void TearDown() {}
    void SetMultiAppStrategy(MultiAppStrategyType multiAppStrategyType, const std::string& strategyName = "");
    std::vector<std::string> CreateVotePkgs();

    std::vector<PkgParam> pkgParams_;
    std::shared_ptr<HgmMultiAppStrategy> multiAppStrategy_;
};

void HgmMultiAppStrategyTest::SetUp()
{
    multiAppStrategy_ = std::make_shared<HgmMultiAppStrategy>();
    // init config
    // set app config
    auto strategyConfigs = multiAppStrategy_->GetStrategyConfigs();
    auto screenSetting = multiAppStrategy_->GetScreenSetting();
    auto &appTypes = screenSetting.appTypes;

    strategyConfigs[settingStrategyName] = { .min = OLED_NULL_HZ, .max = OLED_120_HZ, .down = OLED_144_HZ,
        .dynamicMode = DynamicModeType::TOUCH_ENABLED, .isFactor = true };
    screenSetting.strategy = settingStrategyName;

    strategyConfigs[strategyName0] = { .min = fps0, .max = fps0, .dynamicMode = DynamicModeType::TOUCH_ENABLED,
        .drawMin = OLED_NULL_HZ, .drawMax = OLED_NULL_HZ, .down = downFps0 };
    screenSetting.appList[pkgName0] = strategyName0;
    pkgParams_.push_back({ .pkgName = pkgName0, .fps = fps0, .pid = pid0,
        .linker = std::make_shared<RSRenderFrameRateLinker>(((NodeId)pid0) << nodeIdOffset) });

    strategyConfigs[strategyName1] = { .min = fps1, .max = fps1, .dynamicMode = DynamicModeType::TOUCH_ENABLED,
        .drawMin = OLED_NULL_HZ, .drawMax = OLED_NULL_HZ, .down = downFps1 };
    screenSetting.appList[pkgName1] = strategyName1;
    pkgParams_.push_back({ .pkgName = pkgName1, .fps = fps1, .pid = pid1,
        .linker = std::make_shared<RSRenderFrameRateLinker>(((NodeId)pid1) << nodeIdOffset) });

    for (auto &pkgParam : pkgParams_) {
        pkgParam.linker->SetExpectedRange(FrameRateRange(OLED_NULL_HZ, RANGE_MAX_REFRESHRATE, OLED_NULL_HZ));
    }

    appTypes[appType0] = strategyName0;
    appTypes[appType1] = strategyName1;
    multiAppStrategy_->SetStrategyConfigs(strategyConfigs);
    multiAppStrategy_->SetScreenSetting(screenSetting);
}

void HgmMultiAppStrategyTest::SetMultiAppStrategy(
    MultiAppStrategyType multiAppStrategyType, const std::string& strategyName)
{
    auto screenSetting = multiAppStrategy_->GetScreenSetting();
    screenSetting.multiAppStrategyType = multiAppStrategyType;
    screenSetting.multiAppStrategyName = strategyName;
    multiAppStrategy_->SetScreenSetting(screenSetting);
}

std::vector<std::string> HgmMultiAppStrategyTest::CreateVotePkgs()
{
    std::vector<std::string> pkgs;
    for (auto &pkgParam : pkgParams_) {
        pkgs.push_back(pkgParam.pkgName + ":" + std::to_string(pkgParam.pid));
    }
    return pkgs;
}

/**
 * @tc.name: SingleAppTouch001
 * @tc.desc: Verify the result of SingleAppTouch001 function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HgmMultiAppStrategyTest, SingleAppTouch001, Function | SmallTest | Level1)
{
    PART("CaseDescription") {
        auto &pkgParam = pkgParams_[0]; // first pkg
        std::vector<std::string> voteParam = { pkgParam.pkgName + ":" + std::to_string(pkgParam.pid), };

        PolicyConfigData::StrategyConfig strategyConfig;
        HgmErrCode res;
        SetMultiAppStrategy(MultiAppStrategyType::USE_MAX);

        STEP("1. pkg vote") {
            multiAppStrategy_->HandlePkgsEvent(voteParam);
            res = multiAppStrategy_->GetVoteRes(strategyConfig);
            ASSERT_EQ(res, EXEC_SUCCESS);
            ASSERT_EQ(strategyConfig.min, fps0);
            ASSERT_EQ(strategyConfig.max, fps0);
        }
        STEP("2. handle touch event") {
            HgmMultiAppStrategy::TouchInfo touchInfo = {
                .pkgName = pkgParam.pkgName,
                .touchState = TouchState::DOWN_STATE,
                .upExpectFps = OLED_120_HZ,
            };
            multiAppStrategy_->HandleTouchInfo(touchInfo);
            res = multiAppStrategy_->GetVoteRes(strategyConfig);
            ASSERT_EQ(res, EXEC_SUCCESS);
            ASSERT_EQ(strategyConfig.min, downFps0);
            ASSERT_EQ(strategyConfig.max, downFps0);

            touchInfo = {
                .touchState = TouchState::UP_STATE,
            };
            multiAppStrategy_->HandleTouchInfo(touchInfo);
            res = multiAppStrategy_->GetVoteRes(strategyConfig);
            ASSERT_EQ(res, EXEC_SUCCESS);
            ASSERT_EQ(strategyConfig.min, fps0);
            ASSERT_EQ(strategyConfig.max, fps0);

            touchInfo = {
                .touchState = TouchState::IDLE_STATE,
            };
            multiAppStrategy_->HandleTouchInfo(touchInfo);
            res = multiAppStrategy_->GetVoteRes(strategyConfig);
            ASSERT_EQ(res, EXEC_SUCCESS);
            ASSERT_EQ(strategyConfig.min, fps0);
            ASSERT_EQ(strategyConfig.max, fps0);
        }
    }
}

/**
 * @tc.name: SingleAppTouch002
 * @tc.desc: Verify the result of SingleAppTouch002 function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HgmMultiAppStrategyTest, SingleAppTouch002, Function | SmallTest | Level1)
{
    PART("CaseDescription") {
        std::string unConfigPkgName = "com.pkg.other";
        auto &pkgParam = pkgParams_[0]; // first pkg
        std::vector<std::string> voteParam = { pkgParam.pkgName + ":" + std::to_string(pkgParam.pid), };

        PolicyConfigData::StrategyConfig strategyConfig;
        HgmErrCode res;
        SetMultiAppStrategy(MultiAppStrategyType::USE_MAX);

        STEP("1. pkg vote") {
            multiAppStrategy_->HandlePkgsEvent(voteParam);
            res = multiAppStrategy_->GetVoteRes(strategyConfig);
            ASSERT_EQ(res, EXEC_SUCCESS);
            ASSERT_EQ(strategyConfig.min, fps0);
            ASSERT_EQ(strategyConfig.max, fps0);
        }
        STEP("2. click other pkg which hasn't config") {
            HgmMultiAppStrategy::TouchInfo touchInfo = {
                .pkgName = unConfigPkgName,
                .touchState = TouchState::DOWN_STATE,
                .upExpectFps = OLED_120_HZ,
            };
            multiAppStrategy_->HandleTouchInfo(touchInfo);
            res = multiAppStrategy_->GetVoteRes(strategyConfig);
            ASSERT_EQ(res, EXEC_SUCCESS);
            ASSERT_EQ(strategyConfig.min, OLED_144_HZ);
            ASSERT_EQ(strategyConfig.max, OLED_144_HZ);
            touchInfo = {
                .touchState = TouchState::UP_STATE,
            };
            multiAppStrategy_->HandleTouchInfo(touchInfo);
            touchInfo = {
                .touchState = TouchState::IDLE_STATE,
            };
            multiAppStrategy_->HandleTouchInfo(touchInfo);
            res = multiAppStrategy_->GetVoteRes(strategyConfig);
            ASSERT_EQ(res, EXEC_SUCCESS);
        }
    }
}

/**
 * @tc.name: SingleAppTouch003
 * @tc.desc: Verify the result of SingleAppTouch003 function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HgmMultiAppStrategyTest, SingleAppTouch003, Function | SmallTest | Level1)
{
    PART("CaseDescription") {
        std::string unConfigPkgName = "com.pkg.other";
        auto &pkgParam = pkgParams_[0]; // first pkg
        std::vector<std::string> voteParam = { pkgParam.pkgName + ":" + std::to_string(pkgParam.pid), };

        PolicyConfigData::StrategyConfig strategyConfig;
        HgmErrCode res;
        SetMultiAppStrategy(MultiAppStrategyType::USE_MAX);

        STEP("1. pkg vote") {
            multiAppStrategy_->HandlePkgsEvent(voteParam);
        }
        STEP("2. start other pkg which hasn't config") {
            res = multiAppStrategy_->HandlePkgsEvent({});
            ASSERT_EQ(res, EXEC_SUCCESS);
            multiAppStrategy_->HandlePkgsEvent({ unConfigPkgName, });
            ASSERT_EQ(res, EXEC_SUCCESS);
            res = multiAppStrategy_->GetVoteRes(strategyConfig);
            ASSERT_EQ(res, EXEC_SUCCESS);
            ASSERT_EQ(strategyConfig.min, OLED_NULL_HZ);
            ASSERT_EQ(strategyConfig.max, OLED_120_HZ);

            HgmMultiAppStrategy::TouchInfo touchInfo = {
                .pkgName = unConfigPkgName,
                .touchState = TouchState::DOWN_STATE,
                .upExpectFps = OLED_120_HZ,
            };
            multiAppStrategy_->HandleTouchInfo(touchInfo);
            res = multiAppStrategy_->GetVoteRes(strategyConfig);
            ASSERT_EQ(res, EXEC_SUCCESS);
            ASSERT_EQ(strategyConfig.min, OLED_144_HZ);
            ASSERT_EQ(strategyConfig.max, OLED_144_HZ);

            touchInfo = {
                .touchState = TouchState::UP_STATE,
            };
            multiAppStrategy_->HandleTouchInfo(touchInfo);
            touchInfo = {
                .touchState = TouchState::IDLE_STATE,
            };
            multiAppStrategy_->HandleTouchInfo(touchInfo);
            res = multiAppStrategy_->GetVoteRes(strategyConfig);
            ASSERT_EQ(res, EXEC_SUCCESS);
            ASSERT_EQ(strategyConfig.min, OLED_NULL_HZ);
            ASSERT_EQ(strategyConfig.max, OLED_120_HZ);
        }
    }
}

/**
 * @tc.name: MultiAppTouch001
 * @tc.desc: Verify the result of MultiAppTouch function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HgmMultiAppStrategyTest, MultiAppTouch001, Function | SmallTest | Level1)
{
    PART("CaseDescription") {
        PolicyConfigData::StrategyConfig strategyConfig;
        SetMultiAppStrategy(MultiAppStrategyType::USE_MAX);
        STEP("1. pkg vote") {
            multiAppStrategy_->HandlePkgsEvent(CreateVotePkgs());
            multiAppStrategy_->GetVoteRes(strategyConfig);
            ASSERT_EQ(strategyConfig.min, fps1);
            ASSERT_EQ(strategyConfig.max, fps1);
        }
        STEP("2. handle pkg0 touch event") {
            HgmMultiAppStrategy::TouchInfo touchInfo = {
                .pkgName = pkgParams_[0].pkgName,
                .touchState = TouchState::DOWN_STATE,
                .upExpectFps = OLED_120_HZ,
            };
            multiAppStrategy_->HandleTouchInfo(touchInfo);
            multiAppStrategy_->GetVoteRes(strategyConfig);
            ASSERT_EQ(strategyConfig.min, downFps0);
            ASSERT_EQ(strategyConfig.max, downFps0);

            touchInfo = {
                .touchState = TouchState::UP_STATE,
            };
            multiAppStrategy_->HandleTouchInfo(touchInfo);
            touchInfo = {
                .touchState = TouchState::IDLE_STATE,
            };
            multiAppStrategy_->HandleTouchInfo(touchInfo);

            multiAppStrategy_->GetVoteRes(strategyConfig);
            ASSERT_EQ(strategyConfig.min, fps1);
            ASSERT_EQ(strategyConfig.max, fps1);
        }
    }
}

/**
 * @tc.name: MultiAppTouch002
 * @tc.desc: Verify the result of MultiAppTouch function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HgmMultiAppStrategyTest, MultiAppTouch002, Function | SmallTest | Level1)
{
    PART("CaseDescription") {
        PolicyConfigData::StrategyConfig strategyConfig;
        SetMultiAppStrategy(MultiAppStrategyType::USE_MAX);
        STEP("1. pkg vote") {
            multiAppStrategy_->HandlePkgsEvent(CreateVotePkgs());
        }
        STEP("2. handle pkg1 touch event") {
            HgmMultiAppStrategy::TouchInfo touchInfo = {
                .pkgName = pkgParams_[1].pkgName,
                .touchState = TouchState::DOWN_STATE,
                .upExpectFps = OLED_120_HZ,
            };
            multiAppStrategy_->HandleTouchInfo(touchInfo);
            multiAppStrategy_->GetVoteRes(strategyConfig);
            ASSERT_EQ(strategyConfig.min, downFps1);
            ASSERT_EQ(strategyConfig.max, downFps1);

            touchInfo = {
                .touchState = TouchState::UP_STATE,
            };
            multiAppStrategy_->HandleTouchInfo(touchInfo);
            touchInfo = {
                .touchState = TouchState::IDLE_STATE,
            };
            multiAppStrategy_->HandleTouchInfo(touchInfo);

            multiAppStrategy_->GetVoteRes(strategyConfig);
            ASSERT_EQ(strategyConfig.min, fps1);
            ASSERT_EQ(strategyConfig.max, fps1);
        }
    }
}

/**
 * @tc.name: MultiAppTouch003
 * @tc.desc: Verify the result of MultiAppTouch function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HgmMultiAppStrategyTest, MultiAppTouch003, Function | SmallTest | Level1)
{
    PART("CaseDescription") {
        PolicyConfigData::StrategyConfig strategyConfig;
        SetMultiAppStrategy(MultiAppStrategyType::USE_MAX);
        STEP("1. pkg vote") {
            multiAppStrategy_->HandlePkgsEvent(CreateVotePkgs());
        }
        STEP("2. handle empty pkg touch event") {
            HgmMultiAppStrategy::TouchInfo touchInfo = {
                .pkgName = otherPkgName,
                .touchState = TouchState::DOWN_STATE,
                .upExpectFps = OLED_120_HZ,
            };
            multiAppStrategy_->HandleTouchInfo(touchInfo);
            multiAppStrategy_->GetVoteRes(strategyConfig);
            ASSERT_EQ(strategyConfig.min, OLED_144_HZ);
            ASSERT_EQ(strategyConfig.max, OLED_144_HZ);

            touchInfo = {
                .touchState = TouchState::UP_STATE,
            };
            multiAppStrategy_->HandleTouchInfo(touchInfo);
            touchInfo = {
                .touchState = TouchState::IDLE_STATE,
            };
            multiAppStrategy_->HandleTouchInfo(touchInfo);

            multiAppStrategy_->GetVoteRes(strategyConfig);
            ASSERT_EQ(strategyConfig.min, fps1);
            ASSERT_EQ(strategyConfig.max, fps1);
        }
    }
}

/**
 * @tc.name: UseStrategyNum
 * @tc.desc: Verify the result of UseStrategyNum function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HgmMultiAppStrategyTest, UseStrategyNum, Function | SmallTest | Level1)
{
    PART("CaseDescription") {
        PolicyConfigData::StrategyConfig strategyConfig;
        SetMultiAppStrategy(MultiAppStrategyType::USE_STRATEGY_NUM, "110");
        STEP("1. handle 2 packages") {
            multiAppStrategy_->HandlePkgsEvent(CreateVotePkgs());
            multiAppStrategy_->GetVoteRes(strategyConfig);
            ASSERT_EQ(strategyConfig.min, fps0);
            ASSERT_EQ(strategyConfig.max, fps0);
        }
        STEP("2. empty pkgs") {
            multiAppStrategy_->HandlePkgsEvent({});
            multiAppStrategy_->GetVoteRes(strategyConfig);
            ASSERT_EQ(strategyConfig.min, OledRefreshRate::OLED_NULL_HZ);
            ASSERT_EQ(strategyConfig.max, OledRefreshRate::OLED_120_HZ);
        }
    }
}

/**
 * @tc.name: FollowFocus
 * @tc.desc: Verify the result of FollowFocus function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HgmMultiAppStrategyTest, FollowFocus, Function | SmallTest | Level1)
{
    PART("CaseDescription") {
        PolicyConfigData::StrategyConfig strategyConfig;
        SetMultiAppStrategy(MultiAppStrategyType::FOLLOW_FOCUS);
        STEP("1. handle 2 packages") {
            multiAppStrategy_->HandlePkgsEvent(CreateVotePkgs());
            multiAppStrategy_->GetVoteRes(strategyConfig);

            auto pkgParam = pkgParams_[0];
            ASSERT_EQ(strategyConfig.min, pkgParam.fps);
            ASSERT_EQ(strategyConfig.max, pkgParam.fps);
        }
        STEP("2. empty pkgs") {
            multiAppStrategy_->HandlePkgsEvent({});
            multiAppStrategy_->GetVoteRes(strategyConfig);
            ASSERT_EQ(strategyConfig.min, OledRefreshRate::OLED_NULL_HZ);
            ASSERT_EQ(strategyConfig.max, OledRefreshRate::OLED_120_HZ);
        }
    }
}

/**
 * @tc.name: UseMax
 * @tc.desc: Verify the result of UseMax function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HgmMultiAppStrategyTest, UseMax, Function | SmallTest | Level1)
{
    PART("CaseDescription") {
    PolicyConfigData::StrategyConfig strategyConfig;
    SetMultiAppStrategy(MultiAppStrategyType::USE_MAX);
        STEP("1. handle 2 packages") {
            multiAppStrategy_->HandlePkgsEvent(CreateVotePkgs());
            multiAppStrategy_->GetVoteRes(strategyConfig);
            ASSERT_EQ(strategyConfig.min, fps1);
            ASSERT_EQ(strategyConfig.max, fps1);
        }
        STEP("2. empty pkgs") {
            multiAppStrategy_->HandlePkgsEvent({});
            multiAppStrategy_->GetVoteRes(strategyConfig);
            ASSERT_EQ(strategyConfig.min, OledRefreshRate::OLED_NULL_HZ);
            ASSERT_EQ(strategyConfig.max, OledRefreshRate::OLED_120_HZ);
        }
    }
}

/**
 * @tc.name: AppType
 * @tc.desc: Verify the result of AppType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HgmMultiAppStrategyTest, AppType, Function | SmallTest | Level1)
{
    PART("CaseDescription") {
        PolicyConfigData::StrategyConfig strategyConfig;
        multiAppStrategy_->HandlePkgsEvent({ otherPkgName + ":" + defaultPidStr + ":" + std::to_string(appType0) });
        multiAppStrategy_->GetVoteRes(strategyConfig);
        ASSERT_EQ(strategyConfig.min, fps0);
        ASSERT_EQ(strategyConfig.max, fps0);
        
        multiAppStrategy_->HandlePkgsEvent({ otherPkgName + ":" + defaultPidStr + ":" + std::to_string(appType1) });
        multiAppStrategy_->GetVoteRes(strategyConfig);
        ASSERT_EQ(strategyConfig.min, fps1);
        ASSERT_EQ(strategyConfig.max, fps1);
    }
}

/**
 * @tc.name: LightFactor
 * @tc.desc: Verify the result of LightFactor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HgmMultiAppStrategyTest, LightFactor, Function | SmallTest | Level1)
{
    PART("CaseDescription") {
        PolicyConfigData::StrategyConfig strategyConfig;
        multiAppStrategy_->GetVoteRes(strategyConfig);
        ASSERT_EQ(strategyConfig.min, OledRefreshRate::OLED_NULL_HZ);
        ASSERT_EQ(strategyConfig.max, OledRefreshRate::OLED_120_HZ);

        multiAppStrategy_->HandleLightFactorStatus(true);
        multiAppStrategy_->GetVoteRes(strategyConfig);
        ASSERT_EQ(strategyConfig.min, OledRefreshRate::OLED_120_HZ);
        ASSERT_EQ(strategyConfig.max, OledRefreshRate::OLED_120_HZ);

        multiAppStrategy_->HandleLightFactorStatus(false);
        multiAppStrategy_->GetVoteRes(strategyConfig);
        ASSERT_EQ(strategyConfig.min, OledRefreshRate::OLED_NULL_HZ);
        ASSERT_EQ(strategyConfig.max, OledRefreshRate::OLED_120_HZ);
    }
}

/**
 * @tc.name: BackgroundApp
 * @tc.desc: Verify the result of BackgroundApp
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HgmMultiAppStrategyTest, BackgroundApp, Function | SmallTest | Level1)
{
    constexpr int32_t gameType0 = 10046;
    PART("CaseDescription") {
        multiAppStrategy_->HandlePkgsEvent({ pkgName0 + ":" + std::to_string(pid0) });
        auto foregroundPidAppMap = multiAppStrategy_->GetForegroundPidApp();
        ASSERT_TRUE(foregroundPidAppMap.find(pid0) != foregroundPidAppMap.end());
        
        multiAppStrategy_->HandlePkgsEvent({ pkgName1 + ":" + std::to_string(pid1) + ":" + std::to_string(gameType0) });
        foregroundPidAppMap = multiAppStrategy_->GetForegroundPidApp();
        auto backgroundPid = multiAppStrategy_->GetBackgroundPid();
        ASSERT_TRUE(foregroundPidAppMap.find(pid0) == foregroundPidAppMap.end());
        ASSERT_TRUE(foregroundPidAppMap.find(pid1) != foregroundPidAppMap.end());
        ASSERT_TRUE(backgroundPid.Existed(pid0));
        ASSERT_FALSE(backgroundPid.Existed(pid1));
    }
}

/**
 * @tc.name: CheckPackageInConfigList
 * @tc.desc: Verify the result of CheckPackageInConfigList
 * @tc.type: FUNC
 * @tc.require: IAHFXD
 */
HWTEST_F(HgmMultiAppStrategyTest, CheckPackageInConfigList, Function | SmallTest | Level1)
{
    std::vector<std::string> pkgs = {"com.app10", "com.app15"};
    multiAppStrategy_->CheckPackageInConfigList(pkgs);
    ASSERT_EQ(pkgs[0], "com.app10");
}
} // namespace Rosen
} // namespace OHOS