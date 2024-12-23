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

#include "hgm_core.h"
#include "hgm_frame_rate_manager.h"
#include "hgm_config_callback_manager.h"
#include "hgm_idle_detector.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Rosen {
namespace {
    const std::string otherSurface = "Other_SF";
    const std::string settingStrategyName = "99";
    const int32_t HGM_REFRESHRATE_MODE_HIGH = 2;
    constexpr uint64_t  currTime = 200000000;
    constexpr uint64_t  lastTime = 100000000;
    constexpr pid_t appPid = 0;
    constexpr uint32_t touchCount = 1;
    constexpr uint32_t delay_60Ms = 60;
    constexpr uint32_t delay_110Ms = 110;
    constexpr int32_t OLED_72_HZ = 72;
    constexpr int32_t OLED_50_HZ = 50;
    constexpr int32_t OLED_80_HZ = 80;
    ScreenSize screenSize = {720, 1080, 685, 1218}; // width, height, phyWidth, phyHeight
    constexpr int32_t internalScreenId = 5;
    constexpr int32_t externalScreenId = 0;
    constexpr int32_t frameRateLinkerId1 = 1;
    constexpr int32_t frameRateLinkerId2 = 2;
    constexpr int32_t errorVelocity = -1;
    constexpr int32_t strategy3 = 3;
    const std::string testScene = "TestScene";
}
class HgmFrameRateMgrTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    void InitHgmFrameRateManager(HgmFrameRateManager &frameRateMgr);
};

void HgmFrameRateMgrTest::SetUpTestCase() {}
void HgmFrameRateMgrTest::TearDownTestCase() {}
void HgmFrameRateMgrTest::SetUp() {}
void HgmFrameRateMgrTest::TearDown() {}

class CustomHgmCallback : public IRemoteStub<RSIHgmConfigChangeCallback> {
public:
    explicit CustomHgmCallback() {}
    ~CustomHgmCallback() override {};

    void OnHgmConfigChanged(std::shared_ptr<RSHgmConfigData> configData) override {}
    void OnHgmRefreshRateModeChanged(int32_t refreshRateModeName) override {}
    void OnHgmRefreshRateUpdate(int32_t refreshRateUpdate) override {}
};

/**
 * @tc.name: MergeRangeByPriority
 * @tc.desc: Verify the result of MergeRangeByPriority function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HgmFrameRateMgrTest, MergeRangeByPriority, Function | SmallTest | Level1)
{
    VoteRange voteRange0 = { OLED_40_HZ, OLED_120_HZ };
    VoteRange voteRange1 = { OLED_30_HZ, OLED_40_HZ };
    VoteRange voteRange2 = { OLED_60_HZ, OLED_90_HZ };
    VoteRange voteRange3 = { OLED_120_HZ, OLED_144_HZ };
    VoteRange voteRange4 = { OLED_30_HZ, OLED_144_HZ };
    VoteRange voteRangeRes;

    voteRangeRes = voteRange0;
    HgmFrameRateManager::MergeRangeByPriority(voteRangeRes, voteRange1);
    ASSERT_EQ(voteRangeRes.first, OledRefreshRate::OLED_40_HZ);
    ASSERT_EQ(voteRangeRes.second, OledRefreshRate::OLED_40_HZ);

    voteRangeRes = voteRange0;
    HgmFrameRateManager::MergeRangeByPriority(voteRangeRes, voteRange2);
    ASSERT_EQ(voteRangeRes.first, OledRefreshRate::OLED_60_HZ);
    ASSERT_EQ(voteRangeRes.second, OledRefreshRate::OLED_90_HZ);

    voteRangeRes = voteRange0;
    HgmFrameRateManager::MergeRangeByPriority(voteRangeRes, voteRange3);
    ASSERT_EQ(voteRangeRes.first, OledRefreshRate::OLED_120_HZ);
    ASSERT_EQ(voteRangeRes.second, OledRefreshRate::OLED_120_HZ);

    voteRangeRes = voteRange0;
    HgmFrameRateManager::MergeRangeByPriority(voteRangeRes, voteRange4);
    ASSERT_EQ(voteRangeRes.first, OledRefreshRate::OLED_40_HZ);
    ASSERT_EQ(voteRangeRes.second, OledRefreshRate::OLED_120_HZ);
}

void HgmFrameRateMgrTest::InitHgmFrameRateManager(HgmFrameRateManager &frameRateMgr)
{
    int64_t offset = 0;
    auto vsyncGenerator = CreateVSyncGenerator();
    sptr<Rosen::VSyncController> rsController = new VSyncController(vsyncGenerator, offset);
    sptr<Rosen::VSyncController> appController = new VSyncController(vsyncGenerator, offset);
    frameRateMgr.Init(nullptr, nullptr, nullptr);
    frameRateMgr.Init(rsController, appController, vsyncGenerator);

    auto strategyConfigs = frameRateMgr.multiAppStrategy_.GetStrategyConfigs();
    auto screenSetting = frameRateMgr.multiAppStrategy_.GetScreenSetting();
    strategyConfigs[settingStrategyName] = { .min = OLED_NULL_HZ, .max = OLED_120_HZ, .down = OLED_144_HZ,
        .dynamicMode = DynamicModeType::TOUCH_ENABLED, .isFactor = true };
    screenSetting.strategy = settingStrategyName;
    frameRateMgr.multiAppStrategy_.SetStrategyConfigs(strategyConfigs);
    frameRateMgr.multiAppStrategy_.SetScreenSetting(screenSetting);
    frameRateMgr.ReportHiSysEvent({ .extInfo = "ON" });
}

/**
 * @tc.name: HgmUiFrameworkDirtyNodeTest
 * @tc.desc: Verify the result of HgmUiFrameworkDirtyNodeTest function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HgmFrameRateMgrTest, HgmUiFrameworkDirtyNodeTest, Function | SmallTest | Level1)
{
    HgmFrameRateManager frameRateMgr;
    std::vector<std::weak_ptr<RSRenderNode>> uiFwkDirtyNodes;
    PART("HgmUiFrameworkDirtyNodeTest") {
        STEP("1. Test empty uiFwkDirtyNodes") {
            ASSERT_EQ(uiFwkDirtyNodes.size(), 0);
            frameRateMgr.UpdateUIFrameworkDirtyNodes(uiFwkDirtyNodes, 0);
            frameRateMgr.voterTouchEffective_ = true;
            {
                std::shared_ptr<RSRenderNode> renderNode1 = std::make_shared<RSRenderNode>(0);
                uiFwkDirtyNodes.emplace_back(renderNode1);
                ASSERT_EQ(uiFwkDirtyNodes.size(), 1);
            }
            frameRateMgr.UpdateUIFrameworkDirtyNodes(uiFwkDirtyNodes, 0);
            ASSERT_EQ(uiFwkDirtyNodes.size(), 0);
        }
        STEP("2. Test uiFwkDirtyNodes with a clean renderNode") {
            std::shared_ptr<RSRenderNode> renderNode2 = std::make_shared<RSRenderNode>(0);
            uiFwkDirtyNodes.emplace_back(renderNode2);
            ASSERT_EQ(uiFwkDirtyNodes.size(), 1);
            ASSERT_EQ(renderNode2->IsDirty(), false);
            frameRateMgr.UpdateUIFrameworkDirtyNodes(uiFwkDirtyNodes, 0);
            ASSERT_EQ(uiFwkDirtyNodes.size(), 1);
        }
        STEP("3. Test uiFwkDirtyNodes with a dirty renderNode") {
            std::shared_ptr<RSRenderNode> renderNode3 = std::make_shared<RSRenderNode>(0);
            uiFwkDirtyNodes.emplace_back(renderNode3);
            ASSERT_EQ(uiFwkDirtyNodes.size(), 2);

            frameRateMgr.UpdateUIFrameworkDirtyNodes(uiFwkDirtyNodes, 0);
            ASSERT_EQ(uiFwkDirtyNodes.size(), 1);

            renderNode3->SetDirty();
            ASSERT_EQ(renderNode3->IsDirty(), true);
            frameRateMgr.UpdateUIFrameworkDirtyNodes(uiFwkDirtyNodes, 0);
            ASSERT_EQ(uiFwkDirtyNodes.size(), 1);
        }
        STEP("4. other branch") {
            frameRateMgr.surfaceData_.emplace_back(std::tuple<std::string, pid_t, UIFWKType>());
            frameRateMgr.UpdateUIFrameworkDirtyNodes(uiFwkDirtyNodes, 0);
            frameRateMgr.voterGamesEffective_ = true;
            frameRateMgr.UpdateUIFrameworkDirtyNodes(uiFwkDirtyNodes, 0);
            frameRateMgr.voterTouchEffective_ = false;
            frameRateMgr.UpdateUIFrameworkDirtyNodes(uiFwkDirtyNodes, 0);
        }
    }
    sleep(1);
}

/**
 * @tc.name: HgmConfigCallbackManagerTest
 * @tc.desc: Verify the result of HgmConfigCallbackManagerTest function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HgmFrameRateMgrTest, HgmConfigCallbackManagerTest, Function | SmallTest | Level1)
{
    sptr<HgmConfigCallbackManager> hccMgr = HgmConfigCallbackManager::GetInstance();
    PART("HgmConfigCallbackManagerTest") {
        STEP("1. Callback is nullptr") {
            sptr<CustomHgmCallback> cb1 = new CustomHgmCallback();
            hccMgr->RegisterHgmRefreshRateModeChangeCallback(0, nullptr);
            hccMgr->RegisterHgmRefreshRateModeChangeCallback(1, cb1);
        }
        STEP("2. Test SyncHgmConfigChangeCallback without callback") {
            std::unordered_map<pid_t, sptr<RSIHgmConfigChangeCallback>> emptyCallback;
            std::swap(hccMgr->animDynamicCfgCallbacks_, emptyCallback);
            ASSERT_EQ(hccMgr->animDynamicCfgCallbacks_.empty(), true);
            hccMgr->SyncHgmConfigChangeCallback();
        }
        STEP("3. Test SyncCallback function with callback") {
            sptr<CustomHgmCallback> cb = new CustomHgmCallback();
            hccMgr->animDynamicCfgCallbacks_[0] = cb;
            hccMgr->refreshRateModeCallbacks_[0] = cb;
            hccMgr->SyncHgmConfigChangeCallback();
            hccMgr->SyncRefreshRateModeChangeCallback(0);
            hccMgr->RegisterHgmConfigChangeCallback(0, nullptr);
            hccMgr->RegisterHgmConfigChangeCallback(1, cb);
            hccMgr->RegisterHgmRefreshRateUpdateCallback(0, nullptr);
            hccMgr->RegisterHgmRefreshRateUpdateCallback(1, cb);
            hccMgr->SyncHgmConfigChangeCallback();
            hccMgr->SyncRefreshRateModeChangeCallback(0);
            hccMgr->refreshRateUpdateCallbacks_ = {
                {0, nullptr},
            };
            hccMgr->SyncRefreshRateUpdateCallback(OLED_60_HZ);
            ASSERT_EQ(hccMgr->animDynamicCfgCallbacks_.empty(), false);
            hccMgr->UnRegisterHgmConfigChangeCallback(1);
        }
    }
}

/**
 * @tc.name: MultiThread001
 * @tc.desc: Verify the result of MultiThread001 function
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HgmFrameRateMgrTest, MultiThread001, Function | SmallTest | Level1)
{
    int64_t offset = 0;
    int32_t testThreadNum = 100;
    int32_t touchCnt = 1;
    std::string pkg0 = "com.pkg.other:0:-1";
    std::string pkg1 = "com.ss.hm.ugc.aweme:1001:10067";
    std::string pkg2 = "com.wedobest.fivechess.harm:1002:10110";

    HgmFrameRateManager frameRateMgr;
    auto vsyncGenerator = CreateVSyncGenerator();
    sptr<Rosen::VSyncController> rsController = new VSyncController(vsyncGenerator, offset);
    ASSERT_NE(rsController, nullptr);
    sptr<Rosen::VSyncController> appController = new VSyncController(vsyncGenerator, offset);
    ASSERT_NE(appController, nullptr);
    frameRateMgr.Init(rsController, appController, vsyncGenerator);

    ASSERT_NE(vsyncGenerator, nullptr);
    ASSERT_NE(rsController, nullptr);
    ASSERT_NE(appController, nullptr);
    HgmTaskHandleThread::Instance().PostTask([&]() {
        for (int i = 0; i < testThreadNum; i++) {
            // HandleLightFactorStatus
            frameRateMgr.HandleLightFactorStatus(i, true);
            frameRateMgr.HandleLightFactorStatus(i, false);

            // HandlePackageEvent
            frameRateMgr.HandlePackageEvent(i, {pkg0});
            ASSERT_NE(frameRateMgr.multiAppStrategy_.HandlePkgsEvent({pkg0}), EXEC_SUCCESS);
            frameRateMgr.HandlePackageEvent(i, {pkg1});
            ASSERT_NE(frameRateMgr.multiAppStrategy_.HandlePkgsEvent({pkg1}), EXEC_SUCCESS);
            frameRateMgr.HandlePackageEvent(i, {pkg2});
            ASSERT_NE(frameRateMgr.multiAppStrategy_.HandlePkgsEvent({pkg2}), EXEC_SUCCESS);
            frameRateMgr.HandlePackageEvent(i, {pkg0, pkg1});
            ASSERT_NE(frameRateMgr.multiAppStrategy_.HandlePkgsEvent({pkg0, pkg1}), EXEC_SUCCESS);

            // HandleRefreshRateEvent
            frameRateMgr.HandleRefreshRateEvent(i, {});

            // HandleTouchEvent
            frameRateMgr.HandleTouchEvent(i, TouchStatus::TOUCH_DOWN, touchCnt);
            frameRateMgr.HandleTouchEvent(i, TouchStatus::TOUCH_UP, touchCnt);

            // HandleRefreshRateMode
            // param -1、0、1、2、3：refresh rate mode
            frameRateMgr.HandleRefreshRateMode(-1);
            frameRateMgr.HandleRefreshRateMode(0);
            frameRateMgr.HandleRefreshRateMode(1);
            frameRateMgr.HandleRefreshRateMode(2);
            frameRateMgr.HandleRefreshRateMode(3);

            // HandleScreenPowerStatus
            frameRateMgr.HandleScreenPowerStatus(i, ScreenPowerStatus::POWER_STATUS_ON);
            frameRateMgr.HandleScreenPowerStatus(i, ScreenPowerStatus::POWER_STATUS_OFF);
        }
    });
    sleep(1); // wait for handler task finished
}

/**
 * @tc.name: UpdateGuaranteedPlanVoteTest
 * @tc.desc: Verify the result of UpdateGuaranteedPlanVote
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HgmFrameRateMgrTest, UpdateGuaranteedPlanVoteTest, Function | SmallTest | Level1)
{
    std::unique_ptr<HgmFrameRateManager> mgr = std::make_unique<HgmFrameRateManager>();

    mgr->idleDetector_.SetAppSupportedState(false);
    mgr->UpdateGuaranteedPlanVote(currTime);

    mgr->idleDetector_.SetAppSupportedState(true);
    mgr->UpdateGuaranteedPlanVote(currTime);

    mgr->HandleTouchEvent(appPid, TouchStatus::TOUCH_DOWN, touchCount);
    mgr->HandleTouchEvent(appPid, TouchStatus::TOUCH_UP, touchCount);
    std::this_thread::sleep_for(std::chrono::milliseconds(delay_110Ms));
    mgr->UpdateGuaranteedPlanVote(currTime);

    mgr->idleDetector_.bufferFpsMap_["AceAnimato"] = 90;
    mgr->HandleTouchEvent(appPid, TouchStatus::TOUCH_DOWN, touchCount);
    mgr->HandleTouchEvent(appPid, TouchStatus::TOUCH_UP, touchCount);
    std::this_thread::sleep_for(std::chrono::milliseconds(delay_110Ms));
    mgr->UpdateGuaranteedPlanVote(currTime);

    mgr->idleDetector_.SetAceAnimatorIdleState(false);
    mgr->HandleTouchEvent(appPid, TouchStatus::TOUCH_DOWN, touchCount);
    mgr->HandleTouchEvent(appPid, TouchStatus::TOUCH_UP, touchCount);
    std::this_thread::sleep_for(std::chrono::milliseconds(delay_110Ms));
    mgr->UpdateGuaranteedPlanVote(currTime);
    EXPECT_FALSE(mgr->idleDetector_.GetAceAnimatorIdleState());
}

/**
 * @tc.name: CleanPidCallbackTest
 * @tc.desc: Verify the result of CleanPidCallbackTest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HgmFrameRateMgrTest, CleanPidCallbackTest, Function | SmallTest | Level2)
{
    std::unique_ptr<HgmFrameRateManager> mgr = std::make_unique<HgmFrameRateManager>();
    int32_t defaultPid = 0;
    int32_t gamePid = 10024;
    uint32_t undefinedCallbackType = 0xff;
    std::string defaultScreenStrategyId = "LTPO-DEFAULT";
    std::string invalidScreenStrategyId = "DEFAULT-INVALID";
    auto &hgm = HgmCore::Instance();

    mgr->CleanVote(defaultPid);
    mgr->cleanPidCallback_[gamePid].insert(CleanPidCallbackType::TOUCH_EVENT);
    mgr->cleanPidCallback_[gamePid].insert(CleanPidCallbackType::GAMES);
    mgr->cleanPidCallback_[gamePid].insert(static_cast<CleanPidCallbackType>(undefinedCallbackType));
    mgr->CleanVote(gamePid);

    ASSERT_EQ(mgr->sceneStack_.empty(), true);
    mgr->sceneStack_.push_back(std::make_pair("sceneName", 0));
    ASSERT_EQ(mgr->sceneStack_.empty(), false);

    std::string savedScreenStrategyId = mgr->curScreenStrategyId_;
    ASSERT_EQ(savedScreenStrategyId, defaultScreenStrategyId);
    mgr->curScreenStrategyId_ = invalidScreenStrategyId;
    mgr->UpdateVoteRule();
    EXPECT_NE(hgm.mPolicyConfigData_, nullptr);
    std::shared_ptr<PolicyConfigData> cachedPolicyConfigData = nullptr;
    std::swap(hgm.mPolicyConfigData_, cachedPolicyConfigData);
    EXPECT_EQ(hgm.mPolicyConfigData_, nullptr);
    mgr->UpdateVoteRule();
    mgr->curScreenStrategyId_ = savedScreenStrategyId;
    std::swap(hgm.mPolicyConfigData_, cachedPolicyConfigData);
    EXPECT_NE(hgm.mPolicyConfigData_, nullptr);
    auto frameRateMgr = hgm.GetFrameRateMgr();
    auto screenSetting = frameRateMgr->multiAppStrategy_.GetScreenSetting();
    screenSetting.sceneList.insert(make_pair(testScene, PolicyConfigData::SceneConfig{"1", "1"}));
    screenSetting.gameSceneList.insert(make_pair(testScene, "1"));
    screenSetting.ancoSceneList.insert(make_pair(testScene, PolicyConfigData::SceneConfig{"1", "1"}));
    frameRateMgr->multiAppStrategy_.SetScreenSetting(screenSetting);
    EventInfo eventInfo2 = { .eventName = "VOTER_SCENE", .eventStatus = true, .description = testScene };
    frameRateMgr->HandleRefreshRateEvent(0, eventInfo2);
    frameRateMgr->UpdateVoteRule();
    sleep(1);
}

/**
 * @tc.name: HandleEventTest
 * @tc.desc: Verify the result of HandleEventTest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HgmFrameRateMgrTest, HandleEventTest, Function | SmallTest | Level2)
{
    std::string pkg0 = "com.pkg.other:0:-1";
    std::string pkg1 = "com.pkg.other:1:-1";

    std::unique_ptr<HgmFrameRateManager> mgr = std::make_unique<HgmFrameRateManager>();
    auto &hgm = HgmCore::Instance();
    mgr->DeliverRefreshRateVote({"VOTER_GAMES", 120, 90, 0}, true);

    mgr->GetExpectedFrameRate(static_cast<RSPropertyUnit>(0xff), 100.f);
    EXPECT_NE(hgm.mPolicyConfigData_, nullptr);
    std::shared_ptr<PolicyConfigData> cachedPolicyConfigData = nullptr;
    std::swap(hgm.mPolicyConfigData_, cachedPolicyConfigData);
    EXPECT_EQ(hgm.mPolicyConfigData_, nullptr);
    ASSERT_EQ(nullptr, hgm.GetPolicyConfigData());
    mgr->GetPreferredFps("translate", 100.f);

    EventInfo eventInfo = { .eventName = "VOTER_GAMES", .eventStatus = false,
        .description = pkg0,
    };
    mgr->HandleRefreshRateEvent(0, eventInfo);
    mgr->HandleGamesEvent(0, eventInfo);
    eventInfo.eventStatus = true;
    mgr->HandleGamesEvent(0, eventInfo);
    eventInfo.description = pkg1;
    mgr->HandleGamesEvent(0, eventInfo);
    mgr->HandleGamesEvent(1, eventInfo);
    mgr->HandleIdleEvent(true);
    mgr->HandleIdleEvent(false);
    auto screenSetting = mgr->multiAppStrategy_.GetScreenSetting();
    screenSetting.sceneList.insert(make_pair(testScene, PolicyConfigData::SceneConfig{"1", "1"}));
    screenSetting.gameSceneList.insert(make_pair(testScene, "1"));
    screenSetting.ancoSceneList.insert(make_pair(testScene, PolicyConfigData::SceneConfig{"1", "1"}));
    mgr->multiAppStrategy_.SetScreenSetting(screenSetting);
    EventInfo eventInfo2 = { .eventName = "VOTER_SCENE", .eventStatus = true, .description = testScene };
    mgr->HandleRefreshRateEvent(0, eventInfo2);
    eventInfo2.eventStatus = false;
    mgr->HandleRefreshRateEvent(0, eventInfo2);

    std::swap(hgm.mPolicyConfigData_, cachedPolicyConfigData);
    EXPECT_NE(hgm.mPolicyConfigData_, nullptr);
}


/**
 * @tc.name: GetDrawingFrameRateTest
 * @tc.desc: Verify the result of GetDrawingFrameRateTest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HgmFrameRateMgrTest, GetDrawingFrameRateTest, Function | SmallTest | Level2)
{
    std::unique_ptr<HgmFrameRateManager> mgr = std::make_unique<HgmFrameRateManager>();
    uint32_t refreshRate_60 = 60;
    uint32_t refreshRate_120 = 120;
    FrameRateRange dynamic_120(0, 120, 120);
    EXPECT_EQ(dynamic_120.IsDynamic(), true);
    FrameRateRange static_120(120, 120, 120);
    EXPECT_EQ(static_120.IsDynamic(), false);
    auto &hgmCore = HgmCore::Instance();
    HgmFrameRateManager frameRateMgr;
    hgmCore.adaptiveSync_ = ADAPTIVE_SYNC_ENABLED;
    frameRateMgr.isAdaptive_.store(true);
    frameRateMgr.ProcessAdaptiveSync("VOTER_GAMES");
    frameRateMgr.ProcessAdaptiveSync("VOTER_SCENE");
    frameRateMgr.isAdaptive_.store(false);
    frameRateMgr.ProcessAdaptiveSync("VOTER_GAMES");
    EXPECT_EQ(mgr->GetDrawingFrameRate(refreshRate_60, dynamic_120), 60);
    EXPECT_EQ(mgr->GetDrawingFrameRate(refreshRate_60, static_120), 60);
    EXPECT_EQ(mgr->GetDrawingFrameRate(refreshRate_120, dynamic_120), 120);
    EXPECT_EQ(mgr->GetDrawingFrameRate(refreshRate_120, static_120), 120);
}


/**
 * @tc.name: ProcessRefreshRateVoteTest
 * @tc.desc: Verify the result of ProcessRefreshRateVoteTest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HgmFrameRateMgrTest, ProcessRefreshRateVoteTest, Function | SmallTest | Level2)
{
    HgmFrameRateManager frameRateMgr;
    VoteInfo resultVoteInfo;
    VoteRange voteRange = { OLED_MIN_HZ, OLED_MAX_HZ };
    bool voterGamesEffective = false;
    auto voterIter = std::find(frameRateMgr.voters_.begin(), frameRateMgr.voters_.end(), "VOTER_GAMES");
    frameRateMgr.ProcessRefreshRateVote(voterIter, resultVoteInfo, voteRange, voterGamesEffective);
    frameRateMgr.DeliverRefreshRateVote({"VOTER_GAMES", OLED_120_HZ, OLED_90_HZ, OLED_NULL_HZ}, true);
    frameRateMgr.DeliverRefreshRateVote({"VOTER_THERMAL", OLED_120_HZ, OLED_90_HZ, OLED_NULL_HZ}, true);
    frameRateMgr.DeliverRefreshRateVote({"VOTER_MULTISELFOWNEDSCREEN", OLED_120_HZ, OLED_90_HZ, OLED_NULL_HZ}, true);
    auto screenSetting = frameRateMgr.multiAppStrategy_.GetScreenSetting();
    screenSetting.sceneList.insert(make_pair(testScene, PolicyConfigData::SceneConfig{"1", "1"}));
    screenSetting.gameSceneList.insert(make_pair(testScene, "1"));
    screenSetting.ancoSceneList.insert(make_pair(testScene, PolicyConfigData::SceneConfig{"1", "1"}));
    frameRateMgr.multiAppStrategy_.SetScreenSetting(screenSetting);
    EventInfo eventInfo2 = { .eventName = "VOTER_SCENE", .eventStatus = true, .description = testScene };
    frameRateMgr.HandleRefreshRateEvent(0, eventInfo2);
    frameRateMgr.DeliverRefreshRateVote({"VOTER_ANCO", OLED_120_HZ, OLED_90_HZ, OLED_60_HZ}, true);
    auto resVoteInfo = frameRateMgr.ProcessRefreshRateVote();
    EXPECT_EQ(resVoteInfo.min, OLED_MIN_HZ);
}


/**
 * @tc.name: SetAceAnimatorVoteTest
 * @tc.desc: Verify the result of SetAceAnimatorVoteTest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HgmFrameRateMgrTest, SetAceAnimatorVoteTest, Function | SmallTest | Level2)
{
    HgmFrameRateManager frameRateMgr;
    frameRateMgr.SetAceAnimatorVote(nullptr);
    std::shared_ptr<RSRenderFrameRateLinker> linker = std::make_shared<RSRenderFrameRateLinker>();
    ASSERT_NE(linker, nullptr);
    frameRateMgr.SetAceAnimatorVote(linker);
    linker->SetAnimatorExpectedFrameRate(OLED_60_HZ);
    frameRateMgr.SetAceAnimatorVote(linker);
}


/**
 * @tc.name: HgmOneShotTimerTest
 * @tc.desc: Verify the result of HgmOneShotTimerTest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HgmFrameRateMgrTest, HgmOneShotTimerTest, Function | SmallTest | Level2)
{
    auto timer = HgmOneShotTimer("HgmOneShotTimer", std::chrono::milliseconds(delay_60Ms), nullptr, nullptr);
    ASSERT_NE(timer.handler_, nullptr);
    ASSERT_EQ(timer.name_, "HgmOneShotTimer");
    ASSERT_EQ(timer.interval_, std::chrono::milliseconds(delay_60Ms));
    ASSERT_EQ(timer.resetCallback_, nullptr);
    ASSERT_EQ(timer.expiredCallback_, nullptr);
    timer.Start();
    timer.Reset();
    timer.Stop();
    sleep(1); // wait for timer stop
}

/**
 * @tc.name: HgmSimpleTimerTest
 * @tc.desc: Verify the result of HgmSimpleTimerTest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HgmFrameRateMgrTest, HgmSimpleTimerTest, Function | SmallTest | Level2)
{
    auto timer = HgmSimpleTimer("HgmSimpleTimer", std::chrono::milliseconds(delay_60Ms), nullptr, nullptr);
    ASSERT_NE(timer.handler_, nullptr);
    ASSERT_EQ(timer.name_, "HgmSimpleTimer");
    ASSERT_EQ(timer.interval_, std::chrono::milliseconds(delay_60Ms));
    ASSERT_EQ(timer.startCallback_, nullptr);
    ASSERT_EQ(timer.expiredCallback_, nullptr);
    timer.Start();
    timer.Reset();
    timer.Stop();
    sleep(1); // wait for timer stop
}

/**
 * @tc.name: HgmRsIdleTimerTest
 * @tc.desc: Verify the result of HgmRsIdleTimerTest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HgmFrameRateMgrTest, HgmRsIdleTimerTest, Function | SmallTest | Level2)
{
    int32_t interval = 700; // 700ms waiting time
    HgmFrameRateManager mgr;
    mgr.InitRsIdleTimer();
    ASSERT_NE(mgr.rsIdleTimer_, nullptr);
    std::this_thread::sleep_for(std::chrono::milliseconds(interval));
    mgr.HandleRsFrame();
    mgr.minIdleFps_ = OLED_30_HZ;
    std::this_thread::sleep_for(std::chrono::milliseconds(interval));
    sleep(1); // wait for timer stop
}

/**
 * @tc.name: FrameRateReportTest
 * @tc.desc: Verify the result of FrameRateReportTest
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HgmFrameRateMgrTest, FrameRateReportTest, Function | SmallTest | Level2)
{
    HgmFrameRateManager mgr;
    mgr.FrameRateReport();
    mgr.curRefreshRateMode_ = HGM_REFRESHRATE_MODE_HIGH;
    mgr.FrameRateReport();
    EXPECT_EQ(mgr.schedulePreferredFpsChange_, false);
}

/**
 * @tc.name: CollectFrameRateChange
 * @tc.desc: Verify the result of CollectFrameRateChange
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HgmFrameRateMgrTest, CollectFrameRateChange, Function | SmallTest | Level2)
{
    HgmFrameRateManager mgr;
    InitHgmFrameRateManager(mgr);
    FrameRateRange finalRange = {OLED_60_HZ, OLED_120_HZ, OLED_60_HZ};
    FrameRateRange appExpectedRange = {OLED_60_HZ, OLED_120_HZ, OLED_72_HZ};
    std::shared_ptr<RSRenderFrameRateLinker> rsFrameRateLinker = std::make_shared<RSRenderFrameRateLinker>();
    std::shared_ptr<RSRenderFrameRateLinker> appFrameRateLinker = std::make_shared<RSRenderFrameRateLinker>();
    appFrameRateLinker->SetExpectedRange(appExpectedRange);

    FrameRateLinkerMap appFrameRateLinkers = {
        {frameRateLinkerId1, nullptr},
        {frameRateLinkerId2, appFrameRateLinker}
    };
    EXPECT_EQ(mgr.CollectFrameRateChange(finalRange, rsFrameRateLinker, appFrameRateLinkers), false);
    mgr.controller_ = nullptr;
    EXPECT_EQ(mgr.CollectFrameRateChange(finalRange, rsFrameRateLinker, appFrameRateLinkers), false);
}


/**
 * @tc.name: HandleFrameRateChangeForLTPO
 * @tc.desc: Verify the result of HandleFrameRateChangeForLTPO
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HgmFrameRateMgrTest, HandleFrameRateChangeForLTPO, Function | SmallTest | Level2)
{
    auto &hgmCore = HgmCore::Instance();
    auto frameRateMgr = hgmCore.GetFrameRateMgr();
    hgmCore.SetPendingScreenRefreshRate(OLED_30_HZ);
    frameRateMgr->currRefreshRate_ = OLED_120_HZ;
    hgmCore.lowRateToHighQuickSwitch_.store(false);
    frameRateMgr->HandleFrameRateChangeForLTPO(0, false);
    hgmCore.lowRateToHighQuickSwitch_.store(true);
    frameRateMgr->HandleFrameRateChangeForLTPO(0, false);
    frameRateMgr->forceUpdateCallback_ = nullptr;
    frameRateMgr->HandleFrameRateChangeForLTPO(0, false);
    frameRateMgr->forceUpdateCallback_ = [](bool idleTimerExpired, bool forceUpdate) { return; };
    frameRateMgr->HandleFrameRateChangeForLTPO(0, false);
    EXPECT_EQ(frameRateMgr->GetPreferredFps("translate", errorVelocity), 0);
}

/**
 * @tc.name: GetLowBrightVec
 * @tc.desc: Verify the result of GetLowBrightVec
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HgmFrameRateMgrTest, GetLowBrightVec, Function | SmallTest | Level2)
{
    HgmFrameRateManager mgr;
    std::shared_ptr<PolicyConfigData> configData = std::make_shared<PolicyConfigData>();

    std::vector<std::string> screenConfigs = {"LTPO-DEFAULT", "LTPO-internal", "LTPO-external"};
    for (const auto& screenConfig : screenConfigs) {
        auto iter = configData->supportedModeConfigs_.find(screenConfig);
        if (iter == configData-> supportedModeConfigs_.end()) {
            continue;
        }

        auto& supportedModeConfig = iter->second;
        auto vec = supportedModeConfig.find("LowBright");

        if (vec == supportedModeConfig.end()) {
            continue;
        }

        supportedModeConfig["LowBright"].clear();
        mgr.GetLowBrightVec(configData);
        ASSERT_EQ(mgr.isAmbientEffect_, false);
        ASSERT_TRUE(mgr.lowBrightVec_.empty());

        std::vector<uint32_t> expectedLowBrightVec = {30, 60, 90};
        supportedModeConfig["LowBright"] = expectedLowBrightVec;
        mgr.GetLowBrightVec(configData);
        ASSERT_EQ(mgr.isAmbientEffect_, true);
        ASSERT_EQ(mgr.lowBrightVec_, expectedLowBrightVec);
    }
}

/**
 * @tc.name: GetDrawingFrameRate
 * @tc.desc: Verify the result of HandleFrameRateChangeForLTPO
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HgmFrameRateMgrTest, GetDrawingFrameRate, Function | SmallTest | Level2)
{
    HgmFrameRateManager mgr;
    FrameRateRange finalRange = {OLED_60_HZ, OLED_90_HZ, OLED_60_HZ};
    mgr.GetDrawingFrameRate(OLED_120_HZ, finalRange);
    FrameRateRange finalRange2 = {OLED_50_HZ, OLED_80_HZ, OLED_80_HZ};
    EXPECT_EQ(mgr.GetDrawingFrameRate(OLED_90_HZ, finalRange), OLED_90_HZ);
}

/**
 * @tc.name: HandleScreenPowerStatus
 * @tc.desc: Verify the result of HandleScreenPowerStatus
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HgmFrameRateMgrTest, HandleScreenPowerStatus, Function | SmallTest | Level1)
{
    ScreenId extraScreenId = 1;
    auto &hgmCore = HgmCore::Instance();
    auto frameRateMgr = hgmCore.GetFrameRateMgr();
    auto configData = hgmCore.GetPolicyConfigData();
    if (configData == nullptr || frameRateMgr == nullptr) {
        return;
    }
    // init
    configData->screenStrategyConfigs_["screen0_LTPS"] = "LTPS-DEFAULT";
    configData->screenStrategyConfigs_["screen0_LTPO"] = "LTPO-DEFAULT";
    configData->screenStrategyConfigs_["screen5_LTPS"] = "LTPS-DEFAULT";
    configData->screenStrategyConfigs_["screen5_LTPO"] = "LTPO-DEFAULT";
    EXPECT_EQ(hgmCore.AddScreen(externalScreenId, 0, screenSize), EXEC_SUCCESS);
    EXPECT_EQ(hgmCore.AddScreen(internalScreenId, 0, screenSize), EXEC_SUCCESS);

    // fold -> expand -> fold
    frameRateMgr->HandleScreenPowerStatus(internalScreenId, ScreenPowerStatus::POWER_STATUS_SUSPEND);
    frameRateMgr->HandleScreenPowerStatus(externalScreenId, ScreenPowerStatus::POWER_STATUS_ON);
    EXPECT_EQ(frameRateMgr->curScreenId_, externalScreenId);
    EXPECT_EQ(hgmCore.AddScreen(extraScreenId, 0, screenSize), EXEC_SUCCESS);
    EXPECT_EQ(frameRateMgr->curScreenId_, externalScreenId);
    EXPECT_EQ(hgmCore.RemoveScreen(extraScreenId), EXEC_SUCCESS);
    EXPECT_EQ(frameRateMgr->curScreenId_, externalScreenId);

    EXPECT_EQ(hgmCore.AddScreen(extraScreenId, 0, screenSize), EXEC_SUCCESS);
    frameRateMgr->HandleScreenPowerStatus(externalScreenId, ScreenPowerStatus::POWER_STATUS_SUSPEND);
    frameRateMgr->HandleScreenPowerStatus(internalScreenId, ScreenPowerStatus::POWER_STATUS_ON);
    EXPECT_EQ(frameRateMgr->curScreenId_, internalScreenId);
    EXPECT_EQ(hgmCore.RemoveScreen(extraScreenId), EXEC_SUCCESS);
    EXPECT_EQ(frameRateMgr->curScreenId_, internalScreenId);

    EXPECT_EQ(hgmCore.AddScreen(extraScreenId, 0, screenSize), EXEC_SUCCESS);
    EXPECT_EQ(frameRateMgr->curScreenId_, internalScreenId);
    EXPECT_EQ(hgmCore.RemoveScreen(extraScreenId), EXEC_SUCCESS);

    EXPECT_EQ(hgmCore.AddScreen(extraScreenId, 0, screenSize), EXEC_SUCCESS);
    frameRateMgr->HandleScreenPowerStatus(internalScreenId, ScreenPowerStatus::POWER_STATUS_SUSPEND);
    frameRateMgr->HandleScreenPowerStatus(externalScreenId, ScreenPowerStatus::POWER_STATUS_ON);
    EXPECT_EQ(frameRateMgr->curScreenId_, externalScreenId);
    EXPECT_EQ(hgmCore.RemoveScreen(extraScreenId), EXEC_SUCCESS);
    EXPECT_EQ(frameRateMgr->curScreenId_, externalScreenId);

    // expand -> multiScreen -> expand
    frameRateMgr->HandleScreenPowerStatus(externalScreenId, ScreenPowerStatus::POWER_STATUS_SUSPEND);
    frameRateMgr->HandleScreenPowerStatus(internalScreenId, ScreenPowerStatus::POWER_STATUS_ON);
    EXPECT_EQ(frameRateMgr->curScreenId_, internalScreenId);

    hgmCore.SetMultiSelfOwnedScreenEnable(true);
    frameRateMgr->HandleScreenPowerStatus(externalScreenId, ScreenPowerStatus::POWER_STATUS_ON);
    EXPECT_EQ(frameRateMgr->curScreenId_, internalScreenId);

    hgmCore.SetMultiSelfOwnedScreenEnable(false);
    frameRateMgr->HandleScreenPowerStatus(externalScreenId, ScreenPowerStatus::POWER_STATUS_SUSPEND);
    EXPECT_EQ(frameRateMgr->curScreenId_, internalScreenId);
}

/**
 * @tc.name: HandlePackageEvent
 * @tc.desc: Verify the result of HandlePackageEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HgmFrameRateMgrTest, HandlePackageEvent, Function | SmallTest | Level1)
{
    auto &hgmCore = HgmCore::Instance();
    auto frameRateMgr = hgmCore.GetFrameRateMgr();
    if (frameRateMgr == nullptr) {
        return;
    }
    std::string pkgName0 = "com.pkg0";
    std::string pkgName1 = "com.pkg1";
    std::string scene0 = "SCENE0";
    std::string scene1 = "SCENE1";
    std::string scene2 = "SCENE2";

    auto sceneListConfig = frameRateMgr->GetMultiAppStrategy().GetScreenSetting();
    sceneListConfig.sceneList[scene0] = {"1", "1", false};
    sceneListConfig.sceneList[scene1] = {"1", "1", true};
    sceneListConfig.gameSceneList[scene0] = {"1", "1"};

    frameRateMgr->GetMultiAppStrategy().SetScreenSetting(sceneListConfig);

    auto checkFunc = [frameRateMgr, scene0, scene1] (bool scene0Existed, bool scene1Existed, bool gameScene0Existed,
                                                     bool gameScene1Existed) {
        auto sceneStack = frameRateMgr->sceneStack_;
        EXPECT_EQ(std::find(sceneStack.begin(), sceneStack.end(),
            std::pair<std::string, pid_t>({scene0, DEFAULT_PID})) != sceneStack.end(), scene0Existed);
        EXPECT_EQ(std::find(sceneStack.begin(), sceneStack.end(),
            std::pair<std::string, pid_t>({scene1, DEFAULT_PID})) != sceneStack.end(), scene1Existed);

        auto gameScenes = frameRateMgr->gameScenes_;
        EXPECT_EQ(gameScenes.find(scene0) != gameScenes.end(), gameScene0Existed);
        EXPECT_EQ(gameScenes.find(scene1) != gameScenes.end(), gameScene1Existed);
    };

    frameRateMgr->HandleSceneEvent(DEFAULT_PID, {"VOTER_SCENE", true, OLED_NULL_HZ, OLED_MAX_HZ, scene0});
    checkFunc(true, false, true, false);

    frameRateMgr->HandlePackageEvent(DEFAULT_PID, {pkgName0});
    checkFunc(false, false, false, false);

    // multi scene
    frameRateMgr->HandleSceneEvent(DEFAULT_PID, {"VOTER_SCENE", true, OLED_NULL_HZ, OLED_MAX_HZ, scene0});
    frameRateMgr->HandleSceneEvent(DEFAULT_PID, {"VOTER_SCENE", true, OLED_NULL_HZ, OLED_MAX_HZ, scene1});
    checkFunc(true, true, true, false);

    frameRateMgr->HandlePackageEvent(DEFAULT_PID, {pkgName1});
    checkFunc(false, true, false, false);
}

/**
 * @tc.name: ChangePriority
 * @tc.desc: Verify the result of ChangePriority
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(HgmFrameRateMgrTest, ChangePriority, Function | SmallTest | Level1)
{
    constexpr uint32_t DEFAULT_PRIORITY = 0;
    constexpr uint32_t VOTER_SCENE_PRIORITY_BEFORE_PACKAGES = 1;
    constexpr uint32_t VOTER_LTPO_PRIORITY_BEFORE_PACKAGES = 2;
    auto &hgmCore = HgmCore::Instance();
    auto frameRateMgr = hgmCore.GetFrameRateMgr();
    if (frameRateMgr == nullptr) {
        return;
    }
    
    frameRateMgr->ChangePriority(DEFAULT_PRIORITY);
    auto packagesPos = find(frameRateMgr->voters_.begin(), frameRateMgr->voters_.end(), "VOTER_PACKAGES");
    auto ltpoPos = find(frameRateMgr->voters_.begin(), frameRateMgr->voters_.end(), "VOTER_LTPO");
    auto scenePos = find(frameRateMgr->voters_.begin(), frameRateMgr->voters_.end(), "VOTER_SCENE");
    ASSERT_LT(packagesPos, ltpoPos);
    ASSERT_LT(ltpoPos, scenePos);
    frameRateMgr->ChangePriority(VOTER_SCENE_PRIORITY_BEFORE_PACKAGES);
    auto packagesPos1 = find(frameRateMgr->voters_.begin(), frameRateMgr->voters_.end(), "VOTER_PACKAGES");
    auto ltpoPos1 = find(frameRateMgr->voters_.begin(), frameRateMgr->voters_.end(), "VOTER_LTPO");
    auto scenePos1 = find(frameRateMgr->voters_.begin(), frameRateMgr->voters_.end(), "VOTER_SCENE");
    ASSERT_LT(scenePos1, packagesPos1);
    ASSERT_LT(packagesPos1, ltpoPos1);
    frameRateMgr->ChangePriority(VOTER_LTPO_PRIORITY_BEFORE_PACKAGES);
    auto packagesPos2 = find(frameRateMgr->voters_.begin(), frameRateMgr->voters_.end(), "VOTER_PACKAGES");
    auto ltpoPos2 = find(frameRateMgr->voters_.begin(), frameRateMgr->voters_.end(), "VOTER_LTPO");
    auto scenePos2 = find(frameRateMgr->voters_.begin(), frameRateMgr->voters_.end(), "VOTER_SCENE");
    ASSERT_LT(scenePos2, ltpoPos2);
    ASSERT_LT(ltpoPos2, packagesPos2);
}
} // namesace Rosen
} // namesppace OHOS
