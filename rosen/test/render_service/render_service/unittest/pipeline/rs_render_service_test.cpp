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

#include "feature/param_manager/rs_param_manager.h"
#include "gtest/gtest.h"
#include "limit_number.h"
#include "parameters.h"
#include "pipeline/main_thread/rs_main_thread.h"
#include "pipeline/main_thread/rs_render_service.h"
#include "screen_manager/rs_screen_manager.h"
#include "gfx/dump/rs_dump_manager.h"
#include "want.h"

using namespace testing;
using namespace testing::ext;


namespace OHOS::Rosen {
class RSRenderServiceUnitTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void RSRenderServiceUnitTest::SetUpTestCase() {}
void RSRenderServiceUnitTest::TearDownTestCase() {}
void RSRenderServiceUnitTest::SetUp() {}
void RSRenderServiceUnitTest::TearDown() {}

sptr<RSRenderService> GetAndInitRenderService()
{
    sptr<RSRenderService> renderService(new RSRenderService());
    if (renderService) {
        renderService->mainThread_ = RSMainThread::Instance();
        renderService->screenManager_ = CreateOrGetScreenManager();
    }
    if (renderService->mainThread_) {
        renderService->mainThread_->runner_ = AppExecFwk::EventRunner::Create(true);
        renderService->mainThread_->handler_ =
            std::make_shared<AppExecFwk::EventHandler>(renderService->mainThread_->runner_);
    }
    return renderService;
}

std::string GetDumpResult(sptr<RSRenderService> renderService, std::u16string arg)
{
    std::string dumpString = "";
    std::unordered_set<std::u16string> argSet = { arg };
    renderService->DoDump(argSet, dumpString);
    return dumpString;
}

/**
 * @tc.name: TestRemoveConnection001
 * @tc.desc: RemoveConnection test.
 * @tc.type: FUNC
 * @tc.require: issueI7G75T
 */
HWTEST_F(RSRenderServiceUnitTest, TestRemoveConnection001, TestSize.Level1)
{
    sptr<RSRenderService> renderService(new RSRenderService());
    ASSERT_NE(renderService, nullptr);
    renderService->RemoveConnection(nullptr);
}

/**
 * @tc.name: DoDump001
 * @tc.desc: test DoDump, with empty arg sets.
 * @tc.type: FUNC
 * @tc.require: issueIAJCOS
 */
HWTEST_F(RSRenderServiceUnitTest, DoDump001, TestSize.Level1)
{
    auto renderService = GetAndInitRenderService();
    ASSERT_NE(renderService, nullptr);
    ASSERT_NE(renderService->mainThread_, nullptr);
    ASSERT_NE(renderService->screenManager_, nullptr);

    auto dumpResult = GetDumpResult(renderService, u"");
    ASSERT_NE(dumpResult.size(), 0);
}

/**
 * @tc.name: DoDump002
 * @tc.desc: test DoDump, with key-word allinfo.
 * @tc.type: FUNC
 * @tc.require: issueIAJCOS
 */
HWTEST_F(RSRenderServiceUnitTest, DoDump002, TestSize.Level1)
{
    auto renderService = GetAndInitRenderService();
    ASSERT_NE(renderService, nullptr);
    ASSERT_NE(renderService->mainThread_, nullptr);
    ASSERT_NE(renderService->screenManager_, nullptr);

    auto dumpResult = GetDumpResult(renderService, u"allInfo");
    ASSERT_NE(dumpResult.size(), 0);
}

// resolve the problem of super-lager function.
void DoDumpSingleArg(sptr<RSRenderService> renderService)
{
    std::string dumpResult = "";
    
    dumpResult = GetDumpResult(renderService, u"screen");
    ASSERT_TRUE(dumpResult.find("screen") != std::string::npos);

    dumpResult = GetDumpResult(renderService, u"surface");
    ASSERT_TRUE(dumpResult.find("surface") != std::string::npos);

    dumpResult = GetDumpResult(renderService, u"fps Surface");
    ASSERT_TRUE(dumpResult.find("fps") != std::string::npos);

    dumpResult = GetDumpResult(renderService, u"fps DisplayNode");
    ASSERT_TRUE(dumpResult.find("fps") != std::string::npos);

    dumpResult = GetDumpResult(renderService, u"nodeNotOnTree");
    ASSERT_TRUE(dumpResult.find("nodeNotOnTree") != std::string::npos);

    dumpResult = GetDumpResult(renderService, u"allSurfacesMem");
    ASSERT_TRUE(dumpResult.find("allSurfacesMem") != std::string::npos);

    dumpResult = GetDumpResult(renderService, u"RSTree");
    ASSERT_TRUE(dumpResult.find("RSTree") != std::string::npos);

    dumpResult = GetDumpResult(renderService, u"MultiRSTrees");
    ASSERT_TRUE(dumpResult.find("MultiRSTrees") != std::string::npos);

    dumpResult = GetDumpResult(renderService, u"EventParamList");
    ASSERT_TRUE(dumpResult.find("EventParamList") != std::string::npos);

    dumpResult = GetDumpResult(renderService, u"h");
    ASSERT_TRUE(dumpResult.find("help") != std::string::npos);

    dumpResult = GetDumpResult(renderService, u"trimMem");
    ASSERT_TRUE(dumpResult.find("trimMem") != std::string::npos);

    dumpResult = GetDumpResult(renderService, u"dumpMem");
    ASSERT_TRUE(dumpResult.find("dumpMem") != std::string::npos);

    dumpResult = GetDumpResult(renderService, u"surfacenode");
    ASSERT_TRUE(dumpResult.find("surfacenode") != std::string::npos);

    dumpResult = GetDumpResult(renderService, u"fpsClear Surface");
    ASSERT_TRUE(dumpResult.find("fpsClear") != std::string::npos);

    dumpResult = GetDumpResult(renderService, u"fpsClear DisplayNode");
    ASSERT_TRUE(dumpResult.find("fpsClear") != std::string::npos);

    dumpResult = GetDumpResult(renderService, u"fpsCount");
    ASSERT_TRUE(dumpResult.find("fpsCount") != std::string::npos);

    dumpResult = GetDumpResult(renderService, u"clearFpsCount");
    ASSERT_TRUE(dumpResult.find("clearFpsCount") != std::string::npos);

    dumpResult = GetDumpResult(renderService, u"hitchs");
    ASSERT_TRUE(dumpResult.find("hitchs") != std::string::npos);

    dumpResult = GetDumpResult(renderService, u"rsLogFlag");
    ASSERT_TRUE(dumpResult.find("rsLogFlag") != std::string::npos);

    dumpResult = GetDumpResult(renderService, u"flushJankStatsRs");
    ASSERT_TRUE(dumpResult.find("flushJankStatsRs") != std::string::npos);

    dumpResult = GetDumpResult(renderService, u"client");
    ASSERT_TRUE(dumpResult.find("client") != std::string::npos);
}

/**
 * @tc.name: DoDump003
 * @tc.desc: test DoDump, with different single arg.
 * @tc.type: FUNC
 * @tc.require: issueIAJCOS
 */
HWTEST_F(RSRenderServiceUnitTest, DoDump003, TestSize.Level1)
{
    auto renderService = GetAndInitRenderService();
    ASSERT_NE(renderService, nullptr);
    ASSERT_NE(renderService->mainThread_, nullptr);
    ASSERT_NE(renderService->screenManager_, nullptr);

    DoDumpSingleArg(renderService);
}

/**
 * @tc.name: RSGfxDumpInit001
 * @tc.desc: test RSGfxDumpInit
 * @tc.type: FUNC
 * @tc.require: issueIAJCOS
 */
HWTEST_F(RSRenderServiceUnitTest, RSGfxDumpInit001, TestSize.Level1)
{
    auto renderService = GetAndInitRenderService();
    ASSERT_NE(renderService, nullptr);

    ASSERT_EQ(RSDumpManager::GetInstance().rsDumpHanderMap_.size(), 1);
    renderService->RSGfxDumpInit();
    ASSERT_NE(RSDumpManager::GetInstance().rsDumpHanderMap_.size(), 1);
}

/**
 * @tc.name: RSParamManager001
 * @tc.desc: test RSParamManager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSRenderServiceUnitTest, RSParamManager001, TestSize.Level1)
{
    RSParamManager& paramManager = RSParamManager::GetInstance();
    paramManager.SubscribeEvent();
    ASSERT_NE(paramManager.handleEventFunc_.size(), 0);
    paramManager.UnSubscribeEvent();
}

/**
 * @tc.name: RSParamManager002
 * @tc.desc: test RSParamManager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSRenderServiceUnitTest, RSParamManager002, TestSize.Level1)
{
    RSParamManager& paramManager = RSParamManager::GetInstance();
    paramManager.SubscribeEvent();
    OHOS::AAFwk::Want want;
    want.SetAction("usual.event.DUE_SA_CFG_UPDATED");
    paramManager.OnReceiveEvent(want);
    paramManager.HandleParamUpdate(want);
    int restartParameter = std::atoi(system::GetParameter("debug.graphic.cloudpushrestart", "0").c_str());
    int cloudParameter = std::atoi(system::GetParameter("persist.rosen.disableddgr.enabled", "0").c_str());
    ASSERT_EQ(restartParameter, 1);
    ASSERT_EQ(cloudParameter, 0);
    paramManager.UnSubscribeEvent();
}

/**
 * @tc.name: RSParamManager003
 * @tc.desc: test RSParamManager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSRenderServiceUnitTest, RSParamManager003, TestSize.Level1)
{
    RSParamManager& paramManager = RSParamManager::GetInstance();
    paramManager.SubscribeEvent();
    OHOS::AAFwk::Want want;
    want.SetAction("unexpected_action");
    paramManager.OnReceiveEvent(want);
    paramManager.HandleParamUpdate(want);
    int restartParameter = std::atoi(system::GetParameter("debug.graphic.cloudpushrestart", "0").c_str());
    int cloudParameter = std::atoi(system::GetParameter("persist.rosen.disableddgr.enabled", "0").c_str());
    ASSERT_EQ(restartParameter, 0);
    ASSERT_EQ(cloudParameter, 0);
    paramManager.UnSubscribeEvent();
}

/**
 * @tc.name: RSParamManager004
 * @tc.desc: test RSParamManager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSRenderServiceUnitTest, RSParamManager004, TestSize.Level1)
{
    RSParamManager& paramManager = RSParamManager::GetInstance();
    bool isCloud = paramManager.IsCloudDisableDDGR();
    ASSERT_FALSE(isCloud);
    paramManager.GetHigherVersionPath();
    std::string filePath = "";
    paramManager.GetVersionNums(filePath);
    std::string versionStr = "version=5.0.0.0";
    std::vector<std::string> versionStrSplit = paramManager.SplitString(versionStr, '=');
    ASSERT_EQ(versionStrSplit.size(), 2);
    std::vector<std::string> localVersion = {"4", "0", "0", "0"};
    std::vector<std::string> cloudVersion = {"5", "0", "0", "0"};
    bool versionCompare = paramManager.CompareVersion(localVersion, cloudVersion);
    ASSERT_TRUE(versionCompare);
}

/**
 * @tc.name  : GRSParamManager005
 * @tc.desc  : test RSParamManager
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSRenderServiceUnitTest, RSParamManager005, TestSize.Level1) {
    RSParamManager& paramManager = RSParamManager::GetInstance();
    std::vector<std::string> localVersion1 = {"5", "0", "0", "0"};
    std::vector<std::string> cloudVersion1 = {"4", "0", "0", "0"};
    bool versionCompare1 = paramManager.CompareVersion(localVersion1, cloudVersion1);
    ASSERT_FALSE(versionCompare1);
    std::vector<std::string> localVersion2 = {"5", "0", "0", "0"};
    std::vector<std::string> cloudVersion2 = {"5", "a", "0", "0"};
    bool versionCompare2 = paramManager.CompareVersion(localVersion2, cloudVersion2);
    ASSERT_FALSE(versionCompare2);
}

} // namespace OHOS::Rosen
