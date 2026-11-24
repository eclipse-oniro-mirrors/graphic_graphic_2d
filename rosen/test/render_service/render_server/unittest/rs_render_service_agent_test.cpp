/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, Hardware
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "gtest/gtest.h"

#include <atomic>
#include <chrono>
#include <future>
#include <refbase.h>
#include <iremote_broker.h>

#include "parameters.h"
#include "rs_render_service_agent.h"
#include "rs_render_process_manager.h"
#include "rs_render_service.h"
#include "rs_render_to_composer_connection_proxy.h"
#include "rs_render_to_composer_connection.h"
#include "common/rs_samgr_retry.h"
#include "pipeline/render_thread/rs_uni_render_thread.h"
#include "rs_render_composer_agent.h"
#include "rs_render_composer_manager.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::Rosen {
namespace {
sptr<RSRenderServiceAgent> g_rsAgent = nullptr;
} // namespace

class RSRenderServiceAgentTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void RSRenderServiceAgentTest::SetUpTestCase()
{
    OHOS::system::SetParameter("bootevent.samgr.ready", "false");
}
void RSRenderServiceAgentTest::TearDownTestCase()
{
    g_rsAgent = nullptr;
}
void RSRenderServiceAgentTest::SetUp() {}
void RSRenderServiceAgentTest::TearDown() {}

/**
 * @tc.name: PostTaskImmediate001
 * @tc.desc: PostTaskImmediate Test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSRenderServiceAgentTest, PostTaskImmediate001, TestSize.Level1)
{
    auto renderService = sptr<RSRenderService>::MakeSptr();
    renderService->runner_ = AppExecFwk::EventRunner::Create(false);
    renderService->handler_ = std::make_shared<AppExecFwk::EventHandler>(renderService->runner_);
    sptr<RSRenderServiceAgent> renderServiceAgent = sptr<RSRenderServiceAgent>::MakeSptr(*renderService);
    ASSERT_NE(renderServiceAgent, nullptr);
    RSTaskMessage::RSTask task = []() -> void { return; };
    renderServiceAgent->PostTaskImmediate(task);
}

/**
 * @tc.name: PostTaskImmediateInPlace001
 * @tc.desc: PostTaskImmediateInPlace Test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSRenderServiceAgentTest, PostTaskImmediateInPlace001, TestSize.Level1)
{
    auto renderService = sptr<RSRenderService>::MakeSptr();
    renderService->runner_ = AppExecFwk::EventRunner::Create(false);
    renderService->handler_ = std::make_shared<AppExecFwk::EventHandler>(renderService->runner_);
    sptr<RSRenderServiceAgent> renderServiceAgent = sptr<RSRenderServiceAgent>::MakeSptr(*renderService);
    ASSERT_NE(renderServiceAgent, nullptr);
    RSTaskMessage::RSTask task = []() -> void { return; };
    renderServiceAgent->PostTaskImmediateInPlace(task);
}

/**
 * @tc.name: PostSyncTaskImmediate001
 * @tc.desc: PostSyncTaskImmediate Test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSRenderServiceAgentTest, PostSyncTaskImmediate001, TestSize.Level1)
{
    auto renderService = sptr<RSRenderService>::MakeSptr();
    renderService->runner_ = AppExecFwk::EventRunner::Create(false);
    renderService->handler_ = std::make_shared<AppExecFwk::EventHandler>(renderService->runner_);
    sptr<RSRenderServiceAgent> renderServiceAgent = sptr<RSRenderServiceAgent>::MakeSptr(*renderService);
    ASSERT_NE(renderServiceAgent, nullptr);
    RSTaskMessage::RSTask task = []() -> void { return; };
    renderServiceAgent->PostSyncTaskImmediate(task);
}

/**
 * @tc.name: ScheduleTask001
 * @tc.desc: ScheduleTask Test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSRenderServiceAgentTest, ScheduleTask001, TestSize.Level1)
{
    auto renderService = sptr<RSRenderService>::MakeSptr();
    renderService->runner_ = AppExecFwk::EventRunner::Create(false);
    renderService->handler_ = std::make_shared<AppExecFwk::EventHandler>(renderService->runner_);
    sptr<RSRenderServiceAgent> renderServiceAgent = sptr<RSRenderServiceAgent>::MakeSptr(*renderService);
    auto task = []() {};
    auto future = renderServiceAgent->ScheduleTask(std::move(task));
    ASSERT_EQ(future.valid(), true);
}

/**
 * @tc.name: HandleGameSceneChanged001
 * @tc.desc: HandleGameSceneChanged Test with RsGameFrameHandler nullptr.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSRenderServiceAgentTest, HandleGameSceneChanged001, TestSize.Level1)
{
    auto renderService = sptr<RSRenderService>::MakeSptr();
    auto vsyncManager = sptr<RSVsyncManager>::MakeSptr();
    auto screenManager = sptr<RSScreenManager>::MakeSptr();
    ASSERT_NE(renderService, nullptr);
    ASSERT_NE(vsyncManager, nullptr);
    ASSERT_NE(screenManager, nullptr);
    vsyncManager->init(screenManager);
    renderService->vsyncManager_ = vsyncManager;
    sptr<RSRenderServiceAgent> renderServiceAgent = sptr<RSRenderServiceAgent>::MakeSptr(*renderService);
    ASSERT_NE(renderServiceAgent, nullptr);
    auto& handler = renderService->GetGameFrameHandler();
    ASSERT_EQ(handler, nullptr);
    renderServiceAgent->HandleGameSceneChanged();
}

/**
 * @tc.name: HandleGameSceneChanged002
 * @tc.desc: HandleGameSceneChanged Test with RsGameFrameHandler.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSRenderServiceAgentTest, HandleGameSceneChanged002, TestSize.Level1)
{
    auto renderService = sptr<RSRenderService>::MakeSptr();
    auto vsyncManager = sptr<RSVsyncManager>::MakeSptr();
    auto screenManager = sptr<RSScreenManager>::MakeSptr();
    ASSERT_NE(renderService, nullptr);
    ASSERT_NE(vsyncManager, nullptr);
    ASSERT_NE(screenManager, nullptr);
    vsyncManager->init(screenManager);
    renderService->vsyncManager_ = vsyncManager;
    sptr<RSRenderServiceAgent> renderServiceAgent = sptr<RSRenderServiceAgent>::MakeSptr(*renderService);
    ASSERT_NE(renderServiceAgent, nullptr);
    renderService->InitGameFrameHandler();
    auto& handler = renderService->GetGameFrameHandler();
    ASSERT_NE(handler, nullptr);
    renderServiceAgent->HandleGameSceneChanged();
}

/**
 * @tc.name: GetProcessInfo001
 * @tc.desc: GetProcessInfo Test with null vsyncToken.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSRenderServiceAgentTest, GetProcessInfo001, TestSize.Level1)
{
    auto renderService = sptr<RSRenderService>::MakeSptr();
    ASSERT_NE(renderService, nullptr);
    auto runner = AppExecFwk::EventRunner::Create(false);
    renderService->handler_ = std::make_shared<AppExecFwk::EventHandler>(runner);
    renderService->screenManager_ = sptr<RSScreenManager>::MakeSptr();
    renderService->vsyncManager_ = sptr<RSVsyncManager>::MakeSptr();
    renderService->vsyncManager_->init(renderService->screenManager_);
    renderService->rsRenderComposerManager_ = std::make_shared<RSRenderComposerManager>(renderService->handler_);
    sptr<RSRenderServiceAgent> renderServiceAgent = sptr<RSRenderServiceAgent>::MakeSptr(*renderService);
    ASSERT_NE(renderServiceAgent, nullptr);
    ScreenId screenId = 0;
    sptr<IRemoteObject> vsyncToken = nullptr;
    auto result = renderServiceAgent->GetProcessInfo(screenId, vsyncToken);
    EXPECT_EQ(result.first, nullptr);
    EXPECT_NE(result.second, nullptr);
}

/**
 * @tc.name: RegisterHgmProcessCallback001
 * @tc.desc: RegisterHgmProcessCallback Test.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSRenderServiceAgentTest, RegisterHgmProcessCallback001, TestSize.Level1)
{
    auto renderService = sptr<RSRenderService>::MakeSptr();
    ASSERT_NE(renderService, nullptr);
    sptr<RSRenderServiceAgent> renderServiceAgent = sptr<RSRenderServiceAgent>::MakeSptr(*renderService);
    ASSERT_NE(renderServiceAgent, nullptr);
    HgmProcessCallback callback = [](uint64_t, uint64_t,
        const sptr<HgmProcessToServiceInfo>&, const sptr<HgmServiceToProcessInfo>&) -> void {};
    renderServiceAgent->RegisterHgmProcessCallback(callback);
    renderServiceAgent->RegisterHgmProcessCallback(nullptr);
}

/**
 * @tc.name: RetrySamgrCall001
 * @tc.desc: RetrySamgrCall returns true when the call succeeds immediately
 * @tc.type: FUNC
 * @tc.require: issue#26808
 */
HWTEST_F(RSRenderServiceAgentTest, RetrySamgrCall001, TestSize.Level1)
{
    auto result = RetrySamgrCall("RetrySamgrCall001", [](const sptr<ISystemAbilityManager>&) {
        return ERR_OK;
    });
    EXPECT_TRUE(result);
}

/**
 * @tc.name: RetrySamgrCall002
 * @tc.desc: RetrySamgrCall exhausts retries and returns false when the call always fails
 * @tc.type: FUNC
 * @tc.require: issue#26808
 */
HWTEST_F(RSRenderServiceAgentTest, RetrySamgrCall002, TestSize.Level1)
{
    int callCount = 0;
    auto result = RetrySamgrCall("RetrySamgrCall002",
        [&callCount](const sptr<ISystemAbilityManager>&) {
            callCount++;
            return ERR_INVALID_VALUE;
        });
    EXPECT_FALSE(result);
    // the call runs once per retry attempt (SAMGR_CALL_MAX_RETRY total in the samgr helper)
    EXPECT_EQ(callCount, SAMGR_CALL_MAX_RETRY);
}

/**
 * @tc.name: ScheduleTaskAndWaitVoid001
 * @tc.desc: ScheduleTaskAndWait void overload succeeds when the main handler is running
 * @tc.type: FUNC
 * @tc.require: issue#26808
 */
HWTEST_F(RSRenderServiceAgentTest, ScheduleTaskAndWaitVoid001, TestSize.Level1)
{
    auto renderService = sptr<RSRenderService>::MakeSptr();
    ASSERT_NE(renderService, nullptr);
    auto runner = AppExecFwk::EventRunner::Create(true);
    renderService->runner_ = runner;
    renderService->handler_ = std::make_shared<AppExecFwk::EventHandler>(runner);
    runner->Run();
    sptr<RSRenderServiceAgent> renderServiceAgent = sptr<RSRenderServiceAgent>::MakeSptr(*renderService);
    ASSERT_NE(renderServiceAgent, nullptr);
    std::atomic<bool> taskExecuted = false;
    bool isDone = renderServiceAgent->ScheduleTaskAndWait([&taskExecuted]() {
        taskExecuted.store(true);
    });
    EXPECT_TRUE(isDone);
    EXPECT_TRUE(taskExecuted.load());
}

/**
 * @tc.name: ScheduleTaskAndWaitValue001
 * @tc.desc: ScheduleTaskAndWait value overload returns the task result within the bounded wait
 * @tc.type: FUNC
 * @tc.require: issue#26808
 */
HWTEST_F(RSRenderServiceAgentTest, ScheduleTaskAndWaitValue001, TestSize.Level1)
{
    auto renderService = sptr<RSRenderService>::MakeSptr();
    ASSERT_NE(renderService, nullptr);
    auto runner = AppExecFwk::EventRunner::Create(true);
    renderService->runner_ = runner;
    renderService->handler_ = std::make_shared<AppExecFwk::EventHandler>(runner);
    runner->Run();
    sptr<RSRenderServiceAgent> renderServiceAgent = sptr<RSRenderServiceAgent>::MakeSptr(*renderService);
    ASSERT_NE(renderServiceAgent, nullptr);
    constexpr int32_t expectedResult = 42;
    auto resultOpt = renderServiceAgent->ScheduleTaskAndWait(
        []() -> int32_t { return expectedResult; });
    ASSERT_TRUE(resultOpt.has_value());
    EXPECT_EQ(resultOpt.value(), expectedResult);
}

/**
 * @tc.name: ScheduleTaskAndWaitVoidTimeout001
 * @tc.desc: ScheduleTaskAndWait void overload returns false on a never-started handler
 * @tc.type: FUNC
 * @tc.require: issue#26808
 */
HWTEST_F(RSRenderServiceAgentTest, ScheduleTaskAndWaitVoidTimeout001, TestSize.Level1)
{
    auto renderService = sptr<RSRenderService>::MakeSptr();
    ASSERT_NE(renderService, nullptr);
    // deposited runner: tasks are queued but never executed, the bounded wait must time out
    renderService->runner_ = AppExecFwk::EventRunner::Create(false);
    renderService->handler_ = std::make_shared<AppExecFwk::EventHandler>(renderService->runner_);
    sptr<RSRenderServiceAgent> renderServiceAgent = sptr<RSRenderServiceAgent>::MakeSptr(*renderService);
    ASSERT_NE(renderServiceAgent, nullptr);
    std::atomic<bool> taskExecuted = false;
    bool isDone = renderServiceAgent->ScheduleTaskAndWait([&taskExecuted]() {
        taskExecuted.store(true);
    });
    EXPECT_FALSE(isDone);
    EXPECT_FALSE(taskExecuted.load());
}

/**
 * @tc.name: PostTaskImmediateInPlaceInline001
 * @tc.desc: PostTaskImmediateInPlace executes the task inline when called on the runner thread
 * @tc.type: FUNC
 * @tc.require: issue#26808
 */
HWTEST_F(RSRenderServiceAgentTest, PostTaskImmediateInPlaceInline001, TestSize.Level1)
{
    auto renderService = sptr<RSRenderService>::MakeSptr();
    ASSERT_NE(renderService, nullptr);
    auto runner = AppExecFwk::EventRunner::Create(true);
    renderService->runner_ = runner;
    renderService->handler_ = std::make_shared<AppExecFwk::EventHandler>(runner);
    runner->Run();
    sptr<RSRenderServiceAgent> renderServiceAgent = sptr<RSRenderServiceAgent>::MakeSptr(*renderService);
    ASSERT_NE(renderServiceAgent, nullptr);
    std::promise<void> innerDone;
    auto innerFuture = innerDone.get_future();
    // from the runner thread IsCurrentRunnerThread() is true: the inner task executes inline
    renderService->handler_->PostTask([&renderServiceAgent, &innerDone]() {
        renderServiceAgent->PostTaskImmediateInPlace([&innerDone]() { innerDone.set_value(); });
    });
    ASSERT_EQ(innerFuture.wait_for(std::chrono::seconds(5)), std::future_status::ready);
}

/**
 * @tc.name: ScheduleTaskAndWaitValueTimeout001
 * @tc.desc: ScheduleTaskAndWait value overload returns nullopt on a never-started handler
 * @tc.type: FUNC
 * @tc.require: issue#26808
 */
HWTEST_F(RSRenderServiceAgentTest, ScheduleTaskAndWaitValueTimeout001, TestSize.Level1)
{
    auto renderService = sptr<RSRenderService>::MakeSptr();
    ASSERT_NE(renderService, nullptr);
    // deposited runner: the queued task never runs, the bounded wait times out with nullopt
    renderService->runner_ = AppExecFwk::EventRunner::Create(false);
    renderService->handler_ = std::make_shared<AppExecFwk::EventHandler>(renderService->runner_);
    sptr<RSRenderServiceAgent> renderServiceAgent = sptr<RSRenderServiceAgent>::MakeSptr(*renderService);
    ASSERT_NE(renderServiceAgent, nullptr);
    auto resultOpt = renderServiceAgent->ScheduleTaskAndWait([]() -> int32_t { return 1; });
    EXPECT_FALSE(resultOpt.has_value());
}

/**
 * @tc.name: GetHgmContext001
 * @tc.desc: GetHgmContext returns null when the render service has no hgm context
 * @tc.type: FUNC
 * @tc.require: issue#26808
 */
HWTEST_F(RSRenderServiceAgentTest, GetHgmContext001, TestSize.Level1)
{
    auto renderService = sptr<RSRenderService>::MakeSptr();
    ASSERT_NE(renderService, nullptr);
    // a fresh render service without hgm init: the agent exposes a null hgm context
    sptr<RSRenderServiceAgent> renderServiceAgent = sptr<RSRenderServiceAgent>::MakeSptr(*renderService);
    ASSERT_NE(renderServiceAgent, nullptr);
    EXPECT_EQ(renderServiceAgent->GetHgmContext(), nullptr);
}

/**
 * @tc.name: ReportSyncTaskTimeout001
 * @tc.desc: The bounded-wait timeout path invokes ReportSyncTaskTimeout (log + trace) and returns false
 * @tc.type: FUNC
 * @tc.require: issue#26808
 */
HWTEST_F(RSRenderServiceAgentTest, ReportSyncTaskTimeout001, TestSize.Level1)
{
    auto renderService = sptr<RSRenderService>::MakeSptr();
    ASSERT_NE(renderService, nullptr);
    // deposited runner: the scheduled task never executes, so the bounded wait times out
    renderService->runner_ = AppExecFwk::EventRunner::Create(false);
    renderService->handler_ = std::make_shared<AppExecFwk::EventHandler>(renderService->runner_);
    sptr<RSRenderServiceAgent> renderServiceAgent = sptr<RSRenderServiceAgent>::MakeSptr(*renderService);
    ASSERT_NE(renderServiceAgent, nullptr);
    // a 1ms bounded wait exercises the timeout report (log + trace) quickly
    EXPECT_FALSE(renderServiceAgent->ScheduleTaskAndWait([]() {}, 1));
}

/**
 * @tc.name: GetHgmProcessCallback001
 * @tc.desc: RegisterHgmProcessCallback then GetHgmProcessCallback returns the registered callback
 * @tc.type: FUNC
 * @tc.require: issue#26808
 */
HWTEST_F(RSRenderServiceAgentTest, GetHgmProcessCallback001, TestSize.Level1)
{
    auto renderService = sptr<RSRenderService>::MakeSptr();
    ASSERT_NE(renderService, nullptr);
    sptr<RSRenderServiceAgent> renderServiceAgent = sptr<RSRenderServiceAgent>::MakeSptr(*renderService);
    ASSERT_NE(renderServiceAgent, nullptr);
    EXPECT_EQ(renderServiceAgent->GetHgmProcessCallback(), nullptr);
    HgmProcessCallback callback = [](uint64_t, uint64_t,
        const sptr<HgmProcessToServiceInfo>&, const sptr<HgmServiceToProcessInfo>&) -> void {};
    renderServiceAgent->RegisterHgmProcessCallback(callback);
    EXPECT_NE(renderServiceAgent->GetHgmProcessCallback(), nullptr);
    renderServiceAgent->RegisterHgmProcessCallback(nullptr);
    EXPECT_EQ(renderServiceAgent->GetHgmProcessCallback(), nullptr);
}
} // namespace OHOS::Rosen
