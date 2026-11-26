/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <chrono>
#include "gtest/gtest.h"
#include "memory/rs_memory_res_sched_event_listener.h"
#include "res_value.h"
#include "pipeline/rs_test_util.h"
#include "pipeline/main_thread/rs_main_thread.h"
#include "pipeline/render_thread/rs_render_engine.h"
using namespace testing;
using namespace testing::ext;

namespace OHOS::Rosen {
namespace {
constexpr uint32_t EVENT_NON_MATCHING = 0; // EVENT_START, never triggers midnight clean

uint64_t SteadyNowMs()
{
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
}
} // namespace

class RSMemoryResSchedEventListenerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override
    {
        auto listener = RSMemoryResSchedEventListener::GetInstance();
        if (listener != nullptr) {
            listener->lastCleanTimeMs_ = 0;
        }
    }
    void TearDown() override {}
};

void RSMemoryResSchedEventListenerTest::SetUpTestCase()
{
    auto& rtThread = RSUniRenderThread::Instance();
    if (rtThread.uniRenderEngine_) {
        if (rtThread.uniRenderEngine_->renderContext_) {
            rtThread.uniRenderEngine_->renderContext_->drGPUContext_ = nullptr;
        }
        if (rtThread.uniRenderEngine_->protectedRenderContext_) {
            rtThread.uniRenderEngine_->protectedRenderContext_->drGPUContext_ = nullptr;
        }
        rtThread.uniRenderEngine_->skContext_ = nullptr;
        rtThread.uniRenderEngine_->renderContext_ = nullptr;
        rtThread.uniRenderEngine_->protectedRenderContext_ = nullptr;
        rtThread.uniRenderEngine_->imageManager_ = nullptr;
        rtThread.uniRenderEngine_->gpuCacheManager_ = nullptr;
#ifdef USE_VIDEO_PROCESSING_ENGINE
        rtThread.uniRenderEngine_->colorSpaceConverterDisplay_ = nullptr;
#endif
        rtThread.uniRenderEngine_ = nullptr;
    }
    auto mainThread = RSMainThread::Instance();
    if (mainThread && mainThread->renderEngine_) {
        if (mainThread->renderEngine_->renderContext_) {
            mainThread->renderEngine_->renderContext_->drGPUContext_ = nullptr;
        }
        if (mainThread->renderEngine_->protectedRenderContext_) {
            mainThread->renderEngine_->protectedRenderContext_->drGPUContext_ = nullptr;
        }
        mainThread->renderEngine_->skContext_ = nullptr;
        mainThread->renderEngine_->renderContext_ = nullptr;
        mainThread->renderEngine_->protectedRenderContext_ = nullptr;
        mainThread->renderEngine_->imageManager_ = nullptr;
        mainThread->renderEngine_->gpuCacheManager_ = nullptr;
#ifdef USE_VIDEO_PROCESSING_ENGINE
        mainThread->renderEngine_->colorSpaceConverterDisplay_ = nullptr;
#endif
        mainThread->renderEngine_ = nullptr;
    }
    RSTestUtil::InitRenderNodeGC();
}

void RSMemoryResSchedEventListenerTest::TearDownTestCase()
{
    auto mainThread = RSMainThread::Instance();
    if (!mainThread || !mainThread->context_) {
        return;
    }
    auto& renderNodeMap = mainThread->context_->GetMutableNodeMap();
    renderNodeMap.renderNodeMap_.clear();
    renderNodeMap.surfaceNodeMap_.clear();
    renderNodeMap.residentSurfaceNodeMap_.clear();
    renderNodeMap.screenNodeMap_.clear();
    renderNodeMap.canvasDrawingNodeMap_.clear();
    renderNodeMap.uiExtensionSurfaceNodes_.clear();

    auto& rtThread = RSUniRenderThread::Instance();
    if (rtThread.uniRenderEngine_) {
        if (rtThread.uniRenderEngine_->renderContext_) {
            rtThread.uniRenderEngine_->renderContext_->drGPUContext_ = nullptr;
        }
        if (rtThread.uniRenderEngine_->protectedRenderContext_) {
            rtThread.uniRenderEngine_->protectedRenderContext_->drGPUContext_ = nullptr;
        }
        rtThread.uniRenderEngine_->skContext_ = nullptr;
        rtThread.uniRenderEngine_->renderContext_ = nullptr;
        rtThread.uniRenderEngine_->protectedRenderContext_ = nullptr;
        rtThread.uniRenderEngine_->imageManager_ = nullptr;
        rtThread.uniRenderEngine_->gpuCacheManager_ = nullptr;
#ifdef USE_VIDEO_PROCESSING_ENGINE
        rtThread.uniRenderEngine_->colorSpaceConverterDisplay_ = nullptr;
#endif
        rtThread.uniRenderEngine_ = nullptr;
    }
    if (mainThread && mainThread->renderEngine_) {
        if (mainThread->renderEngine_->renderContext_) {
            mainThread->renderEngine_->renderContext_->drGPUContext_ = nullptr;
        }
        if (mainThread->renderEngine_->protectedRenderContext_) {
            mainThread->renderEngine_->protectedRenderContext_->drGPUContext_ = nullptr;
        }
        mainThread->renderEngine_->skContext_ = nullptr;
        mainThread->renderEngine_->renderContext_ = nullptr;
        mainThread->renderEngine_->protectedRenderContext_ = nullptr;
        mainThread->renderEngine_->imageManager_ = nullptr;
        mainThread->renderEngine_->gpuCacheManager_ = nullptr;
#ifdef USE_VIDEO_PROCESSING_ENGINE
        mainThread->renderEngine_->colorSpaceConverterDisplay_ = nullptr;
#endif
        mainThread->renderEngine_ = nullptr;
    }
}

/**
 * @tc.name: GetInstanceTest001
 * @tc.desc: Verify GetInstance returns the same singleton sptr across calls.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSMemoryResSchedEventListenerTest, GetInstanceTest001, TestSize.Level1)
{
    auto instance1 = RSMemoryResSchedEventListener::GetInstance();
    auto instance2 = RSMemoryResSchedEventListener::GetInstance();
    ASSERT_NE(instance1, nullptr);
    ASSERT_EQ(instance1, instance2);
}

/**
 * @tc.name: OnReceiveEventTest001
 * @tc.desc: OnReceiveEvent with non-matching event type should not trigger clean;
 *           lastCleanTimeMs_ must stay 0.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSMemoryResSchedEventListenerTest, OnReceiveEventTest001, TestSize.Level1)
{
    auto listener = RSMemoryResSchedEventListener::GetInstance();
    ASSERT_NE(listener, nullptr);
    ASSERT_EQ(listener->lastCleanTimeMs_, 0);
    std::unordered_map<std::string, std::string> extInfo;
    listener->OnReceiveEvent(EVENT_NON_MATCHING, 0, extInfo);
    EXPECT_EQ(listener->lastCleanTimeMs_, 0);
}

/**
 * @tc.name: OnReceiveEventTest002
 * @tc.desc: OnReceiveEvent with matching event type (EVENT_MIDNIGHT_CLEAN) should trigger clean;
 *           lastCleanTimeMs_ must be updated to non-zero.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSMemoryResSchedEventListenerTest, OnReceiveEventTest002, TestSize.Level1)
{
    auto listener = RSMemoryResSchedEventListener::GetInstance();
    ASSERT_NE(listener, nullptr);
    ASSERT_EQ(listener->lastCleanTimeMs_, 0);
    std::unordered_map<std::string, std::string> extInfo;
    listener->OnReceiveEvent(ResourceSchedule::ResType::EventType::EVENT_MIDNIGHT_CLEAN, 0, extInfo);
    EXPECT_NE(listener->lastCleanTimeMs_, 0);
}

/**
 * @tc.name: HandleMidnightCleanTest001
 * @tc.desc: First call with lastCleanTimeMs_ == 0 should trigger clean and update
 *           lastCleanTimeMs_ to the current steady clock value.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSMemoryResSchedEventListenerTest, HandleMidnightCleanTest001, TestSize.Level1)
{
    auto listener = RSMemoryResSchedEventListener::GetInstance();
    ASSERT_NE(listener, nullptr);
    ASSERT_EQ(listener->lastCleanTimeMs_, 0);
    uint64_t beforeMs = SteadyNowMs();
    listener->HandleMidnightClean();
    uint64_t afterMs = SteadyNowMs();
    EXPECT_GE(listener->lastCleanTimeMs_, beforeMs);
    EXPECT_LE(listener->lastCleanTimeMs_, afterMs);
}

/**
 * @tc.name: HandleMidnightCleanTest002
 * @tc.desc: Second call within the throttle interval should be suppressed;
 *           lastCleanTimeMs_ must remain unchanged from the first call.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSMemoryResSchedEventListenerTest, HandleMidnightCleanTest002, TestSize.Level1)
{
    auto listener = RSMemoryResSchedEventListener::GetInstance();
    ASSERT_NE(listener, nullptr);
    listener->HandleMidnightClean();
    uint64_t firstCleanTime = listener->lastCleanTimeMs_;
    ASSERT_NE(firstCleanTime, 0);
    listener->HandleMidnightClean();
    EXPECT_EQ(listener->lastCleanTimeMs_, firstCleanTime);
}
} // namespace OHOS::Rosen
