/*
 * Copyright (c) 2025 HUA[REPLACED] Device Co., Ltd.
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
#include "foundation/graphic/graphic_2d/rosen/test/render_service/render_service/unittest/pipeline/rs_test_util.h"
#include "feature/hwc/hpae_offline/rs_hpae_offline_thread_manager.h"
#include "ffrt_inner.h"
#include "event_handler.h"
#include "common/rs_macros.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::Rosen {
class RSHpaeOfflineThreadManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
    RSHpaeOfflineThreadManager offlineMgr_;
};

void RSHpaeOfflineThreadManagerTest::SetUpTestCase()
{
    RSTestUtil::InitRenderNodeGC();
}
void RSHpaeOfflineThreadManagerTest::TearDownTestCase() {}
void RSHpaeOfflineThreadManagerTest::SetUp() {}
void RSHpaeOfflineThreadManagerTest::TearDown() {}

/**
 * @tc.name: PostTaskTest001
 * @tc.desc: Test PostTask when handler_ is not nullptr
 * @tc.type: FUNC
 */
HWTEST_F(RSHpaeOfflineThreadManagerTest, PostTaskTest001, TestSize.Level0)
{
    std::function<void()> task = []() {};
    bool result = offlineMgr_.PostTask(task);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: PostTaskTest002
 * @tc.desc: Test PostTask when queue is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(RSHpaeOfflineThreadManagerTest, PostTaskTest002, TestSize.Level0)
{
    std::function<void()> task = []() {};
    offlineMgr_.queue_ = nullptr;
    bool result = offlineMgr_.PostTask(task);
    EXPECT_TRUE(result);
}
} // namespace OHOS::Rosen