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

#include <gtest/gtest.h>
#include <ostream>
#include <securec.h>
#include <cstdint>
#include "refbase.h"
#include "sync_fence_tracker.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
class SyncFenceTrackerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
};

void SyncFenceTrackerTest::SetUpTestCase()
{
}

void SyncFenceTrackerTest::TearDownTestCase()
{
}

/*
* Function: SyncFenceTracker
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription: 1. call SyncFenceTracker
*                  2. check ret
*/
HWTEST_F(SyncFenceTrackerTest, SyncFenceTrackerTest, Function | MediumTest | Level2)
{
    auto tracker = std::make_shared<SyncFenceTrackerTest>("test sw_sync_fence1");
}

/*
* Function: TrackFence
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription: 1. call TrackFence, call Loop
*                  2. check ret
*/
HWTEST_F(SyncFenceTrackerTest, TrackFenceTest, Function | MediumTest | Level2)
{
    sptr<SyncTimeline> syncTimeline_ = new SyncTimeline();
    bool valid = syncTimeline_->IsValid();
    ASSERT_EQ(true, valid);
    int32_t fd = syncTimeline_->GenerateFence("test sw_sync_fence_timeline", 1);
    sptr<SyncFence> syncFence = new SyncFence(fd);
    ASSERT_GE(fd, 0);

    auto tracker = std::make_shared<SyncFenceTracker>("test sw_sync_fence");
    tracker->TrackFence(syncFence);

    // increase timeline from 0 -> 1
    auto ret = syncTimeline_->IncreaseSyncPoint(1);
    ASSERT_EQ(ret, 0);
    tracker->TrackFence(syncFence);
}


} // namespace OHOS  