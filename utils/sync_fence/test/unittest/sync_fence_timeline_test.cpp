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
#include "sync_fence_timeline.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
class SyncFenceTimelineTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
};

void SyncFenceTest::SetUpTestCase()
{
}

void SyncFenceTest::TearDownTestCase()
{
}

/*
* Function: IsValid
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription: 1. call IsValid
*                  2. check ret
*/
HWTEST_F(SyncFenceTimelineTest, IsValid001, Function | MediumTest | Level2)
{
    sptr<SyncTimeline> syncTimeline_ = new SyncTimeline();
    bool valid = syncTimeline_->IsValid();
    if (valid) {
        ASSERT_EQ(valid, true);
        int32_t fd = syncTimeline_->GenerateFence("test sw_sync_fence", 1);
        sptr<SyncFence> syncFence_ = new SyncFence(fd);
        ASSERT_GE(fd, 0);
        sptr<SyncFenceTime> syncFenceTime_ = new SyncFenceTime(SyncFence_);
        ASSERT_EQ(true, syncFenceTime_->IsValid());
    } else {
        ASSERT_EQ(valid, false);
    }
}

/*
* Function: IsValid, GetSignalTimestamp
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription: 1. call GetSignalTimestamp
*                  2. check ret
*/
HWTEST_F(SyncFenceTimelineTest, GetSignalTimestamp001, Function | MediumTest | Level2)
{
    sptr<SyncTimeline> syncTimeline_ = new SyncTimeline();
    bool valid = syncTimeline_->IsValid();
    if (valid) {
        ASSERT_EQ(valid, true);
        int32_t fd = syncTimeline_->GenerateFence("test sw_sync_fence", 1);
        sptr<SyncFence> syncFence_ = new SyncFence(fd);
        ASSERT_GE(fd, 0);
        sptr<SyncFenceTime> syncFenceTime_ = new SyncFenceTime(SyncFence_);
        ns_sec_t timestamp = syncFenceTime_->GetSignalTimestamp();
        ASSERT_EQ(signaledTimestamps_, timestamp);
    } else {
        ASSERT_EQ(valid, false);
    }
}

/*
* Function: Push
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription: 1. call Push
*                  2. check ret
*/
HWTEST_F(SyncFenceTimelineTest, Push001, Function | MediumTest | Level2)
{
    sptr<SyncTimeline> syncTimeline_ = new SyncTimeline();
    bool valid = syncTimeline_->IsValid();
    if (valid) {
        ASSERT_EQ(valid, true);
        int32_t fd = syncTimeline_->GenerateFence("test sw_sync_fence", 1);
        sptr<SyncFence> syncFence_ = new SyncFence(fd);
        ASSERT_GE(fd, 0);
        auto syncFenceTime_ = std::make_shared<SyncFenceTime>(fd);
        SyncFenceTimeline syncFenceTimeline_ = new SyncFenceTimeline();
        syncFenceTimeline_->Push(syncFenceTime_);
    } else {
        ASSERT_EQ(valid, false);
    }
}

/*
* Function: UpdateFenceTimeline
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription: 1. call UpdateFenceTimeline
*                  2. check ret
*/
HWTEST_F(SyncFenceTimelineTest, UpdateFenceTimeline001, Function | MediumTest | Level2)
{
    sptr<SyncTimeline> syncTimeline_ = new SyncTimeline();
    bool valid = syncTimeline_->IsValid();
    if (valid) {
        ASSERT_EQ(valid, true);
        int32_t fd = syncTimeline_->GenerateFence("test sw_sync_fence", 1);
        sptr<SyncFence> syncFence_ = new SyncFence(fd);
        ASSERT_GE(fd, 0);
        auto syncFenceTime_ = std::make_shared<SyncFenceTime>(fd);
        SyncFenceTimeline syncFenceTimeline_ = new SyncFenceTimeline();
        syncFenceTimeline_->UpdateFenceTimeline();
        syncFenceTimeline_->Push(syncFenceTime_);
        syncFenceTimeline_->UpdateFenceTimeline();

    } else {
        ASSERT_EQ(valid, false);
    }
}

} // namespace OHOS