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
#include <test_header.h>

#include "hgm_idle_detector.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Rosen {
namespace {
    constexpr std::string bufferName = "surface";
    constexpr uint64_t  currTime = 100000000;
    constexpr uint64_t  lastTime = 200000000;
}
class HgmIdleDetectorTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void HgmIdleDetectorTest::SetUpTestCase() {}
void HgmIdleDetectorTest::TearDownTestCase() {}
void HgmIdleDetectorTest::SetUp() {}
void HgmIdleDetectorTest::TearDown() {}

/**
 * @tc.name: SetAndGetAppSupportStatus
 * @tc.desc: Verify the result of SetAndGetAppSupportStatus function
 * @tc.type: FUNC
 * @tc.require: 19N2FS
 */
HWTEST_F(HgmIdleDetectorTest, SetAndGetAppSupportStatus, Function | SmallTest | Level1)
{
    std::unique_ptr<HgmIdleDetector> idledetector = std::make_unique<HgmIdleDetector>();

    PART("CaseDescription") {
        STEP("1. set app support status") {
            idledetector->SetAppSupportStatus(false);
        }
        STEP("2. get app support status") {
            bool ret = idledetector->GetAppSupportStatus();
        }
    }
}

/**
 * @tc.name: SetAndGetAceAnimatorIdleStatus
 * @tc.desc: Verify the result of SetAndGetAceAnimatorIdleStatus function
 * @tc.type: FUNC
 * @tc.require: 19N2FS
 */
HWTEST_F(HgmIdleDetectorTest, SetAndGetAceAnimatorIdleStatus, Function | SmallTest | Level1)
{
    std::unique_ptr<HgmIdleDetector> idledetector = std::make_unique<HgmIdleDetector>();

    PART("CaseDescription") {
        STEP("1. set aceAnimator idle status") {
            idledetector->SetAceAnimatorIdleStatus(false);
        }
        STEP("2. get aceAnimator idle status") {
            bool ret = idledetector->GetAceAnimatorIdleStatus();
        }
    }
}

/**
 * @tc.name: SetAndGetTouchUpTime
 * @tc.desc: Verify the result of SetAndReadAppSupportStatus function
 * @tc.type: FUNC
 * @tc.require: 19N2FS
 */
HWTEST_F(HgmIdleDetectorTest, SetAndGetTouchUpTime, Function | SmallTest | Level1)
{
    std::unique_ptr<HgmIdleDetector> idledetector = std::make_unique<HgmIdleDetector>();

    PART("CaseDescription") {
        STEP("1. set app support status") {
            idledetector->SetTouchUpTime(currTime);
        }
        STEP("2. get app support status") {
            uint64_t time = idledetector->GetTouchUpTime();
        }
    }
}

/**
 * @tc.name: SetAndGetSurfaceTimeStatus
 * @tc.desc: Verify the result of SetAndGetSurfaceTimeStatus function
 * @tc.type: FUNC
 * @tc.require: 19N2FS
 */
HWTEST_F(HgmIdleDetectorTest, SetAndGetSurfaceTimeStatus, Function | SmallTest | Level1)
{
    std::unique_ptr<HgmIdleDetector> idledetector = std::make_unique<HgmIdleDetector>();

    PART("CaseDescription") {
        STEP("1. set app support status") {
            idledetector->SetAppSupportStatus(true);
        }
        STEP("2. set surface time") {
            idledetector->SurfaceTimeUpdate(bufferName, currTime);
        }
        STEP("3. get surface time state") {
            bool ret = idledetector->GetSurFaceIdleState(lastTime);
        }
    }
}
} // namespace Rosen
} // namespace OHOS