/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "vsync_generator.h"
#include "vsync_controller.h"
#include "vsync_distributor.h"

#include <gtest/gtest.h>

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Rosen {
static int64_t SystemTime()
{
    timespec t = {};
    clock_gettime(CLOCK_MONOTONIC, &t);
    return int64_t(t.tv_sec) * 1000000000LL + t.tv_nsec; // 1000000000ns == 1s
}

class VSyncGeneratorTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();

    static inline sptr<VSyncGenerator> vsyncGenerator_;
    static constexpr const int32_t WAIT_SYSTEM_ABILITY_REPORT_DATA_SECONDS = 5;
    static inline sptr<VSyncController> appController;
    static inline sptr<VSyncController> rsController;
    static inline sptr<VSyncDistributor> appDistributor;
    static inline sptr<VSyncDistributor> rsDistributor;
};

void VSyncGeneratorTest::SetUpTestCase()
{
    vsyncGenerator_ = CreateVSyncGenerator();
    appController = new VSyncController(vsyncGenerator_, 0);
    rsController = new VSyncController(vsyncGenerator_, 0);
    appDistributor = new VSyncDistributor(appController, "app");
    rsDistributor = new VSyncDistributor(rsController, "app");
    vsyncGenerator_->SetRSDistributor(rsDistributor);
    vsyncGenerator_->SetAppDistributor(appDistributor);
}

void VSyncGeneratorTest::TearDownTestCase()
{
    sleep(WAIT_SYSTEM_ABILITY_REPORT_DATA_SECONDS);
    vsyncGenerator_ = nullptr;
    DestroyVSyncGenerator();
}

class VSyncGeneratorTestCallback : public VSyncGenerator::Callback {
public:
    void OnVSyncEvent(int64_t now, int64_t period, uint32_t refreshRate, VSyncMode vsyncMode) override;
    void OnPhaseOffsetChanged(int64_t phaseOffset) override;
    void OnConnsRefreshRateChanged(const std::vector<std::pair<uint64_t, uint32_t>> &refreshRates) override;
};

void VSyncGeneratorTestCallback::OnVSyncEvent(int64_t now, int64_t period, uint32_t refreshRate, VSyncMode vsyncMode)
{
}

void VSyncGeneratorTestCallback::OnPhaseOffsetChanged(int64_t phaseOffset)
{
}

void VSyncGeneratorTestCallback::OnConnsRefreshRateChanged(
    const std::vector<std::pair<uint64_t, uint32_t>> &refreshRates)
{
}

namespace {
/*
* Function: UpdateMode001
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription: 1. call UpdateMode
 */
HWTEST_F(VSyncGeneratorTest, UpdateMode001, Function | MediumTest| Level0)
{
    ASSERT_EQ(VSyncGeneratorTest::vsyncGenerator_->UpdateMode(2, 0, 0), VSYNC_ERROR_OK);
}

/*
* Function: UpdateMode002
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription: 1. call UpdateMode
 */
HWTEST_F(VSyncGeneratorTest, UpdateMode002, Function | MediumTest| Level0)
{
    ASSERT_EQ(VSyncGeneratorTest::vsyncGenerator_->UpdateMode(2, 0, -1), VSYNC_ERROR_INVALID_ARGUMENTS);
}

/*
* Function: UpdateMode003
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription: 1. call UpdateMode
 */
HWTEST_F(VSyncGeneratorTest, UpdateMode003, Function | MediumTest| Level0)
{
    VSyncGeneratorTest::vsyncGenerator_->SetVSyncMode(VSYNC_MODE_LTPO);
    ASSERT_EQ(VSyncGeneratorTest::vsyncGenerator_->UpdateMode(0, 0, 0), VSYNC_ERROR_OK);
    // 25000000 is period, refreshRate is 40hz，for JudgeRefreshRateLocked test
    ASSERT_EQ(VSyncGeneratorTest::vsyncGenerator_->UpdateMode(25000000, 0, 0), VSYNC_ERROR_OK);
}

/*
* Function: AddListener001
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription: 1. call AddListener
 */
HWTEST_F(VSyncGeneratorTest, AddListener001, Function | MediumTest| Level0)
{
    sptr<VSyncGeneratorTestCallback> callback1 = new VSyncGeneratorTestCallback;
    ASSERT_EQ(VSyncGeneratorTest::vsyncGenerator_->AddListener(2, callback1), VSYNC_ERROR_OK);
}

/*
* Function: AddListener002
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription: 1. call AddListener
 */
HWTEST_F(VSyncGeneratorTest, AddListener002, Function | MediumTest| Level0)
{
    ASSERT_EQ(VSyncGeneratorTest::vsyncGenerator_->AddListener(2, nullptr), VSYNC_ERROR_INVALID_ARGUMENTS);
}

/*
* Function: AddListener003
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription: 1. call AddListener
 */
HWTEST_F(VSyncGeneratorTest, AddListener003, Function | MediumTest| Level0)
{
    VSyncGeneratorTest::vsyncGenerator_->SetVSyncMode(VSYNC_MODE_LTPO);
    VSyncGeneratorTest::vsyncGenerator_->UpdateMode(2, 0, 0);
    sptr<VSyncGeneratorTestCallback> callback = new VSyncGeneratorTestCallback;
    ASSERT_EQ(VSyncGeneratorTest::vsyncGenerator_->AddListener(2, callback), VSYNC_ERROR_OK);
}

/*
* Function: RemoveListener001
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription: 1. call RemoveListener
 */
HWTEST_F(VSyncGeneratorTest, RemoveListener001, Function | MediumTest| Level0)
{
    sptr<VSyncGeneratorTestCallback> callback2 = new VSyncGeneratorTestCallback;
    VSyncGeneratorTest::vsyncGenerator_->AddListener(2, callback2);
    ASSERT_EQ(VSyncGeneratorTest::vsyncGenerator_->RemoveListener(callback2), VSYNC_ERROR_OK);
}

/*
* Function: RemoveListener002
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription: 1. call RemoveListener
 */
HWTEST_F(VSyncGeneratorTest, RemoveListener002, Function | MediumTest| Level0)
{
    ASSERT_EQ(VSyncGeneratorTest::vsyncGenerator_->RemoveListener(nullptr), VSYNC_ERROR_INVALID_ARGUMENTS);
}

/*
* Function: RemoveListener003
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription: 1. call RemoveListener
 */
HWTEST_F(VSyncGeneratorTest, RemoveListener003, Function | MediumTest| Level0)
{
    sptr<VSyncGeneratorTestCallback> callback3 = new VSyncGeneratorTestCallback;
    VSyncGeneratorTest::vsyncGenerator_->AddListener(2, callback3);
    sptr<VSyncGeneratorTestCallback> callback4 = new VSyncGeneratorTestCallback;
    ASSERT_EQ(VSyncGeneratorTest::vsyncGenerator_->RemoveListener(callback4), VSYNC_ERROR_INVALID_ARGUMENTS);
}

/*
* Function: ChangePhaseOffset001
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription: 1. call ChangePhaseOffset
 */
HWTEST_F(VSyncGeneratorTest, ChangePhaseOffset001, Function | MediumTest| Level0)
{
    sptr<VSyncGeneratorTestCallback> callback5 = new VSyncGeneratorTestCallback;
    VSyncGeneratorTest::vsyncGenerator_->AddListener(2, callback5);
    ASSERT_EQ(VSyncGeneratorTest::vsyncGenerator_->ChangePhaseOffset(callback5, 1), VSYNC_ERROR_OK);
}

/*
* Function: ChangePhaseOffset002
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription: 1. call ChangePhaseOffset
 */
HWTEST_F(VSyncGeneratorTest, ChangePhaseOffset002, Function | MediumTest| Level0)
{
    ASSERT_EQ(VSyncGeneratorTest::vsyncGenerator_->ChangePhaseOffset(nullptr, 1), VSYNC_ERROR_INVALID_ARGUMENTS);
}

/*
* Function: ChangePhaseOffset003
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription: 1. call ChangePhaseOffset
 */
HWTEST_F(VSyncGeneratorTest, ChangePhaseOffset003, Function | MediumTest| Level0)
{
    sptr<VSyncGeneratorTestCallback> callback6 = new VSyncGeneratorTestCallback;
    VSyncGeneratorTest::vsyncGenerator_->AddListener(2, callback6);
    sptr<VSyncGeneratorTestCallback> callback7 = new VSyncGeneratorTestCallback;
    ASSERT_EQ(VSyncGeneratorTest::vsyncGenerator_->ChangePhaseOffset(callback7, 1), VSYNC_ERROR_INVALID_OPERATING);
}

/*
* Function: expectNextVsyncTimeTest001
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription: Test expectNextVsyncTime 0
 */
HWTEST_F(VSyncGeneratorTest, expectNextVsyncTimeTest001, Function | MediumTest| Level0)
{
    int64_t period = 8333333; // 8333333ns
    int64_t referenceTime = SystemTime();
    vsyncGenerator_->SetVSyncMode(VSYNC_MODE_LTPO);
    vsyncGenerator_->UpdateMode(period, 0, referenceTime);
    VSyncGenerator::ListenerRefreshRateData listenerRefreshRates = {};
    VSyncGenerator::ListenerPhaseOffsetData listenerPhaseOffset = {};
    int64_t refreshRate = 120; // 120hz
    int64_t rsVsyncCount = 0;
    auto ret = VSyncGeneratorTest::vsyncGenerator_->ChangeGeneratorRefreshRateModel(
        listenerRefreshRates, listenerPhaseOffset, refreshRate, rsVsyncCount, 0); // expectNextVsyncTime 0
    ASSERT_EQ(ret, VSYNC_ERROR_OK);
}

/*
* Function: expectNextVsyncTimeTest002
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription: Test expectNextVsyncTime -1
 */
HWTEST_F(VSyncGeneratorTest, expectNextVsyncTimeTest002, Function | MediumTest| Level0)
{
    int64_t period = 8333333; // 8333333ns
    int64_t referenceTime = SystemTime();
    vsyncGenerator_->SetVSyncMode(VSYNC_MODE_LTPO);
    vsyncGenerator_->UpdateMode(period, 0, referenceTime);
    VSyncGenerator::ListenerRefreshRateData listenerRefreshRates = {};
    VSyncGenerator::ListenerPhaseOffsetData listenerPhaseOffset = {};
    int64_t refreshRate = 120; // 120hz
    int64_t rsVsyncCount = 0;
    auto ret = VSyncGeneratorTest::vsyncGenerator_->ChangeGeneratorRefreshRateModel(
        listenerRefreshRates, listenerPhaseOffset, refreshRate, rsVsyncCount, -1); // expectNextVsyncTime -1
    ASSERT_EQ(ret, VSYNC_ERROR_OK);
}

/*
* Function: expectNextVsyncTimeTest003
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription: Test expectNextVsyncTime earlier than referenceTime.
 */
HWTEST_F(VSyncGeneratorTest, expectNextVsyncTimeTest003, Function | MediumTest| Level0)
{
    int64_t period = 8333333; // 8333333ns
    int64_t referenceTime = SystemTime();
    vsyncGenerator_->SetVSyncMode(VSYNC_MODE_LTPO);
    vsyncGenerator_->UpdateMode(period, 0, referenceTime);
    VSyncGenerator::ListenerRefreshRateData listenerRefreshRates = {};
    VSyncGenerator::ListenerPhaseOffsetData listenerPhaseOffset = {};
    int64_t refreshRate = 120; // 120hz
    int64_t rsVsyncCount = 0;
     // 10ms == 10000000ns
    auto ret = VSyncGeneratorTest::vsyncGenerator_->ChangeGeneratorRefreshRateModel(
        listenerRefreshRates, listenerPhaseOffset, refreshRate, rsVsyncCount, referenceTime - 10000000);
    ASSERT_EQ(ret, VSYNC_ERROR_INVALID_ARGUMENTS);
}

/*
* Function: expectNextVsyncTimeTest004
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription: Test expectNextVsyncTime current system time.
 */
HWTEST_F(VSyncGeneratorTest, expectNextVsyncTimeTest004, Function | MediumTest| Level0)
{
    int64_t period = 8333333; // 8333333ns
    int64_t referenceTime = SystemTime();
    vsyncGenerator_->SetVSyncMode(VSYNC_MODE_LTPO);
    vsyncGenerator_->UpdateMode(period, 0, referenceTime);
    VSyncGenerator::ListenerRefreshRateData listenerRefreshRates = {};
    VSyncGenerator::ListenerPhaseOffsetData listenerPhaseOffset = {};
    int64_t refreshRate = 120; // 120hz
    int64_t now = SystemTime();
    int64_t rsVsyncCount = 0;
    auto ret = VSyncGeneratorTest::vsyncGenerator_->ChangeGeneratorRefreshRateModel(
        listenerRefreshRates, listenerPhaseOffset, refreshRate, rsVsyncCount, now);
    ASSERT_EQ(ret, VSYNC_ERROR_OK);
}

/*
* Function: expectNextVsyncTimeTest005
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription: Test expectNextVsyncTime current system time plus 5ms.
 */
HWTEST_F(VSyncGeneratorTest, expectNextVsyncTimeTest005, Function | MediumTest| Level0)
{
    int64_t period = 8333333; // 8333333ns
    int64_t referenceTime = SystemTime();
    vsyncGenerator_->SetVSyncMode(VSYNC_MODE_LTPO);
    vsyncGenerator_->UpdateMode(period, 0, referenceTime);
    VSyncGenerator::ListenerRefreshRateData listenerRefreshRates = {};
    VSyncGenerator::ListenerPhaseOffsetData listenerPhaseOffset = {};
    int64_t refreshRate = 120; // 120hz
    int64_t now = SystemTime();
    int64_t rsVsyncCount = 0;
    auto ret = VSyncGeneratorTest::vsyncGenerator_->ChangeGeneratorRefreshRateModel(
        listenerRefreshRates, listenerPhaseOffset, refreshRate, rsVsyncCount, now + 5000000); // 5ms == 5000000ns
    ASSERT_EQ(ret, VSYNC_ERROR_OK);
}

/*
* Function: expectNextVsyncTimeTest006
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription: Test expectNextVsyncTime current system time plus 5.5ms.
 */
HWTEST_F(VSyncGeneratorTest, expectNextVsyncTimeTest006, Function | MediumTest| Level0)
{
    int64_t period = 8333333; // 8333333ns
    int64_t referenceTime = SystemTime();
    vsyncGenerator_->SetVSyncMode(VSYNC_MODE_LTPO);
    vsyncGenerator_->UpdateMode(period, 0, referenceTime);
    VSyncGenerator::ListenerRefreshRateData listenerRefreshRates = {};
    VSyncGenerator::ListenerPhaseOffsetData listenerPhaseOffset = {};
    int64_t refreshRate = 120; // 120hz
    int64_t now = SystemTime();
    int64_t rsVsyncCount = 0;
    auto ret = VSyncGeneratorTest::vsyncGenerator_->ChangeGeneratorRefreshRateModel(
        listenerRefreshRates, listenerPhaseOffset, refreshRate, rsVsyncCount, now + 5500000); // 5.5ms == 5500000ns
    ASSERT_EQ(ret, VSYNC_ERROR_OK);
}

/*
* Function: expectNextVsyncTimeTest007
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription: Test expectNextVsyncTime current system time plus 90ms.
 */
HWTEST_F(VSyncGeneratorTest, expectNextVsyncTimeTest007, Function | MediumTest| Level0)
{
    int64_t period = 8333333; // 8333333ns
    int64_t referenceTime = SystemTime();
    vsyncGenerator_->SetVSyncMode(VSYNC_MODE_LTPO);
    vsyncGenerator_->UpdateMode(period, 0, referenceTime);
    VSyncGenerator::ListenerRefreshRateData listenerRefreshRates = {};
    VSyncGenerator::ListenerPhaseOffsetData listenerPhaseOffset = {};
    int64_t refreshRate = 120; // 120hz
    int64_t now = SystemTime();
    int64_t rsVsyncCount = 0;
    auto ret = VSyncGeneratorTest::vsyncGenerator_->ChangeGeneratorRefreshRateModel(
        listenerRefreshRates, listenerPhaseOffset, refreshRate, rsVsyncCount, now + 90000000); // 90ms == 90000000ns
    ASSERT_EQ(ret, VSYNC_ERROR_OK);
}

/*
* Function: expectNextVsyncTimeTest008
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription: Test expectNextVsyncTime current system time plus 110ms.
 */
HWTEST_F(VSyncGeneratorTest, expectNextVsyncTimeTest008, Function | MediumTest| Level0)
{
    int64_t period = 8333333; // 8333333ns
    int64_t referenceTime = SystemTime();
    vsyncGenerator_->SetVSyncMode(VSYNC_MODE_LTPO);
    vsyncGenerator_->UpdateMode(period, 0, referenceTime);
    VSyncGenerator::ListenerRefreshRateData listenerRefreshRates = {};
    VSyncGenerator::ListenerPhaseOffsetData listenerPhaseOffset = {};
    int64_t refreshRate = 120; // 120hz
    int64_t now = SystemTime();
    int64_t rsVsyncCount = 0;
    auto ret = VSyncGeneratorTest::vsyncGenerator_->ChangeGeneratorRefreshRateModel(
        listenerRefreshRates, listenerPhaseOffset, refreshRate, rsVsyncCount, now + 110000000); // 110ms == 110000000ns
    ASSERT_EQ(ret, VSYNC_ERROR_INVALID_ARGUMENTS);
}
} // namespace
} // namespace Rosen
} // namespace OHOS