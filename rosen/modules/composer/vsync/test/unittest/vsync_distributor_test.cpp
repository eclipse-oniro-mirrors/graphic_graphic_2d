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
#include <gtest/gtest.h>
#include "vsync_distributor.h"
#include "vsync_controller.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Rosen {
class VSyncDistributorTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();

    static inline sptr<VSyncController> vsyncController = nullptr;
    static inline sptr<VSyncDistributor> vsyncDistributor = nullptr;
    static inline sptr<VSyncGenerator> vsyncGenerator = nullptr;
};

void VSyncDistributorTest::SetUpTestCase()
{
    vsyncGenerator = CreateVSyncGenerator();
    vsyncController = new VSyncController(vsyncGenerator, 0);
    vsyncDistributor = new VSyncDistributor(vsyncController, "VSyncConnection");
}

void VSyncDistributorTest::TearDownTestCase()
{
    vsyncGenerator = nullptr;
    DestroyVSyncGenerator();
    vsyncController = nullptr;
    vsyncDistributor = nullptr;
}

namespace {
/*
* Function: AddConnection001
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription: 1. call AddConnection
 */
HWTEST_F(VSyncDistributorTest, AddConnection001, Function | MediumTest| Level3)
{
    ASSERT_EQ(VSyncDistributorTest::vsyncDistributor->AddConnection(nullptr), VSYNC_ERROR_NULLPTR);
}

/*
* Function: AddConnection002
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription: 1. call AddConnection
 */
HWTEST_F(VSyncDistributorTest, AddConnection002, Function | MediumTest| Level3)
{
    sptr<VSyncConnection> conn = new VSyncConnection(vsyncDistributor, "VSyncDistributorTest");
    ASSERT_EQ(VSyncDistributorTest::vsyncDistributor->AddConnection(conn), VSYNC_ERROR_OK);
    ASSERT_EQ(VSyncDistributorTest::vsyncDistributor->AddConnection(conn), VSYNC_ERROR_INVALID_ARGUMENTS);
}

/*
* Function: RemoveConnection001
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription: 1. call RemoveConnection
 */
HWTEST_F(VSyncDistributorTest, RemoveConnection001, Function | MediumTest| Level3)
{
    ASSERT_EQ(VSyncDistributorTest::vsyncDistributor->RemoveConnection(nullptr), VSYNC_ERROR_NULLPTR);
}

/*
* Function: RemoveConnection002
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription: 1. call RemoveConnection
 */
HWTEST_F(VSyncDistributorTest, RemoveConnection002, Function | MediumTest| Level3)
{
    sptr<VSyncConnection> conn = new VSyncConnection(vsyncDistributor, "VSyncDistributorTest");
    ASSERT_EQ(VSyncDistributorTest::vsyncDistributor->RemoveConnection(conn), VSYNC_ERROR_INVALID_ARGUMENTS);
}

/*
* Function: RemoveConnection003
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription: 1. call RemoveConnection
 */
HWTEST_F(VSyncDistributorTest, RemoveConnection003, Function | MediumTest| Level3)
{
    sptr<VSyncConnection> conn = new VSyncConnection(vsyncDistributor, "VSyncDistributorTest");
    VSyncDistributorTest::vsyncDistributor->AddConnection(conn);
    ASSERT_EQ(VSyncDistributorTest::vsyncDistributor->RemoveConnection(conn), VSYNC_ERROR_OK);
}

/*
* Function: RequestNextVSync001
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription: 1. call RequestNextVSync
 */
HWTEST_F(VSyncDistributorTest, RequestNextVSync001, Function | MediumTest| Level3)
{
    ASSERT_EQ(VSyncDistributorTest::vsyncDistributor->RequestNextVSync(nullptr), VSYNC_ERROR_NULLPTR);
}

/*
* Function: RequestNextVSync002
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription: 1. call RequestNextVSync
 */
HWTEST_F(VSyncDistributorTest, RequestNextVSync002, Function | MediumTest| Level3)
{
    sptr<VSyncConnection> conn = new VSyncConnection(vsyncDistributor, "VSyncDistributorTest");
    ASSERT_EQ(VSyncDistributorTest::vsyncDistributor->RequestNextVSync(conn), VSYNC_ERROR_INVALID_ARGUMENTS);
}

/*
* Function: RequestNextVSync003
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription: 1. call RequestNextVSync
 */
HWTEST_F(VSyncDistributorTest, RequestNextVSync003, Function | MediumTest| Level3)
{
    sptr<VSyncConnection> conn = new VSyncConnection(vsyncDistributor, "VSyncDistributorTest");
    VSyncDistributorTest::vsyncDistributor->AddConnection(conn);
    ASSERT_EQ(VSyncDistributorTest::vsyncDistributor->RequestNextVSync(conn), VSYNC_ERROR_OK);
}

/*
* Function: RequestNextVSync004
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription: 1. call RequestNextVSync
 */
HWTEST_F(VSyncDistributorTest, RequestNextVSync004, Function | MediumTest| Level3)
{
    sptr<VSyncConnection> conn = new VSyncConnection(vsyncDistributor, "VSyncDistributorTest");
    VSyncDistributorTest::vsyncDistributor->AddConnection(conn);
    ASSERT_EQ(VSyncDistributorTest::vsyncDistributor->RequestNextVSync(conn, "unknown", 0), VSYNC_ERROR_OK);
}

/*
* Function: SetVSyncRate001
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription: 1. call SetVSyncRate
 */
HWTEST_F(VSyncDistributorTest, SetVSyncRate001, Function | MediumTest| Level3)
{
    ASSERT_EQ(VSyncDistributorTest::vsyncDistributor->SetVSyncRate(0, nullptr), VSYNC_ERROR_INVALID_ARGUMENTS);
}

/*
* Function: SetVSyncRate002
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription: 1. call SetVSyncRate
 */
HWTEST_F(VSyncDistributorTest, SetVSyncRate002, Function | MediumTest| Level3)
{
    sptr<VSyncConnection> conn = new VSyncConnection(vsyncDistributor, "VSyncDistributorTest");
    ASSERT_EQ(VSyncDistributorTest::vsyncDistributor->SetVSyncRate(1, conn), VSYNC_ERROR_INVALID_ARGUMENTS);
}

/*
* Function: SetVSyncRate003
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription: 1. call SetVSyncRate
 */
HWTEST_F(VSyncDistributorTest, SetVSyncRate003, Function | MediumTest| Level3)
{
    sptr<VSyncConnection> conn = new VSyncConnection(vsyncDistributor, "VSyncDistributorTest");
    VSyncDistributorTest::vsyncDistributor->AddConnection(conn);
    ASSERT_EQ(VSyncDistributorTest::vsyncDistributor->SetVSyncRate(1, conn), VSYNC_ERROR_OK);
}

/*
* Function: SetVSyncRate004
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription: 1. call SetVSyncRate
 */
HWTEST_F(VSyncDistributorTest, SetVSyncRate004, Function | MediumTest| Level3)
{
    sptr<VSyncConnection> conn = new VSyncConnection(vsyncDistributor, "VSyncDistributorTest");
    VSyncDistributorTest::vsyncDistributor->AddConnection(conn);
    ASSERT_EQ(VSyncDistributorTest::vsyncDistributor->SetVSyncRate(1, conn), VSYNC_ERROR_OK);
    ASSERT_EQ(VSyncDistributorTest::vsyncDistributor->SetVSyncRate(1, conn), VSYNC_ERROR_INVALID_ARGUMENTS);
}

/*
* Function: SetHighPriorityVSyncRate001
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription: 1. call SetHighPriorityVSyncRate with abnormal parameters and check ret
 */
HWTEST_F(VSyncDistributorTest, SetHighPriorityVSyncRate001, Function | MediumTest| Level3)
{
    ASSERT_EQ(VSyncDistributorTest::vsyncDistributor->SetHighPriorityVSyncRate(0, nullptr),
              VSYNC_ERROR_INVALID_ARGUMENTS);
    ASSERT_EQ(VSyncDistributorTest::vsyncDistributor->SetHighPriorityVSyncRate(1, nullptr),
              VSYNC_ERROR_INVALID_ARGUMENTS);
    sptr<VSyncConnection> conn = new VSyncConnection(vsyncDistributor, "VSyncDistributorTest");
    ASSERT_EQ(VSyncDistributorTest::vsyncDistributor->SetHighPriorityVSyncRate(1, conn), VSYNC_ERROR_INVALID_ARGUMENTS);
}

/*
* Function: SetHighPriorityVSyncRate002
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription: 1. call SetHighPriorityVSyncRate with normal parameters and check ret
 */
HWTEST_F(VSyncDistributorTest, SetHighPriorityVSyncRate002, Function | MediumTest| Level3)
{
    sptr<VSyncConnection> conn = new VSyncConnection(vsyncDistributor, "VSyncDistributorTest");
    VSyncDistributorTest::vsyncDistributor->AddConnection(conn);
    ASSERT_EQ(VSyncDistributorTest::vsyncDistributor->SetHighPriorityVSyncRate(1, conn), VSYNC_ERROR_OK);
    ASSERT_EQ(VSyncDistributorTest::vsyncDistributor->SetHighPriorityVSyncRate(1, conn), VSYNC_ERROR_INVALID_ARGUMENTS);
    ASSERT_EQ(VSyncDistributorTest::vsyncDistributor->SetHighPriorityVSyncRate(2, conn), VSYNC_ERROR_OK);
}

/*
* Function: SetFrameIsRender001
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription: 1. call SetFrameIsRender with render is true
 */
HWTEST_F(VSyncDistributorTest, SetFrameIsRender001, Function | MediumTest| Level3)
{
    VSyncDistributorTest::vsyncDistributor->SetFrameIsRender(true);
}

/*
* Function: SetFrameIsRender002
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription: 1. call SetFrameIsRender with render is false
 */
HWTEST_F(VSyncDistributorTest, SetFrameIsRender002, Function | MediumTest| Level3)
{
    VSyncDistributorTest::vsyncDistributor->SetFrameIsRender(false);
}

/*
* Function: MarkRSAnimate001
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription: 1. call MarkRSAnimate
 */
HWTEST_F(VSyncDistributorTest, MarkRSAnimate001, Function | MediumTest| Level3)
{
    VSyncDistributorTest::vsyncDistributor->MarkRSAnimate();
}

/*
* Function: UnmarkRSAnimate001
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription: 1. call UnmarkRSAnimate
 */
HWTEST_F(VSyncDistributorTest, UnmarkRSAnimate001, Function | MediumTest| Level3)
{
    VSyncDistributorTest::vsyncDistributor->UnmarkRSAnimate();
}

/*
* Function: HasPendingUIRNV001
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription: 1. call HasPendingUIRNV
 */
HWTEST_F(VSyncDistributorTest, HasPendingUIRNV001, Function | MediumTest| Level3)
{
    VSyncDistributorTest::vsyncDistributor->HasPendingUIRNV();
}

/*
* Function: UpdatePendingReferenceTime001
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription: 1. call UpdatePendingReferenceTime
 */
HWTEST_F(VSyncDistributorTest, UpdatePendingReferenceTime001, Function | MediumTest| Level3)
{
    int64_t timeStamp = 0;
    sptr<VSyncConnection> conn = new VSyncConnection(vsyncDistributor, "VSyncDistributorTest");
    VSyncDistributorTest::vsyncDistributor->SetUiDvsyncSwitch(true, conn);
    VSyncDistributorTest::vsyncDistributor->UpdatePendingReferenceTime(timeStamp);
}

/*
* Function: SetHardwareTaskNum001
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription: 1. call SetHardwareTaskNum
 */
HWTEST_F(VSyncDistributorTest, SetHardwareTaskNum001, Function | MediumTest| Level3)
{
    uint32_t num = 0;
    sptr<VSyncConnection> conn = new VSyncConnection(vsyncDistributor, "VSyncDistributorTest");
    VSyncDistributorTest::vsyncDistributor->SetUiDvsyncSwitch(true, conn);
    VSyncDistributorTest::vsyncDistributor->SetHardwareTaskNum(num);
}

/*
* Function: GetUiCommandDelayTime001
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription: 1. call GetUiCommandDelayTime
 */
HWTEST_F(VSyncDistributorTest, GetUiCommandDelayTime001, Function | MediumTest| Level3)
{
    ASSERT_EQ(VSyncDistributorTest::vsyncDistributor->GetUiCommandDelayTime(), 0);
}

/*
* Function: SetUiDvsyncConfig001
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription: 1. call SetUiDvsyncConfig
 */
HWTEST_F(VSyncDistributorTest, SetUiDvsyncConfig001, Function | MediumTest| Level3)
{
    uint32_t bufferCount = 2;
    ASSERT_EQ(VSyncDistributorTest::vsyncDistributor->SetUiDvsyncConfig(bufferCount), VSYNC_ERROR_OK);
}
} // namespace
} // namespace Rosen
} // namespace OHOS