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

#include <if_system_ability_manager.h>
#include <iservice_registry.h>
#include <system_ability_definition.h>

#include "vsync_distributor.h"
#include "vsync_generator.h"
#include "vsync_controller.h"
#include "vsync_connection_proxy.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Rosen {
class VSyncConnectionTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();

    static inline sptr<VSyncController> vsyncController = nullptr;
    static inline sptr<VSyncDistributor> vsyncDistributor = nullptr;
    static inline sptr<VSyncGenerator> vsyncGenerator = nullptr;
    static inline sptr<VSyncConnection> vsyncConnection = nullptr;
    static inline sptr<VSyncConnectionProxy> vsyncConnectionProxy = nullptr;
    static inline sptr<VSyncConnectionProxy> vsyncConnectionProxyMock_ = nullptr;
    static constexpr const int32_t WAIT_SYSTEM_ABILITY_REPORT_DATA_SECONDS = 5;
};

constexpr int MAX_RETRY = 5;
class MockIRemoteObject : public IRemoteObject {
public:
    MockIRemoteObject() : IRemoteObject {u"MockIRemoteObject"}
    {
        count_ = 0;
    }

    ~MockIRemoteObject()
    {
    }

    int32_t GetObjectRefCount()
    {
        return 0;
    }

    int SendRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
    {
        count_++;
        if (count_ <= MAX_RETRY) {
            return UNKNOWN_ERROR;
        }
        return NO_ERROR;
    }

    bool AddDeathRecipient(const sptr<DeathRecipient> &recipient)
    {
        return true;
    }

    bool RemoveDeathRecipient(const sptr<DeathRecipient> &recipient)
    {
        return true;
    }

    int Dump(int fd, const std::vector<std::u16string> &args)
    {
        return 0;
    }

    int sendRequestResult_ = 0;
    int count_ = 0;
};

void VSyncConnectionTest::SetUpTestCase()
{
    vsyncGenerator = CreateVSyncGenerator();
    vsyncController = new VSyncController(vsyncGenerator, 0);
    vsyncDistributor = new VSyncDistributor(vsyncController, "VSyncConnection");
    vsyncConnection = new VSyncConnection(vsyncDistributor, "VSyncConnection");
    auto samgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    ASSERT_NE(samgr, nullptr);
    auto remoteObject = samgr->GetSystemAbility(RENDER_SERVICE);
    vsyncConnectionProxy = new VSyncConnectionProxy(remoteObject);
    auto vsyncConnectionObjectMock = new MockIRemoteObject();
    vsyncConnectionProxyMock_ = new VSyncConnectionProxy(vsyncConnectionObjectMock);
}

void VSyncConnectionTest::TearDownTestCase()
{
    sleep(WAIT_SYSTEM_ABILITY_REPORT_DATA_SECONDS);
    DestroyVSyncGenerator();
    vsyncController = nullptr;
    vsyncGenerator = nullptr;
    vsyncDistributor = nullptr;
    vsyncConnection = nullptr;
    vsyncConnectionProxy = nullptr;
    vsyncConnectionProxyMock_ = nullptr;
}

namespace {
/*
* Function: RequestNextVSync001
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription: 1. call RequestNextVSync
 */
HWTEST_F(VSyncConnectionTest, RequestNextVSync001, Function | MediumTest| Level3)
{
    ASSERT_EQ(VSyncConnectionTest::vsyncConnection->RequestNextVSync(), VSYNC_ERROR_INVALID_ARGUMENTS);
}

/*
* Function: RequestNextVSync002
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription: 1. call RequestNextVSync
 */
HWTEST_F(VSyncConnectionTest, RequestNextVSync002, Function | MediumTest| Level3)
{
    VSyncConnectionTest::vsyncDistributor->AddConnection(VSyncConnectionTest::vsyncConnection);
    ASSERT_EQ(VSyncConnectionTest::vsyncConnection->RequestNextVSync(), VSYNC_ERROR_OK);
    VSyncConnectionTest::vsyncDistributor->RemoveConnection(VSyncConnectionTest::vsyncConnection);
}

/*
* Function: RequestNextVSync003
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription: 1. call RequestNextVSync
 */
HWTEST_F(VSyncConnectionTest, RequestNextVSync003, Function | MediumTest| Level3)
{
    ASSERT_EQ(VSyncConnectionTest::vsyncConnection->RequestNextVSync("unknown", 0), VSYNC_ERROR_INVALID_ARGUMENTS);
}

/**
 * @tc.name: OnRemoteDied001
 * @tc.desc: OnRemoteDied Test
 * @tc.type: FUNC
 * @tc.require: issueICO7O7
 */
HWTEST_F(VSyncConnectionTest, OnRemoteDied001, Function | MediumTest| Level3)
{
    sptr<MockIRemoteObject> remoteObj = new MockIRemoteObject();
    wptr<MockIRemoteObject> remoteObjWeakPtr(remoteObj);
    ASSERT_NE(remoteObj, nullptr);
    ASSERT_NE(VSyncConnectionTest::vsyncConnection->vsyncConnDeathRecipient_, nullptr);
    VSyncConnectionTest::vsyncConnection->vsyncConnDeathRecipient_->OnRemoteDied(nullptr);
    VSyncConnectionTest::vsyncConnection->vsyncConnDeathRecipient_->OnRemoteDied(remoteObjWeakPtr);
    ASSERT_NE(remoteObjWeakPtr, nullptr);
}

/**
 * @tc.name: SetNativeDVSyncSwitch001
 * @tc.desc: SetNativeDVSyncSwitch Test
 * @tc.type: FUNC
 * @tc.require: issueICO7O7
 */
HWTEST_F(VSyncConnectionTest, SetNativeDVSyncSwitch001, Function | MediumTest| Level3)
{
    auto res = vsyncConnectionProxyMock_->SetNativeDVSyncSwitch(true);
    ASSERT_NE(res, NO_ERROR);
}

/*
* Function: SetVSyncRate001
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription: 1. call SetVSyncRate
 */
HWTEST_F(VSyncConnectionTest, SetVSyncRate001, Function | MediumTest| Level3)
{
    ASSERT_EQ(VSyncConnectionTest::vsyncConnection->SetVSyncRate(-2), VSYNC_ERROR_INVALID_ARGUMENTS);
}

/*
* Function: SetVSyncRate002
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription: 1. call SetVSyncRate
 */
HWTEST_F(VSyncConnectionTest, SetVSyncRate002, Function | MediumTest| Level3)
{
    VSyncConnectionTest::vsyncDistributor->AddConnection(VSyncConnectionTest::vsyncConnection);
    ASSERT_EQ(VSyncConnectionTest::vsyncConnection->SetVSyncRate(1), VSYNC_ERROR_OK);
    VSyncConnectionTest::vsyncDistributor->RemoveConnection(VSyncConnectionTest::vsyncConnection);
}

/*
* Function: GetReceiveFd001
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription: 1. call GetReceiveFd
 */
HWTEST_F(VSyncConnectionTest, GetReceiveFd001, Function | MediumTest| Level3)
{
    int32_t fd = -1;
    ASSERT_EQ(VSyncConnectionTest::vsyncConnection->GetReceiveFd(fd), VSYNC_ERROR_OK);
    ASSERT_NE(fd, -1);
}

/**
 * Function: NewVsyncConnection
 * Type: Function
 * Rank: Important(2)
 * EnvConditions: N/A
 * CaseDescription: 1.create VsyncConnection with name
 *                  2.check isRsConn
 */
HWTEST_F(VSyncConnectionTest, NewVsyncConnection001, Function | MediumTest| Level3)
{
    sptr<VSyncConnection> tmpConn1 = new VSyncConnection(vsyncDistributor, "rs");
    EXPECT_EQ(tmpConn1->isRsConn_, true);

    sptr<VSyncConnection> tmpConn2 = new VSyncConnection(vsyncDistributor, "test");
    EXPECT_EQ(tmpConn2->isRsConn_, false);
}

/**
 * Function: AddRequestVsyncTimestamp
 * Type: Function
 * Rank: Important(2)
 * EnvConditions: N/A
 * CaseDescription: 1.create VsyncConnection with name "test"
 *                  2.call AddRequestVsyncTimestamp and IsRequestVsyncTimestampEmpty
 */
HWTEST_F(VSyncConnectionTest, AddRequestVsyncTimestamp001, Function | MediumTest| Level3)
{
    sptr<VSyncConnection> tmpConn1 = new VSyncConnection(vsyncDistributor, "test");
    EXPECT_EQ(tmpConn1->isRsConn_, false);

    EXPECT_EQ(tmpConn1->AddRequestVsyncTimestamp(-1), false);
    EXPECT_EQ(tmpConn1->IsRequestVsyncTimestampEmpty(), true);

    EXPECT_EQ(tmpConn1->AddRequestVsyncTimestamp(0), false);
    EXPECT_EQ(tmpConn1->IsRequestVsyncTimestampEmpty(), true);

    EXPECT_EQ(tmpConn1->AddRequestVsyncTimestamp(1), false);
    EXPECT_EQ(tmpConn1->IsRequestVsyncTimestampEmpty(), true);

    EXPECT_EQ(tmpConn1->AddRequestVsyncTimestamp(1000000000), false);
    EXPECT_EQ(tmpConn1->IsRequestVsyncTimestampEmpty(), true);

    EXPECT_EQ(tmpConn1->NeedTriggeredVsync(0), false);
}

/**
 * Function: AddRequestVsyncTimestamp
 * Type: Function
 * Rank: Important(2)
 * EnvConditions: N/A
 * CaseDescription: 1.create VsyncConnection with name "test"
 *                  2.call AddRequestVsyncTimestamp
 *                  3.call IsRequestVsyncTimestampEmpty
 *                  4.call NeedTriggeredVsync
 *                  5.call RemoveTriggeredVsync
 */
HWTEST_F(VSyncConnectionTest, AddRequestVsyncTimestamp002, Function | MediumTest| Level3)
{
    sptr<VSyncConnection> tmpConn1 = new VSyncConnection(vsyncDistributor, "test");
    EXPECT_EQ(tmpConn1->isRsConn_, false);

    int64_t time = 1000000000;
    EXPECT_EQ(tmpConn1->AddRequestVsyncTimestamp(-1), false);
    EXPECT_EQ(tmpConn1->AddRequestVsyncTimestamp(time), false);
    EXPECT_EQ(tmpConn1->IsRequestVsyncTimestampEmpty(), true);
    EXPECT_EQ(tmpConn1->NeedTriggeredVsync(time), false);
    tmpConn1->RemoveTriggeredVsync(time);
}

/**
 * Function: AddRequestVsyncTimestamp
 * Type: Function
 * Rank: Important(2)
 * EnvConditions: N/A
 * CaseDescription: 1.create VsyncConnection with name "rs"
 *                  2.add -1 to VSyncConnection and check IsRequestVsyncTimestampEmpty value
 *                  3.add 0 to VSyncConnection and check IsRequestVsyncTimestampEmpty value
 *                  4.add 1000000000 to VSyncConnection and check IsRequestVsyncTimestampEmpty value
 */
HWTEST_F(VSyncConnectionTest, AddRequestVsyncTimestamp003, Function | MediumTest| Level3)
{
    sptr<VSyncConnection> tmpConn1 = new VSyncConnection(vsyncDistributor, "rs");
    EXPECT_EQ(tmpConn1->isRsConn_, true);

    EXPECT_EQ(tmpConn1->AddRequestVsyncTimestamp(-1), false);
    EXPECT_EQ(tmpConn1->IsRequestVsyncTimestampEmpty(), true);

    EXPECT_EQ(tmpConn1->AddRequestVsyncTimestamp(0), false);
    EXPECT_EQ(tmpConn1->IsRequestVsyncTimestampEmpty(), true);

    EXPECT_EQ(tmpConn1->AddRequestVsyncTimestamp(1000000000), true);
    EXPECT_EQ(tmpConn1->IsRequestVsyncTimestampEmpty(), false);
}

/**
 * Function: AddRequestVsyncTimestamp
 * Type: Function
 * Rank: Important(2)
 * EnvConditions: N/A
 * CaseDescription: 1.create VsyncConnection with name "rs"
 *                  2.add VsyncTimestamp over MAX_VSYNC_QUEUE_SIZE(30)
 */
HWTEST_F(VSyncConnectionTest, AddRequestVsyncTimestamp004, Function | MediumTest| Level3)
{
    sptr<VSyncConnection> tmpConn1 = new VSyncConnection(vsyncDistributor, "rs");
    EXPECT_EQ(tmpConn1->isRsConn_, true);

    constexpr uint32_t MAX_VSYNC_QUEUE_SIZE = 30;
    int i;
    for (i = 0; i < MAX_VSYNC_QUEUE_SIZE; i++) {
        EXPECT_EQ(tmpConn1->AddRequestVsyncTimestamp(i + 1), true);
    }
    EXPECT_EQ(tmpConn1->AddRequestVsyncTimestamp(i + 1), false);
}

/**
 * Function: AddRequestVsyncTimestamp005
 * Type: Function
 * Rank: Important(2)
 * EnvConditions: N/A
 * CaseDescription: 1.create VsyncConnection with name "rs"
 *                  2.add same VsyncTimestamp over MAX_VSYNC_QUEUE_SIZE(30)
 */
HWTEST_F(VSyncConnectionTest, AddRequestVsyncTimestamp005, Function | MediumTest| Level3)
{
    sptr<VSyncConnection> tmpConn1 = new VSyncConnection(vsyncDistributor, "rs");
    EXPECT_EQ(tmpConn1->isRsConn_, true);

    constexpr uint32_t MAX_VSYNC_QUEUE_SIZE = 30;
    int i;
    for (i = 0; i < MAX_VSYNC_QUEUE_SIZE; i++) {
        EXPECT_EQ(tmpConn1->AddRequestVsyncTimestamp(100000), true);
    }
    EXPECT_EQ(tmpConn1->requestVsyncTimestamp_.size(), 1);
}

/**
 * Function: NeedTriggeredVsync001
 * Type: Function
 * Rank: Important(2)
 * EnvConditions: N/A
 * CaseDescription: 1.create VsyncConnection with name "rs"
 *                  2.add time(1000000000) to VSyncConnection
 *                  3.call NeedTriggeredVsync with time/time + 1/time - 1
 */
HWTEST_F(VSyncConnectionTest, NeedTriggeredVsync001, Function | MediumTest| Level3)
{
    sptr<VSyncConnection> tmpConn1 = new VSyncConnection(vsyncDistributor, "rs");
    EXPECT_EQ(tmpConn1->isRsConn_, true);

    int64_t time = 1000000000;
    EXPECT_EQ(tmpConn1->AddRequestVsyncTimestamp(time), true);
    EXPECT_EQ(tmpConn1->NeedTriggeredVsync(time - 1), false);
    EXPECT_EQ(tmpConn1->NeedTriggeredVsync(time), true);
    EXPECT_EQ(tmpConn1->NeedTriggeredVsync(time + 1), true);

    tmpConn1->RemoveTriggeredVsync(time - 1);
    EXPECT_EQ(tmpConn1->NeedTriggeredVsync(time - 1), false);
    EXPECT_EQ(tmpConn1->NeedTriggeredVsync(time), true);
    EXPECT_EQ(tmpConn1->NeedTriggeredVsync(time + 1), true);

    tmpConn1->RemoveTriggeredVsync(time);
    EXPECT_EQ(tmpConn1->NeedTriggeredVsync(time - 1), false);
    EXPECT_EQ(tmpConn1->NeedTriggeredVsync(time), false);
    EXPECT_EQ(tmpConn1->NeedTriggeredVsync(time + 1), false);
}

/*
* Function: SetUiDvsyncConfig001
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription: 1. call SetUiDvsyncConfig
 */
HWTEST_F(VSyncConnectionTest, SetUiDvsyncConfig001, Function | MediumTest| Level3)
{
    uint32_t bufferCount = 1;
    bool compositeSceneEnable = true;
    bool nativeDelayEnable = true;
    std::vector<std::string> rsDvsyncAnimationList {};
    auto res = vsyncConnectionProxy->SetUiDvsyncConfig(bufferCount, compositeSceneEnable,
        nativeDelayEnable, rsDvsyncAnimationList);
    ASSERT_EQ(res, VSYNC_ERROR_OK);
}

/*
* Function: SetUiDvsyncConfig002
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription: 1. call SetUiDvsyncConfig
 */
HWTEST_F(VSyncConnectionTest, SetUiDvsyncConfig002, Function | MediumTest| Level3)
{
    uint32_t bufferCount = 1;
    bool compositeSceneEnable = true;
    bool nativeDelayEnable = true;
    std::vector<std::string> rsDvsyncAnimationList = {"APP_SWIPER_FLING", "ABILITY_OR_PAGE_SWITCH"};
    auto res = vsyncConnectionProxy->SetUiDvsyncConfig(bufferCount, compositeSceneEnable,
        nativeDelayEnable, rsDvsyncAnimationList);
    ASSERT_EQ(res, VSYNC_ERROR_OK);
}

/*
* Function: SetUiDvsyncConfig003
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription: 1. call SetUiDvsyncConfig
 */
HWTEST_F(VSyncConnectionTest, SetUiDvsyncConfig003, Function | MediumTest| Level3)
{
    uint32_t bufferCount = 1;
    bool compositeSceneEnable = true;
    bool nativeDelayEnable = true;
    std::vector<std::string> rsDvsyncAnimationList = {"APP_SWIPER_FLING", "ABILITY_OR_PAGE_SWITCH",
        "APP_LIST1", "APP_LIST2", "APP_LIST3", "APP_LIST4", "APP_LIST5", "APP_LIST6", "APP_LIST7",
        "APP_LIST8", "APP_LIST9", "APP_LIST10", "APP_LIST11", "APP_LIST12", "APP_LIST13", "APP_LIST14",
        "APP_LIST15", "APP_LIST16", "APP_LIST17", "APP_LIST18", "APP_LIST19", "APP_LIST20", "APP_LIST21"};
    auto res = vsyncConnectionProxy->SetUiDvsyncConfig(bufferCount, compositeSceneEnable,
        nativeDelayEnable, rsDvsyncAnimationList);
    ASSERT_EQ(res, VSYNC_ERROR_OK);
}
} // namespace
} // namespace Rosen
} // namespace OHOS
