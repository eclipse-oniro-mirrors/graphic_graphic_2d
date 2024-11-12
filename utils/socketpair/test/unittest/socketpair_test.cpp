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
#include <hilog/log.h>
#include <cmath>
#include <thread>

#include "local_socketpair.h"

using namespace testing::ext;

namespace OHOS {

static bool g_flag = false;
static void SendDataThread(LocalSocketPair *socketPair)
{
    int32_t data = 10;
    socketPair->SendData((void *)&data, sizeof(int32_t));
    g_flag = true;
}

class LocalSocketPairTest : public testing::Test {
public:
    static constexpr HiviewDFX::HiLogLabel LOG_LABEL = {LOG_CORE, 0, "LocalSocketPairTest"};

    static void SetUpTestCase()
    {}

    static void TearDownTestCase()
    {}
};

/*
* Function: CreateChannel001
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription: CreateChannel
*/
HWTEST_F(LocalSocketPairTest, CreateChannel001, Function | SmallTest | Level2)
{
    LocalSocketPair socketPair;
    socketPair.CreateChannel(8, 8);
    int32_t ret = socketPair.CreateChannel(8, 8);
    ASSERT_EQ(ret, 0);
}
/*
* Function: ReceiveData001
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription: ReceiveData
*/
HWTEST_F(LocalSocketPairTest, ReceiveData001, Function | SmallTest | Level2)
{
    LocalSocketPair socketPair;
    int32_t ret = socketPair.ReceiveData(nullptr, 0);
    ASSERT_EQ(ret, -1);
    socketPair.CreateChannel(8, 8);
    std::thread th(SendDataThread, &socketPair);
    th.join();
    while (!g_flag) {}
    int32_t data = 0;
    ret = socketPair.ReceiveData(&data, sizeof(int32_t));
    ASSERT_EQ(data, 10);
}

/*
* Function: SendData
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription: test SendData without CreateChannel before
*/
HWTEST_F(LocalSocketPairTest, TestSendDataWithoutCreateChannel, Function | SmallTest | Level2)
{
    LocalSocketPair socketPair;
    int32_t data = 10;
    int32_t ret = socketPair.SendData((void *)&data, sizeof(int32_t));
    ASSERT_EQ(ret, -1);
}

/*
* Function: CreateChannel, SendData
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription: test SendData with nullptr
*/
HWTEST_F(LocalSocketPairTest, TestSendNullptr, Function | SmallTest | Level2)
{
    LocalSocketPair socketPair;
    int32_t ret = socketPair.CreateChannel(8, 8);
    ASSERT_EQ(ret, 0);
    ret = socketPair.SendData(nullptr, sizeof(int32_t));
    ASSERT_EQ(ret, -1);
}

/*
* Function: CreateChannel
* Type: Function
* Rank: Important(2)
* EnvConditions: N/A
* CaseDescription: test CreateChannel after closing 0 fd
*/
HWTEST_F(LocalSocketPairTest, Close0Fd, Function | SmallTest | Level2)
{
    LocalSocketPair socketPair;
    close(0);
    int32_t ret = socketPair.CreateChannel(8, 8);
    ASSERT_EQ(ret, 0);
}

/*
 * Function: SendFdToBinder001
 * Type: Function
 * Rank: Important(2)
 * EnvConditions: N/A
 * CaseDescription: test SendFdToBinder
 */
HWTEST_F(LocalSocketPairTest, SendFdToBinder001, Function | SmallTest | Level2)
{
    LocalSocketPair socketPair;
    MessageParcel data;
    int32_t fd = -1;
    int32_t res = socketPair.SendFdToBinder(data, fd);
    EXPECT_EQ(res, -1);

    fd = 1;
    res = socketPair.SendFdToBinder(data, fd);
    EXPECT_EQ(res, 0);
}
}