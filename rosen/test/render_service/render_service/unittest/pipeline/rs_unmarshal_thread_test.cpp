/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "pipeline/rs_unmarshal_thread.h"
#include "platform/common/rs_system_properties.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::Rosen {
class RSUnmarshalThreadTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void RSUnmarshalThreadTest::SetUpTestCase() {}
void RSUnmarshalThreadTest::TearDownTestCase() {}
void RSUnmarshalThreadTest::SetUp() {}
void RSUnmarshalThreadTest::TearDown() {}

/*
 * @tc.name: PostTask001
 * @tc.desc: Test PostTask
 * @tc.type: FUNC
 * @tc.require: issueI6QM6E
 */
HWTEST_F(RSUnmarshalThreadTest, PostTask001, TestSize.Level1)
{
    std::function<void()> func = []() -> void {};
    RSUnmarshalThread::Instance().PostTask(func);
    RSUnmarshalThread::Instance().Start();
    ASSERT_NE(RSUnmarshalThread::Instance().runner_, nullptr);
    ASSERT_NE(RSUnmarshalThread::Instance().handler_, nullptr);
    RSUnmarshalThread::Instance().PostTask(func);
}

/*
 * @tc.name: PostTask001
 * @tc.desc: Test RecvParcel
 * @tc.type: FUNC
 * @tc.require: issueI6QM6E
 */
HWTEST_F(RSUnmarshalThreadTest, RecvParcel001, TestSize.Level1)
{
    RSUnmarshalThread::Instance().Start();
    ASSERT_NE(RSUnmarshalThread::Instance().runner_, nullptr);
    ASSERT_NE(RSUnmarshalThread::Instance().handler_, nullptr);
    
    std::shared_ptr<RSTransactionData> transactionData = std::make_shared<RSTransactionData>();
    std::shared_ptr<MessageParcel> data = std::make_shared<MessageParcel>();

    RSUnmarshalThread::Instance().RecvParcel(data);

    bool success = data->WriteParcelable(transactionData.get());
    ASSERT_EQ(success, true);
    RSUnmarshalThread::Instance().RecvParcel(data);
}

/*
 * @tc.name: RecvParcel002
 * @tc.desc: Test RecvParcel
 * @tc.type: FUNC
 * @tc.require: issueIAI1VN
 */
HWTEST_F(RSUnmarshalThreadTest, RecvParcel002, TestSize.Level1)
{
    RSUnmarshalThread::Instance().Start();
    ASSERT_NE(RSUnmarshalThread::Instance().runner_, nullptr);
    ASSERT_NE(RSUnmarshalThread::Instance().handler_, nullptr);

    std::shared_ptr<RSTransactionData> transactionData = std::make_shared<RSTransactionData>();
    std::shared_ptr<MessageParcel> data = std::make_shared<MessageParcel>();

    RSUnmarshalThread::Instance().RecvParcel(data);

    bool success = data->WriteParcelable(transactionData.get());
    ASSERT_EQ(success, true);
    bool isNonSystemAppCalling = true;
    pid_t callingPid = 1111;
    RSUnmarshalThread::Instance().RecvParcel(data, isNonSystemAppCalling, callingPid);
}

/*
 * @tc.name: TransactionDataStatistics001
 * @tc.desc: Test ReportTransactionDataStatistics and ClearTransactionDataStatistics
 * @tc.type: FUNC
 * @tc.require: issueIAPMUF
 */
HWTEST_F(RSUnmarshalThreadTest, TransactionDataStatistics001, TestSize.Level1)
{
    constexpr pid_t callingPid = -1; // invalid pid
    std::shared_ptr<RSTransactionData> transactionData = std::make_shared<RSTransactionData>();
    constexpr bool isSystemCall = false;
    auto& instance = RSUnmarshalThread::Instance();
    bool terminateEnabled = RSSystemProperties::GetTransactionTerminateEnabled();

    RSUnmarshalThread::Instance().ClearTransactionDataStatistics();
    ASSERT_EQ(instance.ReportTransactionDataStatistics(callingPid, transactionData.get(), !isSystemCall), false);
    ASSERT_EQ(instance.ReportTransactionDataStatistics(callingPid, transactionData.get(), !isSystemCall), false);
    ASSERT_EQ(instance.ReportTransactionDataStatistics(callingPid, transactionData.get(), !isSystemCall), false);

    RSUnmarshalThread::Instance().ClearTransactionDataStatistics();
    ASSERT_EQ(instance.ReportTransactionDataStatistics(callingPid, transactionData.get(), isSystemCall), false);
    ASSERT_EQ(instance.ReportTransactionDataStatistics(callingPid, transactionData.get(), isSystemCall), false);
    ASSERT_EQ(instance.ReportTransactionDataStatistics(callingPid, transactionData.get(), isSystemCall), false);
}
}