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

#include <iremote_stub.h>
#include <message_option.h>
#include <message_parcel.h>

#include "gtest/gtest.h"
#include "limit_number.h"
#include "rs_irender_service.h"
#include "pipeline/rs_render_service.h"
#include "transaction/rs_render_service_stub.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::Rosen {
class RSRenderServiceStubUnitTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
    
    static sptr<RSIConnectionToken> token_;
    static sptr<RSRenderServiceStub> stub_;
};
sptr<RSIConnectionToken> RSRenderServiceStubUnitTest::token_ = new IRemoteStub<RSIConnectionToken>();
sptr<RSRenderServiceStub> RSRenderServiceStubUnitTest::stub_ = new RSRenderService();

void RSRenderServiceStubUnitTest::SetUpTestCase() {}

void RSRenderServiceStubUnitTest::TearDownTestCase()
{
    token_ = nullptr;
    stub_ = nullptr;
}

void RSRenderServiceStubUnitTest::SetUp() {}
void RSRenderServiceStubUnitTest::TearDown() {}

/**
 * @tc.name: TestRSRenderServiceStub0011
 * @tc.desc: Test if data has no content.
 * @tc.type: FUNC
 * @tc.require: issueI60KUK
 */
HWTEST_F(RSRenderServiceStubUnitTest, TestRSRenderServiceStub0011, TestSize.Level1)
{
    MessageOption option;
    MessageParcel data;
    MessageParcel reply;

    uint32_t code = static_cast<uint32_t>(RSIRenderServiceInterfaceCode::CREATE_CONNECTION);
    int res = stub_->OnRemoteRequest(code, data, reply, option);
    ASSERT_EQ(res, ERR_INVALID_STATE);
}

/**
 * @tc.name: TestRSRenderServiceStub0021
 * @tc.desc: Test if remoteObj is nullptr.
 * @tc.type: FUNC
 * @tc.require: issueI60KUK
 */
HWTEST_F(RSRenderServiceStubUnitTest, TestRSRenderServiceStub0021, TestSize.Level1)
{
    MessageParcel data;
    MessageOption option;
    MessageParcel reply;

    data.WriteInterfaceToken(RSIRenderService::GetDescriptor());
    uint32_t code = static_cast<uint32_t>(RSIRenderServiceInterfaceCode::CREATE_CONNECTION);
    int res = stub_->OnRemoteRequest(code, data, reply, option);
    ASSERT_EQ(res, ERR_NULL_OBJECT);
}

/**
 * @tc.name: TestRSRenderServiceStub0031
 * @tc.desc: Test if the code not exists.
 * @tc.type: FUNC
 * @tc.require: issueI60KUK
 */
HWTEST_F(RSRenderServiceStubUnitTest, TestRSRenderServiceStub0031, TestSize.Level1)
{
    MessageOption option;
    MessageParcel data;
    MessageParcel reply;

    int res = stub_->OnRemoteRequest(-1, data, reply, option);
    ASSERT_EQ(res, IPC_STUB_UNKNOW_TRANS_ERR);
}
} // namespace OHOS::Rosen
