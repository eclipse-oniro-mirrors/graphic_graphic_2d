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

#include <gtest/gtest.h>
#include <iremote_stub.h>
#include <message_option.h>
#include <message_parcel.h>

#include "transaction/zidl/rs_connect_to_render_process_stub.h"
#include "transaction/rs_connect_to_render_process.h"
#include "platform/ohos/transaction/rs_iconnect_to_render_process_ipc_interface_code.h"

namespace {
constexpr const uint64_t TEST_TOKEN_MASK_ID = 1000;
}

namespace OHOS::Rosen {

class RSConnectToRenderProcessStubTestImpl : public RSConnectToRenderProcessStub {
public:
    RSConnectToRenderProcessStubTestImpl() = default;
    ~RSConnectToRenderProcessStubTestImpl() noexcept = default;

    std::pair<sptr<RSIClientToRenderConnection>, uint64_t> CreateRenderConnection(uint64_t tokenMaskId,
        const sptr<RSIConnectionToken>& token, bool needRefresh) override
    {
        return { nullptr, 0 };
    }

    bool RemoveConnection(uint64_t tokenMaskId) override
    {
        return false;
    }

    std::pair<sptr<RSIClientToRenderConnection>, uint64_t> FindClientToRenderConnection() override
    {
        return { nullptr, TEST_TOKEN_MASK_ID };
    }
};

class RSConnectToRenderProcessStubTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void RSConnectToRenderProcessStubTest::SetUpTestCase() {}
void RSConnectToRenderProcessStubTest::TearDownTestCase() {}
void RSConnectToRenderProcessStubTest::SetUp() {}
void RSConnectToRenderProcessStubTest::TearDown() {}

/**
 * @tc.name: OnRemoteRequestInvalidInterfaceTokenTest
 * @tc.desc: Test OnRemoteRequest with invalid interface token
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSConnectToRenderProcessStubTest, OnRemoteRequestInvalidInterfaceTokenTest,
    testing::ext::TestSize.Level1)
{
    RSConnectToRenderProcessStubTestImpl stub;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(u"invalid.token");
    uint32_t code = static_cast<uint32_t>(RSIConnectToRenderProcessInterfaceCode::CREATE_CONNECTION);
    int res = stub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_INVALID_STATE);
}

/**
 * @tc.name: OnRemoteRequestCreateConnectionInvalidTokenMaskIdTest
 * @tc.desc: Test CREATE_CONNECTION with invalid tokenMaskId (0)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSConnectToRenderProcessStubTest, OnRemoteRequestCreateConnectionInvalidTokenMaskIdTest,
    testing::ext::TestSize.Level1)
{
    RSConnectToRenderProcessStubTestImpl stub;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(RSIConnectToRenderProcess::GetDescriptor());
    data.WriteUint64(0);
    uint32_t code = static_cast<uint32_t>(RSIConnectToRenderProcessInterfaceCode::CREATE_CONNECTION);
    int res = stub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_INVALID_STATE);
}

/**
 * @tc.name: OnRemoteRequestCreateConnectionNullRemoteObjTest
 * @tc.desc: Test CREATE_CONNECTION with null remote object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSConnectToRenderProcessStubTest, OnRemoteRequestCreateConnectionNullRemoteObjTest,
    testing::ext::TestSize.Level1)
{
    RSConnectToRenderProcessStubTestImpl stub;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(RSIConnectToRenderProcess::GetDescriptor());
    data.WriteUint64(TEST_TOKEN_MASK_ID);
    uint32_t code = static_cast<uint32_t>(RSIConnectToRenderProcessInterfaceCode::CREATE_CONNECTION);
    int res = stub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_NULL_OBJECT);
}

/**
 * @tc.name: OnRemoteRequestCreateConnectionNonProxyObjectTest
 * @tc.desc: Test CREATE_CONNECTION with non-proxy remote object
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSConnectToRenderProcessStubTest, OnRemoteRequestCreateConnectionNonProxyObjectTest,
    testing::ext::TestSize.Level1)
{
    RSConnectToRenderProcessStubTestImpl stub;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(RSIConnectToRenderProcess::GetDescriptor());
    data.WriteUint64(TEST_TOKEN_MASK_ID);
    sptr<IRemoteObject> nonProxyObj = new RSConnectToRenderProcessStubTestImpl();
    data.WriteRemoteObject(nonProxyObj);
    uint32_t code = static_cast<uint32_t>(RSIConnectToRenderProcessInterfaceCode::CREATE_CONNECTION);
    int res = stub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_UNKNOWN_OBJECT);
}

/**
 * @tc.name: OnRemoteRequestRemoveConnectionInvalidTokenMaskIdTest
 * @tc.desc: Test REMOVE_CONNECTION with invalid tokenMaskId (0)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSConnectToRenderProcessStubTest, OnRemoteRequestRemoveConnectionInvalidTokenMaskIdTest,
    testing::ext::TestSize.Level1)
{
    RSConnectToRenderProcessStubTestImpl stub;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(RSIConnectToRenderProcess::GetDescriptor());
    data.WriteUint64(0);
    uint32_t code = static_cast<uint32_t>(RSIConnectToRenderProcessInterfaceCode::REMOVE_CONNECTION);
    int res = stub.OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(res, ERR_UNKNOWN_OBJECT);
}

/**
 * @tc.name: OnRemoteRequestDefaultCaseTest
 * @tc.desc: Test OnRemoteRequest with unknown code falls through to IPCObjectStub
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RSConnectToRenderProcessStubTest, OnRemoteRequestDefaultCaseTest,
    testing::ext::TestSize.Level1)
{
    RSConnectToRenderProcessStubTestImpl stub;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(RSIConnectToRenderProcess::GetDescriptor());
    uint32_t code = 9999;
    int res = stub.OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(res, ERR_NONE);
}

} // namespace OHOS::Rosen
