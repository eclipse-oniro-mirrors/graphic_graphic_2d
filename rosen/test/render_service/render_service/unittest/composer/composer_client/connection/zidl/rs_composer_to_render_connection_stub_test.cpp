/**
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include <set>
#include "rs_composer_to_render_connection_stub.h"
#include "irs_composer_to_render_connection.h"
#include "message_option.h"
#include "message_parcel.h"
#include "sync_fence.h"
#include "surface_type.h"
#include "graphic_common_c.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::Rosen {
class RSComposerToRenderConnectionStubTest : public Test {};

/**
 * Function: Stub_OnRemoteRequest_ReleaseLayerBuffers_Normal
 * Type: Function
 * Rank: Important(2)
 * CaseDescription: 1. write valid token and payload with timestamps only
 *                  2. expect ret OK and reply forwards override return
 */
HWTEST_F(RSComposerToRenderConnectionStubTest, Stub_OnRemoteRequest_ReleaseLayerBuffers_Normal, TestSize.Level1)
{
    class LocalStub : public RSComposerToRenderConnectionStub {
    public:
        int32_t ReleaseLayerBuffers(ReleaseLayerBuffersInfo &info) override
        {
            captured_ = info;
            return 101;
        }
        int32_t NotifyLppLayerToRender(uint64_t, const std::set<uint64_t>&) override { return 0; }
        ReleaseLayerBuffersInfo captured_ {};
    };
    LocalStub stub;

    MessageParcel data;
    MessageParcel reply;
    MessageOption opt;

    ASSERT_TRUE(data.WriteInterfaceToken(IRSComposerToRenderConnection::GetDescriptor()));
    ASSERT_TRUE(data.WriteUint64(9u)); // screenId
    // timestampVec (2 entries)
    ASSERT_TRUE(data.WriteUint32(2u));
    GraphicPresentTimestamp ts1 { GRAPHIC_DISPLAY_PTS_DELAY, 111 };
    GraphicPresentTimestamp ts2 { GRAPHIC_DISPLAY_PTS_TIMESTAMP, 222 };
    ASSERT_TRUE(data.WriteUint64(21u));
    ASSERT_TRUE(data.WriteBool(true));
    ASSERT_TRUE(data.WriteUint32(static_cast<uint32_t>(ts1.type)));
    ASSERT_TRUE(data.WriteInt64(ts1.time));
    ASSERT_TRUE(data.WriteUint64(22u));
    ASSERT_TRUE(data.WriteBool(false));
    ASSERT_TRUE(data.WriteUint32(static_cast<uint32_t>(ts2.type)));
    ASSERT_TRUE(data.WriteInt64(ts2.time));
    // releaseBufferFenceVec (0 entries to avoid buffer serialization)
    ASSERT_TRUE(data.WriteUint32(0u));
    // lastSwapBufferTime
    ASSERT_TRUE(data.WriteInt64(333));

    int ret = stub.OnRemoteRequest(
        IRSComposerToRenderConnection::ICOMPOSER_TO_RENDER_COMPOSER_RELEASE_LAYER_BUFFERS,
        data, reply, opt);
    EXPECT_EQ(ret, COMPOSITOR_ERROR_OK);
    EXPECT_EQ(stub.captured_.screenId, 9u);
    ASSERT_EQ(stub.captured_.timestampVec.size(), 2u);
    EXPECT_EQ(reply.ReadInt32(), 101);
}

/**
 * Function: Stub_OnRemoteRequest_ReleaseLayerBuffers_BadToken
 * Type: Function
 * Rank: Important(2)
 * CaseDescription: 1. write wrong interface token
 *                  2. expect ERR_INVALID_DATA and method not called
 */
HWTEST_F(RSComposerToRenderConnectionStubTest, Stub_OnRemoteRequest_ReleaseLayerBuffers_BadToken, TestSize.Level1)
{
    class LocalStub : public RSComposerToRenderConnectionStub {
    public:
        int32_t ReleaseLayerBuffers(ReleaseLayerBuffersInfo &) override { called_ = true; return 0; }
        int32_t NotifyLppLayerToRender(uint64_t, const std::set<uint64_t>&) override { return 0; }
        bool called_ { false };
    };
    LocalStub stub;

    MessageParcel data;
    MessageParcel reply;
    MessageOption opt;

    ASSERT_TRUE(data.WriteInterfaceToken(u"bad.token"));
    ASSERT_TRUE(data.WriteUint64(1u));
    ASSERT_TRUE(data.WriteUint32(0u));
    ASSERT_TRUE(data.WriteUint32(0u));
    ASSERT_TRUE(data.WriteInt64(0));

    int ret = stub.OnRemoteRequest(
        IRSComposerToRenderConnection::ICOMPOSER_TO_RENDER_COMPOSER_RELEASE_LAYER_BUFFERS,
        data, reply, opt);
    EXPECT_EQ(ret, ERR_INVALID_DATA);
    EXPECT_FALSE(stub.called_);
}

/**
 * Function: Stub_OnRemoteRequest_ReleaseLayerBuffers_ReadBufferFail
 * Type: Function
 * Rank: Important(2)
 * CaseDescription: 1. hasBuffer=true without serialized buffer
 *                  2. expect ERR_INVALID_DATA returned; override still invoked later
 */
HWTEST_F(RSComposerToRenderConnectionStubTest, Stub_OnRemoteRequest_ReleaseLayerBuffers_ReadBufferFail, TestSize.Level1)
{
    class LocalStub : public RSComposerToRenderConnectionStub {
    public:
        int32_t ReleaseLayerBuffers(ReleaseLayerBuffersInfo &info) override
        {
            called_ = true;
            capturedSize_ = info.releaseBufferFenceVec.size();
            return 102;
        }
        int32_t NotifyLppLayerToRender(uint64_t, const std::set<uint64_t>&) override { return 0; }
        bool called_ { false };
        size_t capturedSize_ { 0 };
    };
    LocalStub stub;

    MessageParcel data;
    MessageParcel reply;
    MessageOption opt;

    ASSERT_TRUE(data.WriteInterfaceToken(IRSComposerToRenderConnection::GetDescriptor()));
    ASSERT_TRUE(data.WriteUint64(2u));
    ASSERT_TRUE(data.WriteUint32(0u)); // no timestamps
    ASSERT_TRUE(data.WriteUint32(1u)); // one buffer entry
    ASSERT_TRUE(data.WriteUint64(99u));
    ASSERT_TRUE(data.WriteBool(true)); // hasBuffer but no buffer content serialized
    // write a fence to satisfy following read, though buffer read fails before
    sptr<SyncFence> fence = sptr<SyncFence>::MakeSptr(-1);
    ASSERT_TRUE(fence->WriteToMessageParcel(data));
    ASSERT_TRUE(data.WriteInt64(0));

    int ret = stub.OnRemoteRequest(
        IRSComposerToRenderConnection::ICOMPOSER_TO_RENDER_COMPOSER_RELEASE_LAYER_BUFFERS,
        data, reply, opt);
    EXPECT_EQ(ret, ERR_INVALID_DATA);
    EXPECT_TRUE(stub.called_);
    EXPECT_EQ(stub.capturedSize_, 1u);
    EXPECT_EQ(reply.ReadInt32(), 102);
}

/**
 * Function: Stub_OnRemoteRequest_Notify_Normal
 * Type: Function
 * Rank: Important(2)
 * CaseDescription: 1. write valid token and lpp ids
 *                  2. expect ret OK and reply forwards override return
 */
HWTEST_F(RSComposerToRenderConnectionStubTest, Stub_OnRemoteRequest_Notify_Normal, TestSize.Level1)
{
    class LocalStub : public RSComposerToRenderConnectionStub {
    public:
        int32_t ReleaseLayerBuffers(ReleaseLayerBuffersInfo &) override { return 0; }
        int32_t NotifyLppLayerToRender(uint64_t vsyncId, const std::set<uint64_t> &ids) override
        {
            lastVsync_ = vsyncId;
            lastCount_ = ids.size();
            return 201;
        }
        uint64_t lastVsync_ { 0 };
        size_t lastCount_ { 0 };
    };
    LocalStub stub;

    MessageParcel data;
    MessageParcel reply;
    MessageOption opt;

    ASSERT_TRUE(data.WriteInterfaceToken(IRSComposerToRenderConnection::GetDescriptor()));
    ASSERT_TRUE(data.WriteUint64(777u));
    ASSERT_TRUE(data.WriteInt32(3));
    ASSERT_TRUE(data.WriteUint64(11u));
    ASSERT_TRUE(data.WriteUint64(22u));
    ASSERT_TRUE(data.WriteUint64(33u));

    int ret = stub.OnRemoteRequest(
        IRSComposerToRenderConnection::NOTIFY_LPP_LAYER_TO_RENDER,
        data, reply, opt);
    EXPECT_EQ(ret, COMPOSITOR_ERROR_OK);
    EXPECT_EQ(stub.lastVsync_, 777u);
    EXPECT_EQ(stub.lastCount_, 3u);
    EXPECT_EQ(reply.ReadInt32(), 201);
}

/**
 * Function: Stub_OnRemoteRequest_Notify_BadToken
 * Type: Function
 * Rank: Important(2)
 * CaseDescription: 1. write wrong interface token
 *                  2. expect ERR_INVALID_DATA and method not called
 */
HWTEST_F(RSComposerToRenderConnectionStubTest, Stub_OnRemoteRequest_Notify_BadToken, TestSize.Level1)
{
    class LocalStub : public RSComposerToRenderConnectionStub {
    public:
        int32_t ReleaseLayerBuffers(ReleaseLayerBuffersInfo &) override { return 0; }
        int32_t NotifyLppLayerToRender(uint64_t, const std::set<uint64_t> &) override { called_ = true; return 0; }
        bool called_ { false };
    };
    LocalStub stub;

    MessageParcel data;
    MessageParcel reply;
    MessageOption opt;

    ASSERT_TRUE(data.WriteInterfaceToken(u"bad.token"));
    ASSERT_TRUE(data.WriteUint64(1u));
    ASSERT_TRUE(data.WriteInt32(0));

    int ret = stub.OnRemoteRequest(
        IRSComposerToRenderConnection::NOTIFY_LPP_LAYER_TO_RENDER,
        data, reply, opt);
    EXPECT_EQ(ret, ERR_INVALID_DATA);
    EXPECT_FALSE(stub.called_);
}

/**
 * Function: Stub_OnRemoteRequest_DefaultBranch
 * Type: Function
 * Rank: Important(2)
 * CaseDescription: 1. call with unsupported code
 *                  2. expect COMPOSITOR_ERROR_INVALID_ARGUMENTS
 */
HWTEST_F(RSComposerToRenderConnectionStubTest, Stub_OnRemoteRequest_DefaultBranch, TestSize.Level1)
{
    class LocalStub : public RSComposerToRenderConnectionStub {
    public:
        int32_t ReleaseLayerBuffers(ReleaseLayerBuffersInfo &) override { return 0; }
        int32_t NotifyLppLayerToRender(uint64_t, const std::set<uint64_t>&) override { return 0; }
    };
    LocalStub stub;
    MessageParcel data;
    MessageParcel reply;
    MessageOption opt;
    int ret = stub.OnRemoteRequest(999u, data, reply, opt);
    EXPECT_EQ(ret, COMPOSITOR_ERROR_INVALID_ARGUMENTS);
}
} // namespace OHOS::Rosen