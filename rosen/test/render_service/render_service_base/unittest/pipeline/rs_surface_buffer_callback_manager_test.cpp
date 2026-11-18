/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifdef ROSEN_OHOS

#include <fcntl.h>
#include <unistd.h>

#include <vector>

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "ipc_callbacks/rs_surface_buffer_callback.h"
#include "pipeline/rs_surface_buffer_callback_manager.h"
#include "pipeline/rs_draw_cmd.h"
#include "platform/common/rs_system_properties.h"
#include "surface_buffer.h"
#include "surface_type.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Rosen {
namespace {
constexpr pid_t RELEASE_FENCE_TEST_PID = 5000;
constexpr uint64_t RELEASE_FENCE_TEST_UID = 50001;
constexpr NodeId RELEASE_FENCE_TEST_ROOT_ID = 100;
constexpr NodeId RELEASE_FENCE_OTHER_ROOT_ID = 200;

// register a callback which records every OnFinish ret, then staging can be fed
// through the public path GetOnFinishCb and verified through RunSurfaceBufferCallback
void RegisterRecordCallback(std::vector<FinishCallbackRet>& records)
{
    DefaultSurfaceBufferCallbackFuncs funcs;
    funcs.OnFinish = [&records](const FinishCallbackRet& ret) { records.push_back(ret); };
    funcs.OnAfterAcquireBuffer = [](const AfterAcquireBufferRet&) {};
    sptr<RSDefaultSurfaceBufferCallback> callback =
        new RSDefaultSurfaceBufferCallback(funcs);
    RSSurfaceBufferCallbackManager::Instance().RegisterSurfaceBufferCallback(
        RELEASE_FENCE_TEST_PID, RELEASE_FENCE_TEST_UID, callback);
}

// stage one buffer entry via the public OnFinish path, default releaseFence is INVALID_FENCE
void StageBuffer(uint32_t bufferId, NodeId rootNodeId, bool isRendered)
{
    Drawing::DrawSurfaceBufferFinishCbData data;
    data.pid = RELEASE_FENCE_TEST_PID;
    data.uid = RELEASE_FENCE_TEST_UID;
    data.surfaceBufferId = bufferId;
    data.rootNodeId = rootNodeId;
    data.isRendered = isRendered;
    data.isNeedTriggerCbDirectly = false;
    RSSurfaceBufferCallbackManager::Instance().GetOnFinishCb()(data);
}

// fd of /dev/null: GetStatus returns ERROR (!= SIGNALED), so SetReleaseFence takes the Dup branch
sptr<SyncFence> CreateUnsignaledLikeFence()
{
    int32_t fd = ::open("/dev/null", O_RDONLY);
    if (fd < 0) {
        return SyncFence::InvalidFence();
    }
    return sptr<SyncFence>(new SyncFence(fd));
}

bool IsVulkanLikeGpuApi()
{
    return RSSystemProperties::GetGpuApiType() == GpuApiType::VULKAN ||
        RSSystemProperties::GetGpuApiType() == GpuApiType::DDGR;
}
} // namespace

class RSSurfaceBufferCallbackManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void RSSurfaceBufferCallbackManagerTest::SetUpTestCase() {}
void RSSurfaceBufferCallbackManagerTest::TearDownTestCase() {}
void RSSurfaceBufferCallbackManagerTest::SetUp() {}
// TearDown runs even when a case exits early on ASSERT failure:
// flush the staging map and drop the recorded callback to isolate cases
void RSSurfaceBufferCallbackManagerTest::TearDown()
{
    RSSurfaceBufferCallbackManager::Instance().RunSurfaceBufferCallback();
    RSSurfaceBufferCallbackManager::Instance().UnregisterSurfaceBufferCallback(
        RELEASE_FENCE_TEST_PID, RELEASE_FENCE_TEST_UID);
}

/**
 * @tc.name: UnregisterSurfaceBufferCallback001
 * @tc.desc: Test UnregisterSurfaceBufferCallback(pid_t) clears buffer info
 * @tc.type: FUNC
 * @tc.require: issue28175
 */
HWTEST_F(RSSurfaceBufferCallbackManagerTest, UnregisterSurfaceBufferCallback001, TestSize.Level1)
{
    pid_t testPid = 2000;
    uint64_t testUid1 = 20001;
    uint64_t testUid2 = 20002;
    
    sptr<SurfaceBuffer> buffer1 = SurfaceBuffer::Create();
    DrawingSurfaceBufferInfo info1;
    info1.surfaceBuffer_ = buffer1;
    info1.pid_ = testPid;
    info1.uid_ = testUid1;
    RSSurfaceBufferCallbackManager::Instance().StoreSurfaceBufferInfo(info1);
    
    sptr<SurfaceBuffer> buffer2 = SurfaceBuffer::Create();
    DrawingSurfaceBufferInfo info2;
    info2.surfaceBuffer_ = buffer2;
    info2.pid_ = testPid;
    info2.uid_ = testUid2;
    RSSurfaceBufferCallbackManager::Instance().StoreSurfaceBufferInfo(info2);
    
    auto result1 = RSSurfaceBufferCallbackManager::Instance().GetSurfaceBufferInfoByPid(testPid);
    EXPECT_EQ(result1.size(), 2);
    
    RSSurfaceBufferCallbackManager::Instance().UnregisterSurfaceBufferCallback(testPid);
    
    auto result2 = RSSurfaceBufferCallbackManager::Instance().GetSurfaceBufferInfoByPid(testPid);
    EXPECT_EQ(result2.size(), 0);
}

/**
 * @tc.name: UnregisterSurfaceBufferCallback002
 * @tc.desc: Test UnregisterSurfaceBufferCallback(pid_t) doesn't affect other processes
 * @tc.type: FUNC
 * @tc.require: issue28175
 */
HWTEST_F(RSSurfaceBufferCallbackManagerTest, UnregisterSurfaceBufferCallback002, TestSize.Level1)
{
    pid_t pid1 = 2001;
    pid_t pid2 = 2002;
    uint64_t uid1 = 20011;
    uint64_t uid2 = 20021;
    
    sptr<SurfaceBuffer> buffer1 = SurfaceBuffer::Create();
    DrawingSurfaceBufferInfo info1;
    info1.surfaceBuffer_ = buffer1;
    info1.pid_ = pid1;
    info1.uid_ = uid1;
    RSSurfaceBufferCallbackManager::Instance().StoreSurfaceBufferInfo(info1);
    
    sptr<SurfaceBuffer> buffer2 = SurfaceBuffer::Create();
    DrawingSurfaceBufferInfo info2;
    info2.surfaceBuffer_ = buffer2;
    info2.pid_ = pid2;
    info2.uid_ = uid2;
    RSSurfaceBufferCallbackManager::Instance().StoreSurfaceBufferInfo(info2);
    
    RSSurfaceBufferCallbackManager::Instance().UnregisterSurfaceBufferCallback(pid1);
    
    auto result1 = RSSurfaceBufferCallbackManager::Instance().GetSurfaceBufferInfoByPid(pid1);
    auto result2 = RSSurfaceBufferCallbackManager::Instance().GetSurfaceBufferInfoByPid(pid2);
    
    EXPECT_EQ(result1.size(), 0);
    EXPECT_EQ(result2.size(), 1);
}

/**
 * @tc.name: UnregisterSurfaceBufferCallback003
 * @tc.desc: Test UnregisterSurfaceBufferCallback(pid_t, uid) clears buffer info
 * @tc.type: FUNC
 * @tc.require: issue28175
 */
HWTEST_F(RSSurfaceBufferCallbackManagerTest, UnregisterSurfaceBufferCallback003, TestSize.Level1)
{
    pid_t testPid = 2003;
    uint64_t testUid = 20031;
    
    sptr<SurfaceBuffer> buffer = SurfaceBuffer::Create();
    DrawingSurfaceBufferInfo info;
    info.surfaceBuffer_ = buffer;
    info.pid_ = testPid;
    info.uid_ = testUid;
    RSSurfaceBufferCallbackManager::Instance().StoreSurfaceBufferInfo(info);
    
    auto result1 = RSSurfaceBufferCallbackManager::Instance().GetSurfaceBufferInfoByPid(testPid);
    EXPECT_EQ(result1.size(), 1);
    
    RSSurfaceBufferCallbackManager::Instance().UnregisterSurfaceBufferCallback(testPid, testUid);
    
    auto result2 = RSSurfaceBufferCallbackManager::Instance().GetSurfaceBufferInfoByPid(testPid);
    EXPECT_EQ(result2.size(), 0);
}

/**
 * @tc.name: UnregisterSurfaceBufferCallback004
 * @tc.desc: Test UnregisterSurfaceBufferCallback(pid_t, uid) doesn't affect other uids
 * @tc.type: FUNC
 * @tc.require: issue28175
 */
HWTEST_F(RSSurfaceBufferCallbackManagerTest, UnregisterSurfaceBufferCallback004, TestSize.Level1)
{
    pid_t testPid = 2004;
    uint64_t uid1 = 20041;
    uint64_t uid2 = 20042;
    
    sptr<SurfaceBuffer> buffer1 = SurfaceBuffer::Create();
    DrawingSurfaceBufferInfo info1;
    info1.surfaceBuffer_ = buffer1;
    info1.pid_ = testPid;
    info1.uid_ = uid1;
    RSSurfaceBufferCallbackManager::Instance().StoreSurfaceBufferInfo(info1);
    
    sptr<SurfaceBuffer> buffer2 = SurfaceBuffer::Create();
    DrawingSurfaceBufferInfo info2;
    info2.surfaceBuffer_ = buffer2;
    info2.pid_ = testPid;
    info2.uid_ = uid2;
    RSSurfaceBufferCallbackManager::Instance().StoreSurfaceBufferInfo(info2);
    
    RSSurfaceBufferCallbackManager::Instance().UnregisterSurfaceBufferCallback(testPid, uid1);
    
    auto result = RSSurfaceBufferCallbackManager::Instance().GetSurfaceBufferInfoByPid(testPid);
    EXPECT_EQ(result.size(), 1);
    EXPECT_EQ(result[0].uid_, uid2);
}

/**
 * @tc.name: SetReleaseFence001
 * @tc.desc: Test SetReleaseFence skips all fence syscalls when staging is empty
 * @tc.type: FUNC
 * @tc.require: issue26201
 */
HWTEST_F(RSSurfaceBufferCallbackManagerTest, SetReleaseFence001, TestSize.Level1)
{
    // covers the gpu api guard branch on GL environment, inner branches on VK/DDGR
    if (!IsVulkanLikeGpuApi()) {
        return;
    }
    std::vector<FinishCallbackRet> records;
    RegisterRecordCallback(records);

    RSSurfaceBufferCallbackManager::Instance().SetReleaseFence(CreateUnsignaledLikeFence());
    RSSurfaceBufferCallbackManager::Instance().RunSurfaceBufferCallback();
    EXPECT_TRUE(records.empty());
    // TearDown flushes staging and unregisters the recorded callback
}

/**
 * @tc.name: SetReleaseFence002
 * @tc.desc: Test SetReleaseFence dup'ed from unsignaled acquireFence for rendered matching entry
 * @tc.type: FUNC
 * @tc.require: issue26201
 */
HWTEST_F(RSSurfaceBufferCallbackManagerTest, SetReleaseFence002, TestSize.Level1)
{
    if (!IsVulkanLikeGpuApi()) {
        return;
    }
    std::vector<FinishCallbackRet> records;
    RegisterRecordCallback(records);
    StageBuffer(1, RELEASE_FENCE_TEST_ROOT_ID, true);

    RSSurfaceBufferCallbackManager::Instance().SetReleaseFence(
        CreateUnsignaledLikeFence(), RELEASE_FENCE_TEST_ROOT_ID);
    RSSurfaceBufferCallbackManager::Instance().RunSurfaceBufferCallback();

    ASSERT_EQ(records.size(), 1);
    ASSERT_EQ(records[0].releaseFences.size(), 1);
    EXPECT_NE(records[0].releaseFences[0], nullptr);
    EXPECT_TRUE(records[0].releaseFences[0]->IsValid());
    // TearDown flushes staging and unregisters the recorded callback
}

/**
 * @tc.name: SetReleaseFence003
 * @tc.desc: Test SetReleaseFence falls back to INVALID_FD when acquireFence is null
 * @tc.type: FUNC
 * @tc.require: issue26201
 */
HWTEST_F(RSSurfaceBufferCallbackManagerTest, SetReleaseFence003, TestSize.Level1)
{
    if (!IsVulkanLikeGpuApi()) {
        return;
    }
    std::vector<FinishCallbackRet> records;
    RegisterRecordCallback(records);
    StageBuffer(2, RELEASE_FENCE_TEST_ROOT_ID, true);

    RSSurfaceBufferCallbackManager::Instance().SetReleaseFence(
        sptr<SyncFence>(), RELEASE_FENCE_TEST_ROOT_ID);
    RSSurfaceBufferCallbackManager::Instance().RunSurfaceBufferCallback();

    ASSERT_EQ(records.size(), 1);
    ASSERT_EQ(records[0].releaseFences.size(), 1);
    EXPECT_NE(records[0].releaseFences[0], nullptr);
    EXPECT_FALSE(records[0].releaseFences[0]->IsValid());
    // TearDown flushes staging and unregisters the recorded callback
}

/**
 * @tc.name: SetReleaseFence004
 * @tc.desc: Test int overload uses caller owned fd without closing it
 * @tc.type: FUNC
 * @tc.require: issue26201
 */
HWTEST_F(RSSurfaceBufferCallbackManagerTest, SetReleaseFence004, TestSize.Level1)
{
    if (!IsVulkanLikeGpuApi()) {
        return;
    }
    std::vector<FinishCallbackRet> records;
    RegisterRecordCallback(records);
    StageBuffer(3, RELEASE_FENCE_TEST_ROOT_ID, true);

    int32_t fenceFd = ::open("/dev/null", O_RDONLY);
    ASSERT_GE(fenceFd, 0);
    RSSurfaceBufferCallbackManager::Instance().SetReleaseFence(fenceFd, RELEASE_FENCE_TEST_ROOT_ID);
    // caller keeps fd ownership, SetReleaseFence must not close it
    EXPECT_NE(::fcntl(fenceFd, F_GETFL), -1);
    ::close(fenceFd);

    RSSurfaceBufferCallbackManager::Instance().RunSurfaceBufferCallback();
    ASSERT_EQ(records.size(), 1);
    ASSERT_EQ(records[0].releaseFences.size(), 1);
    EXPECT_NE(records[0].releaseFences[0], nullptr);
    EXPECT_TRUE(records[0].releaseFences[0]->IsValid());
    // TearDown flushes staging and unregisters the recorded callback
}

/**
 * @tc.name: SetReleaseFence005
 * @tc.desc: Test SetReleaseFence keeps staged fence of entries not matching rootNodeId
 * @tc.type: FUNC
 * @tc.require: issue26201
 */
HWTEST_F(RSSurfaceBufferCallbackManagerTest, SetReleaseFence005, TestSize.Level1)
{
    if (!IsVulkanLikeGpuApi()) {
        return;
    }
    std::vector<FinishCallbackRet> records;
    RegisterRecordCallback(records);
    StageBuffer(4, RELEASE_FENCE_OTHER_ROOT_ID, true);

    RSSurfaceBufferCallbackManager::Instance().SetReleaseFence(
        CreateUnsignaledLikeFence(), RELEASE_FENCE_TEST_ROOT_ID);
    RSSurfaceBufferCallbackManager::Instance().RunSurfaceBufferCallback();

    ASSERT_EQ(records.size(), 1);
    ASSERT_EQ(records[0].releaseFences.size(), 1);
    EXPECT_NE(records[0].releaseFences[0], nullptr);
    // rootNodeId mismatch, staged invalid fence is kept as is
    EXPECT_FALSE(records[0].releaseFences[0]->IsValid());
    // TearDown flushes staging and unregisters the recorded callback
}

/**
 * @tc.name: SetReleaseFence006
 * @tc.desc: Test SetReleaseFence only updates rendered entries matching rootNodeId
 * @tc.type: FUNC
 * @tc.require: issue26201
 */
HWTEST_F(RSSurfaceBufferCallbackManagerTest, SetReleaseFence006, TestSize.Level1)
{
    if (!IsVulkanLikeGpuApi()) {
        return;
    }
    std::vector<FinishCallbackRet> records;
    RegisterRecordCallback(records);
    StageBuffer(5, RELEASE_FENCE_TEST_ROOT_ID, true);   // rendered + match, shall be updated
    StageBuffer(6, RELEASE_FENCE_OTHER_ROOT_ID, true);  // rendered + mismatch, shall be kept
    StageBuffer(7, RELEASE_FENCE_TEST_ROOT_ID, false);  // not rendered + match, shall be kept

    RSSurfaceBufferCallbackManager::Instance().SetReleaseFence(
        CreateUnsignaledLikeFence(), RELEASE_FENCE_TEST_ROOT_ID);
    RSSurfaceBufferCallbackManager::Instance().RunSurfaceBufferCallback();

    ASSERT_EQ(records.size(), 1);
    ASSERT_EQ(records[0].releaseFences.size(), 3);
    EXPECT_NE(records[0].releaseFences[0], nullptr);
    EXPECT_TRUE(records[0].releaseFences[0]->IsValid());
    EXPECT_NE(records[0].releaseFences[1], nullptr);
    EXPECT_FALSE(records[0].releaseFences[1]->IsValid());
    EXPECT_NE(records[0].releaseFences[2], nullptr);
    EXPECT_FALSE(records[0].releaseFences[2]->IsValid());
    // TearDown flushes staging and unregisters the recorded callback
}

} // namespace Rosen
} // namespace OHOS

#endif // ROSEN_OHOS
