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

#include "gtest/gtest.h"

#include "memory/rs_memory_manager.h"
#include "render/rs_typeface_cache.h"

using namespace testing;
using namespace testing::ext;
namespace OHOS {
namespace Rosen {

class RSTypefaceCacheTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void RSTypefaceCacheTest::SetUpTestCase() {}
void RSTypefaceCacheTest::TearDownTestCase() {}
void RSTypefaceCacheTest::SetUp() {}
void RSTypefaceCacheTest::TearDown() {}

static void MemoryOverCheckTest(const pid_t pid, const size_t size, bool isGpu)
{
    MemorySnapshotInfo memoryInfo;
    if (isGpu) {
        MemorySnapshot::Instance().AddGpuMemory(pid, size, memoryInfo);
    } else {
        MemorySnapshot::Instance().AddCpuMemory(pid, size, memoryInfo);
    }
}

/**
 * @tc.name: MemorySnapshotTest001
 * @tc.desc: Verify memory info of RSTypefaceCache
 * @tc.type:FUNC
 */
HWTEST_F(RSTypefaceCacheTest, MemorySnapshotTest001, TestSize.Level1)
{
    // prepare: typeface, size, hash, MemoryOverCheck hook
    std::shared_ptr<Drawing::Typeface> typeface = Drawing::Typeface::MakeDefault();
    EXPECT_NE(typeface, nullptr);
    uint32_t size = typeface->GetSize();
    EXPECT_NE(size, 0);
    uint32_t hash = typeface->GetHash();
    EXPECT_NE(hash, 0);
    RSTypefaceCache::Instance().SetMemoryCheckCallback(MemoryOverCheckTest);
    // app1's pid is 123, app2's pid2 is 456, register same typeface
    pid_t pid1 = 123;
    pid_t pid2 = 456;
    uint64_t uniqueId1 = (((uint64_t)pid1) << 32) | (uint64_t)(typeface->GetUniqueID());
    uint64_t uniqueId2 = (((uint64_t)pid2) << 32) | (uint64_t)(typeface->GetUniqueID());

    // Get base memory snapshot info before test
    MemorySnapshotInfo baseInfo1;
    bool ret = MemorySnapshot::Instance().GetMemorySnapshotInfoByPid(pid1, baseInfo1);
    EXPECT_EQ(ret, false);
    MemorySnapshotInfo baseInfo2;
    ret = MemorySnapshot::Instance().GetMemorySnapshotInfoByPid(pid2, baseInfo2);
    EXPECT_EQ(ret, false);

    // branch1: pid1 register typeface
    ret = RSTypefaceCache::Instance().HasTypeface(uniqueId1, hash);
    EXPECT_EQ(ret, false);
    RSTypefaceCache::Instance().CacheDrawingTypeface(uniqueId1, typeface);
    MemorySnapshotInfo currentInfo;
    ret = MemorySnapshot::Instance().GetMemorySnapshotInfoByPid(pid1, currentInfo);
    EXPECT_EQ(ret, true);
    EXPECT_EQ(currentInfo.cpuMemory, baseInfo1.cpuMemory + size);
    // branch2: whether pid2 typeface exits
    ret = RSTypefaceCache::Instance().HasTypeface(uniqueId2, hash);
    EXPECT_EQ(ret, true);
    currentInfo = { 0 };
    ret = MemorySnapshot::Instance().GetMemorySnapshotInfoByPid(pid2, currentInfo);
    EXPECT_EQ(ret, true);
    EXPECT_EQ(currentInfo.cpuMemory, baseInfo2.cpuMemory + size);
    // branch3: pid2 register typeface if exits
    RSTypefaceCache::Instance().CacheDrawingTypeface(uniqueId2, typeface);
    currentInfo = { 0 };
    ret = MemorySnapshot::Instance().GetMemorySnapshotInfoByPid(pid2, currentInfo);
    EXPECT_EQ(ret, true);
    EXPECT_EQ(currentInfo.cpuMemory, baseInfo2.cpuMemory + size);

    // pid1 ungister typeface
    RSTypefaceCache::Instance().RemoveDrawingTypefaceByGlobalUniqueId(uniqueId1);
    currentInfo = { 0 };
    ret = MemorySnapshot::Instance().GetMemorySnapshotInfoByPid(pid1, currentInfo);
    EXPECT_EQ(ret, true);
    EXPECT_EQ(currentInfo.cpuMemory, baseInfo1.cpuMemory);
    // pid2 ungister typeface
    RSTypefaceCache::Instance().RemoveDrawingTypefaceByGlobalUniqueId(uniqueId2);
    currentInfo = { 0 };
    ret = MemorySnapshot::Instance().GetMemorySnapshotInfoByPid(pid2, currentInfo);
    EXPECT_EQ(ret, true);
    EXPECT_EQ(currentInfo.cpuMemory, baseInfo2.cpuMemory);

    // clear context
    RSTypefaceCache::Instance().RemoveDrawingTypefacesByPid(pid1);
    RSTypefaceCache::Instance().RemoveDrawingTypefacesByPid(pid2);
    RSTypefaceCache::Instance().SetMemoryCheckCallback(nullptr);
}

/**
 * @tc.name: GenGlobalUniqueIdTest001
 * @tc.desc: Verify function GenGlobalUniqueId
 * @tc.type:FUNC
 */
HWTEST_F(RSTypefaceCacheTest, GenGlobalUniqueIdTest001, TestSize.Level1)
{
    EXPECT_NE(RSTypefaceCache::Instance().GenGlobalUniqueId(1), 0);
}

/**
 * @tc.name: GetTypefacePidTest001
 * @tc.desc: Verify function GetTypefacePid
 * @tc.type:FUNC
 */
HWTEST_F(RSTypefaceCacheTest, GetTypefacePidTest001, TestSize.Level1)
{
    EXPECT_EQ(RSTypefaceCache::Instance().GetTypefacePid(1), 0);
}

/**
 * @tc.name: GetTypefaceIdTest001
 * @tc.desc: Verify function GetTypefaceId
 * @tc.type:FUNC
 */
HWTEST_F(RSTypefaceCacheTest, GetTypefaceIdTest001, TestSize.Level1)
{
    EXPECT_NE(RSTypefaceCache::Instance().GetTypefaceId(1), 0);
}

/**
 * @tc.name: CacheDrawingTypefaceTest001
 * @tc.desc: Verify function CacheDrawingTypeface
 * @tc.type:FUNC
 */
HWTEST_F(RSTypefaceCacheTest, CacheDrawingTypefaceTest001, TestSize.Level1)
{
    auto typeface = Drawing::Typeface::MakeDefault();
    uint64_t uniqueIdF = 1;
    uint64_t uniqueIdS = 2;
    RSTypefaceCache::Instance().CacheDrawingTypeface(uniqueIdF, typeface);
    RSTypefaceCache::Instance().CacheDrawingTypeface(uniqueIdS, typeface);
    EXPECT_FALSE(RSTypefaceCache::Instance().typefaceHashMap_.empty());
}

/**
 * @tc.name: RemoveDrawingTypefaceByGlobalUniqueIdTest001
 * @tc.desc: Verify function RemoveDrawingTypefaceByGlobalUniqueId
 * @tc.type:FUNC
 */
HWTEST_F(RSTypefaceCacheTest, RemoveDrawingTypefaceByGlobalUniqueIdTest001, TestSize.Level1)
{
    uint64_t uniqueIdF = 1;
    uint64_t uniqueIdS = 3;
    RSTypefaceCache::Instance().RemoveDrawingTypefaceByGlobalUniqueId(uniqueIdF);
    RSTypefaceCache::Instance().RemoveDrawingTypefaceByGlobalUniqueId(uniqueIdS);
    EXPECT_FALSE(RSTypefaceCache::Instance().typefaceHashMap_.empty());
}

/**
 * @tc.name: GetDrawingTypefaceCacheTest001
 * @tc.desc: Verify function GetDrawingTypefaceCache
 * @tc.type:FUNC
 */
HWTEST_F(RSTypefaceCacheTest, GetDrawingTypefaceCacheTest001, TestSize.Level1)
{
    uint64_t uniqueIdF = 1;
    uint64_t uniqueIdS = 2;
    EXPECT_EQ(RSTypefaceCache::Instance().GetDrawingTypefaceCache(uniqueIdF), nullptr);
    EXPECT_NE(RSTypefaceCache::Instance().GetDrawingTypefaceCache(uniqueIdS), nullptr);
}

/**
 * @tc.name: RemoveDrawingTypefacesByPidTest001
 * @tc.desc: Verify function RemoveDrawingTypefacesByPid
 * @tc.type:FUNC
 */
HWTEST_F(RSTypefaceCacheTest, RemoveDrawingTypefacesByPidTest001, TestSize.Level1)
{
    uint64_t uniqueId = 2;
    pid_t pid = static_cast<pid_t>(uniqueId >> 32);
    RSTypefaceCache::Instance().RemoveDrawingTypefacesByPid(uniqueId);
    RSTypefaceCache::Instance().RemoveDrawingTypefacesByPid(pid);
    EXPECT_TRUE(RSTypefaceCache::Instance().typefaceHashCode_.empty());
}

/**
 * @tc.name: AddDelayDestroyQueueTest001
 * @tc.desc: Verify function AddDelayDestroyQueue
 * @tc.type:FUNC
 */
HWTEST_F(RSTypefaceCacheTest, AddDelayDestroyQueueTest001, TestSize.Level1)
{
    uint64_t uniqueId = 1;
    RSTypefaceCache::Instance().AddDelayDestroyQueue(uniqueId);
    EXPECT_TRUE(RSTypefaceCache::Instance().typefaceHashCode_.empty());
}

/**
 * @tc.name: HandleDelayDestroyQueueTest001
 * @tc.desc: Verify function HandleDelayDestroyQueue
 * @tc.type:FUNC
 */
HWTEST_F(RSTypefaceCacheTest, HandleDelayDestroyQueueTest001, TestSize.Level1)
{
    auto typeface = Drawing::Typeface::MakeDefault();
    uint64_t uniqueIdF = 1;
    uint64_t uniqueIdS = 2;
    RSTypefaceCache::Instance().CacheDrawingTypeface(uniqueIdF, typeface);
    RSTypefaceCache::Instance().CacheDrawingTypeface(uniqueIdS, typeface);
    RSTypefaceCache::Instance().HandleDelayDestroyQueue();
    RSTypefaceCache::Instance().Dump();
    EXPECT_FALSE(RSTypefaceCache::Instance().typefaceHashCode_.empty());
}

/**
 * @tc.name: ReplaySerializeTest001
 * @tc.desc: Verify function ReplaySerialize
 * @tc.type:FUNC
 */
HWTEST_F(RSTypefaceCacheTest, ReplaySerializeTest001, TestSize.Level1)
{
    auto typeface = Drawing::Typeface::MakeDefault();
    uint64_t uniqueId = 1;
    RSTypefaceCache::Instance().CacheDrawingTypeface(uniqueId, typeface);

    size_t fontCount = 0;
    std::stringstream fontStream;
    RSTypefaceCache::Instance().ReplaySerialize(fontStream);
    fontStream.read(reinterpret_cast<char*>(&fontCount), sizeof(fontCount));
    EXPECT_NE(fontCount, 0);
}

/**
 * @tc.name: ReplayDeserializeTest001
 * @tc.desc: Verify function ReplayDeserialize
 * @tc.type:FUNC
 */
HWTEST_F(RSTypefaceCacheTest, ReplayDeserializeTest001, TestSize.Level1)
{
    uint64_t uniqueId = 1;
    uint64_t replayMask = (uint64_t)1 << (30 + 32);
    std::stringstream fontStream;
    RSTypefaceCache::Instance().ReplaySerialize(fontStream);
    RSTypefaceCache::Instance().ReplayDeserialize(fontStream);
    EXPECT_NE(RSTypefaceCache::Instance().typefaceHashCode_.find(uniqueId | replayMask),
              RSTypefaceCache::Instance().typefaceHashCode_.end());
}

/**
 * @tc.name: ReplayClearTest001
 * @tc.desc: Verify function ReplayClear
 * @tc.type:FUNC
 */
HWTEST_F(RSTypefaceCacheTest, ReplayClearTest001, TestSize.Level1)
{
    uint64_t uniqueId = 1;
    uint64_t replayMask = (uint64_t)1 << (30 + 32);
    RSTypefaceCache::Instance().ReplayClear();
    EXPECT_EQ(RSTypefaceCache::Instance().typefaceHashCode_.find(uniqueId | replayMask),
              RSTypefaceCache::Instance().typefaceHashCode_.end());
}
} // namespace Rosen
} // namespace OHOS