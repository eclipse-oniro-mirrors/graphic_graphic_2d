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

#include <cstdint>
#include <fcntl.h>
#include <limits>

#include "gtest/gtest.h"
#include "rs_profiler_command.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::Rosen {
class RenderProfilerCommandTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() override {};
    void TearDown() override {};
};

/*
 * @tc.name: CommandArgListTest
 * @tc.desc: RSProfiler Command ArgList public API Test
 * @tc.type: FUNC
 * @tc.require: 22738
 */
HWTEST_F(RenderProfilerCommandTest, CommandArgListTest, TestSize.Level1)
{
    std::vector<std::string> args { "123", "-5", "45738957893", "837983", "1.5", "678.789", "qwe", "" };
    ArgList list { args };

    EXPECT_TRUE(list.Includes("qwe"));
    EXPECT_FALSE(list.Includes("Qwe"));
    EXPECT_TRUE(list.Includes(""));

    EXPECT_EQ(list.Uint32(0), 123);
    EXPECT_EQ(list.Int32(1), -5);
    EXPECT_EQ(list.Uint64(2), 45738957893);
    EXPECT_EQ(list.Int64(3), 837983);
    EXPECT_EQ(list.Fp32(4), 1.5f);
    EXPECT_EQ(list.Fp64(5), 678.789);
    EXPECT_EQ(list.String(6), "qwe");
    EXPECT_EQ(list.Count(), 8);
    EXPECT_TRUE(list.String(7).empty());
    EXPECT_TRUE(list.String(100).empty());

    EXPECT_FALSE(list.Empty());
    list.Clear();
    EXPECT_TRUE(list.Empty());
}

/*
 * @tc.name: CommandArgListDefaultAndClearTest
 * @tc.desc: Verify default-constructed ArgList, GetList and Clear behavior
 * @tc.type: FUNC
 * @tc.require: 22738
 */
HWTEST_F(RenderProfilerCommandTest, CommandArgListDefaultAndClearTest, TestSize.Level1)
{
    ArgList emptyList;
    EXPECT_TRUE(emptyList.Empty());
    EXPECT_EQ(emptyList.Count(), 0u);
    EXPECT_TRUE(emptyList.GetList().empty());
    EXPECT_FALSE(emptyList.Includes("anything"));
    EXPECT_TRUE(emptyList.String().empty());
    EXPECT_FALSE(emptyList.Bool());
    EXPECT_EQ(emptyList.Int32(), 0);
    EXPECT_EQ(emptyList.Uint64(), 0u);

    const std::vector<std::string> items = { "42", "hello" };
    ArgList populated(items);
    EXPECT_EQ(populated.GetList(), items);
    EXPECT_EQ(populated.Count(), items.size());
    populated.Clear();
    EXPECT_TRUE(populated.Empty());
    EXPECT_EQ(populated.Count(), 0u);
    EXPECT_TRUE(populated.GetList().empty());
    EXPECT_FALSE(populated.Includes("42"));
}

/*
 * @tc.name: CommandArgListBoolTest
 * @tc.desc: Verify ArgList::Bool parsing for truthy, falsy and out-of-range indices
 * @tc.type: FUNC
 * @tc.require: 22738
 */
HWTEST_F(RenderProfilerCommandTest, CommandArgListBoolTest, TestSize.Level1)
{
    constexpr size_t idxTrue = 1u;
    constexpr size_t idxZero = 2u;
    constexpr size_t idxFalse = 3u;
    constexpr size_t idxUpperTrue = 4u;
    constexpr size_t idxOther = 5u;
    constexpr size_t idxEmpty = 6u;
    constexpr size_t idxOutOfRange = 10u;

    ArgList list({ "1", "true", "0", "false", "TRUE", "yes", "" });
    EXPECT_TRUE(list.Bool());
    EXPECT_TRUE(list.Bool(idxTrue));
    EXPECT_FALSE(list.Bool(idxZero));
    EXPECT_FALSE(list.Bool(idxFalse));
    EXPECT_FALSE(list.Bool(idxUpperTrue));
    EXPECT_FALSE(list.Bool(idxOther));
    EXPECT_FALSE(list.Bool(idxEmpty));
    EXPECT_FALSE(list.Bool(idxOutOfRange));
}

/*
 * @tc.name: CommandArgListSmallIntegersAndIdsTest
 * @tc.desc: Verify Int8, Int16, Uint8, Uint16, Pid and Node accessors
 * @tc.type: FUNC
 * @tc.require: 22738
 */
HWTEST_F(RenderProfilerCommandTest, CommandArgListSmallIntegersAndIdsTest, TestSize.Level1)
{
    constexpr int8_t minInt8 = std::numeric_limits<int8_t>::min();
    constexpr int16_t maxInt16 = std::numeric_limits<int16_t>::max();
    constexpr uint8_t maxUint8 = std::numeric_limits<uint8_t>::max();
    constexpr uint16_t maxUint16 = std::numeric_limits<uint16_t>::max();
    constexpr pid_t expectedPid = 12345;
    constexpr uint64_t expectedNode = 0x100000002ULL;
    constexpr size_t idxI16 = 1u;
    constexpr size_t idxU8 = 2u;
    constexpr size_t idxU16Clamp = 3u;
    constexpr size_t idxPid = 4u;
    constexpr size_t idxNode = 5u;

    ArgList list({ "-128", "32767", "255", "70000", "12345", "4294967298" });
    EXPECT_EQ(list.Int8(), minInt8);
    EXPECT_EQ(list.Int16(idxI16), maxInt16);
    EXPECT_EQ(list.Uint8(idxU8), maxUint8);
    EXPECT_EQ(list.Uint16(idxU16Clamp), maxUint16);
    EXPECT_EQ(list.Pid(idxPid), expectedPid);
    EXPECT_EQ(list.Node(idxNode), expectedNode);
}

/*
 * @tc.name: CommandArgListOutOfBoundsTest
 * @tc.desc: Verify all ArgList accessors safely return zero/empty when index is out of range
 * @tc.type: FUNC
 * @tc.require: 22738
 */
HWTEST_F(RenderProfilerCommandTest, CommandArgListOutOfBoundsTest, TestSize.Level1)
{
    constexpr size_t outIdx = 5u;
    ArgList list({ "10" });

    EXPECT_TRUE(list.String(outIdx).empty());
    EXPECT_FALSE(list.Bool(outIdx));
    EXPECT_EQ(list.Int8(outIdx), 0);
    EXPECT_EQ(list.Int16(outIdx), 0);
    EXPECT_EQ(list.Int32(outIdx), 0);
    EXPECT_EQ(list.Int64(outIdx), 0);
    EXPECT_EQ(list.Uint8(outIdx), 0u);
    EXPECT_EQ(list.Uint16(outIdx), 0u);
    EXPECT_EQ(list.Uint32(outIdx), 0u);
    EXPECT_EQ(list.Uint64(outIdx), 0u);
    EXPECT_FLOAT_EQ(list.Fp32(outIdx), 0.0f);
    EXPECT_DOUBLE_EQ(list.Fp64(outIdx), 0.0);
    EXPECT_EQ(list.Pid(outIdx), 0);
    EXPECT_EQ(list.Node(outIdx), 0u);
}
} // namespace OHOS::Rosen