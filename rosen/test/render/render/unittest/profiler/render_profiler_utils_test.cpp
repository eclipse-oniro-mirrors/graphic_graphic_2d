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

#include <array>
#include <cstdint>
#include <cstdio>
#include <limits>

#include "gtest/gtest.h"
#include "rs_profiler_utils.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::Rosen {
class RenderProfilerUtilsTest : public testing::Test {
public:
    static void SetUpTestCase() {};
    static void TearDownTestCase() {};
    void SetUp() override {};
    void TearDown() override {};
};

/*
 * @tc.name: UtilsFileTest
 * @tc.desc: RSProfiler Utils File Test
 * @tc.type: FUNC
 * @tc.require: 22738
 */
HWTEST_F(RenderProfilerUtilsTest, UtilsFileTest, TestSize.Level1)
{
    // open not existing file
    auto fd = Utils::FileOpen("</,,,,,,,,,,,/>", "rb");
    EXPECT_FALSE(Utils::IsFileValid(fd));
    EXPECT_EQ(fd, nullptr);
    EXPECT_EQ(Utils::FileSize(fd), 0);
    EXPECT_EQ(Utils::FileTell(fd), 0);

    fd = Utils::FileOpen("file.json", "invalid open options");
    EXPECT_FALSE(Utils::IsFileValid(fd));
    EXPECT_EQ(fd, nullptr);
    EXPECT_EQ(Utils::FileSize(fd), 0);
    EXPECT_EQ(Utils::FileTell(fd), 0);
}

/*
 * @tc.name: UtilsTimeTest
 * @tc.desc: RSProfiler Utils Time Test
 * @tc.type: FUNC
 * @tc.require: 22738
 */
HWTEST_F(RenderProfilerUtilsTest, UtilsTimeTest, TestSize.Level1)
{
    EXPECT_NE(Utils::Now(), 0);
    EXPECT_DOUBLE_EQ(Utils::ToSeconds(500000000), 0.5);
    EXPECT_EQ(Utils::ToNanoseconds(0.25), 250000000);
}

/*
 * @tc.name: UtilsFileInMemoryTest
 * @tc.desc: RSProfiler Utils File recording in memory Test
 * @tc.type: FUNC
 * @tc.require: 22738
 */
HWTEST_F(RenderProfilerUtilsTest, UtilsFileInMemoryTest, TestSize.Level1)
{
    auto fd = Utils::FileOpen("RECORD_IN_MEMORY", "rwbe");
    EXPECT_EQ(fd, reinterpret_cast<FILE*>(1));
    EXPECT_TRUE(Utils::IsFileValid(fd));
    EXPECT_EQ(Utils::FileSize(fd), 0);
    EXPECT_EQ(Utils::FileTell(fd), 0);

    std::vector<char> raw { 0, 1, 2, 3 };
    Utils::FileWrite(fd, raw.data(), raw.size());
    std::vector<char> recovered(4, '\0');
    Utils::FileSeek(fd, 0, SEEK_SET);
    Utils::FileRead(fd, recovered.data(), 4);
    EXPECT_EQ(raw, recovered);
    EXPECT_EQ(Utils::FileTell(fd), 4);

    uint16_t u16 = 0;
    Utils::FileSeek(fd, 1, SEEK_SET);
    Utils::FileRead(fd, &u16, sizeof(u16));
    EXPECT_EQ(u16, 0x0201);

    fd = Utils::FileOpen("RECORD_IN_MEMORY", "wbe");
    EXPECT_TRUE(Utils::IsFileValid(fd));
    EXPECT_EQ(Utils::FileSize(fd), 4); // FileOpen no longer clear the memory
    EXPECT_EQ(Utils::FileTell(fd), 0); // FileOpen still reset the file position
}

/*
 * @tc.name: UtilsIdRoutineTest
 * @tc.desc: RSProfiler Utils identifiers combining routine Test
 * @tc.type: FUNC
 * @tc.require: 22738
 */
HWTEST_F(RenderProfilerUtilsTest, UtilsIdRoutineTest, TestSize.Level1)
{
    constexpr uint64_t id = 0x0102030405060708;
    constexpr uint64_t nodeId = 0x000000000a0b0c0d;
    constexpr pid_t pid = 0x10203040;

    EXPECT_EQ(Utils::ExtractPid(id), 0x01020304);
    EXPECT_EQ(Utils::GetMockPid(pid), 0x50203040);
    EXPECT_EQ(Utils::ExtractNodeId(id), 0x0000000005060708);
    EXPECT_EQ(Utils::ComposeNodeId(pid, nodeId), 0x102030400a0b0c0d);
    EXPECT_EQ(Utils::ComposeMockNodeId(id, nodeId), 0x450607080a0b0c0d);
    EXPECT_EQ(Utils::GetRootNodeId(pid), 0x1020304000000001);
    EXPECT_EQ(Utils::PatchNodeId(id), 0x4102030405060708);
    EXPECT_FALSE(Utils::IsNodeIdPatched(id));
    EXPECT_TRUE(Utils::IsNodeIdPatched(Utils::PatchNodeId(id)));
}

/*
 * @tc.name: UtilsSplitTest
 * @tc.desc: RSProfiler Utils string split Test
 * @tc.type: FUNC
 * @tc.require: 22738
 */
HWTEST_F(RenderProfilerUtilsTest, UtilsSplitTest, TestSize.Level1)
{
    std::string str = "qwe asd zxc";
    std::vector<std::string> result = { "qwe", "asd", "zxc" };
    EXPECT_EQ(Utils::Split(str), result);
}

/*
 * @tc.name: UtilsByteUnitConversionTest
 * @tc.desc: Verify Kilobytes, Megabytes and Gigabytes unit conversions
 * @tc.type: FUNC
 * @tc.require: 22738
 */
HWTEST_F(RenderProfilerUtilsTest, UtilsByteUnitConversionTest, TestSize.Level1)
{
    constexpr size_t bytesPerKb = 1024u;
    constexpr size_t halfKb = 512u;
    constexpr size_t bytesPerMb = bytesPerKb * bytesPerKb;
    constexpr size_t twoMb = bytesPerMb + bytesPerMb;
    constexpr size_t bytesPerGb = bytesPerMb * bytesPerKb;
    constexpr float expectedHalf = 0.5f;
    constexpr float expectedTwo = 2.0f;

    EXPECT_FLOAT_EQ(Utils::Kilobytes(0), 0.0f);
    EXPECT_FLOAT_EQ(Utils::Kilobytes(halfKb), expectedHalf);
    EXPECT_FLOAT_EQ(Utils::Kilobytes(bytesPerKb), 1.0f);
    EXPECT_FLOAT_EQ(Utils::Megabytes(0), 0.0f);
    EXPECT_FLOAT_EQ(Utils::Megabytes(bytesPerMb), 1.0f);
    EXPECT_FLOAT_EQ(Utils::Megabytes(twoMb), expectedTwo);
    EXPECT_FLOAT_EQ(Utils::Gigabytes(0), 0.0f);
    EXPECT_FLOAT_EQ(Utils::Gigabytes(bytesPerGb), 1.0f);
}

/*
 * @tc.name: UtilsTimeAndProcessTest
 * @tc.desc: Verify time boundaries, process lookup and CPU query helpers
 * @tc.type: FUNC
 * @tc.require: 22738
 */
HWTEST_F(RenderProfilerUtilsTest, UtilsTimeAndProcessTest, TestSize.Level1)
{
    constexpr uint64_t oneSecondNs = 1000000000ULL;
    constexpr uint32_t outOfRangeCpu = 65535u;
    const uint64_t startTime = Utils::Now();
    const uint64_t endTime = Utils::Now();
    const pid_t pid = Utils::GetPid();

    EXPECT_LE(startTime, endTime);
    EXPECT_DOUBLE_EQ(Utils::ToSeconds(0), 0.0);
    EXPECT_DOUBLE_EQ(Utils::ToSeconds(oneSecondNs), 1.0);
    EXPECT_EQ(Utils::ToNanoseconds(0.0), 0u);
    EXPECT_EQ(Utils::ToNanoseconds(1.0), oneSecondNs);
    EXPECT_GT(pid, 0);
    EXPECT_EQ(Utils::GetCurrentProcessName(), Utils::GetProcessName(pid));
    EXPECT_TRUE(Utils::GetProcessName(-1).empty());
    EXPECT_GE(Utils::GetCpuId(), 0);
    Utils::SetCpuAffinity(outOfRangeCpu);
}

/*
 * @tc.name: UtilsFormatAndSplitTest
 * @tc.desc: Verify Format and Split with empty, whitespace and formatted inputs
 * @tc.type: FUNC
 * @tc.require: 22738
 */
HWTEST_F(RenderProfilerUtilsTest, UtilsFormatAndSplitTest, TestSize.Level1)
{
    constexpr int32_t frameCount = 42;
    constexpr double ratio = 3.5;

    EXPECT_TRUE(Utils::Format(nullptr).empty());
    EXPECT_TRUE(Utils::Format("").empty());
    EXPECT_EQ(Utils::Format("plain_text"), "plain_text");
    EXPECT_EQ(Utils::Format("%s=%d", "frame", frameCount), "frame=42");
    EXPECT_EQ(Utils::Format("%.2f", ratio), "3.50");

    EXPECT_TRUE(Utils::Split("").empty());
    EXPECT_TRUE(Utils::Split("   \t\n  ").empty());
    const std::vector<std::string> singleExpected = { "token" };
    EXPECT_EQ(Utils::Split("token"), singleExpected);
    const std::vector<std::string> multiExpected = { "alpha", "beta", "gamma" };
    EXPECT_EQ(Utils::Split("  alpha   beta\tgamma\n"), multiExpected);
}

/*
 * @tc.name: UtilsReplaceAndExtractNumberTest
 * @tc.desc: Verify Replace and ExtractNumber across normal and edge inputs
 * @tc.type: FUNC
 * @tc.require: 22738
 */
HWTEST_F(RenderProfilerUtilsTest, UtilsReplaceAndExtractNumberTest, TestSize.Level1)
{
    std::string withCr = "line1\rline2\r";
    Utils::Replace("\r", withCr);
    EXPECT_EQ(withCr, "line1line2");

    std::string withLf = "\na\nb\nc\n";
    Utils::Replace("\n", withLf);
    EXPECT_EQ(withLf, "abc");

    std::string unchanged = "no_match_here";
    Utils::Replace("z", unchanged);
    EXPECT_EQ(unchanged, "no_match_here");

    EXPECT_EQ(Utils::ExtractNumber("frame_12345_end"), "12345");
    EXPECT_EQ(Utils::ExtractNumber("9876"), "9876");
    EXPECT_EQ(Utils::ExtractNumber("abc12def34"), "12");
    EXPECT_EQ(Utils::ExtractNumber("no_digits"), "no_digits");
    EXPECT_TRUE(Utils::ExtractNumber("").empty());
}

/*
 * @tc.name: UtilsSignedIntegerParseTest
 * @tc.desc: Verify ToInt8, ToInt16, ToInt32 and ToInt64 boundary and invalid inputs
 * @tc.type: FUNC
 * @tc.require: 22738
 */
HWTEST_F(RenderProfilerUtilsTest, UtilsSignedIntegerParseTest, TestSize.Level1)
{
    constexpr int8_t minInt8 = std::numeric_limits<int8_t>::min();
    constexpr int8_t maxInt8 = std::numeric_limits<int8_t>::max();
    constexpr int16_t minInt16 = std::numeric_limits<int16_t>::min();
    constexpr int16_t maxInt16 = std::numeric_limits<int16_t>::max();
    constexpr int32_t minInt32 = std::numeric_limits<int32_t>::min();
    constexpr int32_t maxInt32 = std::numeric_limits<int32_t>::max();
    constexpr int64_t posInt64 = 9223372036854775807LL;
    constexpr int64_t negInt64 = -9223372036854775807LL;

    EXPECT_EQ(Utils::ToInt8("-128"), minInt8);
    EXPECT_EQ(Utils::ToInt8("127"), maxInt8);
    EXPECT_EQ(Utils::ToInt8("invalid"), 0);
    EXPECT_EQ(Utils::ToInt16("-32768"), minInt16);
    EXPECT_EQ(Utils::ToInt16("32767"), maxInt16);
    EXPECT_EQ(Utils::ToInt16("12abc"), 0);
    EXPECT_EQ(Utils::ToInt32("-2147483648"), minInt32);
    EXPECT_EQ(Utils::ToInt32("2147483647"), maxInt32);
    EXPECT_EQ(Utils::ToInt32(""), 0);
    EXPECT_EQ(Utils::ToInt32("abc"), 0);
    EXPECT_EQ(Utils::ToInt32("123xyz"), 0);
    EXPECT_EQ(Utils::ToInt32("99999999999999999999999999"), 0);
    EXPECT_EQ(Utils::ToInt64("9223372036854775807"), posInt64);
    EXPECT_EQ(Utils::ToInt64("-9223372036854775807"), negInt64);
}

/*
 * @tc.name: UtilsUnsignedIntegerParseTest
 * @tc.desc: Verify ToUint8, ToUint16, ToUint32 and ToUint64 bounds and clamping
 * @tc.type: FUNC
 * @tc.require: 22738
 */
HWTEST_F(RenderProfilerUtilsTest, UtilsUnsignedIntegerParseTest, TestSize.Level1)
{
    constexpr uint8_t maxUint8 = std::numeric_limits<uint8_t>::max();
    constexpr uint16_t maxUint16 = std::numeric_limits<uint16_t>::max();
    constexpr uint32_t maxUint32 = std::numeric_limits<uint32_t>::max();
    constexpr uint64_t maxUint64 = std::numeric_limits<uint64_t>::max();

    EXPECT_EQ(Utils::ToUint8("0"), 0u);
    EXPECT_EQ(Utils::ToUint8("255"), maxUint8);
    EXPECT_EQ(Utils::ToUint16("0"), 0u);
    EXPECT_EQ(Utils::ToUint16("65535"), maxUint16);
    EXPECT_EQ(Utils::ToUint16("70000"), maxUint16);
    EXPECT_EQ(Utils::ToUint32("0"), 0u);
    EXPECT_EQ(Utils::ToUint32("4294967295"), maxUint32);
    EXPECT_EQ(Utils::ToUint32("5000000000"), maxUint32);
    EXPECT_EQ(Utils::ToUint64("0"), 0u);
    EXPECT_EQ(Utils::ToUint64("18446744073709551615"), maxUint64);
}

/*
 * @tc.name: UtilsFloatAndToNumberTest
 * @tc.desc: Verify ToFp32, ToFp64, template ToNumber and all ToNumber overloads
 * @tc.type: FUNC
 * @tc.require: 22738
 */
HWTEST_F(RenderProfilerUtilsTest, UtilsFloatAndToNumberTest, TestSize.Level1)
{
    constexpr int8_t expectedI8 = -12;
    constexpr int16_t expectedI16 = -1234;
    constexpr int32_t expectedI32 = -4096;
    constexpr int64_t expectedI64 = -9876543210LL;
    constexpr uint8_t expectedU8 = 200u;
    constexpr uint16_t expectedU16 = 50000u;
    constexpr uint32_t expectedU32 = 3000000000u;
    constexpr uint64_t expectedU64 = 1234567890123ULL;
    constexpr float expectedFp32 = -12.5f;
    constexpr double expectedFp64 = 3.25;

    EXPECT_EQ(Utils::ToNumber<int8_t>("-12"), expectedI8);
    EXPECT_EQ(Utils::ToNumber<int16_t>("-1234"), expectedI16);
    EXPECT_EQ(Utils::ToNumber<int32_t>("-4096"), expectedI32);
    EXPECT_EQ(Utils::ToNumber<int64_t>("-9876543210"), expectedI64);
    EXPECT_EQ(Utils::ToNumber<uint8_t>("200"), expectedU8);
    EXPECT_EQ(Utils::ToNumber<uint16_t>("50000"), expectedU16);
    EXPECT_EQ(Utils::ToNumber<uint32_t>("3000000000"), expectedU32);
    EXPECT_EQ(Utils::ToNumber<uint64_t>("1234567890123"), expectedU64);
    EXPECT_FLOAT_EQ(Utils::ToNumber<float>("-12.5"), expectedFp32);
    EXPECT_DOUBLE_EQ(Utils::ToNumber<double>("3.25"), expectedFp64);
    EXPECT_FLOAT_EQ(Utils::ToFp32("-12.5"), expectedFp32);
    EXPECT_DOUBLE_EQ(Utils::ToFp64("3.25"), expectedFp64);
}

/*
 * @tc.name: UtilsMemoryMoveAndSetTest
 * @tc.desc: Verify Move and Set normal, overlapping and invalid parameter paths
 * @tc.type: FUNC
 * @tc.require: 22738
 */
HWTEST_F(RenderProfilerUtilsTest, UtilsMemoryMoveAndSetTest, TestSize.Level1)
{
    constexpr size_t copySize = 4u;
    constexpr size_t overlapSize = 6u;
    constexpr size_t shiftOffset = 2u;
    constexpr uint8_t fillByte = 0x5Au;

    const std::array<uint8_t, copySize> src = { 0x11u, 0x22u, 0x33u, 0x44u };
    std::array<uint8_t, copySize> dst = { 0u, 0u, 0u, 0u };
    EXPECT_TRUE(Utils::Move(dst.data(), dst.size(), src.data(), src.size()));
    EXPECT_EQ(dst, src);

    std::array<uint8_t, overlapSize> overlap = { 0x11u, 0x22u, 0x33u, 0x44u, 0u, 0u };
    const std::array<uint8_t, overlapSize> expectedOverlap = { 0x11u, 0x22u, 0x11u, 0x22u, 0x33u, 0x44u };
    EXPECT_TRUE(Utils::Move(overlap.data() + shiftOffset, copySize, overlap.data(), copySize));
    EXPECT_EQ(overlap, expectedOverlap);

    EXPECT_FALSE(Utils::Move(dst.data(), 1u, src.data(), copySize));
    EXPECT_FALSE(Utils::Move(nullptr, copySize, src.data(), copySize));
    EXPECT_FALSE(Utils::Move(dst.data(), copySize, nullptr, copySize));

    std::array<uint8_t, copySize> fillBuf = { 0u, 0u, 0u, 0u };
    const std::array<uint8_t, copySize> expectedFill = { fillByte, fillByte, fillByte, fillByte };
    EXPECT_TRUE(Utils::Set(fillBuf.data(), fillBuf.size(), fillByte, fillBuf.size()));
    EXPECT_EQ(fillBuf, expectedFill);
    EXPECT_FALSE(Utils::Set(fillBuf.data(), 1u, fillByte, copySize));
    EXPECT_FALSE(Utils::Set(nullptr, copySize, fillByte, copySize));
}

/*
 * @tc.name: UtilsPathManipulationTest
 * @tc.desc: Verify NormalizePath, MakePath, GetFileName and GetDirectory
 * @tc.type: FUNC
 * @tc.require: 22738
 */
HWTEST_F(RenderProfilerUtilsTest, UtilsPathManipulationTest, TestSize.Level1)
{
    EXPECT_EQ(Utils::NormalizePath("/data/local"), "/data/local/");
    EXPECT_EQ(Utils::NormalizePath("/data/local/"), "/data/local/");
    EXPECT_EQ(Utils::NormalizePath("/"), "/");
    EXPECT_EQ(Utils::MakePath("/data/local", "trace.bin"), "/data/local/trace.bin");
    EXPECT_EQ(Utils::MakePath("/data/local/", "trace.bin"), "/data/local/trace.bin");
    EXPECT_EQ(Utils::GetFileName("/data/local/trace.bin"), "trace.bin");
    EXPECT_EQ(Utils::GetFileName("/trace.bin"), "trace.bin");
    EXPECT_EQ(Utils::GetFileName("trace.bin"), "trace.bin");
    EXPECT_TRUE(Utils::GetFileName("/data/local/").empty());
    EXPECT_EQ(Utils::GetDirectory("/data/local/trace.bin"), "/data/local");
    EXPECT_TRUE(Utils::GetDirectory("trace.bin").empty());
    EXPECT_EQ(Utils::GetDirectory("/data/local/"), "/data/local");
}

/*
 * @tc.name: UtilsSandboxAndMissingPathTest
 * @tc.desc: Verify IsSandboxPath rejection and missing path safety behavior
 * @tc.type: FUNC
 * @tc.require: 22738
 */
HWTEST_F(RenderProfilerUtilsTest, UtilsSandboxAndMissingPathTest, TestSize.Level1)
{
    EXPECT_FALSE(Utils::IsSandboxPath(""));
    EXPECT_FALSE(Utils::IsSandboxPath("/data"));
    EXPECT_FALSE(Utils::IsSandboxPath("/etc/passwd"));
    EXPECT_FALSE(Utils::IsSandboxPath("/datax/file"));
    EXPECT_FALSE(Utils::IsSandboxPath("/data/."));
    EXPECT_FALSE(Utils::IsSandboxPath("/data/.."));
    EXPECT_FALSE(Utils::IsSandboxPath("/data/..\\file"));
    EXPECT_FALSE(Utils::IsSandboxPath("/data/local/../file"));

    const std::string missingPath = "/nonexistent_profiler_dir_9999/missing.dat";
    EXPECT_TRUE(Utils::GetRealPath(missingPath).empty());
    EXPECT_FALSE(Utils::IsDirectory(missingPath));
    EXPECT_FALSE(Utils::FileExists(missingPath));

    std::vector<std::string> files = { "existing" };
    Utils::IterateDirectory(missingPath, files);
    EXPECT_EQ(files.size(), 1u);

    std::string line = "stale";
    Utils::LoadLine(missingPath, line);
    EXPECT_TRUE(line.empty());

    std::vector<std::string> lines = { "stale" };
    Utils::LoadLines(missingPath, lines);
    EXPECT_TRUE(lines.empty());

    std::string content = "stale";
    Utils::LoadContent(missingPath, content);
    EXPECT_TRUE(content.empty());
}

/*
 * @tc.name: UtilsFileInMemorySeekAndDeleteTest
 * @tc.desc: Verify RECORD_IN_MEMORY seek origins, close reset and delete cleanup
 * @tc.type: FUNC
 * @tc.require: 22738
 */
HWTEST_F(RenderProfilerUtilsTest, UtilsFileInMemorySeekAndDeleteTest, TestSize.Level1)
{
    constexpr int64_t seekOffset = 2;
    constexpr size_t afterCurOffset = 5u;
    constexpr size_t tailCount = 2u;

    EXPECT_TRUE(Utils::FileDelete("RECORD_IN_MEMORY"));
    EXPECT_TRUE(Utils::FileExists("RECORD_IN_MEMORY"));
    FILE* fd = Utils::FileOpen("RECORD_IN_MEMORY", "rwbe");
    ASSERT_TRUE(Utils::IsFileValid(fd));

    const std::vector<uint8_t> payload = { 10u, 20u, 30u, 40u, 50u, 60u, 70u, 80u };
    EXPECT_TRUE(Utils::FileWrite(fd, payload.data(), payload.size()));
    EXPECT_EQ(Utils::FileSize(fd), payload.size());
    EXPECT_EQ(Utils::FileTell(fd), payload.size());

    uint8_t byteRead = 0u;
    Utils::FileSeek(fd, seekOffset, SEEK_SET);
    EXPECT_EQ(Utils::FileTell(fd), static_cast<size_t>(seekOffset));
    EXPECT_TRUE(Utils::FileRead(fd, &byteRead, sizeof(byteRead)));
    EXPECT_EQ(byteRead, payload[static_cast<size_t>(seekOffset)]);

    Utils::FileSeek(fd, seekOffset, SEEK_CUR);
    EXPECT_EQ(Utils::FileTell(fd), afterCurOffset);
    EXPECT_TRUE(Utils::FileRead(fd, &byteRead, sizeof(byteRead)));
    EXPECT_EQ(byteRead, payload[afterCurOffset]);

    Utils::FileSeek(fd, -seekOffset, SEEK_END);
    std::array<uint8_t, tailCount> tailBytes = { 0u, 0u };
    EXPECT_TRUE(Utils::FileRead(fd, tailBytes.data(), tailBytes.size()));
    EXPECT_EQ(tailBytes[0], payload[payload.size() - tailCount]);
    EXPECT_EQ(tailBytes[1], payload[payload.size() - 1u]);

    Utils::FileClose(fd);
    EXPECT_EQ(Utils::FileTell(fd), 0u);
    EXPECT_TRUE(Utils::FileDelete("RECORD_IN_MEMORY"));
    EXPECT_EQ(Utils::FileSize(fd), 0u);
}

/*
 * @tc.name: UtilsFileEdgeCasesAndIdTest
 * @tc.desc: Verify FileRead/FileWrite edge checks and DataId/SelfDrawingImageId encoding
 * @tc.type: FUNC
 * @tc.require: 22738
 */
HWTEST_F(RenderProfilerUtilsTest, UtilsFileEdgeCasesAndIdTest, TestSize.Level1)
{
    constexpr size_t smallSize = 4u;
    constexpr size_t overLimitSize = 2000000001u;
    constexpr pid_t pid = 0x10203040;
    constexpr uint32_t dataId = 0x0a0b0c0d;
    constexpr uint64_t expectedDataId = 0x902030400a0b0c0dULL;
    constexpr uint64_t rawId = 0x0102030405060708ULL;
    constexpr uint64_t expectedSelfDrawingId = 0xc102030405060708ULL;
    std::array<char, smallSize> buf = { 0, 0, 0, 0 };

    EXPECT_TRUE(Utils::FileDelete("RECORD_IN_MEMORY"));
    Utils::FileClose(nullptr);
    EXPECT_TRUE(Utils::FileRead(nullptr, nullptr, 0));
    EXPECT_FALSE(Utils::FileRead(nullptr, buf.data(), buf.size()));

    FILE* fd = Utils::FileOpen("RECORD_IN_MEMORY", "rwbe");
    ASSERT_TRUE(Utils::IsFileValid(fd));
    EXPECT_FALSE(Utils::FileRead(fd, nullptr, buf.size()));
    EXPECT_TRUE(Utils::FileWrite(fd, nullptr, 0));
    EXPECT_FALSE(Utils::FileWrite(fd, nullptr, buf.size()));
    EXPECT_FALSE(Utils::FileWrite(fd, buf.data(), overLimitSize));
    EXPECT_FALSE(Utils::FileRead(fd, buf.data(), buf.size()));
    EXPECT_TRUE(Utils::FileDelete("RECORD_IN_MEMORY"));

    EXPECT_EQ(Utils::ComposeDataId(pid, dataId), expectedDataId);
    const uint64_t patchedSelfDrawing = Utils::PatchSelfDrawingImageId(rawId);
    EXPECT_EQ(patchedSelfDrawing, expectedSelfDrawingId);
    EXPECT_TRUE(Utils::IsNodeIdPatched(patchedSelfDrawing));
}
} // namespace OHOS::Rosen