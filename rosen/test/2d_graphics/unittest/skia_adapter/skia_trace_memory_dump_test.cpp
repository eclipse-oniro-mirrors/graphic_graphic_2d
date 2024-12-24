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

#include <cstddef>
#include "gtest/gtest.h"
#include "skia_adapter/skia_trace_memory_dump.h"
#include "image/trace_memory_dump.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Rosen {
namespace Drawing {
class SkiaTraceMemoryDumpTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void SkiaTraceMemoryDumpTest::SetUpTestCase() {}
void SkiaTraceMemoryDumpTest::TearDownTestCase() {}
void SkiaTraceMemoryDumpTest::SetUp() {}
void SkiaTraceMemoryDumpTest::TearDown() {}

/**
 * @tc.name: DumpNumericValue001
 * @tc.desc: Test DumpNumericValue
 * @tc.type: FUNC
 * @tc.require:I91EDT
 */
HWTEST_F(SkiaTraceMemoryDumpTest, DumpNumericValue001, TestSize.Level1)
{
    SkiaTraceMemoryDump skiaTraceMemoryDump{"category", false};
    skiaTraceMemoryDump.DumpNumericValue("dumpName1", "valueName", "bytes", 1);
    ASSERT_TRUE(skiaTraceMemoryDump.GetGpuMemorySizeInMB() >= 0);
}

/**
 * @tc.name: DumpNumericValue002
 * @tc.desc: Test DumpNumericValue
 * @tc.type: FUNC
 * @tc.require:I91EDT
 */
HWTEST_F(SkiaTraceMemoryDumpTest, DumpNumericValue002, TestSize.Level1)
{
    SkiaTraceMemoryDump skiaTraceMemoryDump{nullptr, false};
    skiaTraceMemoryDump.DumpNumericValue("dumpName1", "valueName", "bytes", 1);
    ASSERT_TRUE(skiaTraceMemoryDump.GetGpuMemorySizeInMB() >= 0);
}

/**
 * @tc.name: DumpStringValue001
 * @tc.desc: Test DumpStringValue
 * @tc.type: FUNC
 * @tc.require:I91EDT
 */
HWTEST_F(SkiaTraceMemoryDumpTest, DumpStringValue001, TestSize.Level1)
{
    SkiaTraceMemoryDump skiaTraceMemoryDump{"category", false};
    skiaTraceMemoryDump.DumpStringValue("dumpName1", "valueName", "1");
    ASSERT_TRUE(skiaTraceMemoryDump.GetGpuMemorySizeInMB() >= 0);
}


/**
 * @tc.name: DumpStringValue002
 * @tc.desc: Test DumpStringValue
 * @tc.type: FUNC
 * @tc.require:I91EDT
 */
HWTEST_F(SkiaTraceMemoryDumpTest, DumpStringValue002, TestSize.Level1)
{
    SkiaTraceMemoryDump skiaTraceMemoryDump{nullptr, false};
    skiaTraceMemoryDump.DumpStringValue("dumpName1", "valueName", "1");
    ASSERT_TRUE(skiaTraceMemoryDump.GetGpuMemorySizeInMB() >= 0);
}

/**
 * @tc.name: LogOutput001
 * @tc.desc: Test LogOutput
 * @tc.type: FUNC
 * @tc.require:I91EDT
 */
HWTEST_F(SkiaTraceMemoryDumpTest, LogOutput001, TestSize.Level1)
{
    SkiaTraceMemoryDump skiaTraceMemoryDump{"category", false};
    ASSERT_TRUE(skiaTraceMemoryDump.GetGpuMemorySizeInMB() >= 0);
    DfxString log;
    skiaTraceMemoryDump.LogOutput(log);
}


/**
 * @tc.name: LogOutput002
 * @tc.desc: Test LogOutput
 * @tc.type: FUNC
 * @tc.require:I91EDT
 */
HWTEST_F(SkiaTraceMemoryDumpTest, LogOutput002, TestSize.Level1)
{
    SkiaTraceMemoryDump skiaTraceMemoryDump{nullptr, false};
    ASSERT_TRUE(skiaTraceMemoryDump.GetGpuMemorySizeInMB() >= 0);
    DfxString log;
    skiaTraceMemoryDump.LogOutput(log);
}

/**
 * @tc.name: LogTotals001
 * @tc.desc: Test LogTotals
 * @tc.type: FUNC
 * @tc.require:I91EDT
 */
HWTEST_F(SkiaTraceMemoryDumpTest, LogTotals001, TestSize.Level1)
{
    SkiaTraceMemoryDump skiaTraceMemoryDump{"category", false};
    ASSERT_TRUE(skiaTraceMemoryDump.GetGpuMemorySizeInMB() >= 0);
    DfxString log;
    skiaTraceMemoryDump.LogTotals(log);
}

/**
 * @tc.name: LogTotals002
 * @tc.desc: Test LogTotals
 * @tc.type: FUNC
 * @tc.require:I91EDT
 */
HWTEST_F(SkiaTraceMemoryDumpTest, LogTotals002, TestSize.Level1)
{
    SkiaTraceMemoryDump skiaTraceMemoryDump{nullptr, false};
    ASSERT_TRUE(skiaTraceMemoryDump.GetGpuMemorySizeInMB() >= 0);
    DfxString log;
    skiaTraceMemoryDump.LogTotals(log);
}

/**
 * @tc.name: GetGpuMemorySizeInMB001
 * @tc.desc: Test GetGpuMemorySizeInMB
 * @tc.type: FUNC
 * @tc.require:I91EDT
 */
HWTEST_F(SkiaTraceMemoryDumpTest, GetGpuMemorySizeInMB001, TestSize.Level1)
{
    SkiaTraceMemoryDump skiaTraceMemoryDump{"category", false};
    ASSERT_TRUE(skiaTraceMemoryDump.GetGpuMemorySizeInMB() >= 0);
}


/**
 * @tc.name: GetGpuMemorySizeInMB002
 * @tc.desc: Test GetGpuMemorySizeInMB
 * @tc.type: FUNC
 * @tc.require:I91EDT
 */
HWTEST_F(SkiaTraceMemoryDumpTest, GetGpuMemorySizeInMB002, TestSize.Level1)
{
    SkiaTraceMemoryDump skiaTraceMemoryDump{nullptr, false};
    ASSERT_TRUE(skiaTraceMemoryDump.GetGpuMemorySizeInMB() >= 0);
}


/**
 * @tc.name: GetGLMemorySize001
 * @tc.desc: Test GetGLMemorySize
 * @tc.type: FUNC
 * @tc.require:I91EDT
 */
HWTEST_F(SkiaTraceMemoryDumpTest, GetGLMemorySize001, TestSize.Level1)
{
    SkiaTraceMemoryDump skiaTraceMemoryDump{"category", false};
    ASSERT_TRUE(skiaTraceMemoryDump.GetGLMemorySize() >= 0);
}

/**
 * @tc.name: GetGLMemorySize002
 * @tc.desc: Test GetGLMemorySize
 * @tc.type: FUNC
 * @tc.require:I91EDT
 */
HWTEST_F(SkiaTraceMemoryDumpTest, GetGLMemorySize002, TestSize.Level1)
{
    SkiaTraceMemoryDump skiaTraceMemoryDump{nullptr, false};
    ASSERT_TRUE(skiaTraceMemoryDump.GetGLMemorySize() >= 0);
}

/**
 * @tc.name: GetTraceMemoryDump001
 * @tc.desc: Test GetTraceMemoryDump
 * @tc.type: FUNC
 * @tc.require:I91EDT
 */
HWTEST_F(SkiaTraceMemoryDumpTest, GetTraceMemoryDump001, TestSize.Level1)
{
    SkiaTraceMemoryDump skiaTraceMemoryDump{"category", false};
    ASSERT_TRUE(skiaTraceMemoryDump.GetTraceMemoryDump() != nullptr);
}

} // namespace Drawing
} // namespace Rosen
} // namespace OHOS