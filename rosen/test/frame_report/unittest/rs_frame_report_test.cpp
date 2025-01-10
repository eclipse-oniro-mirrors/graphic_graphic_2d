/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, Hardware
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>
#include <string>

#include "rs_frame_report.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Rosen {
class RsFrameReportTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void RsFrameReportTest::SetUpTestCase() {}
void RsFrameReportTest::TearDownTestCase() {}
void RsFrameReportTest::SetUp() {}
void RsFrameReportTest::TearDown() {}

/**
 * @tc.name: GetEnable001
 * @tc.desc: test
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RsFrameReportTest, GetEnable001, TestSize.Level1)
{
    RsFrameReport& fr = RsFrameReport::GetInstance();
    fr.LoadLibrary();
    fr.CloseLibrary();
    fr.GetEnable();
    EXPECT_EQ(fr.GetEnable(), 0);
}

/**
 * @tc.name: ProcessCommandsStart001
 * @tc.desc: test
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RsFrameReportTest, ProcessCommandsStart001, TestSize.Level1)
{
    RsFrameReport& fr = RsFrameReport::GetInstance();
    fr.LoadLibrary();
    EXPECT_TRUE(fr.frameSchedSoLoaded_);
    EXPECT_EQ(fr.processCommandsStartFun_, nullptr);
    fr.ProcessCommandsStart();
    EXPECT_NE(fr.processCommandsStartFun_, nullptr);
    fr.ProcessCommandsStart();
}

/**
 * @tc.name: AnimateStart001
 * @tc.desc: test
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RsFrameReportTest, AnimateStart001, TestSize.Level1)
{
    RsFrameReport& fr = RsFrameReport::GetInstance();
    EXPECT_EQ(fr.animateStartFunc_, nullptr);
    fr.AnimateStart();
    EXPECT_NE(fr.animateStartFunc_, nullptr);
    fr.AnimateStart();
}

/**
 * @tc.name: RenderStart001
 * @tc.desc: test
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RsFrameReportTest, RenderStart001, TestSize.Level1)
{
    RsFrameReport& fr = RsFrameReport::GetInstance();
    EXPECT_EQ(fr.renderStartFunc_, nullptr);
    uint64_t timestamp = static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count());
    fr.RenderStart(timestamp);
    EXPECT_NE(fr.renderStartFunc_, nullptr);
    fr.RenderStart(timestamp);
}

/**
 * @tc.name: RSRenderStart001
 * @tc.desc: test
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RsFrameReportTest, RSRenderStart001, TestSize.Level1)
{
    RsFrameReport& fr = RsFrameReport::GetInstance();
    EXPECT_EQ(fr.parallelRenderStartFunc_, nullptr);
    fr.RSRenderStart();
}

/**
 * @tc.name: RenderEnd001
 * @tc.desc: test
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RsFrameReportTest, RenderEnd001, TestSize.Level1)
{
    RsFrameReport& fr = RsFrameReport::GetInstance();
    EXPECT_EQ(fr.renderEndFunc_, nullptr);
    fr.RenderEnd();
    EXPECT_NE(fr.renderEndFunc_, nullptr);
    fr.RenderEnd();
}

/**
 * @tc.name: RSRenderEnd001
 * @tc.desc: test
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RsFrameReportTest, RSRenderEnd001, TestSize.Level1)
{
    RsFrameReport& fr = RsFrameReport::GetInstance();
    EXPECT_EQ(fr.parallelRenderEndFunc_, nullptr);
    fr.RSRenderEnd();
}

/**
 * @tc.name: SendCommandsStart001
 * @tc.desc: test
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RsFrameReportTest, SendCommandsStart001, TestSize.Level1)
{
    RsFrameReport& fr = RsFrameReport::GetInstance();
    EXPECT_EQ(fr.sendCommandsStartFunc_, nullptr);
    fr.SendCommandsStart();
    EXPECT_NE(fr.sendCommandsStartFunc_, nullptr);
    fr.SendCommandsStart();
}

/**
 * @tc.name: SetFrameParam001
 * @tc.desc: test
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RsFrameReportTest, SetFrameParam001, TestSize.Level1)
{
    RsFrameReport& fr = RsFrameReport::GetInstance();
    EXPECT_EQ(fr.setFrameParamFunc_, nullptr);
    fr.SetFrameParam(0, 0, 0, 0);
    EXPECT_NE(fr.setFrameParamFunc_, nullptr);
    fr.SetFrameParam(1, 1, 1, 1);
}

/**
 * @tc.name: LoadLibrary001
 * @tc.desc: test
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RsFrameReportTest, LoadLibrary001, TestSize.Level1)
{
    RsFrameReport& fr = RsFrameReport::GetInstance();
    fr.CloseLibrary();
    fr.LoadLibrary();
    fr.CloseLibrary();
}

/**
 * @tc.name: LoadSymbol001
 * @tc.desc: test
 * @tc.type:FUNC
 * @tc.require:
 */
HWTEST_F(RsFrameReportTest, LoadSymbol001, TestSize.Level1)
{
    RsFrameReport& fr = RsFrameReport::GetInstance();
    fr.CloseLibrary();
    EXPECT_FALSE(fr.frameSchedSoLoaded_);
    fr.LoadSymbol("function");
    fr.LoadLibrary();
    EXPECT_TRUE(fr.frameSchedSoLoaded_);
    fr.LoadSymbol("function");
    fr.CloseLibrary();
}
} // namespace Rosen
} // namespace OHOS
