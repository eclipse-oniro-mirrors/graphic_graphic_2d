/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <cstdlib>
#include <unistd.h>
#include <parameter.h>
#include <parameters.h>
#include <gtest/gtest.h>

#include "param/sys_param.h"
#include "transaction/rs_render_service_client.h"
#include "platform/common/rs_system_properties.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Rosen {
class RSSystemPropertiesTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void RSSystemPropertiesTest::SetUpTestCase() {}
void RSSystemPropertiesTest::TearDownTestCase() {}
void RSSystemPropertiesTest::SetUp() {}
void RSSystemPropertiesTest::TearDown() {}

/**
 * @tc.name: GetDumpFrameNum
 * @tc.desc: GetDumpFrameNum Test
 * @tc.type:FUNC
 * @tc.require: issueI9JZWC
 */
HWTEST_F(RSSystemPropertiesTest, GetDumpFrameNum, TestSize.Level1)
{
    ASSERT_EQ(RSSystemProperties::GetDumpFrameNum(), 0);
}

/**
 * @tc.name: IsSceneBoardEnabled
 * @tc.desc: IsSceneBoardEnabled Test
 * @tc.type:FUNC
 * @tc.require: issueI9JZWC
 */
HWTEST_F(RSSystemPropertiesTest, IsSceneBoardEnabled, TestSize.Level1)
{
    ASSERT_FALSE(RSSystemProperties::IsSceneBoardEnabled());
}

/**
 * @tc.name: GetUniRenderEnabled
 * @tc.desc: GetUniRenderEnabled Test
 * @tc.type:FUNC
 * @tc.require: issueI9JZWC
 */
HWTEST_F(RSSystemPropertiesTest, GetUniRenderEnabled, TestSize.Level1)
{
    auto uniRenderEnabled = std::static_pointer_cast<RSRenderServiceClient>
        (RSIRenderClient::CreateRenderServiceClient())->GetUniRenderEnabled();
    ASSERT_EQ(RSSystemProperties::GetUniRenderEnabled(), uniRenderEnabled);
    // it is not possible to change RSSystemProperties::uniRenderEnabled from test
    // check the second API calling returns the same value
    ASSERT_EQ(RSSystemProperties::GetUniRenderEnabled(), uniRenderEnabled);
}

/**
 * @tc.name: GetRecordingEnabled
 * @tc.desc: GetRecordingEnabled Test
 * @tc.type:FUNC
 * @tc.require: issueI9JZWC
 */
HWTEST_F(RSSystemPropertiesTest, GetRecordingEnabled, TestSize.Level1)
{
    ASSERT_EQ(RSSystemProperties::GetRecordingEnabled(), 0);
}

/**
 * @tc.name: GetProfilerEnabled
 * @tc.desc: GetProfilerEnabled Test
 * @tc.type:FUNC
 * @tc.require: issueI9JZWC
 */
HWTEST_F(RSSystemPropertiesTest, GetProfilerEnabled, TestSize.Level1)
{
    ASSERT_EQ(RSSystemProperties::GetProfilerEnabled(), 0);
}

/**
 * @tc.name: SetRecordingDisenabled
 * @tc.desc: SetRecordingDisenabled Test
 * @tc.type:FUNC
 * @tc.require: issueI9JZWC
 */
HWTEST_F(RSSystemPropertiesTest, SetRecordingDisenabled, TestSize.Level1)
{
    RSSystemProperties::SetRecordingDisenabled();
    ASSERT_TRUE(true);
}

/**
 * @tc.name: SetInstantRecording
 * @tc.desc: SetInstantRecording Test
 * @tc.type:FUNC
 * @tc.require: issueI9JZWC
 */
HWTEST_F(RSSystemPropertiesTest, SetInstantRecording, TestSize.Level1)
{
    bool flag1 = true;
    RSSystemProperties::SetInstantRecording(flag1);
    ASSERT_TRUE(flag1);
    bool flag2 = false;
    RSSystemProperties::SetInstantRecording(flag2);
}

/**
 * @tc.name: SetSaveRDC
 * @tc.desc: SetSaveRDC Test
 * @tc.type:FUNC
 * @tc.require: issueI9VPIT
 */
HWTEST_F(RSSystemPropertiesTest, SetSaveRDC, TestSize.Level1)
{
    bool flag = false;
    RSSystemProperties::SetSaveRDC(flag);
    ASSERT_FALSE(RSSystemProperties::GetSaveRDC());
}

/**
 * @tc.name: GetSaveRDC
 * @tc.desc: GetSaveRDC Test
 * @tc.type:FUNC
 * @tc.require: issueI9VPIT
 */
HWTEST_F(RSSystemPropertiesTest, GetSaveRDC, TestSize.Level1)
{
    bool flag = true;
    RSSystemProperties::SetSaveRDC(flag);
    ASSERT_TRUE(RSSystemProperties::GetSaveRDC());
}

/**
 * @tc.name: GetDrawOpTraceEnabled
 * @tc.desc: GetDrawOpTraceEnabled Test
 * @tc.type:FUNC
 * @tc.require: issueI9JZWC
 */
HWTEST_F(RSSystemPropertiesTest, GetDrawOpTraceEnabled, TestSize.Level1)
{
    ASSERT_FALSE(RSSystemProperties::GetDrawOpTraceEnabled());
}

/**
 * @tc.name: GetRecordingFile
 * @tc.desc: GetRecordingFile Test
 * @tc.type:FUNC
 * @tc.require: issueI9JZWC
 */
HWTEST_F(RSSystemPropertiesTest, GetRecordingFile, TestSize.Level1)
{
    ASSERT_EQ(RSSystemProperties::GetRecordingFile().size(), 0);
}

/**
 * @tc.name: GetRSScreenRoundCornerEnable
 * @tc.desc: GetRSScreenRoundCornerEnable Test
 * @tc.type:FUNC
 * @tc.require: issueI9JZWC
 */
HWTEST_F(RSSystemPropertiesTest, GetRSScreenRoundCornerEnable, TestSize.Level1)
{
    ASSERT_TRUE(RSSystemProperties::GetRSScreenRoundCornerEnable());
}
} // namespace Rosen
} // namespace OHOS