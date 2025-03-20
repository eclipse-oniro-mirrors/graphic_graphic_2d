/*
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
#include <test_header.h>

#include "multiscreen_param.h"

using namespace testing;
using namespace testing::ext;
namespace OHOS {
namespace Rosen {

class MultiScreenParamTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void MultiScreenParamTest::SetUpTestCase() {}
void MultiScreenParamTest::TearDownTestCase() {}
void MultiScreenParamTest::SetUp() {}
void MultiScreenParamTest::TearDown() {}

/**
 * @tc.name: SetExternalScreenSecure
 * @tc.desc: Verify the SetExternalScreenSecure function
 * @tc.type: FUNC
 * @tc.require: #IBOA5Q
 */
HWTEST_F(MultiScreenParamTest, SetExternalScreenSecure, Function | SmallTest | Level1)
{
    MultiScreenParam multiScreenParam;
    multiScreenParam.SetExternalScreenSecure(true);
    EXPECT_TRUE(multiScreenParam.IsExternalScreenSecure());
    multiScreenParam.SetExternalScreenSecure(false);
    EXPECT_FALSE(multiScreenParam.IsExternalScreenSecure());
}

/**
 * @tc.name: SetSlrScaleEnabled
 * @tc.desc: Verify the SetSlrScaleEnabled function
 * @tc.type: FUNC
 * @tc.require: #IBOA5Q
 */
HWTEST_F(MultiScreenParamTest, SetSlrScaleEnabled, Function | SmallTest | Level1)
{
    MultiScreenParam multiScreenParam;
    multiScreenParam.SetSlrScaleEnabled(true);
    EXPECT_TRUE(multiScreenParam.IsSlrScaleEnabled());
    multiScreenParam.SetSlrScaleEnabled(false);
    EXPECT_FALSE(multiScreenParam.IsSlrScaleEnabled());
}

/**
 * @tc.name: SetRsReportHwcDead
 * @tc.desc: Verify the SetRsReportHwcDead function
 * @tc.type: FUNC
 * @tc.require: #IBOA5Q
 */
HWTEST_F(MultiScreenParamTest, SetRsReportHwcDead, Function | SmallTest | Level1)
{
    MultiScreenParam multiScreenParam;
    multiScreenParam.SetRsReportHwcDead(true);
    EXPECT_TRUE(multiScreenParam.IsRsReportHwcDead());
    multiScreenParam.SetRsReportHwcDead(false);
    EXPECT_FALSE(multiScreenParam.IsRsReportHwcDead());
}

/**
 * @tc.name: SetRsSetScreenPowerStatus
 * @tc.desc: Verify the SetRsSetScreenPowerStatus function
 * @tc.type: FUNC
 * @tc.require: #IBOA5Q
 */
HWTEST_F(MultiScreenParamTest, SetRsSetScreenPowerStatus, Function | SmallTest | Level1)
{
    MultiScreenParam multiScreenParam;
    multiScreenParam.SetRsSetScreenPowerStatus(true);
    EXPECT_TRUE(multiScreenParam.IsRsSetScreenPowerStatus());
    multiScreenParam.SetRsSetScreenPowerStatus(false);
    EXPECT_FALSE(multiScreenParam.IsRsSetScreenPowerStatus());
}
} // namespace Rosen
} // namespace OHOS