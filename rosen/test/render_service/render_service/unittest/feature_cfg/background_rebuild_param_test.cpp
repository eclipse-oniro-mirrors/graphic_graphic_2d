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

#include <gtest/gtest.h>
#include <test_header.h>

#include "background_rebuild_param.h"

using namespace testing;
using namespace testing::ext;
namespace OHOS {
namespace Rosen {

class BackgroundRebuildParamTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void BackgroundRebuildParamTest::SetUpTestCase() {}
void BackgroundRebuildParamTest::TearDownTestCase() {}
void BackgroundRebuildParamTest::SetUp() {}
void BackgroundRebuildParamTest::TearDown() {}

/**
 * @tc.name: SetBackgroundRebuildEnabledTrue
 * @tc.desc: Verify SetBackgroundRebuildEnabled with true value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BackgroundRebuildParamTest, SetBackgroundRebuildEnabledTrue, Function | SmallTest | Level1)
{
    BackgroundRebuildParam::SetBackgroundRebuildEnabled(true);
    EXPECT_EQ(BackgroundRebuildParam::IsBackgroundRebuildEnabled(), true);
}

/**
 * @tc.name: SetBackgroundRebuildEnabledFalse
 * @tc.desc: Verify SetBackgroundRebuildEnabled with false value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BackgroundRebuildParamTest, SetBackgroundRebuildEnabledFalse, Function | SmallTest | Level1)
{
    BackgroundRebuildParam::SetBackgroundRebuildEnabled(false);
    EXPECT_EQ(BackgroundRebuildParam::IsBackgroundRebuildEnabled(), false);
}

/**
 * @tc.name: IsBackgroundRebuildEnabledDefault
 * @tc.desc: Verify IsBackgroundRebuildEnabled in default value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BackgroundRebuildParamTest, IsBackgroundRebuildEnabledDefault, Function | SmallTest | Level1)
{
    EXPECT_EQ(BackgroundRebuildParam::IsBackgroundRebuildEnabled(), false);
}
} // namespace Rosen
} // namespace OHOS
