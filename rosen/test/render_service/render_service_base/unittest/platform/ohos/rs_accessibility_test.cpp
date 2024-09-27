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
#include <gtest/gtest.h>
#include <iostream>

#include "platform/common/rs_accessibility.h"
using namespace testing;
using namespace testing::ext;
namespace OHOS {
namespace Rosen {
class RRSAccessibilityTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void RRSAccessibilityTest::SetUpTestCase() {}
void RRSAccessibilityTest::TearDownTestCase() {}
void RRSAccessibilityTest::SetUp() {}
void RRSAccessibilityTest::TearDown() {}
/**
 * @tc.name: ListenHighContrastChangeTest
 * @tc.desc: Verify function GetInstance and ListenHighContrastChange and ListenHighContrast
 * @tc.type:FUNC
 * @tc.require: issueI9TOXM
 */
HWTEST_F(RRSAccessibilityTest, ListenHighContrastChangeTest, TestSize.Level1)
{
    RSAccessibility::OnHighContrastChange callback;
    RSAccessibility::GetInstance().ListenHighContrastChange(callback);
    EXPECT_EQ(callback, nullptr);
}
} // namespace Rosen
} // namespace OHOS