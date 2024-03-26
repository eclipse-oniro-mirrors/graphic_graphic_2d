/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "render/rs_dynamic_dim_filter.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS::Rosen {
class RSDynamicDimFilterTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void RSDynamicDimFilterTest::SetUpTestCase() {}
void RSDynamicDimFilterTest::TearDownTestCase() {}
void RSDynamicDimFilterTest::SetUp() {}
void RSDynamicDimFilterTest::TearDown() {}

/**
 * @tc.name: RSDynamicDimFilterTest001
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSDynamicDimFilterTest, RSDynamicDimFilterTest001, TestSize.Level1)
{
    float dynamicDimDegree = 1.0f;
    auto filter = std::make_shared<RSDynamicDimFilter>(dynamicDimDegree);
    EXPECT_TRUE(filter != nullptr);

    EXPECT_TRUE(filter->GetDynamicDimDegree() == 1.0f);
    filter->GetDescription();

    auto filter2 = std::make_shared<RSDynamicDimFilter>(dynamicDimDegree);
    auto result = filter->Compose(filter2);
    EXPECT_TRUE(result != nullptr);
}

/**
 * @tc.name: RSDynamicDimFilterTest002
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSDynamicDimFilterTest, RSDynamicDimFilterTest002, TestSize.Level1)
{
    float dynamicDimDegree = 1.0f;
    auto filter = std::make_shared<RSDynamicDimFilter>(dynamicDimDegree);
    EXPECT_TRUE(filter != nullptr);

    auto filter2 = std::make_shared<RSDynamicDimFilter>(dynamicDimDegree);
    EXPECT_TRUE(filter2 != nullptr);

    auto result = filter->Add(filter2);
    EXPECT_TRUE(result != nullptr);

    result = filter->Sub(filter2);
    EXPECT_TRUE(result != nullptr);

    result = filter->Multiply(1.0f);
    EXPECT_TRUE(result != nullptr);

    result = filter->Negate();
    EXPECT_TRUE(result != nullptr);
}

/**
 * @tc.name: GetDynamicDimDegreeTest
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSDynamicDimFilterTest, GetDynamicDimDegreeTest, TestSize.Level1)
{
    float dynamicDimDegree = 1.0f;
    auto filter = std::make_shared<RSDynamicDimFilter>(dynamicDimDegree);
    EXPECT_TRUE(filter != nullptr);
    filter->Add(filter);
    EXPECT_NE(filter->GetDynamicDimDegree(), 0.f);
}

/**
 * @tc.name: ComposeTest
 * @tc.desc:
 * @tc.type:FUNC
 */
HWTEST_F(RSDynamicDimFilterTest, ComposeTest, TestSize.Level1)
{
    float dynamicDimDegree = 1.0f;
    auto filter = std::make_shared<RSDynamicDimFilter>(dynamicDimDegree);
    auto filter_ = std::make_shared<RSDynamicDimFilter>(dynamicDimDegree);
    EXPECT_NE(filter->Compose(filter_), nullptr);
}

/**
 * @tc.name: IsNearEqual001
 * @tc.desc: Verify function IsNearEqual
 * @tc.type:FUNC
 */
HWTEST_F(RSDynamicDimFilterTest, IsNearEqual001, TestSize.Level1)
{
    float dynamicDimDegree = 1.0f;
    float dynamicDimDegree = 1.2f;
    float threshold = 0.5f;
    auto filter = std::make_shared<RSDynamicDimFilter>(dynamicDimDegree);

    std::shared_ptr<RSFilter> other1 = std::make_shared<RSDynamicDimFilter>(dynamicDimDegree);
    EXPECT_TRUE(filter->IsNearEqual(other1, threshold));
}

/**
 * @tc.name: IsNearZero001
 * @tc.desc: Verify function IsNearZero
 * @tc.type:FUNC
 */
HWTEST_F(RSDynamicDimFilterTest, IsNearZero001, TestSize.Level1)
{
    float dynamicDimDegree = 0.2f;
    float threshold = 0.5f;
    auto filter = std::make_shared<RSDynamicDimFilter>(dynamicDimDegree);
    EXPECT_TRUE(filter->IsNearZero(threshold));
}
} // namespace OHOS::Rosen
