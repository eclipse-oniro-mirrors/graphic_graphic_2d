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

#include "occlusion_culling_param.h"

using namespace testing;
using namespace testing::ext;
namespace OHOS {
namespace Rosen {

class OcclusionCullingParamTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void OcclusionCullingParamTest::SetUpTestCase() {}
void OcclusionCullingParamTest::TearDownTestCase() {}
void OcclusionCullingParamTest::SetUp() {}
void OcclusionCullingParamTest::TearDown() {}

/**
 * @tc.name: SetStencilPixelOcclusionCullingEnable
 * @tc.desc: Verify the SetStencilPixelOcclusionCullingEnable function
 * @tc.type: FUNC
 * @tc.require: #IBPXUM
 */
HWTEST_F(OcclusionCullingParamTest, SetStencilPixelOcclusionCullingEnable, Function | SmallTest | Level1)
{
    OcclusionCullingParam::SetStencilPixelOcclusionCullingEnable(true);
    ASSERT_TRUE(OcclusionCullingParam::IsStencilPixelOcclusionCullingEnable());
    OcclusionCullingParam::SetStencilPixelOcclusionCullingEnable(false);
    ASSERT_FALSE(OcclusionCullingParam::IsStencilPixelOcclusionCullingEnable());
}

/**
 * @tc.name: SetIntraAppOcclusionCullingEnable
 * @tc.desc: Verify the result of SetIntraAppOcclusionCullingEnable function
 * @tc.type: FUNC
 * @tc.require: #IBPXUM
 */
HWTEST_F(OcclusionCullingParamTest, SetIntraAppOcclusionCullingEnable, Function | SmallTest | Level1)
{
    OcclusionCullingParam::SetIntraAppOcclusionCullingEnable(true);
    ASSERT_TRUE(OcclusionCullingParam::IsIntraAppOcclusionCullingEnable());
    OcclusionCullingParam::SetIntraAppOcclusionCullingEnable(false);
    ASSERT_FALSE(OcclusionCullingParam::IsIntraAppOcclusionCullingEnable());
}
} // namespace Rosen
} // namespace OHOS