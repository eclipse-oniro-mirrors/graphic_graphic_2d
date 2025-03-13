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

#include "drawing_error_code.h"
#include "drawing_sampling_options.h"
#include "drawing_shader_effect.h"
#include "gtest/gtest.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Rosen {
namespace Drawing {
class NativeDrawingSamplingOptionsTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};


void NativeDrawingSamplingOptionsTest::SetUpTestCase() {}
void NativeDrawingSamplingOptionsTest::TearDownTestCase() {}
void NativeDrawingSamplingOptionsTest::SetUp() {}
void NativeDrawingSamplingOptionsTest::TearDown() {}


/*
 * @tc.name: OH_Drawing_SamplingOptionsCreate
 * @tc.desc: Test OH_Drawing_SamplingOptionsCreate
 * @tc.type: FUNC
 */
HWTEST_F(NativeDrawingSamplingOptionsTest, OH_Drawing_SamplingOptionsCreate, TestSize.Level1)
{
    OH_Drawing_SamplingOptions* option1 = OH_Drawing_SamplingOptionsCreate(OH_Drawing_FilterMode::FILTER_MODE_LINEAR,
        OH_Drawing_MipmapMode::MIPMAP_MODE_NEAREST);
    OH_Drawing_SamplingOptions* option2 = OH_Drawing_SamplingOptionsCreate(OH_Drawing_FilterMode::FILTER_MODE_LINEAR,
        static_cast<OH_Drawing_MipmapMode>(-1));
    OH_Drawing_SamplingOptions* option3 = OH_Drawing_SamplingOptionsCreate(OH_Drawing_FilterMode::FILTER_MODE_LINEAR,
        static_cast<OH_Drawing_MipmapMode>(99));
    EXPECT_NE(option1, nullptr);
    EXPECT_EQ(option2, nullptr);
    EXPECT_EQ(option3, nullptr);

    OH_Drawing_SamplingOptionsDestroy(option1);
    OH_Drawing_SamplingOptionsDestroy(option2);
    OH_Drawing_SamplingOptionsDestroy(option3);
}
} // namespace Drawing
} // namespace Rosen
} // namespace OHOS