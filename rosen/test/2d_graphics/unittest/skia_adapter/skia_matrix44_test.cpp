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
#include "skia_adapter/skia_matrix44.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace Rosen {
namespace Drawing {
class SkiaMatrix44Test : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void SkiaMatrix44Test::SetUpTestCase() {}
void SkiaMatrix44Test::TearDownTestCase() {}
void SkiaMatrix44Test::SetUp() {}
void SkiaMatrix44Test::TearDown() {}

/**
 * @tc.name: SkiaMatrix44001
 * @tc.desc: Test SkiaMatrix44's functions
 * @tc.type: FUNC
 * @tc.require: I8VQSW
 */
HWTEST_F(SkiaMatrix44Test, SkiaMatrix44001, TestSize.Level1)
{
    std::shared_ptr<SkiaMatrix44> skiaMatrix44 = std::make_shared<SkiaMatrix44>();
    scalar dx = 2;
    scalar dy = 2;
    scalar dz = 2;
    skiaMatrix44->Translate(dx, dy, dz);
    skiaMatrix44->PreTranslate(dx, dy, dz);
    skiaMatrix44->PostTranslate(dx, dy, dz);
    skiaMatrix44->Scale(dx, dy, dz);
    skiaMatrix44->PreScale(dx, dy, dz);
    int column = 2;
    scalar w = 2;
    skiaMatrix44->SetCol(column, dx, dy, dz, w);
}
} // namespace Drawing
} // namespace Rosen
} // namespace OHOS