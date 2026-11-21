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

#include "rs_graphic_test_resource_table.h"

namespace OHOS {
namespace Rosen {
namespace {

const std::vector<ResourceEntry> BUILTIN_RESOURCE_ENTRIES = {
    { "/data/local/tmp/3200x2000.jpg", true, 0 },
    { "/data/local/tmp/Images/3200X2000.jpg", true, 0 },
    { "/data/local/tmp/Images/3200x2000.jpg", true, 0 },
    { "/data/local/tmp/Images/450x311.jpg", true, 0 },
    { "/data/local/tmp/Images/475x327.jpg", true, 0 },
    { "/data/local/tmp/Images/940x650.jpg", true, 0 },
    { "/data/local/tmp/Images/AllBlack.jpg", true, 0 },
    { "/data/local/tmp/Images/AllWhite.jpg", true, 0 },
    { "/data/local/tmp/Images/backGroundImage.jpg", true, 0 },
    { "/data/local/tmp/Images/clockEffect.png", true, 0 },
    { "/data/local/tmp/Images/clockImage.png", true, 0 },
    { "/data/local/tmp/Images/colorGrid.jpg", true, 0 },
    { "/data/local/tmp/Images/color_space_p3_1.jpg", true, 0 },
    { "/data/local/tmp/Images/color_space_p3_2.jpg", true, 0 },
    { "/data/local/tmp/Images/color_space_srgb_1.jpg", true, 0 },
    { "/data/local/tmp/Images/color_space_srgb_2.jpg", true, 0 },
    { "/data/local/tmp/Images/distorImage.png", true, 0 },
    { "/data/local/tmp/Images/fg_test.jpg", true, 0 },
    { "/data/local/tmp/Images/perlin_worley_noise_3d_64.png", true, 0 },
    { "/data/local/tmp/appearance_test.jpg", true, 0 },
    { "/data/local/tmp/bg1.png", true, 0 },
    { "/data/local/tmp/bg2.png", true, 0 },
    { "/data/local/tmp/bg3.png", true, 0 },
    { "/data/local/tmp/bg4.png", true, 0 },
    { "/data/local/tmp/bg_test.jpg", true, 0 },
    { "/data/local/tmp/depth1.png", true, 0 },
    { "/data/local/tmp/depth2.png", true, 0 },
    { "/data/local/tmp/depth3.png", true, 0 },
    { "/data/local/tmp/depth4.png", true, 0 },
    { "/data/local/tmp/dr_test.jpg", true, 0 },
    { "/data/local/tmp/fg_mask.jpg", true, 0 },
    { "/data/local/tmp/fg_test.jpg", true, 0 },
    { "/data/local/tmp/geom_test.jpg", true, 0 },
    { "/data/local/tmp/sdfImage0.png", true, 0 },
    { "/data/local/tmp/sdfImage3.png", true, 0 },
    { "/data/local/tmp/sdfImage5.png", true, 0 },
    { "/data/local/tmp/sdfImage6.png", true, 0 },
    { "/data/local/tmp/sdfImage8.png", true, 0 },
    { "/data/local/tmp/sdfImage9.png", true, 0 },
    { "/data/local/tmp/test.astc", true, 0 },
    { "/data/local/tmp/test_bg.jpg", true, 0 },
    { "/data/local/tmp/test_trans.jpg", true, 0 },
};

} // namespace

const std::vector<ResourceEntry>& BuiltinResourceEntries()
{
    return BUILTIN_RESOURCE_ENTRIES;
}

} // namespace Rosen
} // namespace OHOS
