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

#include "skia_font_style_set_ohos.h"

#include "src/ports/skia_ohos/SkFontStyleSet_ohos.h"

namespace OHOS {
namespace Rosen {
namespace Drawing {
SkiaFontStyleSetOhos::SkiaFontStyleSetOhos(
    const std::shared_ptr<FontConfig_OHOS>& fontConfig, int index, bool isFallback)
    : SkiaFontStyleSet(std::make_shared<SkFontStyleSet_OHOS>(fontConfig, index, isFallback)) {}
} // namespace Drawing
} // namespace Rosen
} // namespace OHOS