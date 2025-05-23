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

#ifndef DRAWING_FONT_H
#define DRAWING_FONT_H
#include "rosen_text/font_collection.h"
#include "text/font.h"
#include "text/font_mgr.h"

class DrawingFontUtils {
public:
    static std::shared_ptr<OHOS::Rosen::Drawing::Typeface> GetZhCnTypeface();
    static std::shared_ptr<OHOS::Rosen::Drawing::Font> GetThemeFont(const OHOS::Rosen::Drawing::Font* font);
    static std::shared_ptr<OHOS::Rosen::Drawing::Font> MatchThemeFont(const OHOS::Rosen::Drawing::Font* font,
        int32_t unicode);
    static std::shared_ptr<OHOS::Rosen::Drawing::FontMgr> GetFontMgr(const OHOS::Rosen::Drawing::Font* font);
};
#endif // DRAWING_FONT_H