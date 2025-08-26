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

#ifndef DRAWING_COMMON_H
#define DRAWING_COMMON_H

#include "drawing_text_typography.h"
#include "font_parser.h"

namespace OHOS::Rosen::Drawing {
using OHOS::Rosen::TextEngine::FontParser;
const size_t SUCCESS = 0;
const size_t ERROR_CODE_PARAMETER_OUT_OF_RANGE = 26200001;
const size_t ERROR_CODE_INVALID_PARAMETER = 26200003;
const size_t ERROR_CODE_PARAMETER_TYPE_MISMATCH = 26200004;
bool CopyFontDescriptor(OH_Drawing_FontDescriptor* dst, const FontParser::FontDescriptor& src);
} // namespace OHOS::Rosen::Drawing

#endif // DRAWING_COMMON_H