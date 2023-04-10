/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef ROSEN_MODULES_TEXGINE_SRC_BIDI_PROCESSER_H
#define ROSEN_MODULES_TEXGINE_SRC_BIDI_PROCESSER_H

#include <memory>
#include <vector>

#include "variant_span.h"

namespace Texgine {
struct NewSpanInfo {
    CharGroups cgs_;
    bool rtl_ = false;
};

class BidiProcesser {
public:
    std::vector<VariantSpan> ProcessBidiText(std::vector<VariantSpan> &spans, const TextDirection dir);
    std::vector<NewSpanInfo> DoBidiProcess(CharGroups &cgs, const TextDirection dir);
};
} // namespace Texgine

#endif // ROSEN_MODULES_TEXGINE_SRC_BIDI_PROCESSER_H
