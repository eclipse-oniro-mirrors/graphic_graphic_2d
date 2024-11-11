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

#include "ranges.h"

#include <iomanip>
#include "texgine/utils/exlog.h"

namespace OHOS {
namespace Rosen {
namespace TextEngine {
void Ranges::AddRange(const struct Range &range)
{
    if (range.end - range.start == 1) {
        singles_[range.start] = range.gid;
    } else {
        ranges_.push_back(range);
    }
}

int32_t Ranges::GetGlyphId(uint32_t codepoint) const
{
    if (const auto &it = singles_.find(codepoint); it != singles_.end()) {
        return it->first + it->second;
    }

    for (const auto &[start, end, gid] : ranges_) {
        if (codepoint >= start && codepoint < end) {
            return codepoint + gid;
        }
    }

    return INVALID_GLYPH_ID;
}

void Ranges::Dump() const
{
    for (const auto &[start, end, gid] : ranges_) {
        LOGSO_FUNC_LINE(INFO) << "0x" << std::uppercase << std::hex
            << std::setw(4) << std::setfill('0') << start  //4 means output width
            << " ~ 0x" << std::uppercase << std::hex 
            << std::setw(4) << std::setfill('0') << end   //4 means output width
            << ": offset " << std::dec << end;
    }

    for (const auto &[codepoint, gid] : singles_) {
        LOGSO_FUNC_LINE(INFO) << "0x" << std::uppercase << std::hex
            << std::setw(4) << std::setfill('0') << codepoint  //4 means output width
            << ": glyphid " << std::dec
            << (codepoint + gid) % (1 << 16); //16 means offset; 1 << 16 means residual multiple
    }
}
} // namespace TextEngine
} // namespace Rosen
} // namespace OHOS
