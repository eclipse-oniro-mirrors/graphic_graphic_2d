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

#ifndef ROSEN_MODULES_TEXGINE_SRC_OPENTYPE_PARSER_CMAP_PARSER_H
#define ROSEN_MODULES_TEXGINE_SRC_OPENTYPE_PARSER_CMAP_PARSER_H

#include <cstdint>
#include <string>

#include "ranges.h"

namespace Texgine {
struct CmapSubtable;
class CmapParser {
public:
    static constexpr int32_t InvalidGlyphId = Ranges::InvalidGlyphId;

    int Parse(const char *data, int32_t size);
    int32_t GetGlyphId(int32_t codepoint) const;
    void Dump() const;

private:
    friend void ReportMemoryUsage(const std::string &member, const CmapParser &that, bool needThis);

    int ParseFormat4(const CmapSubtable &subtable, const std::size_t size);
    int ParseFormat12(const CmapSubtable &subtable, const std::size_t size);

    Ranges ranges_;
};
} // namespace Texgine

#endif // ROSEN_MODULES_TEXGINE_SRC_OPENTYPE_PARSER_CMAP_PARSER_H
