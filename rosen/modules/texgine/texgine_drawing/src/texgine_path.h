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

#ifndef ROSEN_MODULES_TEXGINE_SRC_TEXGINE_DRAWING_TEXGINE_PATH_H
#define ROSEN_MODULES_TEXGINE_SRC_TEXGINE_DRAWING_TEXGINE_PATH_H

#include <memory>

#include <include/core/SkPath.h>

#include "texgine_rect.h"

namespace OHOS {
namespace Rosen {
namespace TextEngine {
enum class TexginePathDirection {
    kCW,  // clockwise direction for adding closed contours
    kCCW, // counter-clockwise direction for adding closed contours
};

struct TexginePoint {
    float fX_;
    float fY_;
};

class TexginePath {
public:
    SkPath GetPath();
    void SetPath(std::shared_ptr<SkPath> path);
    TexginePath &AddOval(TexgineRect &oval, TexginePathDirection dir = TexginePathDirection::kCW);
    TexginePath &MoveTo(const TexginePoint &p);
    TexginePath &QuadTo(const TexginePoint &p1, const TexginePoint &p2);
    TexginePath &LineTo(const TexginePoint &p);

private:
    std::shared_ptr<SkPath> path_ = std::make_shared<SkPath>();
};
} // namespace TextEngine
} // namespace Rosen
} // namespace OHOS

#endif // ROSEN_MODULES_TEXGINE_SRC_TEXGINE_DRAWING_TEXGINE_PATH_H
