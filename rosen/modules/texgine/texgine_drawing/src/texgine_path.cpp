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

#include "texgine_path.h"

namespace OHOS {
namespace Rosen {
namespace TextEngine {
SkPath TexginePath::GetPath()
{
    return *path_.get();
}

void TexginePath::SetPath(std::shared_ptr<SkPath> path)
{
    path_ = path;
}

TexginePath &TexginePath::AddOval(TexgineRect &oval, TexginePathDirection dir)
{
    *path_ = path_->addOval(*oval.GetRect(), static_cast<SkPath::Direction>(dir));
    return *this;
}

TexginePath &TexginePath::MoveTo(const TexginePoint &p)
{
    SkPoint point({p.fX_, p.fY_});
    *path_ = path_->moveTo(point);
    return *this;
}

TexginePath &TexginePath::QuadTo(const TexginePoint &p1, const TexginePoint &p2)
{
    SkPoint point1({p1.fX_, p1.fY_});
    SkPoint point2({p2.fX_, p2.fY_});
    *path_ = path_->quadTo(point1, point2);
    return *this;
}

TexginePath &TexginePath::LineTo(const TexginePoint &p)
{
    SkPoint point({p.fX_, p.fY_});
    *path_ = path_->lineTo(point);
    return *this;
}
} // namespace TextEngine
} // namespace Rosen
} // namespace OHOS
