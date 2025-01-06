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

#include "skia_path.h"
#include "skia_path_iterator.h"

#include "draw/path.h"
#include "draw/path_iterator.h"
#include "utils/log.h"

namespace OHOS {
namespace Rosen {
namespace Drawing {

static PathVerb ConvertToPathVerb(const SkPath::Verb& verb)
{
    switch (verb) {
        case SkPath::Verb::kMove_Verb:
            return PathVerb::MOVE;
        case SkPath::Verb::kLine_Verb:
            return PathVerb::LINE;
        case SkPath::Verb::kQuad_Verb:
            return PathVerb::QUAD;
        case SkPath::Verb::kConic_Verb:
            return PathVerb::CONIC;
        case SkPath::Verb::kCubic_Verb:
            return PathVerb::CUBIC;
        case SkPath::Verb::kClose_Verb:
            return PathVerb::CLOSE;
        case SkPath::Verb::kDone_Verb:
            return PathVerb::DONE;
    }
}

SkiaPathIterator::SkiaPathIterator(const Path& path) noexcept: PathIteratorImpl(path)
{
    auto skiaPath = path.GetImpl<SkiaPath>();
    if (!skiaPath) {
        LOGD("skiaPath nullptr, %{public}s, %{public}d", __FUNCTION__, __LINE__);
        return;
    }
    skPathIterator_ = SkPath::RawIter(skiaPath->GetPath());
}

const SkPath::RawIter& SkiaPathIterator::ExportSkiaPathIterator() const
{
    return skPathIterator_;
}

scalar SkiaPathIterator::conicWeight() const
{
    return skPathIterator_.conicWeight();
}

PathVerb SkiaPathIterator::Next(Point* points)
{
    SkPoint* skPoints = reinterpret_cast<SkPoint*>(points);
    SkPath::Verb verb = static_cast<SkPath::Verb>(skPathIterator_.next(skPoints));
    return ConvertToPathVerb(verb);
}

PathVerb SkiaPathIterator::Peek()
{
    return ConvertToPathVerb(skPathIterator_.peek());
}

} // namespace Drawing
} // namespace Rosen
} // namespace OHOS
