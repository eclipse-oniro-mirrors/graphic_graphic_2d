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

#ifndef PATH_ITERATOR_IMPL_H
#define PATH_ITERATOR_IMPL_H

#include <memory>

#include "base_impl.h"
#include "utils/scalar.h"

namespace OHOS {
namespace Rosen {
namespace Drawing {
class PathIterator;
enum class PathVerb;
class PathIteratorImpl : public BaseImpl {
public:
    ~PathIteratorImpl() override {}
    explicit PathIteratorImpl(const Path& p) {}
    virtual void Clone(const PathIterator& other) = 0;
    virtual scalar conicWeight() const = 0;
    virtual PathVerb Next(Point* points) = 0;
    virtual PathVerb Peek() = 0;
};
} // namespace Drawing
} // namespace Rosen
} // namespace OHOS
#endif