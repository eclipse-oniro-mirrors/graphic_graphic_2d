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

#ifndef REGION_H
#define REGION_H

#include "impl_interface/region_impl.h"

namespace OHOS {
namespace Rosen {
namespace Drawing {
enum class RegionOp {
    DIFFERENCE,
    INTERSECT,
    UNION,
    XOR,
    REVERSE_DIFFERENCE,
    REPLACE,
};
class Region {
public:
    Region();
    virtual ~Region() = default;

    /*
     * @brief        Constructs a rectangular Region matching the bounds of rect.
     * @param rectI  Bounds of constructed Region.
     * @return       If rectI is empty, constructs empty and returns false.
     */
    virtual bool SetRect(const RectI& rectI);

    /*
     * @brief        Constructs Region to match outline of path within clip.
     * @param &path  Providing outline
     * @param &clip  Containing path.
     * @return       Return true if constructed Region is not empty.
     */
    virtual bool SetPath(const Path& path, const Region& clip);

    /*
     * @brief         Determines whether it intersects other.
     * @param &other  Other Region object.
     * @return        If true indicates that other and Region have area in common.
     */
    bool IsIntersects(const Region& other) const;

    /*
     * @brief          Replaces Region with the result of Region op region.
     * @param &region  Operand.
     * @param op       Operation type.
     * @return         Returns true if replaced Region is not empty.
     */
    virtual bool Op(const Region& region, RegionOp op);

    /*
     * @brief   Get the adaptation layer instance, called in the adaptation layer.
     * @return  Adaptation Layer instance.
     */
    template<typename T>
    const std::shared_ptr<T> GetImpl() const
    {
        return (impl_ == nullptr) ? nullptr : impl_->DowncastingTo<T>();
    }

private:
    std::shared_ptr<RegionImpl> impl_;
};
} // namespace Drawing
} // namespace Rosen
} // namespace OHOS
#endif
