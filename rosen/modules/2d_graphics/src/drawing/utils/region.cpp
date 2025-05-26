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

#include "utils/region.h"

#include "impl_factory.h"

namespace OHOS {
namespace Rosen {
namespace Drawing {
Region::Region() : impl_(ImplFactory::CreateRegionImpl()) {}

Region::Region(const Region& other) : Region()
{
    impl_->Clone(other);
}

Region& Region::operator=(const Region& other)
{
    impl_->Clone(other);
    return *this;
}

bool Region::operator==(const Region& other) const
{
    return impl_->Equals(other);
}

bool Region::Contains(int32_t x, int32_t y) const
{
    return impl_->Contains(x, y);
}

void Region::SetEmpty()
{
    return impl_->SetEmpty();
}

bool Region::SetRect(const RectI& rectI)
{
    return impl_->SetRect(rectI);
}

bool Region::SetRegion(const Region& region)
{
    return impl_->SetRegion(region);
}

bool Region::SetPath(const Path& path, const Region& clip)
{
    return impl_->SetPath(path, clip);
}

bool Region::GetBoundaryPath(Path* path) const
{
    return impl_->GetBoundaryPath(path);
}

RectI Region::GetBounds() const
{
    return impl_->GetBounds();
}

bool Region::IsComplex() const
{
    return impl_->IsComplex();
}

bool Region::IsIntersects(const Region& other) const
{
    return impl_->IsIntersects(other);
}

bool Region::IsEmpty() const
{
    return impl_->IsEmpty();
}

bool Region::IsRect() const
{
    return impl_->IsRect();
}

bool Region::IsRegionContained(const Region& other) const
{
    return impl_->IsRegionContained(other);
}

bool Region::Op(const Region& region, RegionOp op)
{
    return impl_->Op(region, op);
}

bool Region::QuickReject(const RectI& rectI) const
{
    return impl_->QuickReject(rectI);
}

bool Region::QuickReject(const Region& region) const
{
    return impl_->QuickReject(region);
}

void Region::Translate(int32_t x, int32_t y)
{
    return impl_->Translate(x, y);
}

std::shared_ptr<Data> Region::Serialize() const
{
    return impl_->Serialize();
}

bool Region::Deserialize(std::shared_ptr<Data> data)
{
    return impl_->Deserialize(data);
}
} // namespace Drawing
} // namespace Rosen
} // namespace OHOS
