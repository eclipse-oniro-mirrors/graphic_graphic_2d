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

#ifndef RESOURCE_HOLDER_IMPL_H
#define RESOURCE_HOLDER_IMPL_H

#include "base_impl.h"

namespace OHOS {
namespace Rosen {
namespace Drawing {
class Image;
class ResourceHolderImpl : public BaseImpl {
public:
    ResourceHolderImpl() {}
    ~ResourceHolderImpl() override {}
    virtual void HoldResource(const std::shared_ptr<Drawing::Image>& img) = 0;
    virtual void ReleaseResource() = 0;
    virtual bool IsEmpty() const = 0;
};
} // namespace Drawing
} // namespace Rosen
} // namespace OHOS
#endif // RESOURCE_HOLDER_IMPL_H