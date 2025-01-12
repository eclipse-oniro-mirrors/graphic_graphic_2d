/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef DOCUMENT_IMPL_H
#define DOCUMENT_IMPL_H

#include "base_impl.h"
#include "utils/data.h"
#include "draw/canvas.h"

namespace OHOS {
namespace Rosen {
namespace Drawing {
class DocumentImpl : public BaseImpl {
public:
    DocumentImpl() noexcept {}
    ~DocumentImpl() override {}

    virtual std::shared_ptr<Drawing::Canvas> BeginPage(float width, float height) = 0;
    virtual void EndPage() = 0;
    virtual void Close() = 0;
};
} // namespace Drawing
} // namespace Rosen
} // namespace OHOS
#endif