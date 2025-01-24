/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef PICTUREIMPL_H
#define PICTUREIMPL_H

#include "base_impl.h"
#include "utils/data.h"
#include "utils/serial_procs.h"

namespace OHOS {
namespace Rosen {
namespace Drawing {
class PictureImpl : public BaseImpl {
public:
    PictureImpl() noexcept {}
    ~PictureImpl() override {}

    // using for recording, should to remove after using shared memory
    virtual std::shared_ptr<Data> Serialize() const = 0;
    virtual bool Deserialize(std::shared_ptr<Data> data) = 0;
    virtual int ApproximateOpCount(bool flag) = 0;
    virtual std::shared_ptr<Data> Serialize(SerialProcs* procs) = 0;
};
} // namespace Drawing
} // namespace Rosen
} // namespace OHOS
#endif
