/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef PICTURE_H
#define PICTURE_H

#include "drawing/engine_adapter/impl_interface/picture_impl.h"
#include "utils/serial_procs.h"

namespace OHOS {
namespace Rosen {
namespace Drawing {
class Picture {
public:
    Picture() noexcept;
    virtual ~Picture() {};
    template<typename T>
    T* GetImpl() const
    {
        return pictureImplPtr->DowncastingTo<T>();
    }
    std::shared_ptr<Data> Serialize() const;
    bool Deserialize(std::shared_ptr<Data> data);
    int ApproximateOpCount(bool nested = false);
    std::shared_ptr<Data> Serialize(SerialProcs* proc);

private:
    std::shared_ptr<PictureImpl> pictureImplPtr;
};
} // namespace Drawing
} // namespace Rosen
} // namespace OHOS
#endif