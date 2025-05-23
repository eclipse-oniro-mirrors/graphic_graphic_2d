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

#include "image/picture.h"

#include "impl_factory.h"

namespace OHOS {
namespace Rosen {
namespace Drawing {
Picture::Picture() noexcept : pictureImplPtr(ImplFactory::CreatePictureImpl()) {}

std::shared_ptr<Data> Picture::Serialize() const
{
    return pictureImplPtr->Serialize();
}

bool Picture::Deserialize(std::shared_ptr<Data> data)
{
    return pictureImplPtr->Deserialize(data);
}

int Picture::ApproximateOpCount(bool nested)
{
    return pictureImplPtr->ApproximateOpCount(nested);
}

std::shared_ptr<Data> Picture::Serialize(SerialProcs* proc)
{
    return pictureImplPtr->Serialize(proc);
}
} // namespace Drawing
} // namespace Rosen
} // namespace OHOS