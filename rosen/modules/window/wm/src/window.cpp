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

#include "window.h"
#include "window_impl.h"

namespace OHOS {
namespace Rosen {
sptr<Window> Window::Create(const std::string& id, sptr<WindowProperty>& property)
{
    if (property == nullptr) {
        property = new WindowProperty();
    }
    property->SetWindowId(id);
    return new WindowImpl(property);
}

sptr<Window> Window::Find(const std::string& id)
{
    return WindowImpl::Find(id);
}
}
}
