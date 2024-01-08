/*
 * Copyright (c) Huawei Device Co., Ltd. 2024. All rights reserved.
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

#ifndef ITRANSACT_SURFACE_DELEGATOR_H
#define ITRANSACT_SURFACE_DELEGATOR_H

#include <map>
#include <iremote_stub.h>
#include "surface.h"
#include "itransact_surface_delegator.h"

namespace OHOS {
class ITransactSurfaceDelegator : public IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"surf.TransactSurfaceDelegator");
    ITransactSurfaceDelegator() = default;
    virtual ~ITransactSurfaceDelegator() noexcept = default;

protected:
    enum {
        DEQUEUEBUFFER = 0;
        QUEUEBUFFER = 1;
        ACUIREBUFFER = 2;
        RELESEBUFFER =  3;
        CLEARBUFFERSLOT = 4;
        CLIENT = 5;
        CANCELBUFFER = 6;
        DETACHBUFFER = 7;
    };
};
} // namespace OHOS

#endif // ITRANSACT_SURFACE_DELEGATOR_H
