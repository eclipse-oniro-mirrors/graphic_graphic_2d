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
 
#include "ipc_callbacks/pointer_render/pointer_luminance_change_callback_ipc_interface_code_access_verifier.h"
 
namespace OHOS {
namespace Rosen {
RSIPointerLuminanceChangeCallbackInterfaceCodeAccessVerifier::
    RSIPointerLuminanceChangeCallbackInterfaceCodeAccessVerifier()
{
    CheckCodeUnderlyingTypeStandardized<CodeEnumType>(codeEnumTypeName_);
}
 
bool RSIPointerLuminanceChangeCallbackInterfaceCodeAccessVerifier::IsExclusiveVerificationPassed(
    CodeUnderlyingType code)
{
    bool hasPermission = false;
    switch (code) {
        case static_cast<CodeUnderlyingType>(CodeEnumType::ON_POINTER_LUMINANCE_CHANGED): {
            hasPermission = IsSystemCalling(codeEnumTypeName_ + "::ON_POINTER_LUMINANCE_CHANGED");
            break;
        }
        default: {
            break;
        }
    }
    return hasPermission;
}
} // namespace Rosen
} // namespace OHOS