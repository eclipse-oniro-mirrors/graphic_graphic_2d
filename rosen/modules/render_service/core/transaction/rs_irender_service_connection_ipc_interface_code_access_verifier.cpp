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

#include "platform/ohos/rs_irender_service_connection_ipc_interface_code_access_verifier.h"

namespace OHOS {
namespace Rosen {
RSIRenderServiceConnectionInterfaceCodeAccessVerifier::RSIRenderServiceConnectionInterfaceCodeAccessVerifier()
{
    CheckCodeUnderlyingTypeStandardized<CodeEnumType>(codeEnumTypeName_);
#ifdef ENABLE_IPC_SECURITY
    AddRSIRenderServiceConnectionInterfaceCodePermission();
#endif
}

bool RSIRenderServiceConnectionInterfaceCodeAccessVerifier::IsExclusiveVerificationPassed(CodeUnderlyingType code)
{
    bool hasPermission = true;
    switch (code) {
        case static_cast<CodeUnderlyingType>(CodeEnumType::SET_REFRESH_RATE_MODE): {
            hasPermission = IsSystemApp();
            break;
        }
        case static_cast<CodeUnderlyingType>(CodeEnumType::GET_SHOW_REFRESH_RATE_ENABLED): {
            hasPermission = IsSystemApp();
            break;
        }
        case static_cast<CodeUnderlyingType>(CodeEnumType::SET_SHOW_REFRESH_RATE_ENABLED): {
            hasPermission = IsSystemApp();
            break;
        }
        case static_cast<CodeUnderlyingType>(CodeEnumType::TAKE_SURFACE_CAPTURE): {
            hasPermission = CheckPermission(code);
            break;
        }
        case static_cast<CodeUnderlyingType>(CodeEnumType::GET_MEMORY_GRAPHICS): {
            hasPermission = CheckPermission(code);
            break;
        }
        case static_cast<CodeUnderlyingType>(CodeEnumType::SET_SCREEN_POWER_STATUS): {
            hasPermission = IsSystemCalling(codeEnumTypeName_ + "::SET_SCREEN_POWER_STATUS");
            break;
        }
#ifdef OHOS_BUILD_ENABLE_MAGICCURSOR
        case static_cast<CodeUnderlyingType>(CodeEnumType::SET_POINTER_COLOR_INVERSION_CONFIG): {
            hasPermission = IsSystemCalling(codeEnumTypeName_ + "::SET_POINTER_COLOR_INVERSION_CONFIG");
            break;
        }
        case static_cast<CodeUnderlyingType>(CodeEnumType::SET_POINTER_COLOR_INVERSION_ENABLED): {
            hasPermission = IsSystemCalling(codeEnumTypeName_ + "::SET_POINTER_COLOR_INVERSION_ENABLED");
            break;
        }
        case static_cast<CodeUnderlyingType>(CodeEnumType::REGISTER_POINTER_LUMINANCE_CALLBACK): {
            hasPermission = IsSystemCalling(codeEnumTypeName_ + "::REGISTER_POINTER_LUMINANCE_CALLBACK");
            break;
        }
        case static_cast<CodeUnderlyingType>(CodeEnumType::UNREGISTER_POINTER_LUMINANCE_CALLBACK): {
            hasPermission = IsSystemCalling(codeEnumTypeName_ + "::UNREGISTER_POINTER_LUMINANCE_CALLBACK");
            break;
        }
#endif
        case static_cast<CodeUnderlyingType>(CodeEnumType::SET_VIRTUAL_SCREEN_STATUS): {
            hasPermission = IsSystemCalling(codeEnumTypeName_ + "::SET_VIRTUAL_SCREEN_STATUS");
            break;
        }
#ifdef RS_ENABLE_VK
        case static_cast<CodeUnderlyingType>(CodeEnumType::SET_2D_RENDER_CTRL): {
            hasPermission = IsSystemCalling(codeEnumTypeName_ + "::SET_2D_RENDER_CTRL");
            break;
        }
#endif
        default: {
            break;
        }
    }
    return hasPermission;
}

#ifdef ENABLE_IPC_SECURITY
void RSIRenderServiceConnectionInterfaceCodeAccessVerifier::AddRSIRenderServiceConnectionInterfaceCodePermission()
{
    for (auto& mapping : permissionRSIRenderServiceConnectionInterfaceMappings_) {
        CodeEnumType interfaceName = mapping.first;
        PermissionType permission = mapping.second;
        std::string newPermission = PermissionEnumToString(permission);
        if (newPermission == "unknown") {
            continue;
        }
        CodeUnderlyingType code = static_cast<CodeUnderlyingType>(interfaceName);
        AddPermission(code, newPermission);
    }
}

bool RSIRenderServiceConnectionInterfaceCodeAccessVerifier::IsAccessTimesVerificationPassed(
    CodeUnderlyingType code, uint32_t times) const
{
    auto interfaceName = static_cast<CodeEnumType>(code);
    if (accessRSIRenderServiceConnectionInterfaceTimesRestrictions_.count(interfaceName) == 0) {
        return true;
    }
    uint32_t restrictedTimes = accessRSIRenderServiceConnectionInterfaceTimesRestrictions_.at(interfaceName);
    return times < restrictedTimes;
}
#endif

} // namespace Rosen
} // namespace OHOS
