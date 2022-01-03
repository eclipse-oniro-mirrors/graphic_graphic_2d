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

#include "rs_screen_change_callback_death_recipient.h"

namespace OHOS {
namespace Rosen {
RSScreenChangeCallbackDeathRecipient::RSScreenChangeCallbackDeathRecipient(sptr<RSScreenManager> screenManager)
    : screenManager_(std::move(screenManager))
{
}

void RSScreenChangeCallbackDeathRecipient::OnRemoteDied(const wptr<IRemoteObject> &remote)
{
    screenManager_->OnRemoteScreenChangeCallbackDied(remote);
}
} // namespace Rosen
} // namespace OHOS
