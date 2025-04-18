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

#ifndef FRAMEWORKS_BOOTANIMATION_INCLUDE_BOOT_PLAYER_H
#define FRAMEWORKS_BOOTANIMATION_INCLUDE_BOOT_PLAYER_H

#ifdef PLAYER_FRAMEWORK_ENABLE
#include "player.h"
#endif
#include "transaction/rs_interfaces.h"
#include "util.h"
#include <system_ability_definition.h>
#include <iservice_registry.h>


namespace OHOS {
static const int64_t MAX_WAIT_MEDIA_CREATE_TIME = 5000; // 5S
#ifdef PLAYER_FRAMEWORK_ENABLE
static const int CONTENT_TYPE_UNKNOWN = 0;
static const int STREAM_USAGE_ENFORCED_TONE = 15;
#endif

class BootPlayer {
public:
    virtual ~BootPlayer() {};

    virtual void Play() {};

    std::string GetResPath(const std::string& type)
    {
        if (IsFileExisted(resPath_)) {
            return FILE_PREFIX + resPath_;
        }
        return type == TYPE_VIDEO ? BOOT_VIDEO_PATH : BOOT_SOUND_PATH;
    }

#ifdef PLAYER_FRAMEWORK_ENABLE
    bool SetCustomizedVolume(const int volume)
    {
        if (mediaPlayer_ == nullptr) {
            LOGE("mediaPlayer is nullptr.");
            return false;
        }
        float customizedVolume = (float)volume/MAX_VOLUME;
        LOGE("customizedVolume: %{public}d -> %{public}f", volume, customizedVolume);
        int ret = mediaPlayer_->SetVolume(customizedVolume, customizedVolume);
        if (ret != 0) {
            LOGE("PlayVideo SetVolume fail, errorCode:%{public}d", ret);
            return false;
        }
        return true;
    }

    Media::Format buildMediaFormat()
    {
        Media::Format format;
        format.PutIntValue(Media::PlayerKeys::CONTENT_TYPE, CONTENT_TYPE_UNKNOWN);
        format.PutIntValue(Media::PlayerKeys::STREAM_USAGE, STREAM_USAGE_ENFORCED_TONE);
        format.PutIntValue(Media::PlayerKeys::RENDERER_FLAG, 0);
        return format;
    }

    void CheckAndCreateMedia()
    {
        sptr<ISystemAbilityManager> saMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (saMgr == nullptr) {
            LOGE("saMgr is null");
            return;
        }
        int64_t startTime = GetSystemCurrentTime();
        int64_t endTime = startTime;
        while ((endTime - startTime) < MAX_WAIT_MEDIA_CREATE_TIME
            && (saMgr->CheckSystemAbility(OHOS::PLAYER_DISTRIBUTED_SERVICE_ID)) == nullptr) {
            usleep(SLEEP_TIME_US_10);
            endTime = GetSystemCurrentTime();
        }
        if (saMgr->CheckSystemAbility(OHOS::PLAYER_DISTRIBUTED_SERVICE_ID)) == nullptr) {
            LOGE("CheckMediaSa fail");
            return;
        }
        LOGI("CheckMediaSa success");

        startTime = GetSystemCurrentTime();
        endTime = startTime;
        while ((endTime - startTime) < MAX_WAIT_MEDIA_CREATE_TIME
            && (mediaPlayer_ = Media::PlayerFactory::CreatePlayer()) == nullptr) {
            usleep(SLEEP_TIME_US);
            endTime = GetSystemCurrentTime();
            LOGI("mediaPlayer is nullptr, try create again");
        }
    }
#endif

    Rosen::ScreenId screenId_;
    std::string resPath_;
    bool isSoundEnabled_ = false;
    std::shared_ptr<Media::Player> mediaPlayer_;
};
} // namespace OHOS

#endif // FRAMEWORKS_BOOTANIMATION_INCLUDE_BOOT_PLAYER_H
