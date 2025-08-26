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

#ifndef FRAMEWORKS_BOOTANIMATION_INCLUDE_UTIL_H
#define FRAMEWORKS_BOOTANIMATION_INCLUDE_UTIL_H

#include "boot_animation_config.h"
#include "cJSON.h"
#include "contrib/minizip/unzip.h"
#include "contrib/minizip/zip.h"
#include <cstdint>
#include <dirent.h>
#include <functional>
#include "log.h"
#include <platform/ohos/rs_irender_service.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include "zlib.h"
#include <parameters.h>

namespace OHOS {
static const int NUMBER_TWO = 2;
static const int READ_SIZE = 8192;
static const int MAX_FILE_NAME = 512;
static const int SLEEP_TIME_US = 30000;
static const int SLEEP_TIME_US_10 = 10000;
static const int INVALID_VOLUME = -1;
static const int MIN_VOLUME = 0;
static const int MAX_VOLUME = 15;
constexpr const float MAX_ZORDER = 100000.0f;
constexpr const float HALF = 2.0f;
constexpr const float RATIO_PHONE = 360.0f;
constexpr const float RATIO_OTHER = 800.0f;
constexpr const float RATIO_PHONE_HEIGHT = 780.0f;

constexpr const char* FILE_PREFIX = "file:/";
const std::string BOOT_PIC_CONFIG_FILE = "config.json";
const std::string BOOT_SOUND_PATH = "file://system/etc/graphic/bootsound.wav";
const std::string BOOT_VIDEO_PATH = "file://system/etc/graphic/bootvideo.mp4";
const std::string TYPE_VIDEO = "video";
const std::string TYPE_SOUND = "sound";

const std::string HING_STATUS_INFO_PATH = "/sys/class/sensors/hinge_sensor/hinge_status_info";

constexpr const char* BOOT_ANIMATION_STARTED = "bootevent.bootanimation.started";
constexpr const char* BOOT_ANIMATION_READY = "bootevent.bootanimation.ready";
constexpr const char* BOOT_ANIMATION_FINISHED = "bootevent.bootanimation.finished";
constexpr const char* BOOT_COMPLETED = "bootevent.boot.completed";
constexpr const char* BOOT_SOUND = "const.bootanimation.bootsound";
const std::string DEVICE_TYPE_PHONE = "phone";
const std::string DEVICE_TYPE_WEARABLE = "wearable";

const std::string FOLD_SCREEN_TYPE = system::GetParameter("const.window.foldscreen.type", "");

enum class BootStrategyType {
    ASSOCIATIVE,
    COMPATIBLE,
    INDEPENDENT,
};

using MemStruct = struct MemStruct {
public:
    char* memBuffer = nullptr;
    unsigned long bufsize = 0;
    std::shared_ptr<Rosen::Drawing::Data> data_ = nullptr;
    ~MemStruct()
    {
        if (data_ != nullptr) {
            data_ = nullptr;
        } else {
            free(memBuffer);
            memBuffer = nullptr;
        }
    }
    void setOwnerShip(std::shared_ptr<Rosen::Drawing::Data>& data)
    {
        data_ = data;
    }
    void SetBufferSize(unsigned long ibufsize)
    {
        if (ibufsize == 0) {
            LOGE("MemStruct SetBuffer size is invalid!");
            return;
        }
        if (memBuffer == nullptr) {
            bufsize = ibufsize + 1;
            memBuffer = static_cast<char *>(malloc(bufsize + 1));
        }
        if (memBuffer == nullptr) {
            LOGE("MemStruct malloc memBuffer failed!");
        }
    }
};

using ImageStruct = struct ImageStruct {
public:
    std::string fileName = {};
    std::shared_ptr<Rosen::Drawing::Image> imageData = nullptr;
    MemStruct memPtr;
    ~ImageStruct()
    {
        imageData = nullptr;
    }
};
using ImageStructVec = std::vector<std::shared_ptr<ImageStruct>>;

using FrameRateConfig = struct FrameRateConfig {
public:
    int32_t frameRate = 30;
};

using VSyncCallback = std::function<void(void*)>;
struct BootAnimationCallback {
    void *userData;
    VSyncCallback callback;
};

using PlayerParams = struct PlayerParams {
#ifdef PLAYER_FRAMEWORK_ENABLE
    OHOS::sptr<OHOS::Surface> surface;
#endif
    std::shared_ptr<OHOS::Rosen::RSSurface> rsSurface;
    Rosen::ScreenId screenId;
    bool soundEnabled = false;
    BootAnimationCallback* callback;
    std::string resPath;
};

void PostTask(std::function<void()> func, uint32_t delayTime = 0);

bool IsFileExisted(const std::string& filePath);

bool ParseBootConfig(const std::string& path, int32_t& duration, bool& isCompatible,
    bool& isMultiDisplay, std::vector<BootAnimationConfig>& configs);

void ParseNewConfigFile(cJSON* data, bool& isMultiDisplay, std::vector<BootAnimationConfig>& configs);

void ParseOldConfigFile(cJSON* data, std::vector<BootAnimationConfig>& configs);

void ParseVideoExtraPath(cJSON* data, BootAnimationConfig& config);

void ParseBootDuration(cJSON* data, int32_t& duration);

bool ReadZipFile(const std::string& srcFilePath, ImageStructVec& imgVec, FrameRateConfig& frameConfig);

void SortZipFile(ImageStructVec& imgVec);

bool ReadImageFile(const unzFile zipFile, const std::string& fileName, ImageStructVec& imgVec,
    FrameRateConfig& frameConfig, unsigned long fileSize);

bool ParseImageConfig(const char* fileBuffer, int totalsize, FrameRateConfig& frameConfig);

bool CheckImageData(const std::string& fileName, std::shared_ptr<ImageStruct> imageStruct,
    int32_t bufferLen, ImageStructVec& imgVec);

bool CloseZipFile(const unzFile zipFile, bool ret);

int32_t TranslateVp2Pixel(const int32_t sideLen, const int32_t vp);

int32_t TranslateVp2Pixel(const int32_t sideLen, const int32_t vp, const float ratio);

std::string ReadFile(const std::string &filePath);

std::string GetHingeStatus();

int64_t GetSystemCurrentTime();

std::string GetDeviceType();

void ParseProgressConfig(const std::string& path, std::map<int32_t, BootAnimationProgressConfig>& configs);

void ParseProgressData(cJSON* data, std::map<int32_t, BootAnimationProgressConfig>& configs);

cJSON* ParseFileConfig(const std::string& path);
} // namespace OHOS

#endif // FRAMEWORKS_BOOTANIMATION_INCLUDE_UTIL_H
