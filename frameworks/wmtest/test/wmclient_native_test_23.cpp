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

#include "wmclient_native_test_23.h"

#include <cstdio>
#include <fstream>
#include <sstream>

#include <display_type.h>
#include <gslogger.h>
#include <option_parser.h>
#include <raw_maker.h>
#include <securec.h>
#include <window_manager.h>
#include <zlib.h>

#include "inative_test.h"
#include "native_test_class.h"
#include "util.h"

using namespace OHOS;

namespace {
class WMClientNativeTest23 : public INativeTest, public IScreenShotCallback {
public:
    std::string GetDescription() const override
    {
        constexpr const char *desc = "screen capture (--stride=200 (ms) --total-time=3000 (ms))";
        return desc;
    }

    std::string GetDomain() const override
    {
        constexpr const char *domain = "wmclient";
        return domain;
    }

    int32_t GetID() const override
    {
        constexpr int32_t id = 23;
        return id;
    }

    AutoLoadService GetAutoLoadService() const override
    {
        return AutoLoadService::WindowManager;
    }

    void Run(int32_t argc, const char **argv) override
    {
        OptionParser parser;
        parser.AddOption("s", "stride", stride);
        parser.AddOption("t", "total-time", totalTime);
        if (parser.Parse(argc, argv)) {
            GSLOG2SE(ERROR) << parser.GetErrorString();
            ExitTest();
            return;
        }

        GSLOG2SO(INFO) << totalTime;
        PostTask(std::bind(&WindowManager::ListenNextScreenShot, windowManager, 0, this));
    }

    void OnScreenShot(const struct WMImageInfo &info) override
    {
#if 1
        GSLOG2SO(INFO) << "OnScreenShot";
        maker.SetFilename(captureFilepath);
        maker.SetWidth(info.width);
        maker.SetHeight(info.height);
        maker.SetHeaderType(RAW_HEADER_TYPE_COMPRESSED);
        auto ret = maker.WriteNextData(reinterpret_cast<const uint8_t *>(info.data));
        if (ret) {
            GSLOG2SE(ERROR) << "RawMaker WriteNextData failed with " << ret;
        }
#else
        static bool first = true;
        if (first) {
            first = false;
            std::ofstream rawDataFile(captureFilepath, std::ofstream::binary);
            rawDataFile.write("RAW.diff", 0x8);
            WriteInt(rawDataFile, info.width);
            WriteInt(rawDataFile, info.height);
            GSLOG2SO(INFO) << "generate capture at " << captureFilepath;
        }

        std::ofstream rawDataFile(captureFilepath, std::ofstream::binary | std::ofstream::app);
#if 1
        GSLOG2SO(INFO) << "OnScreenShot compressing";
        auto ptr = static_cast<const uint8_t *>(info.data);
        auto compressed = std::make_unique<uint8_t[]>(compressBound(info.size));
        unsigned long ulength = info.size;
        if (Compress(compressed, ulength, ptr, info.size) != Z_OK) {
            ExitTest();
            return;
        }
        GSLOG2SO(INFO) << "OnScreenShot compressed";

        WriteInt(rawDataFile, 0x2); // header_type
        WriteInt(rawDataFile, 0); // offset
        WriteInt(rawDataFile, info.size); // total length
        WriteInt(rawDataFile, ulength); // ulength
        rawDataFile.write(reinterpret_cast<const char *>(compressed.get()), ulength);
#else
        unsigned long ulength = info.size;
        WriteInt(rawDataFile, 1); // header_type
        WriteInt(rawDataFile, 0); // offset
        WriteInt(rawDataFile, info.size); // total length
        WriteInt(rawDataFile, ulength); // ulength
        rawDataFile.write(reinterpret_cast<const char *>(info.data), ulength);
#endif

        // for SIGBUS ADRALN
        if (ulength % 0x4 != 0) {
            for (uint32_t i = 0; i < 0x4 - (ulength % 0x4); i++) {
                const char *nosence = "\0";
                rawDataFile.write(nosence, 1);
            }
        }
#endif

        GSLOG2SO(INFO) << "OnScreenShot writed";
        totalTime -= stride;
        GSLOG2SO(INFO) << totalTime;
        if (totalTime < 0) {
            GSLOG2SO(INFO) << "ScreenCapture Complete";
            ExitTest();
        } else {
            PostTask(std::bind(&WindowManager::ListenNextScreenShot, windowManager, 0, this));
        }
    }

    void WriteInt(std::ofstream &ofs, int32_t integer)
    {
        ofs.write(reinterpret_cast<const char *>(&integer), sizeof(integer));
    }

    int32_t Compress(const std::unique_ptr<uint8_t[]> &c,
        unsigned long &ul, const uint8_t* &p, uint32_t size) const
    {
        auto ret = compress(c.get(), &ul, p, size);
        if (ret) {
            GSLOG2SE(ERROR) << "compress failed with " << ret;
        }

        return ret;
    }

private:
    int32_t totalTime = 3000;
    int32_t stride = 200;
    static constexpr const char *captureFilepath = "/data/screen_capture.raw";
    RawMaker maker;
} g_autoload;
} // namespace
