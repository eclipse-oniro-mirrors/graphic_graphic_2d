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

#ifndef RS_PROFILER_UTILS_H
#define RS_PROFILER_UTILS_H

#include <cstdlib>
#include <string>
#include <vector>

#ifdef RENDER_PROFILER_APPLICATION
#include "rs_adapt.h"
#else
#include "common/rs_macros.h"
#endif

namespace OHOS::Rosen {

class RSB_EXPORT Utils final {
public:
    static constexpr float MILLI = 1e-3f; // NOLINT
    static constexpr float MICRO = 1e-6f; // NOLINT
    static constexpr float NANO = 1e-9f;  // NOLINT

public:
    // Time routines
    static uint64_t Now();
    static double ToSeconds(uint64_t nano);
    static uint64_t ToNanoseconds(double seconds);

    // Cpu routines
    static int32_t GetCpuId();
    static void SetCpuAffinity(uint32_t cpu);
    static bool GetCpuAffinity(uint32_t cpu);

    // Process routines
    static pid_t GetPid();

    // String routines
    static std::vector<std::string> Split(const std::string& string);
    static void Replace(const std::string& susbtring, std::string& string);

    static std::string ExtractNumber(const std::string& string);

    static int8_t ToInt8(const std::string& string);
    static int16_t ToInt16(const std::string& string);
    static int32_t ToInt32(const std::string& string);
    static int64_t ToInt64(const std::string& string);
    static uint8_t ToUint8(const std::string& string);
    static uint16_t ToUint16(const std::string& string);
    static uint32_t ToUint32(const std::string& string);
    static uint64_t ToUint64(const std::string& string);
    static float ToFp32(const std::string& string);
    static double ToFp64(const std::string& string);

    static void ToNumber(const std::string& string, int8_t& number);
    static void ToNumber(const std::string& string, int16_t& number);
    static void ToNumber(const std::string& string, int32_t& number);
    static void ToNumber(const std::string& string, int64_t& number);
    static void ToNumber(const std::string& string, uint8_t& number);
    static void ToNumber(const std::string& string, uint16_t& number);
    static void ToNumber(const std::string& string, uint32_t& number);
    static void ToNumber(const std::string& string, uint64_t& number);
    static void ToNumber(const std::string& string, float& number);
    static void ToNumber(const std::string& string, double& number);

    template<typename T>
    static T ToNumber(const std::string& string)
    {
        T number = 0;
        ToNumber(string, number);
        return number;
    }

    // Memory routines
    static bool Move(void* destination, size_t destinationSize, const void* source, size_t size);
    static bool Set(void* data, size_t size, int32_t value, size_t count);

    // File system routines
    static std::string GetRealPath(const std::string& path);
    static std::string MakePath(const std::string& directory, const std::string& file);
    static std::string NormalizePath(const std::string& path);
    static std::string GetFileName(const std::string& path);
    static std::string GetDirectory(const std::string& path);
    static bool IsDirectory(const std::string& path);
    static void IterateDirectory(const std::string& path, std::vector<std::string>& files);
    static void LoadLine(const std::string& path, std::string& line);
    static void LoadLines(const std::string& path, std::vector<std::string>& lines);
    static void LoadContent(const std::string& path, std::string& content);

    static bool FileExists(const std::string& path);
    static bool FileDelete(const std::string& path);
    static FILE* FileOpen(const std::string& path, const std::string& options);
    static void FileClose(FILE* file);
    static bool IsFileValid(FILE* file);
    static size_t FileSize(FILE* file);
    static size_t FileTell(FILE* file);
    static void FileSeek(FILE* file, int64_t offset, int32_t origin);
    static void FileRead(FILE* file, void* data, size_t size);
    static void FileWrite(FILE* file, const void* data, size_t size);

    template<typename T>
    static void FileRead(FILE* file, T* data, size_t size)
    {
        FileRead(file, reinterpret_cast<void*>(data), size);
    }

    template<typename T>
    static void FileWrite(FILE* file, const T* data, size_t size)
    {
        FileWrite(file, reinterpret_cast<const void*>(data), size);
    }

    // deprecated
    static void FileRead(void* data, size_t size, size_t count, FILE* file);
    static void FileWrite(const void* data, size_t size, size_t count, FILE* file);

    template<typename T>
    static void FileRead(T* data, size_t size, size_t count, FILE* file)
    {
        FileRead(reinterpret_cast<void*>(data), size, count, file);
    }

    template<typename T>
    static void FileWrite(const T* data, size_t size, size_t count, FILE* file)
    {
        FileWrite(reinterpret_cast<const void*>(data), size, count, file);
    }
    // end of deprecation

    // NodeId/Pid routines
    static constexpr pid_t ExtractPid(uint64_t id)
    {
        constexpr uint32_t bits = 32u;
        return static_cast<pid_t>(id >> bits);
    }

    static constexpr pid_t GetMockPid(pid_t pid)
    {
        constexpr uint32_t bits = 30u;
        return static_cast<pid_t>((1u << bits) | static_cast<uint32_t>(pid));
    }

    static constexpr uint64_t ExtractNodeId(uint64_t id)
    {
        constexpr uint32_t mask = 0xFFFFFFFF;
        return (id & mask);
    }

    static constexpr uint64_t ComposeNodeId(uint64_t pid, uint64_t nodeId)
    {
        constexpr uint32_t bits = 32u;
        return (pid << bits) | nodeId;
    }

    static constexpr uint64_t ComposeMockNodeId(uint64_t id, uint64_t nodeId)
    {
        return ComposeNodeId(GetMockPid(id), nodeId);
    }

    static uint64_t ComposeDataId(pid_t pid, uint32_t id)
    {
        constexpr uint32_t bits = 31u;
        return ComposeNodeId(static_cast<uint32_t>(pid) | (1u << bits), id);
    }

    static constexpr uint64_t GetRootNodeId(uint64_t id)
    {
        return ComposeNodeId(id, 1);
    }

    static constexpr uint64_t PatchNodeId(uint64_t id)
    {
        constexpr uint32_t bits = 62u;
        return id | (static_cast<uint64_t>(1) << bits);
    }

    static constexpr bool IsNodeIdPatched(uint64_t id)
    {
        constexpr uint32_t bits = 62u;
        return id & (static_cast<uint64_t>(1) << bits);
    }
};

} // namespace OHOS::Rosen

#endif // RS_PROFILER_UTILS_H