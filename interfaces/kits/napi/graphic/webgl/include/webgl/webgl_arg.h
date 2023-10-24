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

#ifndef WEBGL_ARG_H
#define WEBGL_ARG_H

#include <climits>
#include "securec.h"
#include "napi/n_class.h"
#include "napi/n_func_arg.h"
#include "napi/n_val.h"
#include "util/log.h"
#include "image_source.h"

namespace OHOS {
namespace Rosen {
using BufferDataType = enum {
    BUFFER_DATA_INT_8 = napi_int8_array,
    BUFFER_DATA_UINT_8 = napi_uint8_array,
    BUFFER_DATA_UINT_8_CLAMPED = napi_uint8_clamped_array,
    BUFFER_DATA_INT_16 = napi_int16_array,
    BUFFER_DATA_UINT_16 = napi_uint16_array,
    BUFFER_DATA_INT_32 = napi_int32_array,
    BUFFER_DATA_UINT_32 = napi_uint32_array,
    BUFFER_DATA_FLOAT_32 = napi_float32_array,
    BUFFER_DATA_FLOAT_64 = napi_float64_array,
    BUFFER_DATA_BIGINT_64 = napi_bigint64_array,
    BUFFER_DATA_BIGUINT_64 = napi_biguint64_array,
    BUFFER_DATA_BOOLEAN,
    BUFFER_DATA_GLENUM,
    BUFFER_DATA_INVALID
};

using BufferType = enum {
    BUFFER_DATA_VIEW,
    BUFFER_ARRAY_BUFFER,
    BUFFER_TYPED_ARRAY,
    BUFFER_ARRAY,
};

using WebGLArgType = enum : int {
    ARG_FLOAT,
    ARG_UINT,
    ARG_INT,
    ARG_ENUM,
    ARG_INTPTR,
    ARG_SIZE,
    ARG_BOOL,
    ARG_SIZEPTR,
};

union WebGLArgValue {
    GLboolean glBool;
    GLfloat glFloat;
    GLuint glUint;
    GLint glInt;
    GLenum glEnum;
    GLintptr glIntptr;
    GLsizei glSizei;
    GLsizeiptr glSizeptr;
};

struct WebGLArgInfo {
    WebGLArgType argType;
    uint32_t argIndex;
    const char* argName;
    WebGLArgInfo(uint32_t index, WebGLArgType type, const char* name)
        : argType(type), argIndex(index), argName(name) {}
    ~WebGLArgInfo() {}
};

struct WebGLImageOption {
    GLenum format;
    GLenum type;
    GLsizei width;
    GLsizei height;
    GLsizei depth;

    WebGLImageOption() : format(0), type(0), width(0), height(0) {}
    WebGLImageOption(GLenum format, GLenum type, GLsizei width, GLsizei height)
    {
        this->format = format;
        this->type = type;
        this->width = width;
        this->height = height;
        this->depth = 1;
    }
    WebGLImageOption(GLenum format, GLenum type, GLsizei width, GLsizei height, GLsizei depth)
    {
        this->format = format;
        this->type = type;
        this->width = width;
        this->height = height;
        this->depth = depth;
    }
    void Assign(const WebGLImageOption &opt)
    {
        this->format = opt.format;
        this->type = opt.type;
        this->width = opt.width;
        this->height = opt.height;
        this->depth = opt.depth;
    }
    void Dump();
};

using ImageDecodeFunc = enum {
    DECODE_RGBA_UBYTE,
    DECODE_RGB_UBYTE,
    DECODE_RGBA_USHORT_4444,
    DECODE_RGBA_USHORT_5551,
    DECODE_RGB_USHORT_565,
    DECODE_LUMINANCE_ALPHA_UBYTE,
    DECODE_LUMINANCE_UBYTE,
    DECODE_ALPHA_UBYTE
};

struct WebGLFormatMap {
    GLenum format;
    GLenum type;
    uint8_t channels;
    uint8_t bytesPrePixel;
    uint16_t decodeFunc;
    BufferDataType dataType;
    WebGLFormatMap(GLenum format, GLenum type, uint8_t channels, uint8_t bytesPrePixel, BufferDataType dataType,
        uint16_t decodeFunc)
    {
        this->format = format;
        this->type = type;
        this->channels = channels;
        this->bytesPrePixel = bytesPrePixel;
        this->dataType = dataType;
        this->decodeFunc = decodeFunc;
    }
};

union ColorParam {
#if BIG_ENDIANNESS
    struct {
        uint8_t alpha;
        uint8_t red;
        uint8_t green;
        uint8_t blue;
    } argb;
#else
    struct {
        uint8_t blue;
        uint8_t green;
        uint8_t red;
        uint8_t alpha;
    } argb;
#endif
    uint32_t value;
};

union ColorParam_4_4_4_4 {
#if BIG_ENDIANNESS
    struct {
        uint8_t alpha : 4;
        uint8_t blue : 4;
        uint8_t green : 4;
        uint8_t red : 4;
    } rgba;
#else
    struct {
        uint8_t red : 4;
        uint8_t green : 4;
        uint8_t blue : 4;
        uint8_t alpha : 4;
    } rgba;
#endif
    uint16_t value;
};

union ColorParam_5_5_5_1 {
#if BIG_ENDIANNESS
    struct {
        uint8_t alpha : 1;
        uint8_t blue : 5;
        uint8_t green : 5;
        uint8_t red : 5;
    } rgba;
#else
    struct {
        uint8_t red : 5;
        uint8_t green : 5;
        uint8_t blue : 5;
        uint8_t alpha : 1;
    } rgba;
#endif
    uint16_t value;
};

union ColorParam_5_6_5 {
#if BIG_ENDIANNESS
    struct {
        uint8_t blue : 5;
        uint8_t green : 6;
        uint8_t red : 5;
    } rgb;
#else
    struct {
        uint8_t red : 5;
        uint8_t green : 6;
        uint8_t blue : 5;
    } rgb;
#endif
    uint16_t value;
};

struct TexImageArg {
    int func;
    GLenum target;
    GLint level;
    GLenum internalFormat;
    GLenum format;
    GLenum type;
    GLsizei width;
    GLsizei height;
    GLsizei border;
    GLsizei depth;
    TexImageArg()
        : func(0), target(0), level(0), internalFormat(0),
        format(0), type(0), width(0), height(0), border(0), depth(0) {}
    TexImageArg(const TexImageArg& arg)
    {
        func = arg.func;
        target = arg.target;
        level = arg.level;
        internalFormat = arg.internalFormat;
        format = arg.format;
        type = arg.type;
        width = arg.width;
        height = arg.height;
        border = arg.border;
        depth = arg.depth;
    }
    TexImageArg(
        GLenum target, GLint level, GLenum internalFormat, GLsizei width, GLsizei height, GLsizei depth, GLenum type)
    {
        this->target = target;
        this->level = level;
        this->internalFormat = internalFormat;
        this->type = type;
        this->width = width;
        this->height = height;
        this->depth = depth;
    }
    virtual void Dump(const std::string& info) const;
};

struct TexStorageArg {
    int func;
    GLenum target;
    GLsizei levels;
    GLenum internalFormat;
    GLsizei width;
    GLsizei height;
    GLsizei depth;
    TexStorageArg() : func(0), target(0), levels(0), internalFormat(0), width(0), height(0), depth(0) {}
    TexStorageArg(const TexStorageArg& arg)
    {
        func = arg.func;
        target = arg.target;
        levels = arg.levels;
        internalFormat = arg.internalFormat;
        width = arg.width;
        height = arg.height;
        depth = arg.depth;
    }
    void Dump(const std::string& info) const;
};

struct TexSubImage2DArg : public TexImageArg {
    GLint xOffset;
    GLint yOffset;
    TexSubImage2DArg() : TexImageArg(), xOffset(0), yOffset{0} {}
    TexSubImage2DArg(const TexSubImage2DArg &arg) : TexImageArg(arg)
    {
        xOffset = arg.xOffset;
        yOffset = arg.yOffset;
    }
    void Dump(const std::string& info) const override;
};
} // namespace Rosen
} // namespace OHOS
#endif // WEBGL_ARG_H
