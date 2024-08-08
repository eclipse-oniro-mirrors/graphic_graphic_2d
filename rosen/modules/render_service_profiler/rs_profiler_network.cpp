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

#include "rs_profiler_network.h"

#include <fstream>
#include <memory>
#include <thread>

#include "rs_profiler_archive.h"
#include "rs_profiler_cache.h"
#include "rs_profiler_capturedata.h"
#include "rs_profiler_file.h"
#include "rs_profiler_packet.h"
#include "rs_profiler_socket.h"
#include "rs_profiler_utils.h"

#include "pipeline/rs_main_thread.h"

namespace OHOS::Rosen {

bool Network::isRunning_ = false;
std::atomic<bool> Network::forceShutdown_ = false;

std::mutex Network::incomingMutex_ {};
std::queue<std::vector<std::string>> Network::incoming_ {};

std::mutex Network::outgoingMutex_ {};
std::queue<std::vector<char>> Network::outgoing_ {};

static void AwakeRenderServiceThread()
{
    RSMainThread::Instance()->SetAccessibilityConfigChanged();
    RSMainThread::Instance()->RequestNextVSync();
    RSMainThread::Instance()->PostTask([]() {
        RSMainThread::Instance()->SetAccessibilityConfigChanged();
        RSMainThread::Instance()->RequestNextVSync();
    });
}

static uint32_t OnBinaryPrepare(RSFile& file, const char* data, size_t size)
{
    file.SetVersion(RSFILE_VERSION_LATEST);
    file.Create(RSFile::GetDefaultPath());
    return BinaryHelper::BinaryCount(data);
}

static void OnBinaryHeader(RSFile& file, const char* data, size_t size)
{
    if (!file.IsOpen()) {
        return;
    }

    std::stringstream stream(std::ios::in | std::ios::out | std::ios::binary);
    stream.write(reinterpret_cast<const char*>(data + 1), size - 1);
    stream.seekg(0);

    double writeStartTime = 0.0;
    stream.read(reinterpret_cast<char*>(&writeStartTime), sizeof(writeStartTime));
    file.SetWriteTime(writeStartTime);

    uint32_t pidCount = 0u;
    stream.read(reinterpret_cast<char*>(&pidCount), sizeof(pidCount));
    for (uint32_t i = 0; i < pidCount; i++) {
        pid_t pid = 0u;
        stream.read(reinterpret_cast<char*>(&pid), sizeof(pid));
        file.AddHeaderPid(pid);
    }
    file.AddLayer();

    std::string dataFirstFrame;
    size_t sizeDataFirstFrame = 0;
    stream.read(reinterpret_cast<char*>(&sizeDataFirstFrame), sizeof(sizeDataFirstFrame));
    dataFirstFrame.resize(sizeDataFirstFrame);
    stream.read(reinterpret_cast<char*>(&dataFirstFrame[0]), sizeDataFirstFrame);
    file.AddHeaderFirstFrame(dataFirstFrame);

    ImageCache::Deserialize(stream);
}

static void OnBinaryChunk(RSFile& file, const char* data, size_t size)
{
    constexpr size_t timeOffset = 8 + 1;
    if (file.IsOpen() && (size >= timeOffset)) {
        const double time = *(reinterpret_cast<const double*>(data + 1));
        file.WriteRSData(time, const_cast<char*>(data) + timeOffset, size - timeOffset);
    }
}

static void OnBinaryFinish(RSFile& file, const char* data, size_t size)
{
    file.Close();
}

void Network::Run()
{
    const uint16_t port = 5050;
    const uint32_t sleepTimeout = 500000u;

    Socket* socket = nullptr;

    isRunning_ = true;
    forceShutdown_ = false;

    while (isRunning_) {
        if (!socket) {
            socket = new Socket();
        }

        const SocketState state = socket->GetState();
        if (forceShutdown_) {
            Shutdown(socket);
            forceShutdown_ = false;
        } else if (state == SocketState::INITIAL) {
            socket->Open(port);
        } else if (state == SocketState::CREATE) {
            socket->AcceptClient();
            usleep(sleepTimeout);
        } else if (state == SocketState::ACCEPT) {
            bool readyToReceive = false;
            bool readyToSend = false;
            socket->GetStatus(readyToReceive, readyToSend);

            if (readyToReceive) {
                ProcessIncoming(*socket);
            }
            if (readyToSend) {
                ProcessOutgoing(*socket);
            }
        } else if (state == SocketState::SHUTDOWN) {
            Shutdown(socket);
        }
    }

    delete socket;
}

void Network::Stop()
{
    isRunning_ = false;
}

std::vector<NetworkStats> Network::GetStats(const std::string& interface)
{
    static const uint32_t INTERFACE_COLUMN = 0u;
    static const uint32_t RECV_BYTES_COLUMN = 1u;
    static const uint32_t SENT_BYTES_COLUMN = 9u;

    std::ifstream netdev("/proc/net/dev");
    if (!netdev.good()) {
        return {};
    }

    std::vector<NetworkStats> results;

    std::string data;
    // skip the first two lines (headers)
    std::getline(netdev, data);
    std::getline(netdev, data);

    while (netdev.good()) {
        std::getline(netdev, data);
        std::vector<std::string> parts = Utils::Split(data);
        if (parts.empty()) {
            continue;
        }

        std::string candidate = parts[INTERFACE_COLUMN];
        // remove the trailing ':' so we can compare against the provided interface
        candidate.pop_back();

        if (("*" == interface) || (candidate == interface)) {
            const uint64_t recvBytes = std::stoull(parts[RECV_BYTES_COLUMN]);
            const uint64_t sentBytes = std::stoull(parts[SENT_BYTES_COLUMN]);

            results.push_back({ .interface = candidate, .receivedBytes = recvBytes, .transmittedBytes = sentBytes });
        }
    };

    return results;
}

void Network::SendPacket(const Packet& packet)
{
    if (isRunning_) {
        const std::lock_guard<std::mutex> guard(outgoingMutex_);
        outgoing_.emplace(const_cast<Packet&>(packet).Release());
    }
}

void Network::SendPath(const std::string& path, PackageID id)
{
    if (!path.empty()) {
        std::string out;
        out += static_cast<char>(id);
        out += path;
        SendBinary(out);
    }
}

void Network::SendRdcPath(const std::string& path)
{
    SendPath(path, PackageID::RS_PROFILER_RDC_BINARY);
}

void Network::SendDclPath(const std::string& path)
{
    SendPath(path, PackageID::RS_PROFILER_DCL_BINARY);
}

void Network::SendMskpPath(const std::string& path)
{
    SendPath(path, PackageID::RS_PROFILER_MSKP_FILEPATH);
}

void Network::SendBetaRecordPath(const std::string& path)
{
    SendPath(path, PackageID::RS_PROFILER_BETAREC_FILEPATH);
}

void Network::SendSkp(const void* data, size_t size)
{
    if (data && (size > 0)) {
        std::vector<char> buffer;
        buffer.reserve(size + 1);
        buffer.push_back(static_cast<char>(PackageID::RS_PROFILER_SKP_BINARY));
        buffer.insert(buffer.end(), static_cast<const char*>(data), static_cast<const char*>(data) + size);
        SendBinary(buffer);
    }
}

void Network::SendCaptureData(const RSCaptureData& data)
{
    std::vector<char> out;
    DataWriter archive(out);
    char headerType = static_cast<char>(PackageID::RS_PROFILER_GFX_METRICS);
    archive.Serialize(headerType);

    const_cast<RSCaptureData&>(data).Serialize(archive);

    // if no data is serialized, we end up with just 1 char header
    if (out.size() > 1) {
        SendBinary(out);
    }
}

void Network::SendRSTreeDumpJSON(const std::string& jsonstr)
{
    Packet packet { Packet::BINARY };
    packet.Write(static_cast<char>(PackageID::RS_PROFILER_RSTREE_DUMP_JSON));
    packet.Write(jsonstr);
    SendPacket(packet);
}

void Network::SendRSTreePerfNodeList(const std::unordered_set<uint64_t>& perfNodesList)
{
    Packet packet { Packet::BINARY };
    packet.Write(static_cast<char>(PackageID::RS_PROFILER_RSTREE_PERF_NODE_LIST));
    packet.Write(perfNodesList);
    SendPacket(packet);
}

void Network::SendRSTreeSingleNodePerf(uint64_t id, uint64_t nanosec)
{
    Packet packet { Packet::BINARY };
    packet.Write(static_cast<char>(PackageID::RS_PROFILER_RSTREE_SINGLE_NODE_PERF));
    packet.Write(id);
    packet.Write(nanosec);
    SendPacket(packet);
}

void Network::SendBinary(const void* data, size_t size)
{
    if (data && (size > 0)) {
        Packet packet { Packet::BINARY };
        packet.Write(data, size);
        SendPacket(packet);
    }
}

void Network::SendBinary(const std::vector<char>& data)
{
    SendBinary(data.data(), data.size());
}

void Network::SendBinary(const std::string& data)
{
    SendBinary(data.data(), data.size());
}

void Network::SendMessage(const std::string& message)
{
    if (!message.empty()) {
        Packet packet { Packet::LOG };
        packet.Write(message);
        SendPacket(packet);
    }
}

void Network::PushCommand(const std::vector<std::string>& args)
{
    if (!args.empty()) {
        const std::lock_guard<std::mutex> guard(incomingMutex_);
        incoming_.emplace(args);
    }
}

bool Network::PopCommand(std::vector<std::string>& args)
{
    args.clear();

    incomingMutex_.lock();
    if (!incoming_.empty()) {
        args.swap(incoming_.front());
        incoming_.pop();
    }
    incomingMutex_.unlock();

    return !args.empty();
}

void Network::ProcessCommand(const char* data, size_t size)
{
    const std::vector<std::string> args = Utils::Split({ data, size });
    if (args.empty()) {
        return;
    }

    PushCommand(args);
    AwakeRenderServiceThread();
}

void Network::ProcessOutgoing(Socket& socket)
{
    std::vector<char> data;

    bool nothingToSend = false;
    while (!nothingToSend) {
        outgoingMutex_.lock();
        nothingToSend = outgoing_.empty();
        if (!nothingToSend) {
            data.swap(outgoing_.front());
            outgoing_.pop();
        }
        outgoingMutex_.unlock();

        if (!nothingToSend) {
            socket.SendWhenReady(data.data(), data.size());
        }
    }
}

void Network::ProcessBinary(const char* data, size_t size)
{
    static uint32_t chunks = 0u;
    static RSFile file;

    const PackageID id = BinaryHelper::Type(data);
    if (id == PackageID::RS_PROFILER_PREPARE) {
        // ping/pong for connection speed measurement
        const char type = static_cast<char>(PackageID::RS_PROFILER_PREPARE);
        SendBinary(&type, sizeof(type));
        // amount of binary packages will be sent
        chunks = OnBinaryPrepare(file, data, size);
    } else if (id == PackageID::RS_PROFILER_HEADER) {
        OnBinaryHeader(file, data, size);
    } else if (id == PackageID::RS_PROFILER_BINARY) {
        OnBinaryChunk(file, data, size);

        chunks--;
        if (chunks == 0) {
            OnBinaryFinish(file, data, size);
            const char type = static_cast<char>(PackageID::RS_PROFILER_PREPARE_DONE);
            SendBinary(&type, sizeof(type));
        }
    }
}

void Network::ForceShutdown()
{
    forceShutdown_ = true;
}

void Network::Shutdown(Socket*& socket)
{
    delete socket;
    socket = nullptr;

    std::string command = "rsrecord_stop";
    ProcessCommand(command.c_str(), command.size());
    command = "rsrecord_replay_stop";
    ProcessCommand(command.c_str(), command.size());
    AwakeRenderServiceThread();
}

void Network::ProcessIncoming(Socket& socket)
{
    const uint32_t sleepTimeout = 500000u;

    Packet packetIncoming { Packet::UNKNOWN };
    auto wannaReceive = Packet::HEADER_SIZE;
    socket.Receive(packetIncoming.Begin(), wannaReceive);

    if (wannaReceive == 0) {
        socket.SetState(SocketState::SHUTDOWN);
        usleep(sleepTimeout);
        return;
    }

    const size_t size = packetIncoming.GetPayloadLength();
    if (size == 0) {
        return;
    }

    std::vector<char> data;
    data.resize(size);
    socket.ReceiveWhenReady(data.data(), data.size());

    if (packetIncoming.IsBinary()) {
        ProcessBinary(data.data(), data.size());
    } else if (packetIncoming.IsCommand()) {
        ProcessCommand(data.data(), data.size());
    }
}

void Network::ReportStats()
{
    constexpr uint32_t bytesToBits = 8u;
    const std::string interface("wlan0");
    const std::vector<NetworkStats> stats = Network::GetStats(interface);

    std::string out = "Interface: " + interface;
    for (const NetworkStats& stat : stats) {
        out += "Transmitted: " + std::to_string(stat.transmittedBytes * bytesToBits);
        out += "Received: " + std::to_string(stat.transmittedBytes * bytesToBits);
    }

    SendMessage(out);
}

} // namespace OHOS::Rosen