#pragma once

#include <windows.h>
#include <vector>
#include <string>
#include <thread>
#include <mutex>
#include <unordered_set>

#include <iostream>
#include <filesystem>

#include "Luau/Compiler.h"
#include "Luau/BytecodeBuilder.h"
#include "Luau/BytecodeUtils.h"

#include "ntdll.h"

namespace offsets {
    // Instance
    constexpr std::uintptr_t This = 0x8;
    constexpr std::uintptr_t Name = 0x70;
    constexpr std::uintptr_t Children = 0x78;
    constexpr std::uintptr_t Parent = 0x68;

    constexpr std::uintptr_t ClassDescriptor = 0x18;
    constexpr std::uintptr_t ClassName = 0x8;

    // Scripts
    constexpr std::uintptr_t ModuleScriptEmbedded = 0x138; // Embedded Source : Bytecode Container
    constexpr std::uintptr_t ModuleFlags = 0x148;
    constexpr std::uintptr_t IsCoreScript = 0x0;
    constexpr std::uintptr_t LocalScriptEmbedded = 0x190;

    constexpr std::uintptr_t Bytecode = 0x10;
    constexpr std::uintptr_t BytecodeSize = 0x28;

    // Other
    constexpr std::uintptr_t LocalPlayer = 0x130;
    constexpr std::uintptr_t ObjectValue = 0xb8;
}

template<typename T>
T read_memory(std::uintptr_t address, HANDLE handle);

template <typename T>
bool write_memory(std::uintptr_t address, const T& value, HANDLE handle);

extern std::mutex clientsMtx;

namespace functions { // functions for rbx
    std::vector<std::uintptr_t> GetChildrenAddresses(std::uintptr_t address, HANDLE handle);
    std::string ReadRobloxString(std::uintptr_t address, HANDLE handle);
}

struct ClassDescriptor {
    const std::uintptr_t Self;
    const std::string Name; // ClassName
    const std::uint64_t Capabilities;

    ClassDescriptor(std::uintptr_t& address, HANDLE& handle) :
        Self(read_memory<std::uintptr_t>(address + offsets::ClassDescriptor, handle)),
        Name(functions::ReadRobloxString(read_memory<std::uintptr_t>(Self + offsets::ClassName, handle), handle)),
        Capabilities(read_memory<std::uint64_t>(Self + 0x370, handle))
    {}
};

class Instance {
private:
    public: const std::uintptr_t _Self; private:
    const ClassDescriptor classDescriptor;
    HANDLE handle;
public:
    Instance(std::uintptr_t address, HANDLE handle) :
        handle(handle),
        _Self(address),
        classDescriptor(address, handle)
    {}

    // Instance functions
    std::vector<std::uintptr_t> GetChildrenAddresses() const {
        return functions::GetChildrenAddresses(_Self, handle);
    }
    std::vector<Instance*> GetChildren() const {
        std::vector<std::uintptr_t> childAddresses = GetChildrenAddresses();
        std::vector<Instance*> children;
        for (std::uintptr_t address : childAddresses) {
            children.push_back(new Instance(address, handle));
        }
        return children;
    }

    std::uintptr_t FindFirstChildAddress(const std::string& name) const {
        std::vector<std::uintptr_t> childAddresses = GetChildrenAddresses();
        for (std::uintptr_t address : childAddresses) {
            if (functions::ReadRobloxString(read_memory<std::uintptr_t>(address + offsets::Name, handle), handle) == name)
                return address;
        }
        return 0;
    }
    Instance* FindFirstChild(const std::string& name) const {
        std::uintptr_t childAddress = FindFirstChildAddress(name);
        if (childAddress != 0)
            return new Instance(childAddress, handle);
        return nullptr;
    }

    std::uintptr_t WaitForChildAddress(const std::string& name, int timeout=9e9) const {
        std::uintptr_t existing = FindFirstChildAddress(name);
        if (existing != 0)
            return existing;
        std::chrono::steady_clock::time_point start_time = std::chrono::steady_clock::now();
        while (std::chrono::steady_clock::now() - start_time <= std::chrono::seconds(timeout))
        {
            if (FindFirstChildAddress(name))
                return FindFirstChildAddress(name);
            Sleep(100);
        }
        return 0;
    }
    Instance* WaitForChild(const std::string& name, int timeout=9e9) const { // timeout: seconds
        std::uintptr_t childAddress = WaitForChildAddress(name, timeout);
        if (childAddress != 0)
            return new Instance(childAddress, handle);
        return nullptr;
    }

    std::uintptr_t FindFirstChildOfClassAddress(const std::string& className) const {
        std::vector<std::uintptr_t> childAddresses = GetChildrenAddresses();
        for (std::uintptr_t address : childAddresses) {
            if (functions::ReadRobloxString(read_memory<std::uintptr_t>(read_memory<std::uintptr_t>(address + offsets::ClassDescriptor, handle) + offsets::ClassName, handle), handle) == className)
                return address;
        }
        return 0;
    }
    Instance* FindFirstChildOfClass(const std::string& className) const {
        std::uintptr_t childAddress = FindFirstChildOfClassAddress(className);
        if (childAddress != 0)
            return new Instance(childAddress, handle);
        return nullptr;
    }

    // Miscellaneous
    bool SetBytecode(const std::string& compressedBytecode, bool revertBytecode=false) const {
        if (ClassName() != "LocalScript" && ClassName() != "ModuleScript")
            return false;

        std::uintptr_t embeddedSourceOffset = (ClassName() == "LocalScript") ? offsets::LocalScriptEmbedded : offsets::ModuleScriptEmbedded;
        std::uintptr_t embeddedPtr = read_memory<std::uintptr_t>(_Self + embeddedSourceOffset, handle);

        if (revertBytecode) {
            std::uintptr_t originalBytecodePtr = read_memory<std::uintptr_t>(embeddedPtr + offsets::Bytecode, handle);
            std::uint64_t originalSize = read_memory<std::uint64_t>(embeddedPtr + offsets::BytecodeSize, handle);

            std::thread([embeddedPtr, originalBytecodePtr, originalSize, handle = this->handle]() {
                Sleep(850);
                write_memory<std::uintptr_t>(embeddedPtr + offsets::Bytecode, originalBytecodePtr, handle);
                write_memory<std::uint64_t>(embeddedPtr + offsets::BytecodeSize, originalSize, handle);
            }).detach();
        }

        LPVOID allocatedAddress = VirtualAllocEx(handle, nullptr, compressedBytecode.size(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (allocatedAddress == 0)
            return false;

        DWORD oldProtection;
        DWORD d;

        VirtualProtectEx(handle, allocatedAddress, compressedBytecode.size(), PAGE_READWRITE, &oldProtection);
        NtWriteVirtualMemory(handle, allocatedAddress, (PVOID)compressedBytecode.c_str(), (ULONG)compressedBytecode.size(), nullptr);

        return VirtualProtectEx(handle, allocatedAddress, compressedBytecode.size(), oldProtection, &d)
            && write_memory<std::uintptr_t>(embeddedPtr + offsets::Bytecode, reinterpret_cast<std::uintptr_t>(allocatedAddress), handle)
            && write_memory<std::uint64_t>(embeddedPtr + offsets::BytecodeSize, compressedBytecode.size(), handle);
    }
    std::string GetBytecode() const;

    void UnlockModule() const {
        if (ClassName() == "ModuleScript") {
            write_memory<std::uintptr_t>(Self() + offsets::ModuleFlags, 0x100000000, handle);
        }
    }

    // Variables
    inline std::uintptr_t Self() const {
        return _Self;
    }
    inline std::string Name() const {
        std::uintptr_t namePtr = read_memory<std::uintptr_t>(_Self + offsets::Name, handle);
        if (namePtr == 0 || namePtr < 0x10000) return "";
        return functions::ReadRobloxString(namePtr, handle);
    }
    inline std::uintptr_t Parent() const {
        return read_memory<std::uintptr_t>(_Self + offsets::Parent, handle);
    }
    inline std::string ClassName() const {
        return classDescriptor.Name;
    }
};

class RBXClient {
private:
    HANDLE handle;
    std::uintptr_t RenderView{};
public:
    std::string Username = "N/A";
    std::string GUID = "";
    DWORD PID;

    std::string TeleportQueue; // for queue_on_teleport

    RBXClient(DWORD processID);

    bool isProcessAlive() const {
        DWORD exitCode;
        if (GetExitCodeProcess(handle, &exitCode)) {
            return exitCode == STILL_ACTIVE;
        }
        return false;
    }

    inline std::uintptr_t FetchDataModel() const;

    void execute(const std::string& source) const;
    bool loadstring(const std::string& source, std::string& script_name, std::string& chunk_name) const;

    void UnlockModule(const std::string& script_name) const;
    std::string GetBytecode(const std::string& objectval_name) const;
    std::uintptr_t GetObjectValuePtr(const std::string& objectval_name) const;
    void SpoofInstance(const std::string& objectval_name, std::uintptr_t new_address) const;
};

struct SimpleClient {
    const char* Username;
    int ProcessID;
};

class bytecode_encoder_t : public Luau::BytecodeEncoder {
    uint8_t encodeOp(uint8_t op) override {
        return op * 227;
    }
    void encode(uint32_t* data, size_t count) override {
        for (auto i = 0u; i < count;) {
            auto& opcode = *reinterpret_cast<uint8_t*>(data + i);
            i += Luau::getOpLength(LuauOpcode(opcode));
            opcode *= 227;
        }
    }
};

std::vector<DWORD> GetRobloxClients();
std::uintptr_t GetRV(HANDLE handle);

std::string compilable(const std::string& source);
std::string Compile(const std::string& source);
std::string decompress(const std::string& compressed);

HWND GetHWNDFromPID(DWORD process_id);