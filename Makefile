CXX = x86_64-w64-mingw32-g++
# OR on Windows with MSVC: cl.exe
CFLAGS = -std=c++17 -O2 -DNDEBUG -I. -ILuau/include
LDFLAGS = -static -s

LUAU_SRC = $(wildcard Luau/src/*.cpp)
LUAU_OBJ = $(LUAU_SRC:.cpp=.o)

all: xeno.exe esp_aimbot.exe aimbot.exe money_hack.exe dumper.exe

# Xeno Executor
xeno.exe: main.o worker.o ntdll.o $(LUAU_OBJ)
	$(CXX) $(LDFLAGS) -o $@ $^ -lxxhash -lzstd -lpsapi -ladvapi32 -lole32 -loleaut32 -luuid

# ESP + Aimbot
esp_aimbot.exe: esp_aimbot.cpp
	$(CXX) $(CFLAGS) $(LDFLAGS) -mwindows -o $@ $< -lgdi32 -ldwmapi -lpsapi -ladvapi32

# Aimbot only
aimbot.exe: aimbot.cpp
	$(CXX) $(CFLAGS) $(LDFLAGS) -o $@ $< -lgdi32 -lpsapi -ladvapi32

# Money hack
money_hack.exe: money_hack.cpp
	$(CXX) $(CFLAGS) $(LDFLAGS) -o $@ $< -lpsapi -ladvapi32

# Offset dumper
dumper.exe: dumper.cpp
	$(CXX) $(CFLAGS) $(LDFLAGS) -o $@ $< -lpsapi -ladvapi32

%.o: %.cpp
	$(CXX) $(CFLAGS) -c $< -o $@

clean:
	del /Q *.o *.exe Luau\src\*.o 2>nul || rm -f *.o *.exe Luau/src/*.o

.PHONY: all clean
