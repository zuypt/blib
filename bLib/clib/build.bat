mkdir build32
cmake -G"Visual Studio 16 2019" -A win32 . -B build32
cmake --build build32 --config Release

mkdir build64
cmake -G"Visual Studio 16 2019" -A x64 . -B build64
cmake --build build64 --config Release
