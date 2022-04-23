# CMakeList.txt : CMake project for smol, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)
set (CMAKE_CXX_STANDARD 20)

project ("asm-kernel-cpp")
# find_package(SDL2)
# Add source to this project's executable.
add_executable (asm-kernel-cpp
	"asm-kernel.cpp"
)

target_include_directories(asm-kernel-cpp  PUBLIC ".")
# target_include_directories(smol  PUBLIC "microui")
# target_include_directories(smol  PUBLIC "tree-sitter/lib/src")
# target_include_directories(smol  PUBLIC "tree-sitter/lib/include")

# link_directories(${CMAKE_SOURCE_DIR}/sdl/lib/x64/)

target_link_libraries(asm-kernel-cpp zmq)
target_link_libraries(asm-kernel-cpp ssl)
target_link_libraries(asm-kernel-cpp crypto)
# target_link_libraries(smol opengl32)
# target_link_libraries(smol ${CMAKE_SOURCE_DIR}/sdl/lib/x64/SDL2.lib)
