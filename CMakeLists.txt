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
    build/ir/REPLLib.o
)

target_include_directories(asm-kernel-cpp  PUBLIC ".")
# target_include_directories(smol  PUBLIC "microui")
# target_include_directories(smol  PUBLIC "tree-sitter/lib/src")
# target_include_directories(smol  PUBLIC "tree-sitter/lib/include")

# link_directories(${CMAKE_SOURCE_DIR}/sdl/lib/x64/)


add_compile_options(-fsanitize=address)
add_compile_options(-fsanitize=undefined)
add_link_options(-fsanitize=address)
add_link_options(-fsanitize=undefined)


link_directories("/home/bollu/work/lean4/build/stage0/lib/lean/")
# target_link_libraries(asm-kernel-cpp zmq)
# target_link_libraries(asm-kernel-cpp ssl)
# target_link_libraries(asm-kernel-cpp crypto)
execute_process (
    COMMAND bash -c "leanc --print-ldflags"
    OUTPUT_VARIABLE LEAN_LD_FLAGS
)
string(STRIP ${LEAN_LD_FLAGS} LEAN_LD_FLAGS)
target_link_libraries(asm-kernel-cpp PUBLIC "-lzmq -lssl -lcrypto" "${LEAN_LD_FLAGS}")

# add_link_options("--start-group -lleancpp -lInit -lStd -lLean --end-group -L/home/bollu/work/lean4/build/stage0/lib/lean/")
# target_link_libraries(asm-kernel-cpp leancpp)
# target_link_libraries(smol opengl32)
# target_link_libraries(smol ${CMAKE_SOURCE_DIR}/sdl/lib/x64/SDL2.lib)
