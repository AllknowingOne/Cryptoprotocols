cmake_minimum_required(VERSION 3.2)
project(TestProject)
add_compile_options(-O0)
add_executable(TestProject
        main.cpp
        LSX.hpp LSX.cpp auxiliary.hpp Streebog.hpp hmac.hpp)
