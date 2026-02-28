cmake_minimum_required(VERSION 3.18)
project("anti_segv" LANGUAGES C)

add_library(anti_segv SHARED anti_segv.c)
target_link_libraries(anti_segv log)
