CMAKE_MINIMUM_REQUIRED(VERSION 2.8)
INCLUDE(../../cmake/toolchain.cmake)

# include
INCLUDE_DIRECTORIES(./include)

AUX_SOURCE_DIRECTORY(. LIBSOURCE)

ADD_LIBRARY(sonic ${LIBSOURCE})

INSTALL(TARGETS sonic DESTINATION ${INSTALL_PATH}/lib)
INSTALL(FILES sonic.h DESTINATION ${INSTALL_PATH}/include)


