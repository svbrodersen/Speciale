add_executable (pp-l1d-send sender.c)
#target_link_libraries (pp-l1d-send LINK_PUBLIC util)
add_executable (pp-l1d-recv receiver.c)
#target_link_libraries (pp-l1d-recv LINK_PUBLIC util)

ExternalProject_Add(mastik
    URL https://gitlab.com/r0l/mastik/-/archive/v0.03/mastik-v0.03.tar
    DOWNLOAD_DIR ${PROJECT_SOURCE_DIR}/cc-libs
    SOURCE_DIR ${PROJECT_SOURCE_DIR}/cc-libs/mastik-0.02
    BUILD_IN_SOURCE TRUE
    BUILD_COMMAND "make"
    CONFIGURE_COMMAND "./configure"
    INSTALL_COMMAND ""
    BUILD_COMMAND ""
)
ExternalProject_Get_Property(mastik source_dir)
include_directories(${source_dir}/src ${PROJECT_SOURCE_DIR}/cc-libs)
add_dependencies(pp-l1d-send mastik)
add_dependencies(pp-l1d-recv mastik)
target_link_libraries(pp-l1d-send ${source_dir}/src/l1.o)
target_link_libraries(pp-l1d-recv ${source_dir}/src/l1.o)
