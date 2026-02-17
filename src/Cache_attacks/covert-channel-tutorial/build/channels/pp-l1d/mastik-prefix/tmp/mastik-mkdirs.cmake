# Distributed under the OSI-approved BSD 3-Clause License.  See accompanying
# file Copyright.txt or https://cmake.org/licensing for details.

cmake_minimum_required(VERSION ${CMAKE_VERSION}) # this file comes with cmake

# If CMAKE_DISABLE_SOURCE_CHANGES is set to true and the source directory is an
# existing directory in our source tree, calling file(MAKE_DIRECTORY) on it
# would cause a fatal error, even though it would be a no-op.
if(NOT EXISTS "/home/simon/Programming/MSc_cs/Speciale/src/Cache_attacks/covert-channel-tutorial/cc-libs/mastik-0.02")
  file(MAKE_DIRECTORY "/home/simon/Programming/MSc_cs/Speciale/src/Cache_attacks/covert-channel-tutorial/cc-libs/mastik-0.02")
endif()
file(MAKE_DIRECTORY
  "/home/simon/Programming/MSc_cs/Speciale/src/Cache_attacks/covert-channel-tutorial/build/channels/pp-l1d/mastik-prefix/src/mastik-build"
  "/home/simon/Programming/MSc_cs/Speciale/src/Cache_attacks/covert-channel-tutorial/build/channels/pp-l1d/mastik-prefix"
  "/home/simon/Programming/MSc_cs/Speciale/src/Cache_attacks/covert-channel-tutorial/build/channels/pp-l1d/mastik-prefix/tmp"
  "/home/simon/Programming/MSc_cs/Speciale/src/Cache_attacks/covert-channel-tutorial/build/channels/pp-l1d/mastik-prefix/src/mastik-stamp"
  "/home/simon/Programming/MSc_cs/Speciale/src/Cache_attacks/covert-channel-tutorial/cc-libs"
  "/home/simon/Programming/MSc_cs/Speciale/src/Cache_attacks/covert-channel-tutorial/build/channels/pp-l1d/mastik-prefix/src/mastik-stamp"
)

set(configSubDirs )
foreach(subDir IN LISTS configSubDirs)
    file(MAKE_DIRECTORY "/home/simon/Programming/MSc_cs/Speciale/src/Cache_attacks/covert-channel-tutorial/build/channels/pp-l1d/mastik-prefix/src/mastik-stamp/${subDir}")
endforeach()
if(cfgdir)
  file(MAKE_DIRECTORY "/home/simon/Programming/MSc_cs/Speciale/src/Cache_attacks/covert-channel-tutorial/build/channels/pp-l1d/mastik-prefix/src/mastik-stamp${cfgdir}") # cfgdir has leading slash
endif()
