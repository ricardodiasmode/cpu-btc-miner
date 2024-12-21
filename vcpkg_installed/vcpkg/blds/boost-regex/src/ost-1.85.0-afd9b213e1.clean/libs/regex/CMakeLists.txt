# Copyright 2018 Mike Dev
# Copyright 2019 Peter Dimov
# Distributed under the Boost Software License, Version 1.0.
# See accompanying file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt

# We support CMake 3.5, but prefer 3.16 policies and behavior
cmake_minimum_required(VERSION 3.5...3.16)

project(boost_regex VERSION "${BOOST_SUPERPROJECT_VERSION}" LANGUAGES CXX)

set(regex_compat_sources
 "src/posix_api.cpp"
 "src/wide_posix_api.cpp"
 "src/regex.cpp"
 "src/regex_debug.cpp"
 "src/static_mutex.cpp"
)

add_library(boost_regex "${regex_compat_sources}")
add_library(Boost::regex ALIAS boost_regex)

target_include_directories(boost_regex PUBLIC include)

option(BOOST_REGEX_STANDALONE "Boost.Regex: Enable Standalone Mode (i.e. no Boost dependencies)")

if(NOT BOOST_REGEX_STANDALONE)

   target_link_libraries(boost_regex
     PUBLIC
       Boost::config
       Boost::throw_exception
       Boost::predef
       Boost::assert
   )

else()

   target_compile_definitions(boost_regex
     INTERFACE BOOST_REGEX_STANDALONE
   )

endif()

find_package(ICU COMPONENTS data i18n uc QUIET)
option(BOOST_REGEX_ENABLE_ICU "Boost.Regex: enable ICU support" ${ICU_FOUND})

if(BOOST_REGEX_ENABLE_ICU)

   add_library(boost_regex_icu INTERFACE)
   add_library(Boost::regex_icu ALIAS boost_regex_icu)

   target_include_directories(boost_regex_icu INTERFACE include)

   if(NOT BOOST_REGEX_STANDALONE)

      target_link_libraries(boost_regex_icu
        INTERFACE
          Boost::config
          Boost::throw_exception
          Boost::predef
          Boost::assert
      )

   else()

      target_compile_definitions(boost_regex_icu
        INTERFACE BOOST_REGEX_STANDALONE
      )

   endif()

   find_package(ICU COMPONENTS data i18n uc REQUIRED)

   target_link_libraries(boost_regex_icu INTERFACE ICU::data ICU::i18n ICU::uc)

endif()

