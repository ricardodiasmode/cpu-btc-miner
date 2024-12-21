   cmake_minimum_required(VERSION 3.25) 
 
  project(Boost VERSION 1.85.0 LANGUAGES CXX) 
 
  set(BOOST_SUPERPROJECT_VERSION ${PROJECT_VERSION}) 
  set(BOOST_SUPERPROJECT_SOURCE_DIR "${PROJECT_SOURCE_DIR}") 
 
  list(APPEND CMAKE_MODULE_PATH "C:/Users/ricar/source/repos/btc-miner/vcpkg_installed/x64-windows/share/boost/cmake-build") 
 
  include(BoostRoot) 
  