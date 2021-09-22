cmake_minimum_required(VERSION 3.12.0)

project(pineapple
	VERSION 1.0.0
	DESCRIPTION "X86 Dissassembler framework")

option(PINEAPPLE_ENABLE_TESTING "Enable testing of the pineapple library." ON)
option(PINEAPPLE_ENABLE_INSTALL "Enable installation of pineapple. (Projects embedding benchmark may want to turn this OFF.)" ON)

list(APPEND CMAKE_MODULE_PATH "${PINEAPPLE_SOURCE_DIR}/cmake")

if(${CMAKE_SYSTEM_NAME} MATCHES "Windows")
	set(PINEAPPLE_INC_INSTALL_DIR "include")
	set(PINEAPPLE_RUNTIME_INSTALL_DIR "bin")
	set(PINEAPPLE_LIBRARY_INSTALL_DIR "lib")
	set(PINEAPPLE_ARCHIVE_INSTALL_DIR "lib")
	set(PINEAPPLE_FRAMEWORK_INSTALL_DIR "lib")
	set(PINEAPPLE_CMAKE_CONFIG_INSTALL_DIR "lib/pineapple/cmake")
	set(PINEAPPLE_ADDITIONAL_FILES_INSTALL_DIR "lib/pineapple")
	set(CMAKE_WINDOWS_EXPORT_ALL_SYMBOLS ON)
elseif(${CMAKE_SYSTEM_NAME} MATCHES "Linux" OR ${CMAKE_SYSTEM_NAME} MATCHES "Darwin")
	include(GNUInstallDirs)
	set(PINEAPPLE_INC_INSTALL_DIR "${CMAKE_INSTALL_INCLUDEDIR}")
	set(PINEAPPLE_RUNTIME_INSTALL_DIR "${CMAKE_INSTALL_BINDIR}")
	set(PINEAPPLE_LIBRARY_INSTALL_DIR "${CMAKE_INSTALL_LIBDIR}")
	set(PINEAPPLE_ARCHIVE_INSTALL_DIR "${CMAKE_INSTALL_LIBDIR}")
	set(PINEAPPLE_FRAMEWORK_INSTALL_DIR "${CMAKE_INSTALL_LIBDIR}")
	set(PINEAPPLE_CMAKE_CONFIG_INSTALL_DIR "${CMAKE_INSTALL_LIBDIR}/pineapple/cmake")
	set(PINEAPPLE_ADDITIONAL_FILES_INSTALL_DIR "${CMAKE_INSTALL_DATADIR}/pineapple")
else()
	message(FATAL_ERROR "Could not set install folders for this platform!")
endif()

if(CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
	set_property(GLOBAL PROPERTY USE_FOLDERS ON)

	find_package(Doxygen)
	if(Doxygen_FOUND)
		add_subdirectory(docs)
	else()
		message(STATUS "Doxygen not found, not building docs")
	endif()
endif()

include(FetchContent)
if(${CMAKE_VERSION} VERSION_LESS 3.14)
	include(add_FetchContent_MakeAvailable)
endif()

add_subdirectory(src)

if((CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME) AND PINEAPPLE_ENABLE_TESTING)
	enable_testing()
	add_subdirectory(test)
endif()
