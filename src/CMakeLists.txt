set(headers
	"${pineapple_SOURCE_DIR}/include/pineapple/pineapple.h"
	"${pineapple_SOURCE_DIR}/include/pineapple/common/utils.h"
	"${pineapple_SOURCE_DIR}/include/pineapple/arch/x86/decoder.h"
	"${pineapple_SOURCE_DIR}/include/pineapple/arch/x86/mnemonic.h"
	"${pineapple_SOURCE_DIR}/include/pineapple/arch/x86/prefix.h"
	"${pineapple_SOURCE_DIR}/include/pineapple/arch/x86/printer.h"
	"${pineapple_SOURCE_DIR}/include/pineapple/arch/x86/register.h"
	"${pineapple_SOURCE_DIR}/include/pineapple/arch/x86/x86.h")

add_library(pineapple
			${headers}
			"pineapple.c"
			"common/utils.c"
			"arch/x86/decoder.c"
			"arch/x86/intel_printer.c"
			)

target_include_directories(pineapple PUBLIC
                       $<BUILD_INTERFACE:${pineapple_SOURCE_DIR}/include>
                       $<INSTALL_INTERFACE:${pineapple_INC_INSTALL_DIR}>
					   )

set(generated_dir "${CMAKE_CURRENT_BINARY_DIR}/generated")

set(project_config "${generated_dir}/${PROJECT_NAME}Config.cmake")
set(version_config "${generated_dir}/${PROJECT_NAME}ConfigVersion.cmake")
set(targets_export_name "${PROJECT_NAME}Targets")

include(CMakePackageConfigHelpers)
configure_package_config_file(
	"${pineapple_SOURCE_DIR}/cmake/${PROJECT_NAME}Config.cmake.in"
	"${project_config}"
	INSTALL_DESTINATION ${PINEAPPLE_CMAKE_CONFIG_INSTALL_DIR})
write_basic_package_version_file("${version_config}" COMPATIBILITY SameMajorVersion)

if (pineapple_ENABLE_INSTALL)
	install(TARGETS pineapple
			EXPORT ${targets_export_name}
			ARCHIVE DESTINATION ${PINEAPPLE_CMAKE_CONFIG_INSTALL_DIR}
			LIBRARY DESTINATION ${PINEAPPLE_CMAKE_CONFIG_INSTALL_DIR}
			RUNTIME DESTINATION ${PINEAPPLE_CMAKE_CONFIG_INSTALL_DIR}
			FRAMEWORK DESTINATION ${PINEAPPLE_CMAKE_CONFIG_INSTALL_DIR})

	install(
		DIRECTORY "${pineapple_SOURCE_DIR}/include/pineapple"
		DESTINATION ${PINEAPPLE_CMAKE_CONFIG_INSTALL_DIR}
		FILES_MATCHING PATTERN "*.h")

	install(
      FILES "${project_config}" "${version_config}"
      DESTINATION "${PINEAPPLE_CMAKE_CONFIG_INSTALL_DIR}")

	install(
		EXPORT ${targets_export_name}
		DESTINATION ${PINEAPPLE_CMAKE_CONFIG_INSTALL_DIR})
endif()
