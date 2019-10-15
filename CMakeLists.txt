#
# file: CMakeLists.txt
#
# This is the main CMakeLists.txt for azure-iot-sdk-c integration with distortos
#
# author: Copyright (C) 2019 Kamil Szczygiel http://www.distortec.com http://www.freddiechopin.info
#
# This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of the MPL was not
# distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
#

cmake_minimum_required(VERSION 3.8)
project(azure-iot-sdk-c-integration)

cmake_policy(SET CMP0079 NEW)

if(NOT DEFINED AZURE_IOT_SDK_C_DIRECTORY)
	message(SEND_ERROR "Variable with path to azure-iot-sdk-c directory - AZURE_IOT_SDK_C_DIRECTORY - is not defined")
endif()
if(NOT IS_DIRECTORY "${AZURE_IOT_SDK_C_DIRECTORY}")
	message(SEND_ERROR "Path to azure-iot-sdk-c directory - AZURE_IOT_SDK_C_DIRECTORY = ${AZURE_IOT_SDK_C_DIRECTORY} - "
			"is not valid")
endif()
if(NOT EXISTS "${AZURE_IOT_SDK_C_DIRECTORY}/CMakeLists.txt")
	message(SEND_ERROR "Path to azure-iot-sdk-c directory - AZURE_IOT_SDK_C_DIRECTORY = ${AZURE_IOT_SDK_C_DIRECTORY} - "
			"does not contain CMakeLists.txt")
endif()

set(AZURE_CUSTOM_PLATFORM TRUE)
add_subdirectory("${AZURE_IOT_SDK_C_DIRECTORY}" azure-iot-sdk-c EXCLUDE_FROM_ALL)

add_library(azure-iot-sdk-c-object-library OBJECT
		${CMAKE_CURRENT_LIST_DIR}/platform.cpp)
target_include_directories(azure-iot-sdk-c-object-library PRIVATE
		$<TARGET_PROPERTY:aziotsharedutil,INTERFACE_INCLUDE_DIRECTORIES>)
target_compile_definitions(azure-iot-sdk-c-object-library PRIVATE
		$<TARGET_PROPERTY:aziotsharedutil,INTERFACE_COMPILE_DEFINITIONS>)

target_compile_definitions(aziotsharedutil PRIVATE
		send=lwip_send
		recv=lwip_recv)
target_compile_options(aziotsharedutil PRIVATE
		-Wno-type-limits)
target_include_directories(aziotsharedutil INTERFACE
		${AZURE_IOT_SDK_C_DIRECTORY}/certs
		${AZURE_IOT_SDK_C_DIRECTORY}/deps/azure-macro-utils-c/inc
		${AZURE_IOT_SDK_C_DIRECTORY}/deps/umock-c/inc)
target_link_libraries(aziotsharedutil
		lwIP::core)
target_sources(aziotsharedutil PRIVATE
		${AZURE_IOT_SDK_C_DIRECTORY}/certs/certs.c
		$<TARGET_OBJECTS:azure-iot-sdk-c-object-library>)

target_compile_options(iothub_client PRIVATE
		-Wno-type-limits)
target_include_directories(iothub_client INTERFACE
		${AZURE_IOT_SDK_C_DIRECTORY}/iothub_client/inc)

target_compile_options(iothub_client_mqtt_transport PRIVATE
		-Wno-maybe-uninitialized
		-Wno-type-limits)

target_compile_options(iothub_client_mqtt_ws_transport PRIVATE
		-Wno-maybe-uninitialized
		-Wno-type-limits)

target_include_directories(prov_device_ll_client INTERFACE
		${AZURE_IOT_SDK_C_DIRECTORY}/provisioning_client/inc)

target_compile_options(umqtt PRIVATE
		-Wno-sign-compare
		-Wno-type-limits)

distortosAppendToSavedConfiguration(build_as_dynamic)
distortosAppendToSavedConfiguration(build_provisioning_service_client)
distortosAppendToSavedConfiguration(build_python)
distortosAppendToSavedConfiguration(build_service_client)
distortosAppendToSavedConfiguration(compileOption_C)
distortosAppendToSavedConfiguration(compileOption_CXX)
distortosAppendToSavedConfiguration(dont_use_uploadtoblob)
distortosAppendToSavedConfiguration(enable_raw_logging)
distortosAppendToSavedConfiguration(hsm_custom_lib)
distortosAppendToSavedConfiguration(hsm_type_custom)
distortosAppendToSavedConfiguration(hsm_type_sastoken)
distortosAppendToSavedConfiguration(hsm_type_symm_key)
distortosAppendToSavedConfiguration(hsm_type_x509)
distortosAppendToSavedConfiguration(linkerOption)
distortosAppendToSavedConfiguration(memory_trace)
distortosAppendToSavedConfiguration(no_logging)
distortosAppendToSavedConfiguration(nuget_e2e_tests)
distortosAppendToSavedConfiguration(OPENSSL_ROOT_DIR)
distortosAppendToSavedConfiguration(run_e2e_tests)
distortosAppendToSavedConfiguration(run_int_tests)
distortosAppendToSavedConfiguration(run_longhaul_tests)
distortosAppendToSavedConfiguration(run_sfc_tests)
distortosAppendToSavedConfiguration(run_unittests)
distortosAppendToSavedConfiguration(run_valgrind)
distortosAppendToSavedConfiguration(skip_samples)
distortosAppendToSavedConfiguration(suppress_header_searches)
distortosAppendToSavedConfiguration(use_amqp)
distortosAppendToSavedConfiguration(use_builtin_httpapi)
distortosAppendToSavedConfiguration(use_condition)
distortosAppendToSavedConfiguration(use_cppunittest)
distortosAppendToSavedConfiguration(use_custom_heap)
distortosAppendToSavedConfiguration(use_default_uuid)
distortosAppendToSavedConfiguration(use_edge_modules)
distortosAppendToSavedConfiguration(use_emulator)
distortosAppendToSavedConfiguration(use_floats)
distortosAppendToSavedConfiguration(use_http)
distortosAppendToSavedConfiguration(use_installed_dependencies)
distortosAppendToSavedConfiguration(use_mbedtls)
distortosAppendToSavedConfiguration(use_mqtt)
distortosAppendToSavedConfiguration(use_openssl)
distortosAppendToSavedConfiguration(use_prov_client)
distortosAppendToSavedConfiguration(use_sample_trusted_cert)
distortosAppendToSavedConfiguration(use_schannel)
distortosAppendToSavedConfiguration(use_socketio)
distortosAppendToSavedConfiguration(use_tpm_simulator)
distortosAppendToSavedConfiguration(use_wolfssl)
distortosAppendToSavedConfiguration(use_wsio)
