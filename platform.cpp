/**
 * \file
 * \brief Definitions of platform-related functions for azure-iot-sdk-c
 *
 * \author Copyright (C) 2019 Kamil Szczygiel http://www.distortec.com http://www.freddiechopin.info
 *
 * \par License
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of the MPL was not
 * distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#include "azure_c_shared_utility/platform.h"
#include "azure_c_shared_utility/tlsio_mbedtls.h"

/*---------------------------------------------------------------------------------------------------------------------+
| global functions
+---------------------------------------------------------------------------------------------------------------------*/

extern "C" void platform_deinit()
{

}

extern "C" const IO_INTERFACE_DESCRIPTION* platform_get_default_tlsio()
{
	return tlsio_mbedtls_get_interface_description();
}

extern "C" STRING_HANDLE platform_get_platform_info(PLATFORM_INFO_OPTION)
{
	// expected format - "(<runtime name>; <operating system name>; <platform>)"
	return STRING_construct("(native; distortos; undefined)");
}

extern "C" int platform_init()
{
	return {};
}
