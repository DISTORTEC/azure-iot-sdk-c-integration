/**
 * \file
 * \brief Definitions of ThreadAPI-related functions for azure-iot-sdk-c
 *
 * \author Copyright (C) 2019 Kamil Szczygiel http://www.distortec.com http://www.freddiechopin.info
 *
 * \par License
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of the MPL was not
 * distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#include "azure_c_shared_utility/threadapi.h"

#include "distortos/ThisThread.hpp"

/*---------------------------------------------------------------------------------------------------------------------+
| global functions
+---------------------------------------------------------------------------------------------------------------------*/

extern "C" void ThreadAPI_Sleep(const unsigned int milliseconds)
{
	distortos::ThisThread::sleepFor(std::chrono::milliseconds{milliseconds});
}
