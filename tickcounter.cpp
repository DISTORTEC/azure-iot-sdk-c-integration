/**
 * \file
 * \brief Definitions of tickcounter-related functions for azure-iot-sdk-c
 *
 * \author Copyright (C) 2019 Kamil Szczygiel http://www.distortec.com http://www.freddiechopin.info
 *
 * \par License
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of the MPL was not
 * distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#include "azure_c_shared_utility/tickcounter.h"

#include "distortos/assert.h"
#include "distortos/TickClock.hpp"

namespace
{

/*---------------------------------------------------------------------------------------------------------------------+
| local objects
+---------------------------------------------------------------------------------------------------------------------*/

const uint8_t dummy {};

}	// namespace

/*---------------------------------------------------------------------------------------------------------------------+
| global functions
+---------------------------------------------------------------------------------------------------------------------*/

extern "C" TICK_COUNTER_HANDLE tickcounter_create()
{
	return reinterpret_cast<TICK_COUNTER_HANDLE>(const_cast<uint8_t*>(&dummy));
}

extern "C" void tickcounter_destroy(const TICK_COUNTER_HANDLE tickCounter)
{
    assert(tickCounter == reinterpret_cast<const void*>(&dummy));
}

extern "C" int tickcounter_get_current_ms(const TICK_COUNTER_HANDLE tickCounter, tickcounter_ms_t* const milliseconds)
{
	assert(tickCounter == reinterpret_cast<const void*>(&dummy));
	assert(milliseconds != nullptr);
	*milliseconds = std::chrono::milliseconds{distortos::TickClock::now().time_since_epoch()}.count();
	return {};
}
