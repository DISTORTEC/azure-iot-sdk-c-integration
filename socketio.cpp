/**
 * \file
 * \brief Definitions of socketio-related functions for azure-iot-sdk-c
 *
 * \author Copyright (C) 2020 Kamil Szczygiel http://www.distortec.com http://www.freddiechopin.info
 *
 * \par License
 * This Source Code Form is subject to the terms of the Mozilla Public License, v. 2.0. If a copy of the MPL was not
 * distributed with this file, You can obtain one at http://mozilla.org/MPL/2.0/.
 */

#include "azure_c_shared_utility/singlylinkedlist.h"
#include "azure_c_shared_utility/socketio.h"

#include "distortos/assert.h"

#include "estd/ScopeGuard.hpp"

#include "lwip/netdb.h"

#include <memory>

namespace
{

/*---------------------------------------------------------------------------------------------------------------------+
| local types
+---------------------------------------------------------------------------------------------------------------------*/

/// possible state of socketio instance
enum class IoState : uint8_t
{
	/// closed
	closed,
	/// open
	open,
	/// error
	error
};

/// single chunk of queued pending data that should be sent
struct PendingIo
{
	/// buffer with data that should be sent
	unsigned char* buffer;
	/// size of \a buffer
	size_t size;
	/// callback to execute after the data is sent successfully
	ON_SEND_COMPLETE onSendComplete;
	/// argument for \a onSendComplete
	void* onSendCompleteArgument;
};

/// instance of socketio
struct SocketIoInstance
{
	/// underlying socket
	int socket;
	/// callback to execute after the data is received
	ON_BYTES_RECEIVED onBytesReceived;
	/// argument for \a onBytesReceived
	void* onBytesReceivedArgument;
	/// callback to execute after an error is encountered
	ON_IO_ERROR onIoError;
	/// argument for \a onIoError
	void* onIoErrorArgument;
	/// hostname of Azure server
	char* hostname;
	/// list of pending data that should be sent
	SINGLYLINKEDLIST_HANDLE pendingIoList;
	/// port of Azure server
	uint16_t port;
	/// current state of socketio instance
	IoState ioState;
};

/*---------------------------------------------------------------------------------------------------------------------+
| local objects
+---------------------------------------------------------------------------------------------------------------------*/

/// connection timeout, seconds
constexpr unsigned int connectionTimeout {10};

/// invalid, non-initialized socket
constexpr int invalidSocket {-1};

/*---------------------------------------------------------------------------------------------------------------------+
| local functions
+---------------------------------------------------------------------------------------------------------------------*/

int addPendingIo(const SocketIoInstance& instance, const void* const buffer, const size_t size,
		const ON_SEND_COMPLETE onSendComplete, void* const onSendCompleteArgument)
{
	std::unique_ptr<PendingIo> pendingIo {new (std::nothrow) PendingIo{}};
	if (pendingIo == nullptr)
	{
		LogError("addPendingIo: failed allocating PendingIo");
		return MU_FAILURE;
	}

	std::unique_ptr<uint8_t[]> pendingIoBuffer {new (std::nothrow) uint8_t[size]};
	if (pendingIoBuffer == nullptr)
	{
		LogError("addPendingIo: failed allocating buffer");
		return MU_FAILURE;
	}

	memcpy(pendingIoBuffer.get(), buffer, size);

	pendingIo->buffer = pendingIoBuffer.get();
	pendingIo->size = size;
	pendingIo->onSendComplete = onSendComplete;
	pendingIo->onSendCompleteArgument = onSendCompleteArgument;

	if (singlylinkedlist_add(instance.pendingIoList, pendingIo.get()) == nullptr)
	{
		LogError("addPendingIo: failed adding to list");
		return MU_FAILURE;
	}

	pendingIoBuffer.release();
	pendingIo.release();
	return {};
}

void* cloneOption(const char*, const void*)
{
    return {};
}

void destroyOption(const char*, const void*)
{

}

void indicateError(SocketIoInstance& instance)
{
	instance.ioState = IoState::error;
	if (instance.onIoError != nullptr)
		instance.onIoError(instance.onIoErrorArgument);
}

int lookupAddressAndInitializeConnection(SocketIoInstance& instance)
{
	addrinfo* addressInformation;

	{
		char portString[sizeof("65535")];
		{
			const auto ret = sniprintf(portString, sizeof(portString), "%" PRIu16, instance.port);
			assert(ret > 0 && static_cast<size_t>(ret) < sizeof(portString));
		}

		addrinfo hint {};
		hint.ai_family = AF_INET;
		hint.ai_socktype = SOCK_STREAM;

		const auto ret = lwip_getaddrinfo(instance.hostname, portString, &hint, &addressInformation);
		if (ret != 0)
		{
			LogError("lookupAddressAndInitializeConnection: lwip_getaddrinfo() failed, ret = %d", ret);
			return MU_FAILURE;
		}
	}

	const auto addressInformationScopeGuard = estd::makeScopeGuard(
			[addressInformation]()
			{
				lwip_freeaddrinfo(addressInformation);
			});

	const auto flags = lwip_fcntl(instance.socket, F_GETFL, 0);
	if (flags == -1)
	{
		LogError("lookupAddressAndInitializeConnection: lwip_fcntl(F_GETFL) failed, errno = %d", errno);
		return MU_FAILURE;
	}

	{
		const auto ret = lwip_fcntl(instance.socket, F_SETFL, flags | O_NONBLOCK);
		if (ret == -1)
		{
			LogError("lookupAddressAndInitializeConnection: lwip_fcntl(F_SETFL) failed, errno = %d", errno);
			return MU_FAILURE;
		}
	}

	const auto ret = lwip_connect(instance.socket, addressInformation->ai_addr, sizeof(*addressInformation->ai_addr));
	if (ret != 0 && errno != EINPROGRESS)
	{
		LogError("lookupAddressAndInitializeConnection: lwip_connect() failed, errno = %d", errno);
		return MU_FAILURE;
	}

	return {};
}

OPTIONHANDLER_HANDLE retrieveOptions(const CONCRETE_IO_HANDLE handle)
{
	if (handle == nullptr)
		return {};

	return OptionHandler_Create(cloneOption, destroyOption, socketio_setoption);
}

int waitForConnection(SocketIoInstance& instance)
{
	{
		fd_set fdSet;
		FD_ZERO(&fdSet);
		FD_SET(instance.socket, &fdSet);

		timeval timeout;
		timeout.tv_sec = connectionTimeout;
		timeout.tv_usec = 0;

		const auto ret = lwip_select(instance.socket + 1, nullptr, &fdSet, nullptr, &timeout);
		if (ret != 1)
		{
			LogError("waitForConnection: lwip_select() failed, errno = %d", errno);
			return MU_FAILURE;
		}
	}

	int error {};
	socklen_t errorLength {sizeof(error)};
	const auto ret = lwip_getsockopt(instance.socket, SOL_SOCKET, SO_ERROR, &error, &errorLength);
	if (ret != 0)
	{
		LogError("waitForConnection: lwip_getsockopt() failed, errno = %d", errno);
		return MU_FAILURE;
	}
	if (error != 0)
	{
		LogError("waitForConnection: connection failed, error = %d", error);
		return MU_FAILURE;
	}

	return {};
}

}   // namespace

/*---------------------------------------------------------------------------------------------------------------------+
| global functions
+---------------------------------------------------------------------------------------------------------------------*/

int socketio_close(const CONCRETE_IO_HANDLE handle, const ON_IO_CLOSE_COMPLETE onIoCloseComplete,
		void* const onIoCloseCompleteArgument)
{
	if (handle == nullptr)
		return MU_FAILURE;

	auto& instance = *static_cast<SocketIoInstance*>(handle);
	if (instance.ioState == IoState::closed)
		return MU_FAILURE;

	lwip_shutdown(instance.socket, SHUT_RDWR);
	lwip_close(instance.socket);
	instance.socket = invalidSocket;
	instance.ioState = IoState::closed;

	if (onIoCloseComplete != nullptr)
		onIoCloseComplete(onIoCloseCompleteArgument);

	return {};
}

CONCRETE_IO_HANDLE socketio_create(void* const parameters)
{
	if (parameters == nullptr)
	{
		LogError("socketio_create: invalid argument");
		return {};
	}

	const auto& configuration = *static_cast<const SOCKETIO_CONFIG*>(parameters);
	std::unique_ptr<SocketIoInstance> instance {new (std::nothrow) SocketIoInstance{}};
	if (instance == nullptr)
	{
		LogError("socketio_create: failed allocating SocketIoInstance");
		return {};
	}

	instance->pendingIoList = singlylinkedlist_create();
	if (instance->pendingIoList == nullptr)
	{
		LogError("socketio_create: failed allocating pendingIoList");
		return {};
	}

	auto pendingIoListScopeGuard = estd::makeScopeGuard(
			[&instance]()
			{
				singlylinkedlist_destroy(instance->pendingIoList);
			});

	if (configuration.hostname == nullptr)
	{
		instance->hostname = {};
		instance->socket = *static_cast<int*>(configuration.accepted_socket);
		if (instance->socket == invalidSocket)
		{
			LogError("socketio_create: invalid socket");
			return {};
		}
	}
	else
	{
		instance->hostname = strdup(configuration.hostname);
		if (instance->hostname == nullptr)
		{
			LogError("socketio_create: failed allocating hostname");
			return {};
		}

		instance->socket = invalidSocket;
	}

	instance->port = configuration.port;
	instance->ioState = IoState::closed;
	pendingIoListScopeGuard.release();
	return instance.release();
}

void socketio_destroy(const CONCRETE_IO_HANDLE handle)
{
	if (handle == nullptr)
		return;

	const auto& instance = *static_cast<SocketIoInstance*>(handle);
	if (instance.socket != invalidSocket)
		lwip_close(instance.socket);

	decltype(singlylinkedlist_get_head_item(instance.pendingIoList)) pendingIoItem;
	while (pendingIoItem = singlylinkedlist_get_head_item(instance.pendingIoList), pendingIoItem != nullptr)
	{
		const auto pendingIo = static_cast<const PendingIo*>(singlylinkedlist_item_get_value(pendingIoItem));
		assert(pendingIo != nullptr);
		free(pendingIo->buffer);
		free(const_cast<PendingIo*>(pendingIo));

		singlylinkedlist_remove(instance.pendingIoList, pendingIoItem);
	}

	singlylinkedlist_destroy(instance.pendingIoList);
	free(instance.hostname);
	delete &instance;
}

void socketio_dowork(const CONCRETE_IO_HANDLE handle)
{
	if (handle == nullptr)
		return;

	auto& instance = *static_cast<SocketIoInstance*>(handle);

	decltype(singlylinkedlist_get_head_item(instance.pendingIoList)) pendingIoItem;
	while (pendingIoItem = singlylinkedlist_get_head_item(instance.pendingIoList),
			pendingIoItem != nullptr && instance.ioState == IoState::open)
	{
		const auto pendingIo =
				static_cast<PendingIo*>(const_cast<void*>(singlylinkedlist_item_get_value(pendingIoItem)));
		assert(pendingIo != nullptr);

		const auto ret = lwip_send(instance.socket, pendingIo->buffer, pendingIo->size, 0);
		if (ret < 0)
		{
			if (errno == EAGAIN)
				break;	// cannot send more now, try again next time

			LogError("socketio_dowork: lwip_send() failed, errno = %d", errno);
			indicateError(instance);
			return;
		}

		if (static_cast<size_t>(ret) != pendingIo->size)
		{
			// part of buffer sent, next time try to send the rest
			memmove(pendingIo->buffer, pendingIo->buffer + ret, pendingIo->size - ret);
			pendingIo->size -= ret;
			break;
		}

		free(pendingIo->buffer);
		free(const_cast<PendingIo*>(pendingIo));
		singlylinkedlist_remove(instance.pendingIoList, pendingIoItem);

		if (pendingIo->onSendComplete != nullptr)
			pendingIo->onSendComplete(pendingIo->onSendCompleteArgument, IO_SEND_OK);
	}

	while(instance.ioState == IoState::open)
	{
		uint8_t buffer[RECEIVE_BYTES_VALUE];
		const auto ret = lwip_recv(instance.socket, buffer, sizeof(buffer), 0);
		if (ret < 0)
		{
			if (errno == EAGAIN)
				break;	// no more data to receive at this moment

			LogError("socketio_dowork: lwip_recv() failed, errno = %d", errno);
			indicateError(instance);
			return;
		}

		if (ret == 0)
			indicateError(instance);	// remote end has shut down the connection

		if (ret != 0 && instance.onBytesReceived != nullptr)
			instance.onBytesReceived(instance.onBytesReceivedArgument, buffer, ret);
	}
}

const IO_INTERFACE_DESCRIPTION* socketio_get_interface_description()
{
	static const IO_INTERFACE_DESCRIPTION socketIoInterfaceDescription
	{
			retrieveOptions,
			socketio_create,
			socketio_destroy,
			socketio_open,
			socketio_close,
			socketio_send,
			socketio_dowork,
			socketio_setoption
	};

	return &socketIoInterfaceDescription;
}

int socketio_open(const CONCRETE_IO_HANDLE handle, const ON_IO_OPEN_COMPLETE onIoOpenComplete,
		void* const onIoOpenCompleteContext, const ON_BYTES_RECEIVED onBytesReceived,
		void* const onBytesReceivedArgument, const ON_IO_ERROR onIoError, void* const onIoErrorArgument)
{
	auto ioOpenErrorScopeGuard = estd::makeScopeGuard(
			[onIoOpenComplete, onIoOpenCompleteContext]()
			{
				if (onIoOpenComplete != nullptr)
					onIoOpenComplete(onIoOpenCompleteContext, IO_OPEN_ERROR);
			});

	if (handle == nullptr)
	{
		LogError("socketio_open: invalid argument");
		return MU_FAILURE;
	}

	auto& instance = *static_cast<SocketIoInstance*>(handle);
	if (instance.ioState != IoState::closed)
	{
		LogError("socketio_open: socket is not closed");
		return MU_FAILURE;
	}

	if (instance.socket == invalidSocket)	// opening a listen socket?
	{
		instance.socket = lwip_socket(AF_INET, SOCK_STREAM, 0);
		if (instance.socket < 0)
		{
			LogError("socketio_open: failed opening socket, errno = %d", errno);
			return MU_FAILURE;
		}

		auto socketScopeGuard = estd::makeScopeGuard(
				[&instance]()
				{
					lwip_close(instance.socket);
					instance.socket = invalidSocket;
				});

		if (lookupAddressAndInitializeConnection(instance) != 0)
		{
			LogError("socketio_open: failed looking up address and/or connection initialization");
			return MU_FAILURE;
		}

		if (waitForConnection(instance) != 0)
		{
			LogError("socketio_open: failed waiting for connection");
			return MU_FAILURE;
		}

		socketScopeGuard.release();
	}

	instance.onBytesReceived = onBytesReceived;
	instance.onBytesReceivedArgument = onBytesReceivedArgument;
	instance.onIoError = onIoError;
	instance.onIoErrorArgument = onIoErrorArgument;
	instance.ioState = IoState::open;

	ioOpenErrorScopeGuard.release();

	if (onIoOpenComplete != nullptr)
		onIoOpenComplete(onIoOpenCompleteContext, IO_OPEN_OK);

	return {};
}

int socketio_send(const CONCRETE_IO_HANDLE handle, const void* const buffer, const size_t size,
		const ON_SEND_COMPLETE onSendComplete, void* const onSendCompleteArgument)
{
	if (handle == nullptr || buffer == nullptr || size == 0)
	{
		LogError("socketio_send: invalid argument");
		return MU_FAILURE;
	}

	auto& instance = *static_cast<SocketIoInstance*>(handle);
	if (instance.ioState != IoState::open)
	{
		LogError("socketio_send: socket is not opened");
		return MU_FAILURE;
	}

	size_t sent {};
	if (singlylinkedlist_get_head_item(instance.pendingIoList) == nullptr)	// no pending data?
	{
		const auto ret = lwip_send(instance.socket, buffer, size, 0);
		if (ret < 0 && errno != EAGAIN)	// fatal error?
		{
			LogError("socketio_send: lwip_send() failed, errno = %d", errno);
			return MU_FAILURE;
		}

		if (ret > 0)
			sent = ret;
	}

	if (sent == size)
	{
		if (onSendComplete != nullptr)
			onSendComplete(onSendCompleteArgument, IO_SEND_OK);

		return {};
	}

	const auto ret = addPendingIo(instance, static_cast<const uint8_t*>(buffer) + sent, size - sent, onSendComplete,
			onSendCompleteArgument);
	if (ret != 0)
	{
		LogError("socketio_send: addPendingIo() failed");
		return MU_FAILURE;
	}

	return {};
}

int socketio_setoption(const CONCRETE_IO_HANDLE handle, const char* const name, const void* const value)
{
	if (handle == nullptr || name == nullptr || value == nullptr)
		return MU_FAILURE;

	const auto& instance = *static_cast<SocketIoInstance*>(handle);

	if (strcmp(name, "tcp_keepalive") == 0)
	{
		const auto ret = lwip_setsockopt(instance.socket, SOL_SOCKET, SO_KEEPALIVE, value, sizeof(int));
		return ret == 0 ? 0 : errno;
	}

	if (strcmp(name, "tcp_keepalive_interval") == 0)
	{
		const auto ret = lwip_setsockopt(instance.socket, IPPROTO_TCP, TCP_KEEPINTVL, value, sizeof(int));
		return ret == 0 ? 0 : errno;
	}

	if (strcmp(name, "tcp_keepalive_time") == 0)
	{
		const auto ret = lwip_setsockopt(instance.socket, IPPROTO_TCP, TCP_KEEPIDLE, value, sizeof(int));
		return ret == 0 ? 0 : errno;
	}

	LogError("socketio_setoption: option \"%s\" is not supported", name);
	return MU_FAILURE;
}
