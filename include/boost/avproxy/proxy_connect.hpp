﻿
#pragma once

#ifdef __llvm__
#pragma GCC diagnostic ignored "-Wdangling-else"
#endif

#include <boost/bind.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/io_service.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/detail/handler_alloc_helpers.hpp>
#include <boost/asio/detail/handler_cont_helpers.hpp>
#include <boost/asio/detail/handler_invoke_helpers.hpp>
#include <boost/asio/detail/handler_type_requirements.hpp>
#include <boost/asio/async_result.hpp>

#include "detail/proxy_chain.hpp"

namespace avproxy {

// convient helper class that made for direct TCP connection without proxy
// usage:
//    avproxy::async_connect(  socket ,  ip::tcp::resolve::query( "host" ,  "port" ) ,  handler );
// the hander should be this signature
//    void handle_connect(
//         const boost::system::error_code & ec
//    )
class async_connect
{
public:
	typedef void result_type; // for boost::bind
public:
	template<class Socket, class Handler>
	async_connect(Socket & socket,const typename Socket::protocol_type::resolver::query & _query, BOOST_ASIO_MOVE_ARG(Handler) handler)
	{
		//BOOST_ASIO_CONNECT_HANDLER_CHECK(Handler, handler) type_check;
		_async_connect(socket, _query, boost::function<void (const boost::system::error_code&)>(handler));
	}

	template<class Handler, class Socket>
	void operator()(const boost::system::error_code & ec, typename Socket::protocol_type::resolver::results_type resolve_result, Socket & socket, boost::shared_ptr<typename Socket::protocol_type::resolver> resolver, Handler handler)
	{
		boost::asio::async_connect(socket, resolve_result, [handler, resolver](auto ec, auto endpoint){
			handler(ec);
		});
	}

private:
	template<class Socket, class Handler>
	void _async_connect(Socket & socket,const typename Socket::protocol_type::resolver::query & _query, BOOST_ASIO_MOVE_ARG(Handler) handler)
	{
		//BOOST_ASIO_CONNECT_HANDLER_CHECK(Handler, handler) type_check;

		typedef typename Socket::protocol_type::resolver resolver_type;

		boost::shared_ptr<resolver_type>
			resolver(new resolver_type(socket.get_io_service()));
		resolver->async_resolve(_query, boost::bind(*this, _1, _2, boost::ref(socket), resolver, handler));
	}
};

// 带　proxy 执行连接.
template<typename Handler>
class async_proxy_connect_op : boost::asio::coroutine
{
public:
	typedef void result_type; // for boost::bind_handler
public:
	async_proxy_connect_op(const proxy_chain &proxy_chain, Handler &handler)
		: proxy_chain_(proxy_chain)
		, m_handler(handler)
	{
	}

	void operator()(boost::system::error_code ec)
	{
		BOOST_ASIO_CORO_REENTER(this)
		{
			do
			{
				// resolve
				BOOST_ASIO_CORO_YIELD proxy_chain_.begin()->async_connect(*this);
				proxy_chain_.pop_front();
			}while(proxy_chain_.size() && !ec);
			m_handler(ec);
		}
	}
private:
	proxy_chain proxy_chain_;
	Handler m_handler;
};

template <typename RealHandler>
inline BOOST_ASIO_INITFN_RESULT_TYPE(RealHandler,
	void(boost::system::error_code))
	async_proxy_connect(const proxy_chain &proxy_chain, BOOST_ASIO_MOVE_ARG(RealHandler) handler)
{
	using namespace boost::asio;

	BOOST_ASIO_CONNECT_HANDLER_CHECK(RealHandler, handler) type_check;

	boost::asio::async_completion<RealHandler, void(boost::system::error_code)>
		init(BOOST_ASIO_MOVE_CAST(RealHandler)(handler));

	async_proxy_connect_op<BOOST_ASIO_HANDLER_TYPE(
		RealHandler, void(boost::system::error_code))>(proxy_chain, init.completion_handler)
		(boost::system::error_code());
	return init.result.get();

}

}
