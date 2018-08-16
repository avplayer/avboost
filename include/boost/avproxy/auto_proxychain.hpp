#pragma once

#include <cstdlib>
#include <boost/asio/io_service.hpp>

#include "detail/proxy_chain.hpp"
#include "proxies.hpp"

#include "boost/xpressive/xpressive.hpp"

namespace avproxy{

namespace detail{

static boost::asio::ip::tcp::resolver::query queryfromstr(std::string str)
{
	const boost::xpressive::sregex url_expr = (boost::xpressive::s1= (boost::xpressive::as_xpr("http://") | boost::xpressive::as_xpr("socks5://")) )
		>> (boost::xpressive::s2= +boost::xpressive::set[ boost::xpressive::range('a','z') | boost::xpressive::range('A', 'Z') | boost::xpressive::range('0', '9') | '.' ] )
		>>  -! ( ':' >>  (boost::xpressive::s3= +boost::xpressive::set[boost::xpressive::range('0', '9')]) )
		>> '/';

	boost::xpressive::smatch what_url;

	if (boost::xpressive::regex_match(str, what_url, url_expr))
	{
		std::string host = what_url[2].str();
		std::string optional_port = what_url[3].str();

		if ( what_url[1].str() == "http://")
		{
			// 应该是 http_proxy=http://host[:port]
			if (optional_port.empty())
				optional_port = "80";
			return boost::asio::ip::tcp::resolver::query(host, optional_port);
		}

		if ( what_url[1].str() == "socks5://")
		{
			// 应该是 http_proxy=http://host[:port]
			if (optional_port.empty())
				optional_port = "1080";
			return boost::asio::ip::tcp::resolver::query(host, optional_port);
		}
	}

	auto pos = str.find(':');
	std::string host = str.substr(0, pos);
	std::string port = str.substr(pos+1);
	return boost::asio::ip::tcp::resolver::query(host, port);
}

}
// automanticaly build proxychain
// accourding to env variables http_proxy and socks5_proxy
// to use socks5 proxy, set socks5_proxy="host:port"
template<class Socket>
proxy_chain autoproxychain(Socket & socket, const typename Socket::protocol_type::resolver::query & _query)
{
	proxy_chain _proxychain(socket.get_io_service());
	if (std::getenv("socks5_proxy"))
	{ // add socks5_proxy
		_proxychain.add(proxy::tcp(socket, detail::queryfromstr(std::getenv("socks5_proxy"))));
		_proxychain.add(proxy::socks5(socket, _query));
	}else if (std::getenv("http_proxy")){
		_proxychain.add(proxy::tcp(socket, detail::queryfromstr(std::getenv("http_proxy"))));
		_proxychain.add(proxy::http(socket, _query));
	}else{
		_proxychain.add(proxy::tcp(socket, _query));
	}
	return _proxychain;
}

}
