#pragma once

#include <boost/asio.hpp>
#include <boost/function/function0.hpp>
#include <list>
namespace detail{
class IdleService
	: public boost::asio::detail::service_base<IdleService>
{
	virtual void shutdown_service(){

	}

	std::list<boost::function0<void> >	op_queue;

public:

	IdleService( boost::asio::io_service& owner )
	  : boost::asio::detail::service_base<IdleService>(owner){}

	bool has_idle() const {
		return !op_queue.empty();
	}

	template<class Handler>
	void post(Handler handler){
		op_queue.push_back(handler);
	}

	void poll_one()
	{
		//op_queue;
		get_io_service().dispatch( op_queue.front() );
		op_queue.pop_front();
	}
};

#ifdef _WIN32
class Win32MsgLoopService
	: public boost::asio::detail::service_base<IdleService>
{
	virtual void shutdown_service()
	{
		m_is_stoped = true;
		PostQuitMessage(0);
	}

	bool m_is_stoped;

public:

	Win32MsgLoopService(boost::asio::io_service& owner)
		: boost::asio::detail::service_base<IdleService>(owner){}

	bool has_message() const
	{
		if (m_is_stoped)
			return false;
		MSG msg;
		return PeekMessage(&msg, 0, 0, 0, 0);
	}

	void poll_one()
	{
		MSG msg;
		if (PeekMessage(&msg, 0, 0, 0, 1))
		{
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}
		if (msg.message == WM_QUIT)
		{
			m_is_stoped = true;
		}
	}
};
#endif
}

template<class Handler>
void avloop_idle_post(boost::asio::io_service & io_service, Handler handler)
{
	using namespace ::detail;
	if (!boost::asio::has_service<IdleService>(io_service))
	{
		boost::asio::add_service(io_service, new IdleService(io_service));
	}

	boost::asio::use_service<IdleService>(io_service).post(handler);
}


static inline void avloop_run(boost::asio::io_service & io_service)
{
	using namespace ::detail;
	boost::asio::io_service::work work(io_service);
	if (!boost::asio::has_service<IdleService>(io_service))
	{
		boost::asio::add_service(io_service, new IdleService(io_service));
	}

	while (!io_service.stopped())
	{
		if(!boost::asio::use_service<IdleService>(io_service).has_idle()){
			io_service.run_one();
		}else{
			while (io_service.poll()){};
			// 执行 idle handler!
			boost::asio::use_service<IdleService>(io_service).poll_one();
		}
	}
}

#ifdef _WIN32
// MsgWaitForMultipleObjectsEx 集成进去
static inline void avloop_run_gui(boost::asio::io_service & io_service)
{
	using namespace ::detail;
	boost::asio::io_service::work work(io_service);
	if (!boost::asio::has_service<IdleService>(io_service))
	{
		boost::asio::add_service(io_service, new IdleService(io_service));
	}
	if (!boost::asio::has_service<Win32MsgLoopService>(io_service))
	{
		boost::asio::add_service(io_service, new Win32MsgLoopService(io_service));
	}

	while (!io_service.stopped())
	{
		// 首先处理 asio 的消息
		while (io_service.poll())
		{
			// 然后执行 gui 循环，看有没有 gui 事件
			if (boost::asio::use_service<Win32MsgLoopService>(io_service).has_message())
			{
				// 执行以下
				boost::asio::use_service<Win32MsgLoopService>(io_service).poll_one();
			}
		}
		// 然后执行 gui 循环，看有没有 gui 事件
		while(boost::asio::use_service<Win32MsgLoopService>(io_service).has_message())
		{
			// 执行以下
			boost::asio::use_service<Win32MsgLoopService>(io_service).poll_one();
		}

		// 执行 idle handler!
		if (!boost::asio::use_service<IdleService>(io_service).has_idle())
			boost::asio::use_service<IdleService>(io_service).poll_one();

		// 都没有事件了，执行 一次 1ms 的超时等待

		auto ret = MsgWaitForMultipleObjectsEx(0, nullptr, 1, QS_ALLEVENTS, MWMO_WAITALL|MWMO_ALERTABLE | MWMO_INPUTAVAILABLE);
		// 可能是有 gui 消息了， 呵呵， 从头来吧
	}
}
#else
static inline void avloop_run_gui(boost::asio::io_service & io_service)
{
	return avloop_run(io_service);
}
#endif
