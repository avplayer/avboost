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
		get_io_service().post( op_queue.front() );
		op_queue.pop_front();
	}
};
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

// MsgWaitForMultipleObjectsEx 集成进去
static inline void avloop_run_gui(boost::asio::io_service & io_service)
{
	using namespace ::detail;
	boost::asio::io_service::work work(io_service);
	if (!boost::asio::has_service<IdleService>(io_service))
	{
		boost::asio::add_service(io_service, new IdleService(io_service));
	}

	while (!io_service.stopped())
	{
		if (!boost::asio::use_service<IdleService>(io_service).has_idle()){

			MsgWaitForMultipleObjectsEx(0, 0, 50, QS_ALLEVENTS, MWMO_ALERTABLE | MWMO_INPUTAVAILABLE);
			MSG msg;
			if (PeekMessage(&msg, 0, 0, 0, 1))
			{
				TranslateMessage(&msg);
				DispatchMessage(&msg);
			};

			io_service.run_one();
		}
		else{
			while (io_service.poll()){};
			// 执行 idle handler!
			boost::asio::use_service<IdleService>(io_service).poll_one();
		}
	}
}
