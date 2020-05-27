#include <chrono>
#include <iostream>
#include <sstream>
#include <thread>

#include "short_conn_client.h"

using namespace std::literals;

class HttpRequest : public short_conn_client::Request {
 public:
  std::tuple<uint32_t, uint16_t> Ipv4Port() const noexcept override {
    return std::make_tuple<uint32_t, uint16_t>(0xa1c2cf0, 80);
  }
  std::string_view ToSend() const noexcept override {
    return "GET / HTTP/1.1\r\nHost: git.code.oa.com\r\nUser-Agent: curl/7.42.1\r\nAccept: */*\r\n\r\n"sv;
  }
};

int main(int argc, char* argv[]) {
  short_conn_client::Machine machine(
      1, 1, [](std::string&& msg) { std::cerr << "fatal: " << msg << std::endl; });
  machine.BlockStart();

  auto cb = [](std::unique_ptr<short_conn_client::Request>&& ptr_req,
               std::unique_ptr<short_conn_client::Response>&& ptr_rsp) {
    auto& rsp = *ptr_rsp;
    {
      std::ostringstream buf;
      rsp.MileStones().Each(
          [&buf, &tp_comein = rsp.MileStones().At(short_conn_client::Response::MileStone::kComeIn)](
              short_conn_client::Response::MileStone idx,
              const std::chrono::steady_clock::time_point& tp) {
            if (tp.time_since_epoch() == std::chrono::steady_clock::duration::zero()) {
              buf << "X ";
              return;
            }
            buf << std::chrono::duration_cast<std::chrono::microseconds>(tp - tp_comein).count()
                << ' ';
          });
      std::cout << buf.str() << std::endl;
    }

    if (rsp.Http().Complete()) {
      std::ostringstream buf;
      buf << ">>>status line:" << rsp.Http().StatusLine() << std::endl;
#if 0
      buf << ">>>headers:" << rsp.Http().HeaderMap().size() << std::endl;
      for (auto& kv : rsp.Http().HeaderMap()) {
        buf << kv.first << '|' << kv.second << std::endl;
      }
      buf << ">>>" << rsp.Http().Body() << "<<<" << std::endl;
#endif
      std::cout << buf.str() << std::endl;
    } else if (rsp.Fail().has_value()) {
      auto& info = rsp.Fail().value();
      std::cout << info.line_num_ << '|' << info.errno_ << '|' << info.msg_ << std::endl;
    } else {
      std::cout << "timed out" << std::endl;
    }
  };

  {
    auto req = std::make_unique<HttpRequest>();
    machine.AsyncRequest(std::move(req), 8ms, cb);
  }
  std::this_thread::sleep_for(1ms);
  {
    auto req = std::make_unique<HttpRequest>();
    machine.AsyncRequest(std::move(req), 60ms, cb);
  }

  short_conn_client::Machine::Status stat;
  auto PrintStat = [&stat]() {
    std::ostringstream buf;
    buf << "IO(session:" << stat.io_session_alive << ", pending_expire:" << stat.io_pending_expire
        << ") HandlerNorm(";
    for (size_t len : stat.handler_norm_queue_len) {
      buf << len << ',';
    }
    buf << ") HandlerTimtout(";
    for (size_t len : stat.handler_timeout_queue_len) {
      buf << len << ',';
    }
    buf << ')';
    return buf.str();
  };

  machine.StatusReport(stat);
  std::cout << PrintStat() << std::endl;

  std::this_thread::sleep_for(3s);

  machine.StatusReport(stat);
  std::cout << PrintStat() << std::endl;

  machine.BlockStop();
  return 0;
}