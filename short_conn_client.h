#pragma once
#include <chrono>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace short_conn_client {

class Request {
 public:
  virtual ~Request() = default;
  virtual std::tuple<uint32_t, uint16_t> Ipv4Port() const noexcept = 0;
  // 建议http req设置"Connection: close"头，让服务端知道咱是短连结
  virtual std::string_view ToSend() const noexcept = 0;
};

class Response {
 public:
  virtual ~Response() = default;
  enum class MileStone : size_t {
    kComeIn,       // 发起异步调用
    kFinishSend,   // 请求发送完
    kFinishRecv,   // 回包接收完（包含解析）
    kFoundExpire,  // 被发现超时
    kBeginHandle,  // handler开始处理它
    kCnt,
  };
  class MileStoneTimepoints {
   public:
    virtual const std::chrono::steady_clock::time_point& At(MileStone idx) const noexcept = 0;
    virtual void Each(std::function<void(MileStone, const std::chrono::steady_clock::time_point&)>)
        const noexcept = 0;
  };
  virtual const MileStoneTimepoints& MileStones() const noexcept = 0;

  struct FailInfo {
    int line_num_;
    int errno_ = 0;  // 系统调用出错一般有设置这个
    const char* msg_ = nullptr;  // 逻辑出错一般会设置这个，指向一个静态生命周期的null结尾字符串
  };
  virtual const std::optional<FailInfo>& Fail() const noexcept = 0;

  class Parser {
   public:
    virtual bool Feed(std::string_view part) noexcept = 0;
  };

  class Parsed {
   public:
    virtual bool Complete() const noexcept = 0;
  };

  class ParsedHttp : public Parsed {
   public:
    virtual const std::string& StatusLine() const noexcept = 0;
    virtual const std::vector<std::string>& HeaderList() const noexcept = 0;
    virtual const std::unordered_map<std::string_view, std::string_view>& HeaderMap()
        const noexcept = 0;
    virtual const std::string_view& Body() const noexcept = 0;
  };
  virtual const ParsedHttp& Http() const noexcept = 0;
};

#ifdef UNIT_TEST
// 给单元测试用的，调用方不要管理内存，因为肯定是泄露的
std::tuple<Response::Parser*, Response::ParsedHttp*> CreateHttpParserForTest();
#endif

class Machine {
 public:
  Machine(
      int normal_handler_cnt = 1, int timeout_handler_cnt = 1,
      std::function<void(std::string&&)> fatal_handler = [](std::string&&) {});
  ~Machine();
  void AsyncRequest(
      std::unique_ptr<Request>&& req, const std::chrono::steady_clock::duration timeout_duration,
      std::function<void(std::unique_ptr<Request>&&, std::unique_ptr<Response>&&)> cb) noexcept;
  void BlockStart();
  void BlockStop();
  struct Status {
    size_t io_session_alive;
    size_t io_pending_expire;
    std::vector<size_t> handler_norm_queue_len;
    std::vector<size_t> handler_timeout_queue_len;
  };
  void StatusReport(Status&);

 private:
  class Imp;
  std::unique_ptr<Imp> imp_;
};

namespace util {
/*!
 * @param pc
 * String representing an IPv4 address.
 * pcIP should end with space or nothing.
 * eg. "192.168.1.101", "192.168.1.101 " and "192.168.1.101 blabla" are all valid.
 * Forms like "192.168.1.101/24" is also supported.
 *
 * @param out_bytes
 * Make sure at leat 4 bytes is available to write.
 *
 * @returns
 * -1 indicates a failure.
 * Success when typical IPv4 (eg. "192.168.1.101") : 33
 * Success when IPv4 plus netmask code (eg. "192.168.1.101/24") : netmask code (0..32)
 */
int ParseIPv4(const char* pc, uint8_t* out_bytes);
}  // namespace util

}  // namespace short_conn_client