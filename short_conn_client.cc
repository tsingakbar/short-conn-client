#include "short_conn_client.h"

#include <fcntl.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/prctl.h>
#include <sys/timerfd.h>
#include <sys/un.h>
#include <unistd.h>

#include <array>
#include <atomic>
#include <condition_variable>
#include <iostream>
#include <list>
#include <map>
#include <mutex>
#include <shared_mutex>
#include <sstream>
#include <thread>

//#define DEBUGLOG std::cerr
#define DEBUGLOG \
  if (false) std::cerr

using namespace std::literals;
using MileStone = short_conn_client::Response::MileStone;

namespace {
class RAIIClose {
 public:
  explicit RAIIClose(int fd) : fd_(fd) {}
  ~RAIIClose() {
    if (fd_ > 0) {
      close(fd_);
    }
  }
  void CancelClose() { fd_ = -1; }

 private:
  int fd_;
};

}  // namespace

namespace short_conn_client {
namespace util {
std::tuple<uint8_t, const char*> ParseStrToUInt8(const char* pc, int at_most_digit) {
  uint8_t parsed_num = 0;
  while (*pc >= '0' && *pc <= '9' && at_most_digit > 0) {
    --at_most_digit;
    parsed_num = parsed_num * 10 + (*pc++ - '0');
  }
  return std::make_tuple(parsed_num, pc);
}
int ParseIPv4(const char* pc, uint8_t* out_bytes) {
  int i = -1;
  do {
    const char* pc_prev = pc;
    std::tie(out_bytes[++i], pc) = ParseStrToUInt8(pc, 3);
    if (pc == pc_prev) {
      return -1;
    }
  } while (out_bytes[i] >= 0 && out_bytes[i] <= 255 && i < 3 && *pc++ == '.');
  if (!(i == 3 && out_bytes[3] >= 0 && out_bytes[3] <= 255)) {
    return -1;
  }
  if (*pc == '/') {
    uint8_t mask_cnt;
    std::tie(mask_cnt, pc) = ParseStrToUInt8(++pc, 2);
    if ((*pc < '0' || *pc > '9') && mask_cnt >= 0 && mask_cnt <= 32) {
      return mask_cnt;
    } else {
      return -1;
    }
  }
  return 33;
}
}  // namespace util
}  // namespace short_conn_client

namespace short_conn_client {

class RequestInternal {
 public:
  explicit RequestInternal(std::unique_ptr<Request>&& req) : user_(std::move(req)) {}
  void Sent(size_t cnt) noexcept { sent_offset_ += cnt; }
  size_t SentOffset() const noexcept { return sent_offset_; }

  void SetTimeout(std::chrono::steady_clock::duration timeout) { timeout_duration_ = timeout; }

 public:
  std::unique_ptr<Request> user_;
  std::function<void(std::unique_ptr<Request>&&, std::unique_ptr<Response>&&)> callback_;

 private:
  size_t sent_offset_ = 0;
  std::chrono::steady_clock::duration timeout_duration_;
};

class ResponseInternal : public Response {
 public:
  ResponseInternal(const std::chrono::steady_clock::duration& timeout_duration) {
    milestones_.Mark(MileStone::kComeIn);
    tp_expire_ = milestones_.At(MileStone::kComeIn) + timeout_duration;
  }
  const std::chrono::steady_clock::time_point& ExpireAt() const noexcept { return tp_expire_; }

  const MileStoneTimepoints& MileStones() const noexcept override { return milestones_; }
  const std::optional<FailInfo>& Fail() const noexcept override { return fail_; };
  const ParsedHttp& Http() const noexcept override { return http_; };

 public:
  class FD {
   public:
    void Set(int fd) noexcept { fd_ = fd; }
    int Get() const noexcept { return fd_; }
    // 只close一次，避免close到复用的同值fd
    void Close() noexcept {
      if (!fd_closed_ && fd_ > 0) {
        close(fd_);
        fd_closed_ = true;
      }
    }

   private:
    int fd_ = -1;
    bool fd_closed_ = false;
  } fd_;

  class HttpParserImp : public Response::ParsedHttp {
   public:
    bool Complete() const noexcept override { return parse_stat_ == ParseStat::kComplete; }
    const std::string& StatusLine() const noexcept override { return status_line_; }
    const std::vector<std::string>& HeaderList() const noexcept override { return headers_; }
    const std::unordered_map<std::string_view, std::string_view>& HeaderMap()
        const noexcept override {
      return header_value_by_name_;
    }
    const std::string_view& Body() const noexcept override { return body_view_; }

    bool Feed(std::string_view part) noexcept {
      if (parse_stat_ == ParseStat::kComplete) {
        return true;
      }
      while (!part.empty()) {
        switch (parse_stat_) {
          case ParseStat::kFillStatusLine: {
            bool stop_at_joint = MovePartToPrevUntilJoint(status_line_, part);
            if (status_line_.length() > 8 * 1024) {
              return false;  // 太长了，应该是异常
            }
            if (stop_at_joint) {
              parse_stat_ = ParseStat::kFillHeaders;
            }
          } break;
          case ParseStat::kFillHeaders: {
            bool stop_at_joint = MovePartToPrevUntilJoint(header_line_buf_, part);
            if (header_line_buf_.length() > 8 * 1024) {
              return false;  // 太长了，应该是异常
            }
            if (!stop_at_joint) {
              continue;
            }
            if (!header_line_buf_.empty()) {
              auto sep_pos = header_line_buf_.find(": "s);
              if (sep_pos == std::string::npos) {
                return false;  // 没有冒号不能是header
              }
              headers_.push_back(std::move(header_line_buf_));
              header_line_buf_.clear();  // 下一轮还要用呢
              std::string_view view(headers_.back());
              header_value_by_name_.insert({view.substr(0, sep_pos), view.substr(sep_pos + 2)});
            } else {
              // the empty line seperate headers and body
              // 接下来我们要按照header的指示决定body的解析方法
              // RFC里说header名字大小写不敏感，这里偷懒不做大小写转换，减少IO线程工作量，业务如果有问题再改
              if (auto itr_content_length = header_value_by_name_.find("Content-Length"sv);
                  itr_content_length != header_value_by_name_.end()) {
                try {
                  size_t len = std::stoull(std::string(itr_content_length->second));
                  if (len > 1 * 1024 * 1024) {
                    // 大于1MiB，让我申请大块连续内存，风险太高，干掉
                    return false;
                  }
                  body_bytes_.resize(len);
                  parse_stat_ = ParseStat::kFillBodyByContentLength;
                } catch (std::exception& ex) {
                  return false;  // 不能不是数字
                }
              } else if (auto itr_transfer_encoding =
                             header_value_by_name_.find("Transfer-Encoding"sv);
                         itr_transfer_encoding != header_value_by_name_.end()) {
                parse_stat_ = ParseStat::kFillBodyByChunked;
              } else {
                return false;  // 不知道咋解
              }
            }
          } break;
          case ParseStat::kFillBodyByContentLength: {
            size_t to_copy_size = std::min(body_bytes_.size() - body_view_.size(), part.size());
            if (to_copy_size > 0) {
              memcpy(body_bytes_.data() + body_view_.size(), part.data(), to_copy_size);
              part = part.substr(to_copy_size);
              body_view_ = std::string_view(body_bytes_.data(), body_view_.size() + to_copy_size);
            }
            if (body_view_.size() == body_bytes_.size()) {
              parse_stat_ = ParseStat::kComplete;
            }
          } break;
          case ParseStat::kFillBodyByChunked: {
            return false;  // 暂时不支持
          } break;
          case ParseStat::kComplete: {
            //"Content-Encoding"sv;  // 后续可以考虑如果是压缩的，解个压啥的
            return true;
          } break;
        }
      }
      return true;
    }

   private:
    // 把part往prev后面搬，直到遇到接合点；如果搬运到了接合点才停止的，则返回ture
    bool MovePartToPrevUntilJoint(std::string& prev, std::string_view& part) {
      // 因为\r和\n可能分开，探测逻辑就复杂一些
      auto pos = part.find_first_of('\n');
      if (pos != std::string_view::npos) {
        if (pos > 0) {
          if (part[pos - 1] == '\r') {
            prev.append(part.substr(0, pos - 1));
            part = part.substr(pos + 1);
            return true;
          }
        } else {
          if (!prev.empty() && prev.back() == '\r') {
            prev.pop_back();
            part = part.substr(pos + 1);
            return true;
          }
        }
      }
      // 没有找到\r\n接合点的，整个贴上去，即便可能最后带了部分接合点的信息
      prev.append(part);
      part = std::string_view();
      return false;
    }

   private:
    std::string status_line_;
    std::vector<std::string> headers_;
    std::unordered_map<std::string_view, std::string_view>
        header_value_by_name_;    // 基于headers_的内存
    std::string_view body_view_;  // 基于body_bytes_的内存，使用方不应该直接使用前者

   private:
    enum class ParseStat {
      kFillStatusLine,
      kFillHeaders,
      kFillBodyByContentLength,
      kFillBodyByChunked,
      kComplete,
    } parse_stat_ = ParseStat::kFillStatusLine;
    std::string header_line_buf_;
    std::vector<char> body_bytes_;
  } http_;

  class MileStoneTimepointsImp : public Response::MileStoneTimepoints {
   public:
    void Mark(MileStone idx) noexcept {
      milestone_tps_[static_cast<size_t>(idx)] = std::chrono::steady_clock::now();
    }
    const std::chrono::steady_clock::time_point& At(MileStone idx) const noexcept override {
      return milestone_tps_[static_cast<size_t>(idx)];
    }
    virtual void Each(std::function<void(MileStone, const std::chrono::steady_clock::time_point&)>
                          func) const noexcept override {
      for (size_t i = 1; i < milestone_tps_.size(); ++i) {
        func(static_cast<MileStone>(i), milestone_tps_[i]);
      }
    }

   private:
    std::array<std::chrono::steady_clock::time_point, static_cast<size_t>(MileStone::kCnt)>
        milestone_tps_;
  } milestones_;

  std::optional<FailInfo> fail_;

 private:
  std::chrono::steady_clock::time_point tp_expire_;
};

struct Session {
  std::unique_ptr<RequestInternal> req;
  std::unique_ptr<ResponseInternal> rsp;
};

class HandleLoop {
 public:
  HandleLoop() = default;
  HandleLoop(const HandleLoop&) = delete;
  HandleLoop& operator()(const HandleLoop&) = delete;
  HandleLoop(HandleLoop&&) = delete;
  HandleLoop& operator()(HandleLoop&&) = delete;
  bool SetHandlerName(const std::string& name) {
    // 线程短名字包含结尾'\0'最多16byte，否则会截断
    name_ = name;
    return name.length() < 16;
  }
  void NotifyTerminate() {
    std::scoped_lock<std::mutex> lk(this->sessions_mtx_);
    terminate_ = true;
    sessions_cv_.notify_one();
  }
  void Schedule(Session&& session) {
    std::scoped_lock<std::mutex> lk(this->sessions_mtx_);
    sessions_.push_back(std::move(session));
    sessions_cv_.notify_one();
  }
  size_t QueueLen() {
    std::scoped_lock<std::mutex> lk(this->sessions_mtx_);
    return sessions_.size();
  }
  void ConsumeLoop() {
    if (!name_.empty()) {
      prctl(PR_SET_NAME, name_.c_str(), NULL, NULL, NULL);
    }
    while (!terminate_) {
      std::optional<Session> session;
      {
        std::unique_lock<std::mutex> lk(sessions_mtx_);
        sessions_cv_.wait(lk, [this]() { return this->terminate_ || !this->sessions_.empty(); });
        if (!sessions_.empty()) {
          session = std::move(sessions_.front());
          sessions_.pop_front();
        }
      }
      if (!session.has_value()) {
        continue;  // 要终止loop了应该
      }
      session.value().rsp->milestones_.Mark(MileStone::kBeginHandle);
      // 没有回调的也挂到队列，走到这里消费，是为了避免在IO线程里面析构全套session，毕竟req
      // rsp可能是用户的子类，析构较慢
      if (session.value().req->callback_) {
        try {
          session.value().req->callback_(std::move(session.value().req->user_),
                                         std::move(session.value().rsp));
        } catch (std::exception& ex) {
        }
      }
    }
  }

 private:
  bool terminate_ = false;
  std::list<Session> sessions_;
  std::mutex sessions_mtx_;
  std::condition_variable sessions_cv_;
  std::string name_;
};

class Machine::Imp {
 public:
  explicit Imp(int normal_handler_cnt, int timeout_handler_cnt,
               std::function<void(std::string&&)> fatal_handler)
      : fatal_handler_(fatal_handler),
        handlers_normal_(normal_handler_cnt),
        handlers_timeout_(timeout_handler_cnt) {
    for (auto& handler : handlers_normal_) {
      handler.SetHandlerName("http_hdl_nrm"s);
    }
    for (auto& handler : handlers_timeout_) {
      handler.SetHandlerName("http_hdl_tmot"s);
    }
  }

  void BlockStart() {
    // handler和IO线程启动
    io_thread_ = std::thread(&Imp::IOLoop, this);
    for (auto& handler : handlers_normal_) {
      handler_threads_.emplace_back(&HandleLoop::ConsumeLoop, &handler);
    }
    for (auto& handler : handlers_timeout_) {
      handler_threads_.emplace_back(&HandleLoop::ConsumeLoop, &handler);
    }
    while (machine_state_ == MachineStat::kReady) {
      // 需要等待变成kGo或者kStop
      std::this_thread::sleep_for(1ms);
    }
  }

  void BlockStop() {
    {
      // io线程强制唤醒，用timerfd凑合下
      struct itimerspec ts {
        .it_interval = {0, 0}, .it_value = {
          .tv_sec = 0,
          .tv_nsec = 1000 * 1000,
        }
      };
      timerfd_settime(timer_fd_, 0, &ts, NULL);
    }
    for (auto& handler : handlers_normal_) {
      handler.NotifyTerminate();
    }
    for (auto& handler : handlers_timeout_) {
      handler.NotifyTerminate();
    }
    machine_state_.store(MachineStat::kStop);
    for (auto& t : handler_threads_) {
      t.join();
    }
    io_thread_.join();
  }

  void StatusReport(Machine::Status& status) {
    status.io_session_alive = SessionAliveCount();
    status.io_pending_expire = PendingExpireCount();
    status.handler_norm_queue_len.clear();
    status.handler_norm_queue_len.reserve(handlers_normal_.size());
    for (auto& handler : handlers_normal_) {
      status.handler_norm_queue_len.push_back(handler.QueueLen());
    }
    status.handler_timeout_queue_len.clear();
    status.handler_timeout_queue_len.reserve(handlers_timeout_.size());
    for (auto& handler : handlers_timeout_) {
      status.handler_timeout_queue_len.push_back(handler.QueueLen());
    }
  }

  void AsyncRequest(
      std::unique_ptr<Request>&& req, const std::chrono::steady_clock::duration timeout_duration,
      std::function<void(std::unique_ptr<Request>&&, std::unique_ptr<Response>&&)> cb) noexcept {
    Session session{.req = std::make_unique<RequestInternal>(std::move(req)),
                    .rsp = std::make_unique<ResponseInternal>(timeout_duration)};
    session.req->callback_ = std::move(cb);

    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    session.rsp->fd_.Set(fd);
    if (fd < 0) {
      session.rsp->fail_ = {
          .line_num_ = __LINE__,
          .errno_ = errno,
      };
      FinishSessionAsFailed(std::move(session));
      return;
    }

    RAIIClose fd_closer(fd);  // 后续异常的return会自动关闭fd

    int fcntl_val = ::fcntl(fd, F_GETFL, 0);
    if (fcntl_val < 0) {
      session.rsp->fail_ = {
          .line_num_ = __LINE__,
          .errno_ = errno,
      };
      FinishSessionAsFailed(std::move(session));
      return;
    }
    if (::fcntl(fd, F_SETFL, fcntl_val | O_NONBLOCK) < 0) {
      session.rsp->fail_ = {
          .line_num_ = __LINE__,
          .errno_ = errno,
      };
      FinishSessionAsFailed(std::move(session));
      return;
    }
    struct linger st_linger {
      .l_onoff = 1,       // close后还有未发送数据允许逗留
          .l_linger = 0,  // 逗留时间是0秒
    };
    if (::setsockopt(fd, SOL_SOCKET, SO_LINGER, reinterpret_cast<const void*>(&st_linger),
                     sizeof(linger)) < 0) {
      session.rsp->fail_ = {
          .line_num_ = __LINE__,
          .errno_ = errno,
      };
      FinishSessionAsFailed(std::move(session));
      return;
    }
    struct sockaddr_in peer_addr;
    ::bzero(&peer_addr, sizeof(peer_addr));
    peer_addr.sin_family = AF_INET;
    auto [ipv4, port] = session.req->user_->Ipv4Port();
    peer_addr.sin_addr.s_addr = htonl(ipv4);
    peer_addr.sin_port = htons(port);
    if (::connect(fd, reinterpret_cast<sockaddr*>(&peer_addr), sizeof(peer_addr)) < 0 &&
        errno != EINPROGRESS) {
      session.rsp->fail_ = {
          .line_num_ = __LINE__,
          .errno_ = errno,
      };
      FinishSessionAsFailed(std::move(session));
      return;
    }

    // 前面操作比较多，这里重新检查下是不是已经超时了
    auto tp_now = std::chrono::steady_clock::now();
    auto tp_expire = session.rsp->ExpireAt();
    if (tp_expire <= tp_now) {
      FinishSessionAsTimeout(std::move(session));
      return;
    }

    uint64_t uniq_id = StoreSession(std::move(session));
    if (PushExpireMightBecameLead(tp_expire, uniq_id)) {
      // 插入后发现自己才是最小的，需要更改timer_fd的定时
      auto gap_nano =
          std::chrono::duration_cast<std::chrono::nanoseconds>(tp_expire - tp_now).count();
      struct itimerspec ts {
        .it_interval = {0, 0}, .it_value = {
          .tv_sec = gap_nano / (1000 * 1000 * 1000),
          .tv_nsec = gap_nano % (1000 * 1000 * 1000),
        }
      };
      if (timerfd_settime(timer_fd_, 0, &ts, NULL) < 0) {
        int copy_errno = errno;

        auto session = EraseSession(uniq_id);
        if (session.has_value()) {
          session.value().rsp->fail_ = {
              .line_num_ = __LINE__,
              .errno_ = copy_errno,
          };
          FinishSessionAsFailed(std::move(session.value()));
        }

        std::ostringstream buf_fatal_msg;
        buf_fatal_msg << "timerfd_settime(" << ts.it_value.tv_sec << "sec, " << ts.it_value.tv_nsec
                      << "nano) failed with errno " << copy_errno;
        fatal_handler_(std::move(buf_fatal_msg.str()));
        machine_state_.store(MachineStat::kStop);

        return;
      }
    }

    struct epoll_event ev {
      .events = EPOLLIN | EPOLLOUT | EPOLLET,
      .data = {
          .u64 = uniq_id,
      },
    };
    if (::epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, fd, &ev) < 0) {
      int copy_errno = errno;
      auto session = EraseSession(uniq_id);
      if (session.has_value()) {
        session.value().rsp->fail_ = {
            .line_num_ = __LINE__,
            .errno_ = copy_errno,
        };
        FinishSessionAsFailed(std::move(session.value()));
      }
      return;
    }

    fd_closer.CancelClose();  // 一切正常，fd保持开启
  }

  void IOLoop() {
    prctl(PR_SET_NAME, "http_io_loop", NULL, NULL, NULL);  // 线程短名字最多16byte

    epoll_fd_ = ::epoll_create1(0);
    if (epoll_fd_ < 0) {
      int copy_errno = errno;
      machine_state_.store(MachineStat::kStop);
      fatal_handler_("epoll_create1(0) failed with errno " + std::to_string(copy_errno));
      return;
    }
    timer_fd_ = ::timerfd_create(CLOCK_MONOTONIC, 0);
    if (timer_fd_ < 0) {
      int copy_errno = errno;
      machine_state_.store(MachineStat::kStop);
      fatal_handler_("timerfd_create() failed with errno " + std::to_string(copy_errno));
      return;
    }

    RAIIClose fd_closer(timer_fd_);  // 无论后续流程异常正常，io线程结束的时候都要关掉

    struct epoll_event ev_timer_fd {
      .events = EPOLLIN,
      .data = {
          .u64 = kTimerFdUniqId,
      },
    };
    if (::epoll_ctl(epoll_fd_, EPOLL_CTL_ADD, timer_fd_, &ev_timer_fd) < 0) {
      int copy_errno = errno;
      machine_state_.store(MachineStat::kStop);
      fatal_handler_("epoll_ctl(add, timer_fd_) failed with errno " + std::to_string(copy_errno));
      return;
    }

    machine_state_.store(MachineStat::kGo);
    while (machine_state_ == MachineStat::kGo) {
      int active_ev_cnt_ = ::epoll_wait(epoll_fd_, active_evs_.data(), active_evs_.size(), -1);
      if (active_ev_cnt_ < 0) {
        int copy_errno = errno;
        if (copy_errno == EINTR) {
          continue;  // 重新epoll_wait即可
        }
        fatal_handler_("epoll_wait() failed with errno " + std::to_string(copy_errno));
        return;
      }
      for (int i = 0; i < active_ev_cnt_; ++i) {
        auto& ev = active_evs_[i];
        DEBUGLOG << "epoll wake uniq_id=" << ev.data.u64 << " events=" << ev.events << std::endl;

        if (ev.data.u64 == kTimerFdUniqId) {
          [this, &ev]() {
            if (ev.events & (EPOLLERR | EPOLLHUP)) {
              // 计时器出错了，不应该会出现
              fatal_handler_("timer_fd triggered with event EPOLLERR|EPOLLHUP");
              this->machine_state_.store(MachineStat::kStop);
              return;
            }
            if (ev.events & EPOLLIN) {
              // 计时器正常触发了  不读出来会马上就再次触发
              uint64_t expire_cnt;
              read(timer_fd_, &expire_cnt, sizeof(expire_cnt));
            }
            this->HarvestTimeoutInIOThread();
          }();
          continue;
        }

        if (ev.events & (EPOLLERR | EPOLLHUP)) {
          [this, &ev]() {
            auto session = this->EraseSession(ev.data.u64);
            if (session.has_value()) {
              session.value().rsp->fd_.Close();  // 会从epoll_wait中自动清理，下同
              session.value().rsp->fail_ = {
                  .line_num_ = __LINE__,
                  .errno_ = 0,
                  .msg_ = "match EPOLLERR|EPOLLHUP",
              };
              this->FinishSessionAsFailed(std::move(session.value()));
            }
          }();
          continue;
        }

        if (ev.events & EPOLLIN) {
          [this, &ev]() {
            auto ref_session = RefSessionInIOThread(ev.data.u64);
            if (!ref_session.has_value()) {
              return;
            }
            ResponseInternal* rsp = nullptr;
            std::tie(std::ignore, rsp) =
                ref_session.value();  // 只有IO线程有机会删除当前session，放心使用
            std::array<char, 8 * 1024> recvbuf;  // stack is faster
            int recved = 0;
            while (recved = ::recv(rsp->fd_.Get(), recvbuf.data(), recvbuf.size(), 0), recved > 0) {
              if (!rsp->http_.Feed(std::string_view(recvbuf.data(), recved))) {
                // 喂着喂着吐奶了
                auto session = EraseSession(ev.data.u64);
                if (session.has_value()) {
                  session.value().rsp->fd_.Close();
                  session.value().rsp->fail_ = {
                      .line_num_ = __LINE__,
                      .errno_ = 0,
                      .msg_ = "http resp parse failure",
                  };
                  FinishSessionAsFailed(std::move(session.value()));
                }
                return;
              }
              if (rsp->http_.Complete()) {
                rsp->milestones_.Mark(MileStone::kFinishRecv);
                auto session = EraseSession(ev.data.u64);
                if (session.has_value()) {
                  session.value().rsp->fd_.Close();
                  FinishSessionAsOk(std::move(session.value()));
                }
                return;
              }
            }
            int copy_errno = errno;
            if (!(recved == 0 || copy_errno == EAGAIN)) {
              auto session = EraseSession(ev.data.u64);
              if (session.has_value()) {
                session.value().rsp->fd_.Close();
                session.value().rsp->fail_ = {
                    .line_num_ = __LINE__,
                    .errno_ = copy_errno,
                };
                FinishSessionAsFailed(std::move(session.value()));
              }
            }
          }();
          continue;
        }

        if (ev.events & EPOLLOUT) {
          [this, &ev]() {
            auto ref_session = RefSessionInIOThread(ev.data.u64);
            if (!ref_session.has_value()) {
              return;
            }
            auto [req, rsp] = ref_session.value();  // 只有IO线程有机会删除当前session，放心使用
            if (req->SentOffset() >= req->user_->ToSend().length()) {
              // 之前已经发送完毕了
              return;
            }
            int copy_errno = 0;
            int sent = 0;
            do {
              auto tosend = req->user_->ToSend().substr(req->SentOffset());
              sent = ::send(rsp->fd_.Get(), tosend.data(), tosend.size(), 0);
              // TODO 一旦 sent < tosend.size() 是不是就不用多循环一次了
              if (sent > 0) {
                req->Sent(sent);
              } else {
                copy_errno = errno;
              }
            } while (req->SentOffset() < req->user_->ToSend().length() && sent > 0);
            if (sent > 0) {
              rsp->milestones_.Mark(MileStone::kFinishSend);
            } else if (!(sent == 0 || copy_errno == EAGAIN)) {
              auto session = EraseSession(ev.data.u64);
              if (session.has_value()) {
                session.value().rsp->fd_.Close();
                session.value().rsp->fail_ = {
                    .line_num_ = __LINE__,
                    .errno_ = copy_errno,
                };
                FinishSessionAsFailed(std::move(session.value()));
              }
            }
          }();
          continue;
        }
      }
    }
  }

  void HarvestTimeoutInIOThread() noexcept {
    auto tp_now = std::chrono::steady_clock::now();

    auto gap_nano = [this, &tp_now]() {
      while (true) {
        std::optional<typename decltype(uniq_id_by_expire_tp_)::iterator> head_expire =
            FetchHeadExpireInIOThread();
        // 因为除了当前的IO线程，没有线程可以删除超时队列内的请求，所以这个itr可以一直有效
        // 注意到了这个位置，存在可能 head_expire 已经不是 head 了，下面的逻辑不要与此冲突。
        if (!head_expire.has_value()) {
          return std::optional<int64_t>();
        }
        auto& [tp_expire, ref_uniq_id] = *head_expire.value();
        if (!IsSessionAliveInIOThread(ref_uniq_id)) {
          // 超时队列中无效的请求只有在此处被动删除
          DEBUGLOG << "purge not alive uniq_id " << ref_uniq_id << std::endl;
          EraseExpireInIOThread(head_expire.value());
          continue;
        }
        if (tp_expire <= tp_now) {
          uint64_t uniq_id = ref_uniq_id;
          EraseExpireInIOThread(head_expire.value());
          auto session = EraseSession(uniq_id);
          if (session.has_value()) {
            session.value().rsp->fd_.Close();
            FinishSessionAsTimeout(std::move(session.value()));
          }
          continue;
        }
        return std::make_optional(
            std::chrono::duration_cast<std::chrono::nanoseconds>(tp_expire - tp_now).count());
      }
    }();

    if (!gap_nano.has_value()) {
      // timer_fd不设置就不会被唤醒：
      // 刚才检测的时候暂时没有请求了，虽说这会可能又有了，但是插入请求的线程应该重新设置定时器了
      return;
    }

    // 隐患：有较少的可能刚刚插入了一条过期时间早于gap_nano的，在插入处也设置了超时，
    // 但是此处我们会重置定时器到gap_nano，导致刚刚那条无法及时唤醒。
    struct itimerspec ts {
      .it_interval = {0, 0}, .it_value = {
        .tv_sec = gap_nano.value() / (1000 * 1000 * 1000),
        .tv_nsec = gap_nano.value() % (1000 * 1000 * 1000),
      }
    };
    if (timerfd_settime(timer_fd_, 0, &ts, NULL) < 0) {
      int copy_errno = errno;
      std::ostringstream buf_fatal_msg;
      buf_fatal_msg << "timerfd_settime(" << ts.it_value.tv_sec << "sec, " << ts.it_value.tv_nsec
                    << "nano) in io thread failed with errno " << copy_errno;
      fatal_handler_(std::move(buf_fatal_msg.str()));
      machine_state_.store(MachineStat::kStop);
      return;
    }
  }

  void FinishSessionAsOk(Session&& session) {
    auto idx = session.rsp->milestones_.At(MileStone::kComeIn).time_since_epoch().count() %
               handlers_normal_.size();
    handlers_normal_[idx].Schedule(std::move(session));
  }

  void FinishSessionAsTimeout(Session&& session) {
    session.rsp->milestones_.Mark(MileStone::kFoundExpire);
    auto idx = session.rsp->milestones_.At(MileStone::kComeIn).time_since_epoch().count() %
               handlers_timeout_.size();
    handlers_timeout_[idx].Schedule(std::move(session));
  }

  void FinishSessionAsFailed(Session&& session) {
    auto idx = session.rsp->milestones_.At(MileStone::kComeIn).time_since_epoch().count() %
               handlers_normal_.size();
    handlers_normal_[idx].Schedule(std::move(session));
  }

 private:
  std::function<void(std::string&&)> fatal_handler_;  // 非预期的挂逼会调用它
  enum class MachineStat : size_t {
    kReady,
    kGo,
    kStop,
  };
  std::atomic<MachineStat> machine_state_ = MachineStat::kReady;
  int epoll_fd_ = -1;
  std::array<struct epoll_event, 1024> active_evs_;
  int timer_fd_ = -1;
  const uint64_t kTimerFdUniqId = std::numeric_limits<uint64_t>::max();
  std::vector<HandleLoop> handlers_normal_,
      handlers_timeout_;  // 超时的请求会放在后者处理，以期望能更快送达业务逻辑
  std::vector<std::thread> handler_threads_;
  std::thread io_thread_;

 private:
  uint64_t uniq_id_gen_ = 0;
  std::unordered_map<uint64_t, Session> session_by_uniq_id_;
  std::shared_mutex session_by_uniq_id_mtx_;
  uint64_t StoreSession(Session&& session) {
    uint64_t uniq_id;
    std::unique_lock lk(session_by_uniq_id_mtx_);
    do {
      uniq_id = ++uniq_id_gen_;
    } while (uniq_id == kTimerFdUniqId);
    session_by_uniq_id_[uniq_id] = std::move(session);
    return uniq_id;
  }
  std::optional<Session> EraseSession(uint64_t uniq_id) {
    std::optional<Session> session;
    {
      std::unique_lock lk(session_by_uniq_id_mtx_);
      auto itr_session = session_by_uniq_id_.find(uniq_id);
      if (itr_session != session_by_uniq_id_.end()) {
        session = std::move(itr_session->second);
        this->session_by_uniq_id_.erase(itr_session);
      }
    }
    return session;
  }
  std::optional<std::tuple<RequestInternal*, ResponseInternal*>> RefSessionInIOThread(
      uint64_t uniq_id) {
    std::optional<std::tuple<RequestInternal*, ResponseInternal*>> ret;
    {
      std::shared_lock lk(session_by_uniq_id_mtx_);
      auto itr_session = session_by_uniq_id_.find(uniq_id);
      if (itr_session != session_by_uniq_id_.end()) {
        ret = std::make_tuple(itr_session->second.req.get(), itr_session->second.rsp.get());
      }
    }
    return ret;
  }
  bool IsSessionAliveInIOThread(uint64_t uniq_id) {
    std::shared_lock lk(session_by_uniq_id_mtx_);
    auto itr_session = session_by_uniq_id_.find(uniq_id);
    return (itr_session != session_by_uniq_id_.end());
  }
  size_t SessionAliveCount() {
    std::shared_lock lk(session_by_uniq_id_mtx_);
    return session_by_uniq_id_.size();
  }

 private:
  std::multimap<std::chrono::steady_clock::time_point, uint64_t> uniq_id_by_expire_tp_;
  std::shared_mutex uniq_id_by_expire_tp_mtx_;

  std::optional<typename decltype(uniq_id_by_expire_tp_)::iterator> FetchHeadExpireInIOThread() {
    std::shared_lock lk(uniq_id_by_expire_tp_mtx_);
    if (!uniq_id_by_expire_tp_.empty()) {
      return std::make_optional(uniq_id_by_expire_tp_.begin());
    }
    return std::optional<typename decltype(uniq_id_by_expire_tp_)::iterator>();
  }

  void EraseExpireInIOThread(typename decltype(uniq_id_by_expire_tp_)::iterator itr) {
    std::unique_lock lk(uniq_id_by_expire_tp_mtx_);
    uniq_id_by_expire_tp_.erase(itr);
  }

  bool PushExpireMightBecameLead(const std::chrono::steady_clock::time_point& tp_expire,
                                 uint64_t uniq_id) {
    std::unique_lock lk(uniq_id_by_expire_tp_mtx_);
    uniq_id_by_expire_tp_.insert({tp_expire, uniq_id});
    // 如果tp_expire比之前最小的过期时间还小，返回true
    // 特殊case是如果之前是空的，逻辑上tp_expire也是比之前的小，也返回true
    return (uniq_id_by_expire_tp_.size() == 1 || tp_expire < uniq_id_by_expire_tp_.begin()->first);
  }

  size_t PendingExpireCount() {
    std::shared_lock lk(uniq_id_by_expire_tp_mtx_);
    return uniq_id_by_expire_tp_.size();
  }
};

Machine::Machine(int normal_handler_cnt, int timeout_handler_cnt,
                 std::function<void(std::string&&)> fatal_handler)
    : imp_(std::make_unique<Imp>(normal_handler_cnt, timeout_handler_cnt, fatal_handler)) {}

Machine::~Machine() = default;

void Machine::BlockStart() { imp_->BlockStart(); }

void Machine::BlockStop() { imp_->BlockStop(); }

void Machine::StatusReport(Status& status) { imp_->StatusReport(status); }

void Machine::AsyncRequest(
    std::unique_ptr<Request>&& req, const std::chrono::steady_clock::duration timeout_duration,
    std::function<void(std::unique_ptr<Request>&&, std::unique_ptr<Response>&&)> cb) noexcept {
  imp_->AsyncRequest(std::move(req), timeout_duration, std::move(cb));
}

}  // namespace short_conn_client