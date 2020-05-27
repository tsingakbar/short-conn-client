#include "gtest/gtest.h"
#include "short_conn_client.h"

using namespace std::literals;

#if 0
TEST(Response, HTTPParse) {
  short_conn_client::Response rsp;
  rsp.http_.Feed("HTTP/1.1 30"sv);
  rsp.http_.Feed("1 Moved Permanently\r");
  rsp.http_.Feed("\nServ");
  rsp.http_.Feed("");
  rsp.http_.Feed("er: openresty\r\nDate: Sun, 24 May 2020 06:21:50 GMT\r");
  rsp.http_.Feed("\nContent-Type: text/html");
  rsp.http_.Feed("\r\nContent-Length: 175\r\nConnection: keep-alive\r\n");
  rsp.http_.Feed("\r");
  rsp.http_.Feed(
      "\n<html>\n<head><title>301 Moved Permanently</title></head>\n<body bgcolor=\"white\">\n");
  rsp.http_.Feed(
      "<center><h1>301 Moved Permanently</h1></center>\n<hr><center>openresty</center>\n");
  rsp.http_.Feed("</body>\n</html>\n");

  EXPECT_EQ(rsp.Http().Complete(), true);
  EXPECT_EQ(rsp.Http().StatusLine(), "HTTP/1.1 301 Moved Permanently"s);
  auto itr_header = rsp.Http().HeaderMap().find("Content-Type"sv);
  EXPECT_NE(itr_header, rsp.Http().HeaderMap().end());
  EXPECT_EQ(itr_header->second, "text/html"sv);
  EXPECT_EQ(rsp.Http().Body().length(), 175);
}
#endif

TEST(IPParser, Basic) {
  std::array<uint8_t, 4> parsed;

  int mask_cnt = short_conn_client::util::ParseIPv4("192.168.1.2", parsed.data());
  EXPECT_EQ(parsed, (std::array<uint8_t, 4>{192, 168, 1, 2}));
  EXPECT_EQ(mask_cnt, 33);

  mask_cnt = short_conn_client::util::ParseIPv4("192.168.1.2/22", parsed.data());
  EXPECT_EQ(parsed, (std::array<uint8_t, 4>{192, 168, 1, 2}));
  EXPECT_EQ(mask_cnt, 22);

  mask_cnt = short_conn_client::util::ParseIPv4("192.168.1.2/222", parsed.data());
  EXPECT_EQ(parsed, (std::array<uint8_t, 4>{192, 168, 1, 2}));
  EXPECT_EQ(mask_cnt, -1);

  mask_cnt = short_conn_client::util::ParseIPv4("192.168.1111.2", parsed.data());
  EXPECT_EQ(mask_cnt, -1);

  mask_cnt = short_conn_client::util::ParseIPv4("192.168.1.2balabala", parsed.data());
  EXPECT_EQ(parsed, (std::array<uint8_t, 4>{192, 168, 1, 2}));
  EXPECT_EQ(mask_cnt, 33);
}

int main(int argc, char** argv) {
  ::testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
