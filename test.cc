#include "gtest/gtest.h"

#define UNIT_TEST
#include "short_conn_client.h"

using namespace std::literals;

TEST(HTTPParser, Main) {
  auto [parser, parsed] = short_conn_client::CreateHttpParserForTest();
  parser->Feed("HTTP/1.1 30"sv);
  parser->Feed("1 Moved Permanently\r");
  parser->Feed("\nServ");
  parser->Feed("");
  parser->Feed("er: openresty\r\nDate: Sun, 24 May 2020 06:21:50 GMT\r");
  parser->Feed("\nContent-Type: text/html");
  parser->Feed("\r\nContent-Length: 175\r\nConnection: keep-alive\r\n");
  parser->Feed("\r");
  parser->Feed(
      "\n<html>\n<head><title>301 Moved Permanently</title></head>\n<body bgcolor=\"white\">\n");
  parser->Feed("<center><h1>301 Moved Permanently</h1></center>\n<hr><center>openresty</center>\n");
  parser->Feed("</body>\n</html>\n");

  EXPECT_EQ(parsed->Complete(), true);
  EXPECT_EQ(parsed->StatusLine(), "HTTP/1.1 301 Moved Permanently"s);
  auto itr_header = parsed->HeaderMap().find("Content-Type"sv);
  EXPECT_NE(itr_header, parsed->HeaderMap().end());
  EXPECT_EQ(itr_header->second, "text/html"sv);
  EXPECT_EQ(parsed->Body().length(), 175);
}

TEST(IPParser, Main) {
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
