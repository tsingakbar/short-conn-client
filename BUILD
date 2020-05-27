load("@rules_cc//cc:defs.bzl", "cc_binary", "cc_library", "cc_test")

package(default_visibility = ["//visibility:public"])

cc_library(
    name = "short_conn_client",
    srcs = ["short_conn_client.cc"],
    hdrs = ["short_conn_client.h"],
)

cc_binary(
    name = "httpclient_demo",
    srcs = ["main.cc"],
    linkopts = [
        "-pthread -ldl",
    ],
    deps = [
        "short_conn_client",
    ],
)

cc_test(
    name = "httpclient_test",
    srcs = ["test.cc"],
    deps =
        [
            "short_conn_client",
            "@gtest",
        ],
)
