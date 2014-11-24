SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)

ADD_EXECUTABLE(connectmany connectmany.cc)
ADD_EXECUTABLE(redirect redirect.cc)
ADD_EXECUTABLE(fakeserver fakeserver.cc)

TARGET_LINK_LIBRARIES(connectmany
  tcpmany
)

TARGET_LINK_LIBRARIES(redirect
  tcpmany
  pcap
)
