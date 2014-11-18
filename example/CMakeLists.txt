SET(EXECUTABLE_OUTPUT_PATH ${PROJECT_BINARY_DIR}/bin)

ADD_EXECUTABLE(connectmany connectmany.cc)

TARGET_LINK_LIBRARIES(connectmany
  tcpmany
)

