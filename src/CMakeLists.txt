SET(LIBRARY_OUTPUT_PATH ${PROJECT_BINARY_DIR}/lib)

ADD_LIBRARY(tcpmany STATIC
  connection.cc
  kernel.cc
)
