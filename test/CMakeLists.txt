## The KirHut Security Center Library
## CMake Test Folder File
##
## Copyright © KirHut Software Company

cmake_minimum_required(VERSION 3.21)

enable_testing()

set(TESTS_TO_EXECUTE
    CipherUnicorn
)

configure_file(SmallBlock.txt SmallBlock.txt COPYONLY)
configure_file(TestBlock1.txt tfolder/TestBlock1.txt COPYONLY)
configure_file(TestBlock2.txt tfolder/TestBlock2.txt COPYONLY)
configure_file(TestBlock3.txt tfolder/TestBlock3.txt COPYONLY)
configure_file(TestBlock4.txt tfolder/TestBlock4.txt COPYONLY)
configure_file(TestBlock5.txt tfolder/TestBlock5.txt COPYONLY)
configure_file(LargeBlock1.txt lfolder/LargeBlock1.txt COPYONLY)
configure_file(LargeBlock2.txt lfolder/LargeBlock2.txt COPYONLY)
configure_file(LargeBlock3.txt lfolder/LargeBlock3.txt COPYONLY)

foreach(TESTNAME ${TESTS_TO_EXECUTE})
    add_executable(KSCTest${TESTNAME} Test${TESTNAME}.cpp)
    add_test(NAME ${TESTNAME} COMMAND KSCTest${TESTNAME})
    target_include_directories(KSCTest${TESTNAME} PRIVATE ${PROJECT_SOURCE_DIR}/extern/include)
    target_link_libraries(KSCTest${TESTNAME} PRIVATE libKSC Qt6::Test)
endforeach()
