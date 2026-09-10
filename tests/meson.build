gtest_dep = dependency('gtest', main: false, required: false)  # main: false - we provide our own
gmock_dep = dependency('gmock', required: false)
if not gtest_dep.found() or not gmock_dep.found()
  cmake = import('cmake')
  opt_var = cmake.subproject_options()
 
  # Keep warning levels aligned with project policy
  opt_var.add_cmake_defines({'CMAKE_CXX_FLAGS': '-Wno-pedantic'})
  opt_var.set_override_option('warning_level', '3')
  opt_var.set_override_option('werror', 'true')
 
  # Bring in googletest via CMake subproject (wrap), if not present on system
  gtest_proj = cmake.subproject('gtest', options: opt_var, required: true)
  if gtest_proj.found()
    gtest_dep = declare_dependency(
      dependencies: [dependency('threads'), gtest_proj.dependency('gtest')]
    )
    gmock_dep = gtest_proj.dependency('gmock')
  else
    assert(not get_option('tests').enabled(), 'Googletest is required if tests are enabled')
  endif
endif

# Common build arguments shared by all three test executables
_common_deps = [
  gtest_dep,
  gmock_dep,
  sdbusplus,
  sdeventplus,
  phosphor_dbus_interfaces,
  phosphor_logging_dep,
  openssl_dep,
]
_common_link_args = [
  '-lcrypt',
  '-lstdc++fs',
  '-Wl,--allow-multiple-definition',
]
_common_cpp_args = [
  '-DBOOST_ALL_NO_LIB',
  '-DBOOST_SYSTEM_NO_DEPRECATED',
  '-DBOOST_ERROR_CODE_HEADER_ONLY',
]
_prod_sources = [
  '../src/licensecontrol.cpp',
  '../src/licenseDbus.cpp',
  '../src/licenseDecrypt.cpp',
]


lc_sources = [
  'test_main.cpp',
  'test_license_control.cpp',
] + _prod_sources

lc_exe = executable(
  'test_licensecontrol',
  lc_sources,
  include_directories: include_directories('..'),
  dependencies: _common_deps,
  link_args: _common_link_args,
  cpp_args: _common_cpp_args,
)


dbus_sources = [
  'test_main.cpp',
  'test_license_dbus.cpp',
] + _prod_sources

dbus_exe = executable(
  'test_licensedbus',
  dbus_sources,
  include_directories: include_directories('..'),
  dependencies: _common_deps,
  link_args: _common_link_args,
  cpp_args: _common_cpp_args,
)

decrypt_sources = [
  'test_main.cpp',
  'test_license_decrypt.cpp',
] + _prod_sources

decrypt_exe = executable(
  'test_licensedecrypt',
  decrypt_sources,
  include_directories: include_directories('..'),
  dependencies: _common_deps,
  link_args: _common_link_args,
  cpp_args: _common_cpp_args,
)

test('test_licensecontrol', lc_exe)
test('test_licensedbus', dbus_exe)
test('test_licensedecrypt', decrypt_exe)
