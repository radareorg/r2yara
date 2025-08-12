project(
  'r2yara',
  ['c'],
  license : 'LGPL3',
  meson_version : '>=0.50.1',
  version : '1.2.0'
)

r2yara_sources = [
  'src/core_r2yara.c',
]

incdirs = [
  'src',
]

res = run_command(['radare2','-HR2_LIBR_PLUGINS'], capture:true, check:false)
if res.returncode() == 0
  r2_plugdir = res.stdout().strip()
else
  prefix = get_option('prefix')
  r2_plugdir = prefix + '/lib/radare2/plugins'
endif

add_global_arguments('-DR2Y_VERSION="1.1.2"', language:'c')
c = meson.get_compiler('c')
if c.get_id() == 'msvc'
  incdirs += [
    'radare2/include/libr',
    'radare2/include/libr/sdb',
  ]
  add_global_arguments('-D_WINDOWS', language:'c')
  r2libdir = [
    meson.current_source_dir() + '\\radare2\\lib',
    'C:\\radare2\\lib'
  ]
  r_core = [
    c.find_library('r_core', dirs: r2libdir),
    c.find_library('r_io', dirs: r2libdir),
    c.find_library('r_bin', dirs: r2libdir),
    c.find_library('r_cons', dirs: r2libdir),
    c.find_library('r_asm', dirs: r2libdir),
    c.find_library('r_esil', dirs: r2libdir),
    c.find_library('r_arch', dirs: r2libdir),
    c.find_library('r_flag', dirs: r2libdir),
    c.find_library('r_reg', dirs: r2libdir),
    c.find_library('r_util', dirs: r2libdir),
    c.find_library('r_anal', dirs: r2libdir),
    c.find_library('r_config', dirs: r2libdir),
  ]
else
  r_core = dependency('r_core')
endif
libyara = dependency('yara')

r2yara_incdirs = include_directories(incdirs)

r2yara_core_sources = [
  r2yara_sources,
  'src/core_r2yara.c'
]

threads = dependency('threads')

r2yara_core_plugin = library('core_r2yara',
  r2yara_core_sources,
  dependencies: [r_core, libyara, threads],
  link_args: ['-lm'],
  include_directories: r2yara_incdirs,
  install: true,
  install_dir: r2_plugdir
)
