# r2yara XPS integration for radare2.
# Included from libr/xps/meson.build when r2yara sources live under
# libr/xps/p/r2yara/. Appends sources and include paths to the r_core
# aggregate so the static plugin is linked into libr_core.

core_plugins += ['r2yara']

r_core_additional_inc += include_directories(join_paths('..', 'src'))

r_core_additional_sources += files(
  '../src/core_r2yara.c',
)

# XPS has no per-plugin dependency hook; platform_deps is consumed by
# libr_core's dependency list, so libyara is appended there.
platform_deps += dependency('yara')
