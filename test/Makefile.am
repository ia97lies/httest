test_htt_stack_SOURCES=test_htt_stack.c $(top_srcdir)/src/htt_stack.c
test_htt_expr_SOURCES=test_htt_expr.c $(top_srcdir)/src/htt_expr.c
test_htt_bufreader_SOURCES=test_htt_bufreader.c $(top_srcdir)/src/htt_bufreader.c
test_htt_core_SOURCES=test_htt_core.c $(top_srcdir)/src/htt_core.c $(top_srcdir)/src/htt_context.c \
		      $(top_srcdir)/src/htt_executable.c $(top_srcdir)/src/htt_map.c \
		      $(top_srcdir)/src/htt_log.c $(top_srcdir)/src/htt_util.c $(top_srcdir)/src/htt_stack.c \
		      $(top_srcdir)/src/htt_bufreader.c $(top_srcdir)/src/htt_replacer.c \
		      $(top_srcdir)/src/htt_string.c $(top_srcdir)/src/htt_function.c \
		      $(top_srcdir)/src/htt_command.c $(top_srcdir)/src/htt_expr.c \
		      $(top_srcdir)/src/thread_module.c \
		      $(top_srcdir)/src/exception_module.c \
		      $(top_srcdir)/src/core_module.c $(top_srcdir)/src/htt_modules.c
test_thread_module_SOURCES=test_thread_module.c $(top_srcdir)/src/htt_core.c \
		      $(top_srcdir)/src/htt_context.c $(top_srcdir)/src/htt_executable.c \
		      $(top_srcdir)/src/htt_map.c $(top_srcdir)/src/htt_log.c \
		      $(top_srcdir)/src/htt_util.c $(top_srcdir)/src/htt_stack.c \
		      $(top_srcdir)/src/htt_bufreader.c $(top_srcdir)/src/htt_replacer.c \
		      $(top_srcdir)/src/htt_string.c $(top_srcdir)/src/htt_function.c \
		      $(top_srcdir)/src/htt_command.c $(top_srcdir)/src/htt_expr.c \
		      $(top_srcdir)/src/thread_module.c \
		      $(top_srcdir)/src/exception_module.c \
		      $(top_srcdir)/src/core_module.c $(top_srcdir)/src/htt_modules.c
test_exception_module_SOURCES=test_exception_module.c $(top_srcdir)/src/htt_core.c \
		      $(top_srcdir)/src/htt_context.c $(top_srcdir)/src/htt_executable.c \
		      $(top_srcdir)/src/htt_map.c $(top_srcdir)/src/htt_log.c \
		      $(top_srcdir)/src/htt_util.c $(top_srcdir)/src/htt_stack.c \
		      $(top_srcdir)/src/htt_bufreader.c $(top_srcdir)/src/htt_replacer.c \
		      $(top_srcdir)/src/htt_string.c $(top_srcdir)/src/htt_function.c \
		      $(top_srcdir)/src/htt_command.c $(top_srcdir)/src/htt_expr.c \
		      $(top_srcdir)/src/thread_module.c \
		      $(top_srcdir)/src/exception_module.c \
		      $(top_srcdir)/src/core_module.c $(top_srcdir)/src/htt_modules.c
EXTRA_DIST=finally.ht3
AM_CFLAGS=-I$(top_srcdir)/src
check_PROGRAMS=test_htt_stack test_htt_bufreader test_htt_expr test_htt_core test_thread_module test_exception_module
TESTS = test_htt_stack test_htt_bufreader test_htt_expr test_htt_core test_thread_module test_exception_module run_all.sh
