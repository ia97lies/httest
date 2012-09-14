test_htt_stack_SOURCES=test_htt_stack.c $(top_srcdir)/src/htt_stack.c
test_htt_expr_SOURCES=test_htt_expr.c $(top_srcdir)/src/htt_expr.c
test_htt_bufreader_SOURCES=test_htt_bufreader.c $(top_srcdir)/src/htt_bufreader.c
test_htt_core_SOURCES=test_htt_core.c $(top_srcdir)/src/htt_core.c $(top_srcdir)/src/htt_context.c \
		      $(top_srcdir)/src/htt_executable.c $(top_srcdir)/src/htt_map.c \
		      $(top_srcdir)/src/htt_log.c $(top_srcdir)/src/htt_util.c $(top_srcdir)/src/htt_stack.c \
		      $(top_srcdir)/src/htt_bufreader.c $(top_srcdir)/src/htt_replacer.c \
		      $(top_srcdir)/src/htt_string.c $(top_srcdir)/src/htt_function.c \
		      $(top_srcdir)/src/htt_command.c $(top_srcdir)/src/htt_expr.c \
		      $(top_srcdir)/src/core_module.c $(top_srcdir)/src/htt_modules.c
test_htt_core_thread_SOURCES=test_htt_core_thread.c $(top_srcdir)/src/htt_core.c \
		      $(top_srcdir)/src/htt_context.c $(top_srcdir)/src/htt_executable.c \
		      $(top_srcdir)/src/htt_map.c $(top_srcdir)/src/htt_log.c \
		      $(top_srcdir)/src/htt_util.c $(top_srcdir)/src/htt_stack.c \
		      $(top_srcdir)/src/htt_bufreader.c $(top_srcdir)/src/htt_replacer.c \
		      $(top_srcdir)/src/htt_string.c $(top_srcdir)/src/htt_function.c \
		      $(top_srcdir)/src/htt_command.c $(top_srcdir)/src/htt_expr.c \
		      $(top_srcdir)/src/core_module.c $(top_srcdir)/src/htt_modules.c
AM_CFLAGS=-I$(top_srcdir)/src
check_PROGRAMS=test_htt_stack test_htt_bufreader test_htt_expr test_htt_core test_htt_core_thread
TESTS = test_htt_stack test_htt_bufreader test_htt_expr test_htt_core test_htt_core_thread
