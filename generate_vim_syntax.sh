#!/bin/bash

cat << EOF
" Vim syntax file
" Language:     Httest  
" Maintainer:   Christian Liesch <ia97lies@users.sourceforge.net>       
" Last Change:  2011 Feb 2 

if version < 600
  syntax clear
elseif exists("b:current_syntax")
  finish
endif

" Global commands
syn keyword httStorageClass     CLIENT SERVER DAEMON BLOCK END
syn keyword httInclude          INCLUDE
syn keyword httStatement        SET GO EXEC TIMEOUT AUTO_CLOSE PROCESS FILE MODULE
EOF

./src/httest -L | grep "\<_" | grep -v "\<_[A-Z]\+:[A-Z]\+" | grep -v "_RPS" | grep -v "_LOOP"| grep -v "_FOR"| grep -v "_IF" | grep -v "_BPS" | grep -v "_ERROR" | awk '{ printf "syn keyword httStatement        %s\n", $1 }'
./src/httest -L  | grep -v "\->" | grep "_[A-Z]\+:" | awk '{ printf "syn match httStatement          \"\\<%s\\>\"\n", $1}'

cat << EOF
syn keyword httRepeat           _LOOP _FOR _BPS _RPS _SOCKET _IGNORE_BODY
syn match httRepeat             "\<_END SOCKET\>"
syn match httRepeat             "\<_END LOOP\>"
syn match httRepeat             "\<_END FOR\>"
syn match httRepeat             "\<_END BPS\>"
syn match httRepeat             "\<_END RPS\>"
syn keyword httConditional      _IF _ELSE _ERROR
syn match httConditional        "\<_END IF\>"
syn match httConditional        "\<_END ERROR\>"

" Constants
syn keyword httConstant         POLL CHUNKED DO_NOT_CHECK AUTO on off On Off SSL SSL2 SSL3 TLS1 OK FAILED
syn keyword httOperator         NOT MATCH EQUAL LT GT LE GE EQ ADD SUB MUL DIV
EOF

echo 'syn match httIdentifier         "$[^ /.:\$"]\+"'
echo 'syn match httIdentifier         "${[^ /.:\$}"]\+}"'
echo 'syn match httNumber             "\<[0-9]\+\>"'

cat << EOF
syn match httFunction           "^ *__.*" contains=httIdentifier,httConstant
syn match httFunction           "^ *_-.*" contains=httIdentifier
syn match   httSpecial contained "\\\d\d\d\|\\."
syn region  httString             start=+"+  skip=+\\\\\|\\"+  end=+"+  contains=basicSpecial,httIdentifier
syn region httComment           display oneline start="^ *#" end="$" contains=httTodo
syn keyword httTodo             contained TODO FIXME XXX NOTE
syn keyword httType             EXEC HEADERS BODY VAR exec headers body var Exec Headers Body Var

" Define the default highlighting.
" For version 5.7 and earlier: only when not done already
" For version 5.8 and later: only when an item doesn't have highlighting yet
if version >= 508 || !exists("did_htt_syntax_inits")
  if version < 508
    let did_htt_syntax_inits = 1
    command -nargs=+ HiLink hi link <args>
  else
    command -nargs=+ HiLink hi def link <args>
  endif

  " The default methods for highlighting.  Can be overridden later
  HiLink httStatement    Statement
  HiLink httFunction     Macro
  HiLink httIdentifier   Identifier
  HiLink httNumber       Number
  HiLink httComment      Comment
  HiLink httTodo         Todo
  HiLink httString       String
  HiLink httRepeat       Repeat
  HiLink httConditional  Conditional
  HiLink httOperator     Operator
  HiLink httStorageClass StorageClass
  HiLink httInclude      Include
  HiLink httConstant     Constant
  HiLink httType         Type

  delcommand HiLink
endif

let b:current_syntax = "htt"

" vim: ts=8
EOF

