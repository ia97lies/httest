" Vim syntax file
" Language:     Httest	
" Maintainer:   Christian Liesch <ia97lies@users.sourceforge.net>	
" Last Change:	2011 Feb 2 

if version < 600
  syntax clear
elseif exists("b:current_syntax")
  finish
endif

syn keyword httInclude          include
syn keyword httStatement        body
syn keyword httStatement        if
syn keyword httStatement        eval
syn keyword httStatement        function 
syn keyword httStatement        echo
syn keyword httStatement        set
syn keyword httStatement        exit
syn keyword httRepeat           loop end
syn keyword httConditional      if end

" Constants
syn keyword httOperator         not and or 
syn match httIdentifier		"$[^ -+/*%&|.:\$"]\+" 
syn match httIdentifier		"${[^ -+/*%&|.:\$}"]\+}" 
syn match httIdentifier		"$[^ -+/*%&|.:\$]\+([^)]\+)" 
syn match httNumber		"\<[0-9]\+\>"
syn region  httString		  start=+"+  skip=+\\\\\|\\"+  end=+"+  contains=basicSpecial,httIdentifier
syn region httComment	        display oneline start="^ *#" end="$" contains=httTodo
syn keyword httTodo             contained TODO FIXME XXX NOTE
syn keyword httConstant         ok fail skip

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
  HiLink httIdentifier	 Identifier
  HiLink httNumber	 Number
  HiLink httComment	 Comment
  HiLink httTodo	 Todo
  HiLink httString       String
  HiLink httRepeat       Repeat
  HiLink httConditional	 Conditional
  HiLink httOperator     Operator
  HiLink httStorageClass StorageClass
  HiLink httInclude      Include
  HiLink httConstant     Constant
  HiLink httType         Type 

  delcommand HiLink
endif

let b:current_syntax = "ht3"

" vim: ts=8
