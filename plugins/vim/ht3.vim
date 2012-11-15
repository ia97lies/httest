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
syn keyword httStorageClass     body
syn keyword httStatement        finally
syn keyword httStatement        assert
syn keyword httStorageClass     daemon
syn keyword httStorageClass     thread
syn keyword httStatement        begin
syn keyword httStatement        join
syn keyword httStatement        lock
syn keyword httStatement        unlock
syn keyword httStorageClass     if
syn keyword httStatement        eval
syn keyword httStorageClass     function 
syn keyword httStorageClass     end 
syn keyword httStatement        echo
syn keyword httStatement        set
syn keyword httStatement        exit
syn keyword httStatement        local
syn keyword httStatement        req
syn keyword httStatement        wait
syn keyword httStatement        expect
syn keyword httStatement        match
syn keyword httStatement        sleep
syn keyword httStatement        _
syn keyword httStorageClass     loop
syn keyword httStorageClass     if

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
