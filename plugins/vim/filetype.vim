" Load your own filetypes.
if exists("did_load_my_filetypes")
  finish
endif
let did_load_my_filetypes = 1

" Line continuation is used here, remove 'C' from 'cpoptions'
let s:cpo_save = &cpo
set cpo&vim

augroup filetypedetect

" Httest scripts. If you have allready a filetypes.vim do add the following
" line
au BufNewFile,BufRead *.htt,*.htb,*.man		setf htt

augroup END

" Restore 'cpoptions'
let &cpo = s:cpo_save
unlet s:cpo_save

set ofu=syntaxcomplete#Complete

