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
au BufNewFile,BufRead *.ht3,*.hb3,*.ma3		setf ht3

augroup END

" Restore 'cpoptions'
let &cpo = s:cpo_save
unlet s:cpo_save

