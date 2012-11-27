ifndef VERSION 
  VERSION=undef
endif

all:
	sed < title.tex.tmpl -e s/@VERSION@/${VERSION}/g >title.tex
	pdflatex users-guide.tex users-guide.pdf
