bin_PROGRAMS    = redir
redir_SOURCES   = redir.c
redir_CFLAGS    = -W -Wall -Wextra
dist_man1_MANS  = redir.1
doc_DATA        = README.md transproxy.txt
EXTRA_DIST      = $(doc_DATA) ChangeLog.md

## Target to run when building a release
release: distcheck
	@for file in $(DIST_ARCHIVES); do	\
		md5sum $$file > ../$$file.md5;	\
	done
	@mv $(DIST_ARCHIVES) ../
	@echo
	@echo "Resulting release files:"
	@echo "================================================================="
	@for file in $(DIST_ARCHIVES); do					\
		printf "$$file    \tDistribution tarball\n";			\
		printf "$$file.md5\t"; cat ../$$file.md5 | cut -f1 -d' ';	\
	done
