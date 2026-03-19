ifeq ($(REV),)
GITREV=$(shell git rev-parse HEAD)
ifeq ("$(shell git diff --shortstat)", "")
	REV=$(GITREV)
else
	REV=$(GITREV)+
endif
endif
ifeq ($(GITREVDATE),)
GITREVDATE=$(shell git log -n 1 --format="%cd" --date=format:%Y%m%d-%H%M%S)
endif
