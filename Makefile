SYSINFO=sysinfo-snapshot.py
VERSION  := $(shell grep ^version $(SYSINFO) | cut -d '=' -f 2 | sed 's/"//g;s/[ \t]//g')
ARCHIVE=sysinfo-snapshot-$(VERSION).tgz
README=README-sysinfo-snapshot.txt

help:
	@echo Usage:
	@echo make archive

archive:
	git archive --format tar --output /dev/fd/1  $(VERSION) $(SYSINFO) $(README) | gzip -c > $(ARCHIVE)

clean:
	@rm -rf tmp
	@rm -f $(ARCHIVE) sysinfo-snapshot*tgz
