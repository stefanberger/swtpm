#!/bin/bash

make -f /usr/share/selinux/devel/Makefile
if [ $? -ne 0 ]; then
	sed -i 's/^attribute_role /# attribute_role /' swtpmcuse.te
	sed -i 's/^roleattribute /# roleattribute /'   swtpmcuse.te
fi
