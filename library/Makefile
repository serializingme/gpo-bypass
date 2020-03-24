#
# Copyright (C) 2020 Duarte Silva
#
# This file is part of GPO Bypass.
#
# GPO Bypass is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# GPO Bypass is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with GPO Bypass. If not, see <http://www.gnu.org/licenses/>.
#
CC = x86_64-w64-mingw32-gcc
LINK = x86_64-w64-mingw32-gcc
WINDRES = x86_64-w64-mingw32-windres
OBJS = build/obj/main.o build/obj/resource.res
LDFLAGS = -shared -municode -L../common/build
LIBS = -s -lcommon
BIN = ../build/library.dll
CFLAGS = -Wall -Wextra -DUNICODE -D_UNICODE -DLIBRARY_BUILD
INCS = -I../common/include

all: prepare $(BIN)

prepare:
	@mkdir -p build/obj

clean:
	@rm -rf build

$(BIN): $(OBJS)
	$(LINK) $(LDFLAGS) $(OBJS) -o "$(BIN)" $(LIBS)

build/obj/%.o: src/%.c
	$(CC) -c $< -o $@ $(CFLAGS) $(INCS)

build/obj/%.res: res/%.rc
	$(WINDRES) $< --input-format=rc -o $@ -O coff

