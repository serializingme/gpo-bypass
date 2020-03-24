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
AR = x86_64-w64-mingw32-ar
WINDRES = x86_64-w64-mingw32-windres
OBJS = build/obj/helper.o build/obj/detour.o build/obj/inject.o
BIN = build/common.lib
CFLAGS = -Wall -Wextra -DUNICODE -D_UNICODE
INCS = -Iinclude

all: prepare $(BIN)

prepare:
	@mkdir -p build/obj

clean:
	@rm -rf build

$(BIN): $(OBJS)
	$(AR) rcs "$(BIN)" $(OBJS)

build/obj/%.o: src/%.c
	$(CC) -c $< -o $@ $(CFLAGS) $(INCS)
