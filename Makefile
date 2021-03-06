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

all: prepare
	cd common && $(MAKE) all
	cd library && $(MAKE) all
	cd injector && $(MAKE) all

prepare:
	@mkdir -p build

	cd common && $(MAKE) prepare
	cd library && $(MAKE) prepare
	cd injector && $(MAKE) prepare

clean:
	@rm -rf build

	cd common && $(MAKE) clean
	cd library && $(MAKE) clean
	cd injector && $(MAKE) clean
