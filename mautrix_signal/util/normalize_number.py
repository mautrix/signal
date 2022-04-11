# mautrix-signal - A Matrix-Signal puppeting bridge
# Copyright (C) 2022 Tulir Asokan, Sumner Evans
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

remove_extra_chars = str.maketrans("", "", " .,-()")


def normalize_number(number: str) -> str:
    phone = number.translate(remove_extra_chars)
    if not number.startswith("+") or not phone[1:].isdecimal():
        raise Exception("Phone number must be entered in international format")
    return phone
