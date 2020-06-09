#! /usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright (C) 2020  T+A elektroakustik GmbH & Co. KG
#
# This file is part of StrBo-REST.
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
# MA  02110-1301, USA.

import string
import shlex

from .utils import get_logger
log = get_logger()


class VersionNumber:
    """Structured StrBo version number."""
    def __init__(self, major, minor, patch, *, beta=None, hotfix=None):
        if major is None or minor is None or patch is None:
            raise RuntimeError('First three components are mandatory')

        if beta is not None and hotfix is not None:
            raise RuntimeError('Beta and hotfix exclude each other')

        self._is_pattern = \
            (major == '*' or minor == '*' or patch == '*' or beta == '*') and \
            hotfix is None
        self._specificity = 0

        def check(component, is_none_allowed=False):
            if is_none_allowed and component is None:
                return

            if self._is_pattern and component == '*':
                return

            if not isinstance(component, int) or component < 0:
                raise RuntimeError('Bad version component')

            self._specificity = self._specificity + 1

        check(major)
        check(minor)
        check(patch)
        check(beta, True)

        if hotfix is not None and \
                (hotfix not in string.ascii_lowercase or self._is_pattern):
            raise RuntimeError('Bad version component')

        self.major = major
        self.minor = minor
        self.patch = patch
        self.beta = beta
        self.hotfix = hotfix

    def is_pattern(self):
        return self._is_pattern

    def pattern_specificity(self):
        """Number of specified, non-wildcard components

        :doctest:
            >>> VersionNumber(0, 1, 2).pattern_specificity()
            3
            >>> VersionNumber(1, 3, '*').pattern_specificity()
            2
            >>> VersionNumber(1, '*', '*').pattern_specificity()
            1
            >>> VersionNumber('*', '*', '*').pattern_specificity()
            0
            >>> VersionNumber('*', '*', 4).pattern_specificity()
            1
            >>> VersionNumber(2, 3, 4, beta=5).pattern_specificity()
            4
            >>> VersionNumber(2, 3, 4, beta='*').pattern_specificity()
            3
            >>> VersionNumber('*', '*', '*', beta='*').pattern_specificity()
            0
            >>> VersionNumber(1, '*', '*', beta='*').pattern_specificity()
            1
            >>> VersionNumber(1, 1, 3, hotfix='a').pattern_specificity()
            3
        """
        return self._specificity

    def matches(self, version):
        """Match non-pattern version against this version (possibly pattern).

        Simple matches

        :doctest:
            >>> VersionNumber(1, 0, 0).matches(VersionNumber(1, 0, 0))
            True
            >>> VersionNumber(1, 0, 0).matches(VersionNumber(1, 0, 1))
            False
            >>> VersionNumber(1, 0, 0).matches(VersionNumber(2, 0, 0))
            False
            >>> VersionNumber(1, 0, 0, beta=0) \
                    .matches(VersionNumber(1, 0, 0, beta=0))
            True
            >>> VersionNumber(1, 0, 0, beta=0) \
                    .matches(VersionNumber(1, 0, 0, beta=1))
            False
            >>> VersionNumber(1, 0, 0, beta=0).matches(VersionNumber(1, 0, 0))
            False
            >>> VersionNumber(1, 0, 0).matches(VersionNumber(1, 0, 0, beta=0))
            False
            >>> VersionNumber(1, 0, 0, hotfix='x') \
                    .matches(VersionNumber(1, 0, 0, hotfix='x'))
            True
            >>> VersionNumber(1, 0, 0, hotfix='b').matches(VersionNumber(1, 0, 0))
            False
            >>> VersionNumber(1, 0, 0).matches(VersionNumber(1, 0, 0, hotfix='b'))
            False

        Matches with patterns

        :doctest:
            >>> VersionNumber(1, 0, '*').matches(VersionNumber(1, 0, 0))
            True
            >>> VersionNumber(1, 0, '*').matches(VersionNumber(1, 0, 1))
            True
            >>> VersionNumber(1, 0, '*') \
                    .matches(VersionNumber(1, 0, 5, hotfix='e'))
            True
            >>> VersionNumber(1, 0, '*').matches(VersionNumber(1, 0, 5, beta=0))
            False
            >>> VersionNumber(1, 0, '*').matches(VersionNumber(1, 1, 0))
            False
            >>> VersionNumber(1, 0, '*').matches(VersionNumber(2, 0, 0))
            False
            >>> VersionNumber('*', '*', '*') \
                    .matches(VersionNumber(3, 9, 23, hotfix='b'))
            True
            >>> VersionNumber('*', '*', '*').matches(VersionNumber(0, 0, 21))
            True
            >>> VersionNumber('*', '*', '*') \
                    .matches(VersionNumber(1, 0, 0, beta=1))
            False

        Try to match a pattern against the reference raises an exception

        :doctest:
            >>> VersionNumber(1, 0, 0).matches(VersionNumber(1, 0, '*'))
            Traceback (most recent call last):
                ...
            RuntimeError: Cannot match pattern against reference
        """
        if version.is_pattern():
            raise RuntimeError('Cannot match pattern against reference')

        if not self.is_pattern():
            return self == version

        if (self.beta is None) != (version.beta is None):
            return False

        if self._specificity >= 1 and self.major != version.major:
            return False

        if self._specificity >= 2 and self.minor != version.minor:
            return False

        if self._specificity >= 3 and \
                (self.patch != version.patch or self.hotfix != version.hotfix):
            return False

        if self._specificity >= 4 and self.beta != version.beta:
            return False

        return True

    def __str__(self):
        """String representation of structured version number

        :doctest:
            >>> str(VersionNumber(2, 4, 6))
            '2.4.6'
            >>> str(VersionNumber(1, 3, 2, beta=7))
            '1.3.2.7'
            >>> str(VersionNumber(3, 6, 1, hotfix='b'))
            '3.6.1b'
        """
        return '{}.{}.{}{}{}' \
            .format(self.major, self.minor, self.patch,
                    '.' + str(self.beta) if self.beta is not None else '',
                    self.hotfix if self.hotfix is not None else '')

    def __lt__(self, other):
        """Check if this version number is a predecessor of other version

        Stable version ordering, including hotfixes

        :doctest:
            >>> VersionNumber(1, 2, 3) < VersionNumber(1, 2, 3)
            False
            >>> VersionNumber(1, 2, 3) < VersionNumber(1, 2, 3, hotfix='a')
            True
            >>> VersionNumber(1, 2, 3, hotfix='a') < VersionNumber(1, 2, 3)
            False
            >>> VersionNumber(1, 2, 3, hotfix='a') < VersionNumber(1, 2, 3, \
                                                                   hotfix='z')
            True
            >>> VersionNumber(1, 2, 3, hotfix='a') < VersionNumber(1, 2, 3, \
                                                                   hotfix='a')
            False
            >>> VersionNumber(1, 2, 3) < VersionNumber(1, 2, 4)
            True
            >>> VersionNumber(1, 2, 4) < VersionNumber(1, 2, 3)
            False
            >>> VersionNumber(1, 5, 5) < VersionNumber(2, 0, 0)
            True
            >>> VersionNumber(1, 5, 5) < VersionNumber(1, 6, 0)
            True

        Beta version ordering

        :doctest:
            >>> VersionNumber(1, 2, 3, beta=0) < VersionNumber(1, 2, 3, beta=0)
            False
            >>> VersionNumber(1, 2, 3, beta=0) < VersionNumber(1, 2, 3, beta=1)
            True
            >>> VersionNumber(1, 3, 4, beta=5) < VersionNumber(2, 0, 0, beta=0)
            True
            >>> VersionNumber(1, 3, 3, beta=0) < VersionNumber(1, 2, 3, beta=3)
            False
            >>> VersionNumber(1, 2, 3, beta=0) < VersionNumber(1, 2, 2, beta=0)
            False
            >>> VersionNumber(1, 2, 2, beta=0) < VersionNumber(1, 2, 3, beta=0)
            True

        Beta versions are always more recent that their stable origin

        :doctest:
            >>> VersionNumber(1, 5, 5) < VersionNumber(1, 5, 5, beta=0)
            True
            >>> VersionNumber(1, 5, 5) < VersionNumber(1, 5, 5, beta=1)
            True
            >>> VersionNumber(1, 5, 5, hotfix='a') < VersionNumber(1, 5, 5, beta=1)
            True
            >>> VersionNumber(1, 5, 6) < VersionNumber(1, 5, 5, beta=1)
            False
            >>> VersionNumber(1, 5, 5, beta=0) < VersionNumber(1, 5, 5)
            False
            >>> VersionNumber(1, 5, 5, hotfix='c') < VersionNumber(1, 5, 5, beta=0)
            True
        """
        def is_smaller(a, b):
            if isinstance(a, int) and isinstance(b, int):
                return a < b
            else:
                return False

        if self.major != other.major:
            return is_smaller(self.major, other.major)
        elif self.minor != other.minor:
            return is_smaller(self.minor, other.minor)
        elif self.patch != other.patch:
            return is_smaller(self.patch, other.patch)

        if self.beta is not None and other.beta is not None:
            # two beta versions originating from the same stable version
            return is_smaller(self.beta, other.beta)
        elif self.beta is None and other.beta is None:
            # two stable versions
            if self.hotfix is None and other.hotfix is not None:
                # other version is a hotfix version of this stable version
                return True
            elif self.hotfix is not None and other.hotfix is None:
                # this version is a hotfix version of other stable version
                return False
            elif self.hotfix is not None and other.hotfix is not None:
                # two hotfix versions for the same stable version
                return self.hotfix < other.hotfix
        elif other.beta is not None:
            # other version is a beta of this stable version
            return True

        return False

    def __eq__(self, other):
        """Check if this version number is the same as other version

        Expected equalities

        :doctest:
            >>> VersionNumber(1, 2, 3) == VersionNumber(1, 2, 3)
            True
            >>> VersionNumber(1, 2, 3, beta=4) == VersionNumber(1, 2, 3, beta=4)
            True
            >>> VersionNumber(1, 2, 3, hotfix='n') == \
                VersionNumber(1, 2, 3, hotfix='n')
            True

        Also works with patterns, but only by literal components (use
        VersionNumber.matches() for proper version comparisons)

        :doctest:
            >>> VersionNumber(1, 2, '*') == VersionNumber(1, 2, 3)
            False
            >>> VersionNumber(1, 2, 3) == VersionNumber(1, 2, '*')
            False
            >>> VersionNumber(1, 2, '*') == VersionNumber(1, 2, '*')
            True

        Not equal if not exactly the same

        :doctest:
            >>> VersionNumber(1, 2, 3) == VersionNumber(1, 2, 4)
            False
            >>> VersionNumber(1, 2, 3) == VersionNumber(1, 4, 3)
            False
            >>> VersionNumber(1, 2, 3) == VersionNumber(4, 2, 3)
            False
            >>> VersionNumber(1, 2, 3, beta=4) == VersionNumber(1, 2, 3, beta=5)
            False
            >>> VersionNumber(1, 2, 3, beta=5) == VersionNumber(1, 2, 3, beta=4)
            False
            >>> VersionNumber(1, 2, 3, hotfix='n') == \
                VersionNumber(1, 2, 3, hotfix='b')
            False
            >>> VersionNumber(1, 2, 3, hotfix='b') == \
                VersionNumber(1, 2, 3, hotfix='n')
            False
            >>> VersionNumber(1, 2, 3, hotfix='a') == \
                VersionNumber(1, 2, 3, beta=0)
            False
            >>> VersionNumber(1, 2, 3, beta=0) == \
                VersionNumber(1, 2, 3, hotfix='a')
            False
            >>> VersionNumber(1, 2, 3) == None
            False
            >>> None == VersionNumber(1, 2, 3)
            False
        """
        return \
            other is not None and \
            self.major == other.major and self.minor == other.minor and \
            self.patch == other.patch and self.hotfix == other.hotfix and \
            self.beta == other.beta

    def __le__(self, other): return NotImplemented

    def __gt__(self, other): return NotImplemented

    def __ge__(self, other): return NotImplemented

    @staticmethod
    def from_string(version, is_pattern_allowed=False):
        """Parse version information from version string

        Plain version numbers

        :doctest:
            >>> str(VersionNumber.from_string('1.6.3'))
            '1.6.3'
            >>> str(VersionNumber.from_string('2.3.4d'))
            '2.3.4d'
            >>> str(VersionNumber.from_string('1.4.1.7'))
            '1.4.1.7'

        Also works with 'V' prefix

        :doctest:
            >>> str(VersionNumber.from_string('V1.6.3'))
            '1.6.3'
            >>> str(VersionNumber.from_string('V2.3.4d'))
            '2.3.4d'
            >>> str(VersionNumber.from_string('V1.4.1.7'))
            '1.4.1.7'

        Parsing with wildcards fails if not explicitly requested

        :doctest:

            >>> str(VersionNumber.from_string('1.6.*'))
            Traceback (most recent call last):
                ...
            ValueError: invalid literal for int() with base 10: '*'
            >>> str(VersionNumber.from_string('V1.6.*'))
            Traceback (most recent call last):
                ...
            ValueError: invalid literal for int() with base 10: '*'
            >>> str(VersionNumber.from_string('V2.0.3.*'))
            Traceback (most recent call last):
                ...
            ValueError: invalid literal for int() with base 10: '*'

        Parsing with wildcards

        :doctest:

            >>> str(VersionNumber.from_string('1.6.*', True))
            '1.6.*'
            >>> str(VersionNumber.from_string('1.*.*', True))
            '1.*.*'
            >>> str(VersionNumber.from_string('*.*.*', True))
            '*.*.*'
            >>> str(VersionNumber.from_string('2.99.4.*', True))
            '2.99.4.*'
            >>> str(VersionNumber.from_string('2.99.*.*', True))
            '2.99.*.*'
            >>> str(VersionNumber.from_string('V1.*.*.*', True))
            '1.*.*.*'
            >>> str(VersionNumber.from_string('V*.*.*.*', True))
            '*.*.*.*'
            >>> VersionNumber.from_string('1.6.*', True).is_pattern()
            True
            >>> VersionNumber.from_string('1.6.5', True).is_pattern()
            False
            >>> VersionNumber.from_string('1.6.5', False).is_pattern()
            False

        Wildcards cannot appear in the middle, but must be aligned to the right

        :doctest:
            >>> str(VersionNumber.from_string('V1.*.2.1', True))
            Traceback (most recent call last):
                ...
            ValueError: invalid literal for int() with base 10: '*'
            >>> str(VersionNumber.from_string('V1.*.2.*', True))
            Traceback (most recent call last):
                ...
            ValueError: invalid literal for int() with base 10: '*'
            >>> str(VersionNumber.from_string('V*.1.2.3', True))
            Traceback (most recent call last):
                ...
            ValueError: invalid literal for int() with base 10: '*'
            >>> str(VersionNumber.from_string('*.3.1.*', True))
            Traceback (most recent call last):
                ...
            ValueError: invalid literal for int() with base 10: '*'

        """
        v = version.split('.')
        if len(v) < 3 or len(v) > 4:
            raise RuntimeError('Version string must contain 2 or 3 dots')

        major = v[0][1:] if v[0][0] == 'V' else v[0]
        minor = v[1]

        if len(v) == 3:
            beta = None
            if v[2][-1] in string.ascii_lowercase:
                hotfix = v[2][-1]
                patch = v[2][:-1]
            else:
                hotfix = None
                patch = v[2]
        else:
            hotfix = None
            patch = v[2]
            beta = v[3]

        def parse_component(component, is_pattern_allowed):
            if component is None or (is_pattern_allowed and component == '*'):
                return component, is_pattern_allowed
            else:
                return int(component), False

        beta, is_pattern_allowed = parse_component(beta, is_pattern_allowed)
        patch, is_pattern_allowed = parse_component(patch, is_pattern_allowed)
        minor, is_pattern_allowed = parse_component(minor, is_pattern_allowed)
        major, is_pattern_allowed = parse_component(major, is_pattern_allowed)

        return VersionNumber(major, minor, patch, beta=beta, hotfix=hotfix)


class VersionRange:
    """Range of StrBo version numbers."""
    def __init__(self, min_version, max_version):
        if max_version is not None:
            if (min_version.beta is None) != (max_version.beta is None):
                raise RuntimeError('vrange boundaries mismatch')

            if max_version < min_version:
                raise RuntimeError('bad vrange boundaries order')

        self.min_version = min_version
        self.max_version = None if min_version == max_version else max_version

    def contains(self, version):
        """Check if this version range contains given version.

        Specific boundaries

        :doctest:
            >>> VersionRange.from_vrange(['1.0.0', '1.2.3']) \
                    .contains(VersionNumber.from_string('1.1.0'))
            True
            >>> VersionRange.from_vrange(['1.0.0', '1.2.3']) \
                    .contains(VersionNumber.from_string('1.1.0a'))
            True
            >>> VersionRange.from_vrange(['1.0.0', '1.2.3']) \
                    .contains(VersionNumber.from_string('1.0.0'))
            True
            >>> VersionRange.from_vrange(['1.0.0', '1.2.3']) \
                    .contains(VersionNumber.from_string('1.2.3'))
            True
            >>> VersionRange.from_vrange(['1.0.0', '1.2.3']) \
                    .contains(VersionNumber.from_string('0.99.999'))
            False
            >>> VersionRange.from_vrange(['1.0.0', '1.2.3']) \
                    .contains(VersionNumber.from_string('1.2.4'))
            False
            >>> VersionRange.from_vrange(['1.0.0', '2.1.0']) \
                    .contains(VersionNumber.from_string('1.2.4'))
            False
            >>> VersionRange.from_vrange(['1.0.0', '2.1.0']) \
                    .contains(VersionNumber.from_string('1.0.0.0'))
            False
            >>> VersionRange.from_vrange(['1.0.0', '2.1.0']) \
                    .contains(VersionNumber.from_string('1.0.0.2'))
            False
            >>> VersionRange.from_vrange(['1.0.0d', '1.2.0b']) \
                    .contains(VersionNumber.from_string('1.0.0d'))
            True
            >>> VersionRange.from_vrange(['1.0.0d', '1.2.0b']) \
                    .contains(VersionNumber.from_string('1.0.0'))
            False
            >>> VersionRange.from_vrange(['1.0.0d', '1.2.0b']) \
                    .contains(VersionNumber.from_string('1.0.0c'))
            False
            >>> VersionRange.from_vrange(['1.0.0d', '1.2.0b']) \
                    .contains(VersionNumber.from_string('1.2.0'))
            True
            >>> VersionRange.from_vrange(['1.0.0d', '1.2.0b']) \
                    .contains(VersionNumber.from_string('1.2.0a'))
            True
            >>> VersionRange.from_vrange(['1.0.0d', '1.2.0b']) \
                    .contains(VersionNumber.from_string('1.2.0b'))
            True
            >>> VersionRange.from_vrange(['1.0.0d', '1.2.0b']) \
                    .contains(VersionNumber.from_string('1.2.0c'))
            False
            >>> VersionRange.from_vrange(['1.0.0d', '1.2.0b']) \
                    .contains(VersionNumber.from_string('1.1.0'))
            True
            >>> VersionRange.from_vrange(['1.0.0d', '1.2.0b']) \
                    .contains(VersionNumber.from_string('1.1.0a'))
            True

        Single version number

        :doctest:
            >>> VersionRange.from_vrange('2.4.5') \
                    .contains(VersionNumber.from_string('2.4.5'))
            True
            >>> VersionRange.from_vrange('2.4.5') \
                    .contains(VersionNumber.from_string('2.4.5a'))
            False
            >>> VersionRange.from_vrange('2.4.5') \
                    .contains(VersionNumber.from_string('2.4.4'))
            False
            >>> VersionRange.from_vrange('2.4.5') \
                    .contains(VersionNumber.from_string('2.4.6'))
            False

        Single version pattern

        :doctest:
            >>> VersionRange.from_vrange('2.*.*') \
                    .contains(VersionNumber.from_string('2.4.5'))
            True
            >>> VersionRange.from_vrange('2.*.*') \
                    .contains(VersionNumber.from_string('2.0.0'))
            True
            >>> VersionRange.from_vrange('2.*.*') \
                    .contains(VersionNumber.from_string('2.999.999'))
            True
            >>> VersionRange.from_vrange('2.*.*') \
                    .contains(VersionNumber.from_string('1.0.0'))
            False
            >>> VersionRange.from_vrange('2.*.*') \
                    .contains(VersionNumber.from_string('3.0.0'))
            False
            >>> VersionRange.from_vrange('2.4.*') \
                    .contains(VersionNumber.from_string('2.4.5'))
            True
            >>> VersionRange.from_vrange('2.4.*') \
                    .contains(VersionNumber.from_string('2.4.0'))
            True
            >>> VersionRange.from_vrange('2.4.*') \
                    .contains(VersionNumber.from_string('2.4.0a'))
            True
            >>> VersionRange.from_vrange('2.4.*') \
                    .contains(VersionNumber.from_string('2.4.98n'))
            True
            >>> VersionRange.from_vrange('2.4.*') \
                    .contains(VersionNumber.from_string('2.4.999'))
            True
            >>> VersionRange.from_vrange('2.4.*') \
                    .contains(VersionNumber.from_string('2.3.0'))
            False
            >>> VersionRange.from_vrange('2.4.*') \
                    .contains(VersionNumber.from_string('2.5.0'))
            False
            >>> VersionRange.from_vrange('2.4.*') \
                    .contains(VersionNumber.from_string('1.0.0'))
            False
            >>> VersionRange.from_vrange('2.4.*') \
                    .contains(VersionNumber.from_string('3.0.0'))
            False
            >>> VersionRange.from_vrange('2.4.*') \
                    .contains(VersionNumber.from_string('2.4.0.0'))
            False
            >>> VersionRange.from_vrange('2.4.*') \
                    .contains(VersionNumber.from_string('2.4.0.1'))
            False
            >>> VersionRange.from_vrange('*.*.*') \
                    .contains(VersionNumber.from_string('0.0.0'))
            True
            >>> VersionRange.from_vrange('*.*.*') \
                    .contains(VersionNumber.from_string('99.99.99'))
            True
            >>> VersionRange.from_vrange('*.*.*') \
                    .contains(VersionNumber.from_string('1.0.0.0'))
            False
            >>> VersionRange.from_vrange('*.*.*.*') \
                    .contains(VersionNumber.from_string('0.0.0.0'))
            True
            >>> VersionRange.from_vrange('*.*.*.*') \
                    .contains(VersionNumber.from_string('99.99.99.99'))
            True
            >>> VersionRange.from_vrange('*.*.*.*') \
                    .contains(VersionNumber.from_string('1.0.0'))
            False

        With pattern as upper boundary

        :doctest:
            >>> VersionRange.from_vrange(['2.3.4', '2.*.*']) \
                    .contains(VersionNumber.from_string('2.3.4'))
            True
            >>> VersionRange.from_vrange(['2.3.4', '2.*.*']) \
                    .contains(VersionNumber.from_string('2.5.99'))
            True
            >>> VersionRange.from_vrange(['2.3.4', '2.*.*']) \
                    .contains(VersionNumber.from_string('2.9.0'))
            True
            >>> VersionRange.from_vrange(['2.3.4', '2.*.*']) \
                    .contains(VersionNumber.from_string('2.3.3'))
            False
            >>> VersionRange.from_vrange(['2.3.4', '2.*.*']) \
                    .contains(VersionNumber.from_string('2.1.2'))
            False
            >>> VersionRange.from_vrange(['2.3.4', '2.*.*']) \
                    .contains(VersionNumber.from_string('3.4.5'))
            False

        With pattern as lower boundary

        :doctest:
            >>> VersionRange.from_vrange(['2.*.*', '2.3.4']) \
                    .contains(VersionNumber.from_string('2.3.4'))
            True
            >>> VersionRange.from_vrange(['2.*.*', '2.3.4']) \
                    .contains(VersionNumber.from_string('2.3.3'))
            True
            >>> VersionRange.from_vrange(['2.*.*', '2.3.4']) \
                    .contains(VersionNumber.from_string('2.0.0'))
            True
            >>> VersionRange.from_vrange(['2.*.*', '2.3.4']) \
                    .contains(VersionNumber.from_string('2.3.5'))
            False
            >>> VersionRange.from_vrange(['2.*.*', '2.3.4']) \
                    .contains(VersionNumber.from_string('2.5.99'))
            False
            >>> VersionRange.from_vrange(['2.*.*', '2.3.4']) \
                    .contains(VersionNumber.from_string('3.1.0'))
            False

        With patterns in both boundaries

        :doctest:
            >>> VersionRange.from_vrange(['2.1.*', '2.5.*']) \
                    .contains(VersionNumber.from_string('2.1.0'))
            True
            >>> VersionRange.from_vrange(['2.1.*', '2.5.*']) \
                    .contains(VersionNumber.from_string('2.3.0'))
            True
            >>> VersionRange.from_vrange(['2.1.*', '2.5.*']) \
                    .contains(VersionNumber.from_string('2.5.999'))
            True
            >>> VersionRange.from_vrange(['2.1.*', '2.5.*']) \
                    .contains(VersionNumber.from_string('2.0.999'))
            False
            >>> VersionRange.from_vrange(['2.1.*', '2.5.*']) \
                    .contains(VersionNumber.from_string('2.6.0'))
            False
            >>> VersionRange.from_vrange(['2.1.*.*', '4.5.*.*']) \
                    .contains(VersionNumber.from_string('3.3.0.0'))
            True
            >>> VersionRange.from_vrange(['*.*.*.*', '4.5.*.*']) \
                    .contains(VersionNumber.from_string('3.3.0.0'))
            True
            >>> VersionRange.from_vrange(['*.*.*.*', '4.5.*.*']) \
                    .contains(VersionNumber.from_string('4.5.9.12'))
            True
            >>> VersionRange.from_vrange(['*.*.*.*', '4.5.*.*']) \
                    .contains(VersionNumber.from_string('4.6.0.0'))
            False
            >>> VersionRange.from_vrange(['2.1.*.*', '*.*.*.*']) \
                    .contains(VersionNumber.from_string('3.3.0.0'))
            True
            >>> VersionRange.from_vrange(['2.1.*.*', '*.*.*.*']) \
                    .contains(VersionNumber.from_string('2.1.0.0'))
            True
            >>> VersionRange.from_vrange(['2.1.*.*', '*.*.*.*']) \
                    .contains(VersionNumber.from_string('2.0.0.0'))
            False
        """
        if version.is_pattern():
            raise RuntimeError('Cannot match pattern with range')

        if (version.beta is None) != (self.min_version.beta is None):
            return False

        if self.max_version is None:
            return self.min_version.matches(version)

        # check lower boundary
        s = self.min_version.pattern_specificity()

        if s >= 1:
            if version.major < self.min_version.major:
                return False

            if version.major == self.min_version.major and s >= 2:
                if version.minor < self.min_version.minor:
                    return False

                if version.minor == self.min_version.minor and s >= 3:
                    if version.patch < self.min_version.patch:
                        return False

                    if version.patch == self.min_version.patch:
                        if version.hotfix is None:
                            if self.min_version.hotfix is not None:
                                return False
                        elif self.min_version.hotfix is not None and \
                                version.hotfix < self.min_version.hotfix:
                            return False

                        if s >= 4 and version.beta < self.min_version.beta:
                            return False

        # check upper boundary
        s = self.max_version.pattern_specificity()

        if s >= 1:
            if version.major > self.max_version.major:
                return False

            if version.major and self.max_version.major and s >= 2:
                if version.minor > self.max_version.minor:
                    return False

                if version.minor == self.max_version.minor and s >= 3:
                    if version.patch > self.max_version.patch:
                        return False

                    if version.patch == self.max_version.patch:
                        if self.max_version.hotfix is None:
                            if version.hotfix is not None:
                                return False
                        elif version.hotfix is not None and \
                                version.hotfix > self.max_version.hotfix:
                            return False

                        if s >= 4 and version.beta > self.max_version.beta:
                            return False

        return True

    @staticmethod
    def from_vrange(vrange):
        """Parse a vrange specification from a JSON spec.

        Single, exact version string

        :doctest:
            >>> str(VersionRange.from_vrange('2.0.1'))
            '2.0.1'
            >>> str(VersionRange.from_vrange('V1.2.3'))
            '1.2.3'

        Single version pattern

        :doctest:
            >>> str(VersionRange.from_vrange('2.0.*'))
            '2.0.*'
            >>> str(VersionRange.from_vrange('V1.1.2.*'))
            '1.1.2.*'

        Ranges with exact version string boundaries and pattern boundaries

        :doctest:
            >>> str(VersionRange.from_vrange(['1.0.0', '1.0.0']))
            '1.0.0'
            >>> str(VersionRange.from_vrange(['1.0.0', '1.1.99']))
            '1.0.0...1.1.99'
            >>> str(VersionRange.from_vrange(['2.1.0b', '2.1.2']))
            '2.1.0b...2.1.2'
            >>> str(VersionRange.from_vrange(['2.1.0.4', '2.2.5.2']))
            '2.1.0.4...2.2.5.2'
            >>> str(VersionRange.from_vrange(['1.0.0', '1.1.*']))
            '1.0.0...1.1.*'
            >>> str(VersionRange.from_vrange(['2.1.0b', '2.*.*']))
            '2.1.0b...2.*.*'
            >>> str(VersionRange.from_vrange(['2.*.*', '2.1.0b']))
            '2.*.*...2.1.0b'
            >>> str(VersionRange.from_vrange(['2.1.0.*', '2.2.5.2']))
            '2.1.0.*...2.2.5.2'
            >>> str(VersionRange.from_vrange(['1.0.*', '1.5.*']))
            '1.0.*...1.5.*'

        Ranges must have the smaller version number on the left-hand side

        :doctest:
            >>> str(VersionRange.from_vrange(['1.0.1', '1.0.0']))
            Traceback (most recent call last):
                ...
            RuntimeError: bad vrange boundaries order

        Ranges cannot mix beta and stable versions

        :doctest:
            >>> str(VersionRange.from_vrange(['1.0.0', '1.0.0.0']))
            Traceback (most recent call last):
                ...
            RuntimeError: vrange boundaries mismatch
            >>> str(VersionRange.from_vrange(['1.0.0.0', '1.1.0']))
            Traceback (most recent call last):
                ...
            RuntimeError: vrange boundaries mismatch
        """
        if isinstance(vrange, str):
            return VersionRange(VersionNumber.from_string(vrange, True), None)

        if not isinstance(vrange, list):
            raise RuntimeError('vrange is neither a string nor a list')

        if len(vrange) != 2:
            raise RuntimeError('vrange list has {} items'.len(vrange))

        return VersionRange(VersionNumber.from_string(vrange[0], True),
                            VersionNumber.from_string(vrange[1], True))

    def __str__(self):
        """String representation of a version range

        :doctest:
            >>> str(VersionRange(VersionNumber(1, 3, 2, beta=7), \
                                 VersionNumber(1, 3, 2, beta=20)))
            '1.3.2.7...1.3.2.20'
            >>> str(VersionRange(VersionNumber(2, 1, 5, hotfix='b'), \
                                 VersionNumber(2, 2, 3)))
            '2.1.5b...2.2.3'
            >>> str(VersionRange(VersionNumber(1, 4, 2), None))
            '1.4.2'
            >>> str(VersionRange(VersionNumber(1, 4, '*'), None))
            '1.4.*'
        """
        if self.max_version:
            return '{}...{}'.format(self.min_version, self.max_version)
        else:
            return str(self.min_version)


def _parse_shell_style_file(path):
    values = {}

    try:
        with path.open('r') as f:
            raw_content = f.read()
            if not raw_content:
                return values

            for line in shlex.split(raw_content):
                key, value = line.split('=', 1)
                if key:
                    values[key] = value
    except Exception as e:
        log.error('Error reading file {}: {}'.format(path, e))
        values = None

    return values


class VersionInfo:
    """StrBo version information including the details."""
    def __init__(self, version_number, release_line, flavor,
                 time_stamp, commit_id):
        self._version_number = version_number
        self._release_line = release_line
        self._flavor = flavor
        self._time_stamp = time_stamp
        self._commit_id = commit_id

    def __str__(self):
        return 'Version "{}" Line "{}" Flavor "{}" Time "{}" Commit "{}"' \
               .format(self._version_number, self._release_line, self._flavor,
                       self._time_stamp, self._commit_id)

    def get_release_line(self):
        return self._release_line

    def get_flavor(self):
        return self._flavor

    def get_version_number(self, as_string=False):
        if self._version_number is None:
            return None

        return str(self._version_number) if as_string else self._version_number

    def get_time_stamp(self):
        return self._time_stamp

    def get_commit_id(self):
        return self._commit_id

    @staticmethod
    def from_strbo_release(values):
        if not values:
            return None

        return VersionInfo(VersionNumber.from_string(values['STRBO_VERSION']),
                           values['STRBO_RELEASE_LINE'],
                           values['STRBO_FLAVOR'],
                           values['STRBO_DATETIME'],
                           values['STRBO_GIT_COMMIT'])


def read_strbo_release_file(path):
    try:
        values = _parse_shell_style_file(path)
        return VersionInfo.from_strbo_release(values)
    except Exception as e:
        log.error('Failed reading version information from {}: {}'
                  .format(path, e))
        return None


if __name__ == '__main__':
    import doctest
    doctest.testmod()
