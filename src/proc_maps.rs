// Copyright (C) 2026 Luana C. M. de F. Barbosa
//
// This file is part of spec_gen.
//
// spec_gen is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, version 3 only.
//
// spec_gen is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
// See the GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License along
// with spec_gen. If not, see <https://www.gnu.org/licenses/>.

// Parser and helper functions for dealing with /proc/[PID]/maps files
// See <https://www.man7.org/linux/man-pages/man5/proc_pid_maps.5.html>

use std::{
    convert::From,
};

use nom::{
    branch::alt,
    bytes::{
        complete::tag,
        take_until,
        take_while,
    },
    character::complete::anychar,
    combinator::{
        map,
        map_res,
        value,
    },
    multi::separated_list0,
    sequence::{
        separated_pair,
        terminated,
    },
    IResult,
    Parser,
};

#[derive(Debug)]
pub struct ProcMapEntry<'a> {
    start_addr: u64,
    end_addr: u64,
    perm: PermissionSet,
    path: &'a [u8],
}

#[derive(Debug, PartialEq, Eq)]
pub struct PermissionSet {
    read: bool,
    write: bool,
    execute: bool,
}

impl From<(bool, bool, bool)> for PermissionSet {
    fn from(rwx: (bool, bool, bool)) -> Self {
        let (read, write, execute) = rwx;
        PermissionSet {
            read,
            write,
            execute,
        }
    }
}

fn parse_addr_range<'a>(input: &[u8]) -> IResult<&[u8], (u64, u64)> {
    separated_pair(parse_hex, tag(b"-".as_slice()), parse_hex).parse(input)
}

// "pure" hex, without 0x prefix
fn parse_hex<'a>(input: &[u8]) -> IResult<&[u8], u64> {
    map_res(
        take_while(|x: u8| x.is_ascii_hexdigit()),
        // ideally we shouldn't need to convert ot &str first but...
        |s: &[u8]| u64::from_str_radix(
            str::from_utf8(s).expect("/proc/PID/maps has invalid UTF-8"), 16)
    ).parse(input)
}

fn parse_permissions<'a>(input: &[u8]) -> IResult<&[u8], PermissionSet> {
    let rwx_parser = (parse_read_perm,
        parse_write_perm,
        parse_execute_perm);
    map(
        terminated(rwx_parser, anychar), // discard 4th field
        PermissionSet::from
    ).parse(input)
}

fn parse_read_perm<'a>(input: &'a [u8]) -> IResult<&'a [u8], bool> {
    alt(
        (value(true, tag(b"r".as_slice())), parse_empty_permission)
    ).parse(input)
}

fn parse_write_perm<'a>(input: &'a [u8]) -> IResult<&'a [u8], bool> {
    alt(
        (value(true, tag(b"w".as_slice())), parse_empty_permission)
    ).parse(input)
}

fn parse_execute_perm<'a>(input: &'a [u8]) -> IResult<&'a [u8], bool> {
    alt(
        (value(true, tag(b"x".as_slice())), parse_empty_permission)
    ).parse(input)
}

fn parse_empty_permission<'a>(input: &'a [u8]) -> IResult<&'a [u8], bool> {
    value(false, tag(b"-".as_slice())).parse(input)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn perm_parser1() {
        let perms = PermissionSet {
            read: true,
            write: true,
            execute: false,
        };
        assert_eq!(parse_permissions(b"rw-p"), Ok((b"".as_slice(), perms)));
    }

    #[test]
    fn perm_parser2() {
        let perms = PermissionSet {
            read: true,
            write: false,
            execute: true,
        };
        assert_eq!(parse_permissions(b"r-xp"), Ok((b"".as_slice(), perms)));
    }

    #[test]
    fn perm_parser3() {
        let perms = PermissionSet {
            read: false,
            write: false,
            execute: false,
        };
        assert_eq!(parse_permissions(b"---p"), Ok((b"".as_slice(), perms)));
    }

    #[test]
    fn addr_range_parser1() {
        let expected = (0x400000, 0x452000);
        assert_eq!(
            parse_addr_range(b"00400000-00452000 etc"),
            Ok((b" etc".as_slice(), expected)));
    }

    #[test]
    fn addr_range_parser2() {
        let expected = (0x35b1800000, 0x35b1820000);
        assert_eq!(
            parse_addr_range(b"35b1800000-35b1820000 foo"),
            Ok((b" foo".as_slice(), expected)));
    }
}
