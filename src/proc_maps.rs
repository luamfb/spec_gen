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
    iter::Iterator,
    fs::File,
    io::{
        Cursor,
        Bytes,
        Read,
    },
};

use anyhow::Context;
use nom::{
    branch::alt,
    bytes::complete::{
        tag,
        take_while,
        take_till,
    },
    character::complete::anychar,
    combinator::{
        eof,
        map,
        map_res,
        value,
    },
    error::Error,
    multi::{
        count,
        many0,
    },
    sequence::{
        separated_pair,
        preceded,
        terminated,
    },
    IResult,
    Finish,
    Parser,
};

#[derive(Debug, PartialEq, Eq)]
pub struct ProcMapEntry {
    start_addr: u64,
    end_addr: u64,
    perm: PermissionSet,
    path: Vec<u8>,
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

#[derive(Debug)]
pub struct ProcMapParser<R> {
    // Since we're (presumably) reading from the /proc filesystem, there's
    // no need to use a BufReader; calling `read` for each byte should be fine
    bytes: Bytes<R>,
}

impl ProcMapParser<File> {
    pub fn from_path(path: &str) -> anyhow::Result<Self> {
        let file = File::open(path)
            .context(format!("failed to open process memory map file '{}'",
                    path))?;
        Ok(ProcMapParser {
            bytes: file.bytes()
        })
    }
}

impl ProcMapParser<Cursor<Vec<u8>>> {
    pub fn from_mem(mem: Vec<u8>) -> Self {
        let cursor = Cursor::new(mem);
        ProcMapParser {
            bytes: cursor.bytes()
        }
    }
}

impl<R: Read> ProcMapParser<R> {
    pub fn from_read(r: R) -> Self {
        ProcMapParser {
            bytes: r.bytes()
        }
    }

    // helper function for the iterator
    fn next_line(&mut self) -> anyhow::Result<Vec<u8>> {
        let mut line = Vec::new();
        while let Some(res) = self.bytes.next() {
            let byte = res
                .context("failed to read next byte from process memory map")?;
            line.push(byte);
            if byte == b'\n' {
                break;
            }
        }
        Ok(line)
    }
}

impl<R:Read> Iterator for ProcMapParser<R> {
    type Item = anyhow::Result<ProcMapEntry>;

    fn next(&mut self) -> Option<Self::Item> {
        // alas, we can't use `?` in either of those
        let line = match self.next_line() {
            Err(e) => return Some(Err(e)),
            Ok(s) => s,
        };
        if line.len() == 0 {
            return None;
        }
        match parse_proc_maps_entry(&line) {
            Err(err) => Some(Err(err.into())),
            Ok(entry) => Some(Ok(entry))
        }
    }
}

fn parse_proc_maps_entry(input: &[u8])
        -> Result<ProcMapEntry, nom::error::Error<String>> {

    match parse_single_line(&input).finish() {
        // discard remaining input, return entry only
        Ok((_input, entry)) => Ok(entry),
        Err(e) => {
            // Due to trait bounds in `nom`, nom::error::Error only implements
            // the std::error::Error trait (necessary for `anyhow` to work)
            // when the input type implements Display, which &[u8] doesn't.
            // So we first make a new error with a string input type.
            let conv_err = nom::error::Error::new(
                String::from_utf8_lossy(e.input).into_owned(),
                e.code);
            Err(conv_err)
        },
    }
}

fn parse_single_line(input: &[u8]) -> IResult<&[u8], ProcMapEntry> {
    map(
        separated_pair(
            parse_addr_range,
            parse_whitespace,
            separated_pair(
                parse_permissions,
                parse_whitespace,
                preceded(
                    // offset, dev and inode -- discarded
                    count(terminated(discard_field, parse_whitespace), 3),
                    // pathname
                    terminated(parse_field_owned, parse_newline_or_eof)))),
        |((start_addr, end_addr), (perm, path))| ProcMapEntry {
            start_addr, end_addr, perm, path
        }
    ).parse(input)
}

fn parse_addr_range(input: &[u8]) -> IResult<&[u8], (u64, u64)> {
    separated_pair(parse_hex, tag(b"-".as_slice()), parse_hex).parse(input)
}

// "pure" hex, without 0x prefix
fn parse_hex(input: &[u8]) -> IResult<&[u8], u64> {
    map_res(
        take_while(|x: u8| x.is_ascii_hexdigit()),
        // ideally we shouldn't need to convert ot &str first but...
        |s: &[u8]| u64::from_str_radix(
            str::from_utf8(s).expect("/proc/PID/maps has invalid UTF-8"), 16)
    ).parse(input)
}

fn parse_permissions(input: &[u8]) -> IResult<&[u8], PermissionSet> {
    let rwx_parser = (parse_read_perm,
        parse_write_perm,
        parse_execute_perm);
    map(
        terminated(rwx_parser, anychar), // discard 4th field
        PermissionSet::from
    ).parse(input)
}

fn parse_read_perm(input: &[u8]) -> IResult<&[u8], bool> {
    alt(
        (value(true, tag(b"r".as_slice())), parse_empty_permission)
    ).parse(input)
}

fn parse_write_perm(input: &[u8]) -> IResult<&[u8], bool> {
    alt(
        (value(true, tag(b"w".as_slice())), parse_empty_permission)
    ).parse(input)
}

fn parse_execute_perm(input: &[u8]) -> IResult<&[u8], bool> {
    alt(
        (value(true, tag(b"x".as_slice())), parse_empty_permission)
    ).parse(input)
}

fn parse_empty_permission(input: &[u8]) -> IResult<&[u8], bool> {
    value(false, tag(b"-".as_slice())).parse(input)
}

fn parse_field_owned(input: &[u8]) -> IResult<&[u8], Vec<u8>> {
    map(
        take_till(|x: u8| x.is_ascii_whitespace()),
        |s: &[u8]| s.to_vec(),
    ).parse(input)
}

fn discard_field(input: &[u8]) -> IResult<&[u8], ()> {
    map(take_till(|x: u8| x.is_ascii_whitespace()), |_s| ()).parse(input)
}


fn parse_whitespace(input: &[u8]) -> IResult<&[u8], ()> {
    map(take_while(|x: u8| x.is_ascii_whitespace()), |_s| ()).parse(input)
}

fn parse_newline_or_eof(input: &[u8]) -> IResult<&[u8], ()> {
    map(alt((tag(b"\n".as_slice()), eof)), |_s| ()).parse(input)
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
            parse_addr_range(b"00400000-00452000"),
            Ok((b"".as_slice(), expected)));
    }

    #[test]
    fn addr_range_parser2() {
        let expected = (0x35b1800000, 0x35b1820000);
        assert_eq!(
            parse_addr_range(b"35b1800000-35b1820000"),
            Ok((b"".as_slice(), expected)));
    }

    #[test]
    fn newline_or_eof_parser() {
        let no_input = b"".as_slice();
        let newline = b"\n".as_slice();
        assert_eq!(
            parse_newline_or_eof(no_input),
            Ok((b"".as_slice(), ())));
        assert_eq!(
            parse_newline_or_eof(newline),
            Ok((b"".as_slice(), ())));
    }

    #[test]
    fn parse_field_space() {
        let input = b"my_field ";
        assert_eq!(
            parse_field_owned(input.as_slice()),
            Ok((b" ".as_slice(), b"my_field".to_vec())));
    }

    #[test]
    fn parse_field_newline() {
        let input = b"my_field\n";
        assert_eq!(
            parse_field_owned(input.as_slice()),
            Ok((b"\n".as_slice(), b"my_field".to_vec())));
    }

    #[test]
    fn parse_field_eof() {
        let input = b"01:02";
        assert_eq!(
            parse_field_owned(input.as_slice()),
            Ok((b"".as_slice(), input.to_vec())));
    }

    #[test]
    fn single_line_parse_newline() {
        let input = b"00651000-00652000 r--p 00051000 08:02 173521      /usr/bin/dbus-daemon\n";
        let expected = ProcMapEntry {
            start_addr: 0x651000,
            end_addr: 0x00652000,
            perm: PermissionSet {
                read: true,
                write: false,
                execute: false,
            },
            path: b"/usr/bin/dbus-daemon".to_vec(),
        };
        assert_eq!(
            parse_single_line(input.as_slice()),
            Ok((b"".as_slice(), expected)));
    }

    #[test]
    fn single_line_parse_eof() {
        let input = b"00e03000-00e24000 rw-p 00000000 00:00 0           [heap]";
        let expected = ProcMapEntry {
            start_addr: 0xe03000,
            end_addr: 0xe24000,
            perm: PermissionSet {
                read: true,
                write: true,
                execute: false,
            },
            path: b"[heap]".to_vec(),
        };
        assert_eq!(
            parse_single_line(input.as_slice()),
            Ok((b"".as_slice(), expected)));
    }

    #[test]
    fn full_file_parse() {
        let input =
b"35b1800000-35b1820000 r-xp 00000000 08:02 135522  /usr/lib64/ld-2.15.so
35b1a1f000-35b1a20000 r--p 0001f000 08:02 135522  /usr/lib64/ld-2.15.so
35b1a20000-35b1a21000 rw-p 00020000 08:02 135522  /usr/lib64/ld-2.15.so
";
        let entry1 = ProcMapEntry {
            start_addr: 0x35b1800000,
            end_addr: 0x35b1820000,
            perm: PermissionSet {
                read: true,
                write: false,
                execute: true,
            },
            path: b"/usr/lib64/ld-2.15.so".to_vec(),
        };
        let entry2 = ProcMapEntry {
            start_addr: 0x35b1a1f000,
            end_addr: 0x35b1a20000,
            perm: PermissionSet {
                read: true,
                write: false,
                execute: false,
            },
            path: b"/usr/lib64/ld-2.15.so".to_vec(),
        };
        let entry3 = ProcMapEntry {
            start_addr: 0x35b1a20000,
            end_addr: 0x35b1a21000,
            perm: PermissionSet {
                read: true,
                write: true,
                execute: false,
            },
            path: b"/usr/lib64/ld-2.15.so".to_vec(),
        };

        let mut parser = ProcMapParser::from_mem(input.to_vec());
        assert_eq!(
            parser.next().expect("1st entry is None").expect("1st entry is Err"),
            entry1);
        assert_eq!(
            parser.next().expect("2nd entry is None").expect("2nd entry is Err"),
            entry2);
        assert_eq!(
            parser.next().expect("3rd entry is None").expect("3rd entry is Err"),
            entry3);
        assert!(parser.next().is_none());
    }
}
