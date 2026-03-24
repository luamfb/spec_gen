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

use std::{
    io,
    error::Error,
    default::Default,
};

use gimli::{
    DebuggingInformationEntry,
    Dwarf,
    EndianSlice,
    RunTimeEndian,
    Unit,
};
use object::{Object, ObjectSection};

pub struct DebugInfo<'a> {
    obj: object::File<'a>,
    dwarf: Dwarf<EndianSlice<'a, RunTimeEndian>>,
}

type EntryType<'a> = DebuggingInformationEntry<EndianSlice<'a, RunTimeEndian>, usize>;
type UnitType<'a> = Unit<EndianSlice<'a, RunTimeEndian>, usize>;

impl<'a> DebugInfo<'a> {
    pub fn new(data: &'a [u8]) -> Result<Self, object::Error>  {
        let obj = object::File::parse(&*data)?;
        let endian = if obj.is_little_endian() {
            RunTimeEndian::Little
        } else {
            RunTimeEndian::Big
        };
        let section_loader = |id: gimli::SectionId|
            -> Result<EndianSlice<'a, RunTimeEndian>, object::Error> {
                let section_data = match obj.section_by_name(id.name()) {
                    Some(section) => section.data()?,
                    None => Default::default(),
                };
                Ok(EndianSlice::new(section_data, endian))
            };
        let dwarf = Dwarf::load(section_loader)?;
        Ok(DebugInfo {
            obj,
            dwarf,
        })
    }

    //FIXME less generic error type
    pub fn dump_sections<F: io::Write>(&self, file: &mut F) -> Result<(), Box<dyn Error>> {
        for section in self.obj.sections() {
            let sec_name = section.name()?;
            writeln!(file, "{}", sec_name)?;
        }
        Ok(())
    }

    // FIXME less generic error type
    pub fn dump_functions<F: io::Write>(&self, file: &mut F) -> Result<(), Box<dyn Error>> 
    {
        for header in self.dwarf.units() {
            let header = header?;
            let unit = self.dwarf.unit(header)?;
            let mut entries = unit.entries();
            while let Some(entry) = entries.next_dfs()? {
                if entry.tag() == gimli::DW_TAG_subprogram {
                    if let Some(name) = self.entry_name(&unit, &entry) {
                        writeln!(file, "{}", name)?;
                    }
                }
            }
        }
        Ok(())
    }

    pub fn entry_name(&self, unit: &UnitType<'a>, entry: &EntryType<'a>)
            -> Option<&'a str> {
        for attr in entry.attrs.iter() {
            if attr.name() == gimli::constants::DW_AT_name {
                if let Some(endian_slice) =
                        self.dwarf.attr_string(&unit, attr.value()).ok() {
                    let opt_name = endian_slice.to_string().ok();
                    if opt_name.is_some() {
                        return opt_name;
                    }
                }
            }
        }
        None
    }
}
