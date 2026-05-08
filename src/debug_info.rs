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
    fmt::Debug,
    error::Error,
    default::Default,
};

use anyhow::{
    anyhow,
    bail,
    Context,
};
use gimli::{
    constants,
    AttributeValue,
    DebuggingInformationEntry,
    Dwarf,
    EntriesCursor,
    EndianSlice,
    RunTimeEndian,
    Unit,
};
use object::{Object, ObjectSection};
use log::{
    debug,
    info,
    warn,
};

pub struct DebugInfo<'a> {
    obj: object::File<'a>,
    dwarf: Dwarf<EndianSlice<'a, RunTimeEndian>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VarLocation {
    /// general purpose registers
    Register,
    /// for floating-point values in x86
    SseRegister,
    // TODO add memory locations
}

#[derive(Default, Clone, PartialEq, Eq)]
pub struct DebugEntryData<'a> {
    pub name: &'a str,
    pub addr: Option<u64>,
    pub params: Vec<(&'a str, VarLocation)>,
}

type ReaderType<'a> = EndianSlice<'a, RunTimeEndian>;
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

    pub fn get_architecture(&self) -> object::Architecture {
        self.obj.architecture()
    }

    pub fn dump_sections<F: io::Write + Debug>(&self, file: &mut F)
            -> anyhow::Result<()> {
        for section in self.obj.sections() {
            let sec_name = section.name()
                .context("name of object section is not a valid UTF-8 string")?;
            writeln!(file, "{}", sec_name)
                .context(format!("failed to write to file '{:?}'", file))?;
        }
        Ok(())
    }

    pub fn get_all_func_name_and_addr(&self)
            -> anyhow::Result<Vec<DebugEntryData<'a>>> {
        let mut entries_data = Vec::new();
        let mut cur_entry_data = DebugEntryData::default();
        for header in self.dwarf.units() {
            let header = header
                .context("failed to get DWARF unit header")?;
            let unit = self.dwarf.unit(header)
                .context("failed to construct DWARF unit from header")?;
            self.parse_entries(&unit, &mut entries_data, &mut cur_entry_data)?;
        }
        Ok(entries_data)
    }

    fn parse_entries(&self,
        unit: &UnitType<'a>,
        entries_data: &mut Vec<DebugEntryData<'a>>,
        cur_entry_data: &mut DebugEntryData<'a>) -> anyhow::Result<()> {

        let mut entries = unit.entries();
        let mut inside_fn_subtree = false;

        while let Some(entry) = entries.next_dfs()
            .context("failed to get debugging information entry")? {
            if entry.tag() == gimli::DW_TAG_subprogram {
                Self::finish_entry(entries_data, cur_entry_data);
                let name = match self.entry_name(&unit, &entry) {
                    None => {
                        info!("function without a name found in debug info; skipping");
                        continue;
                    },
                    Some(s) => s,
                };

                inside_fn_subtree = true;

                let opt_low_pc_addr = self.entry_low_pc(&entry);
                debug!("got function data from debug info: name = {}, addr = {:x?}",
                    name, opt_low_pc_addr);
                cur_entry_data.name = name;
                cur_entry_data.addr = opt_low_pc_addr;
            } else if inside_fn_subtree
                && entry.tag() == gimli::DW_TAG_formal_parameter {
                    if let Some(name) = self.entry_name(&unit, &entry) {
                        debug!("found parameter name: {}", name);
                        let param_loc = self.entry_location(&unit, &entry)?;
                        debug!("found parameter location: {:?}", param_loc);
                        cur_entry_data.params.push((name, param_loc));
                    }
            } else {
                inside_fn_subtree = false;
                Self::finish_entry(entries_data, cur_entry_data);
            }
        }
        Self::finish_entry(entries_data, cur_entry_data);
        Ok(())
    }

    fn finish_entry(entries_data: &mut Vec<DebugEntryData<'a>>,
        cur_entry_data: &mut DebugEntryData<'a>) {
        if *cur_entry_data != DebugEntryData::default() {
            // this clone() call is just here to make the borrow checker
            // happy, since we'll overwrite cur_entry_data immediately
            entries_data.push(cur_entry_data.clone());
            *cur_entry_data = DebugEntryData::default();
        }
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

    // get the address in DW_AT_low_pc DWARF attribute
    pub fn entry_low_pc(&self, entry: &EntryType<'a>) -> Option<u64> {
        for attr in entry.attrs.iter() {
            if attr.name() == gimli::constants::DW_AT_low_pc {
                if let AttributeValue::Addr(addr) = attr.value() {
                    return Some(addr);
                }
            }
        }
        None
    }

    // get entry's location.
    fn entry_location(&self, unit: &UnitType<'a>, entry: &EntryType<'a>)
            -> anyhow::Result<VarLocation> {
        for attr in entry.attrs.iter() {
            // in x86-64, we need the entry's type to determine if it goes in
            // a general purpose register or an SSE one.
            // TODO get memory locations in i386
            if attr.name() == constants::DW_AT_type {
                let type_entry = self.resolve_ref_to_entry(unit, &attr.value())?;
                debug!("entry's type has tag {}", type_entry.tag());
                if type_entry.tag() == constants::DW_TAG_pointer_type {
                    debug!("entry has pointer type");
                    return Ok(VarLocation::Register);
                } else {
                    for attr in type_entry.attrs.iter() {
                        if let AttributeValue::Encoding(enc) = attr.value() {
                            debug!("entry has attribute DW_AT_encoding = '{}'",
                                enc);
                            let loc = match enc {
                                constants::DW_ATE_float
                                | constants::DW_ATE_imaginary_float
                                | constants::DW_ATE_complex_float =>
                                    VarLocation::SseRegister,
                                _ => VarLocation::Register,
                            };
                            return Ok(loc);
                        }
                    }
                }
            }
        }
        return Err(anyhow!("failed to find entry's location"));
    }

    // resolves an AttibuteValue that is a reference to another
    // debugging information entry.
    fn resolve_ref_to_entry(&self,
        unit: &UnitType<'a>,
        attr_val: &AttributeValue<ReaderType<'a>>)
            -> anyhow::Result<EntryType<'a>> {
        let ref_entry_offset = match attr_val {
            AttributeValue::UnitRef(offset) => *offset,
            AttributeValue::DebugInfoRef(offset) => offset
                .to_unit_offset(unit)
                .context("failed to convert .debug_info reference to unit reference")?,
            unk => bail!("unknown offset {:?} in debug info", unk),
        };
        let mut ref_entry_cursor = unit
            .entries_at_offset(ref_entry_offset)
            .context(format!("failed to get debug info entry cursor at offset {:?}",
                    ref_entry_offset))?;
        ref_entry_cursor.next_entry()
            .context("failed to move entry cursor to first entry")?;

        let ref_entry = ref_entry_cursor
            .current()
            .context(format!("failed to get debug info entry at offset {:?}",
                    ref_entry_offset))?;
        // cloning here is not ideal, but the data from ref_entry_cursor
        // will be dropped after this function returns
        Ok(ref_entry.clone())
    }
}
