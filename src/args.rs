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

use clap::Parser;
use std::{
    ffi::CString,
};

#[derive(Parser)]
#[command(name = "spec_gen")]
#[command(about = "Generate specifications for C/C++ programs")]
pub struct Cli {
    /// Full path to command to be executed
    pub cmd: CString,
    /// Arguments to be passed to the command
    pub args: Vec<CString>,
}
