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

mod args;
mod debug_info;
mod proc_maps;
mod tracer;

use std::{
    fs,
    io,
};

use clap::Parser;

use crate::{
    args::Cli,
    debug_info::DebugInfo,
};

fn main() {
    env_logger::init();

    let mut cli = Cli::parse();
    cli.args.insert(0, cli.cmd.clone()); // use command name as argv[0]

    tracer::fork_exec(&cli.cmd, &cli.args);
}
