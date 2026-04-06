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

fn dump_prog_functions(filename: &str) {
    let data = fs::read(filename).expect("failed to read file");
    let debug_info = DebugInfo::new(&data).expect("failed to get debug info");
    debug_info.dump_functions(&mut io::stdout()).expect("dump_functions failed");
}

fn main() {
    let mut cli = Cli::parse();
    cli.args.insert(0, cli.cmd.clone()); // use command name as argv[0]

    dump_prog_functions(
        cli.cmd
        .to_str()
        .expect("failed to convert name to &str"));

    tracer::fork_exec(&cli.cmd, &cli.args);
}
