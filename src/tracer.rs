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
    cell::Cell,
    collections::HashMap,
    default::Default,
    fs,
    io,
    ffi::{
        CStr,
    },
};

use anyhow::Context;

use nix::{
    libc::{self, c_long, c_void},
    unistd::{self, ForkResult, Pid},
    sys::{
        personality::{self, Persona},
        ptrace,
        wait,
    },
};

use crate::{
    proc_maps,
    debug_info::DebugInfo,
};

// TODO other architectures
const X86_BREAK_INSTR : c_long = 0xcc; // int 3

pub fn fork_exec<S: AsRef<CStr>>(cmd: &CStr, argv: &[S]) {
    let orig_persona = personality::get()
        .expect("failed to get original persona");

    match unsafe {unistd::fork()} {
        Err(_) => panic!("fork() failed!"),
        Ok(ForkResult::Child) => {
            child(cmd, argv, orig_persona);
        },
        Ok(ForkResult::Parent {child : child_pid}) => {
            parent(child_pid, cmd);
        },
    }
}

fn child<S: AsRef<CStr>>(cmd: &CStr, argv: &[S], orig_persona: Persona) {
    if let Err(_) = ptrace::traceme() {
        async_safe_die(b"traceme() failed!\n");
    }

    let new_persona = Persona::union(orig_persona,
        Persona::ADDR_NO_RANDOMIZE);

    // note: must be set before exec'ing
    if let Err(_) = personality::set(new_persona) {
        async_safe_die(b"personality() failed!\n");
    }

    let Err(_) = unistd::execv(cmd, argv);

    // if we're still here, an error occurred
    async_safe_die(b"execv() failed!\n");
}

fn parent(child_pid: Pid, child_path: &CStr) {
    println!("child PID: {}", child_pid);
    // child should be sent a signal when calling execve()
    wait::waitpid(child_pid, None)
        .expect("waipid() failed!");

    if let Err(e) = set_breakpoints(child_pid, child_path) {
        // even on error, we want to wait for the child process.
        eprintln!("failed to set breakpoint in child process: {}", e);
        ptrace::cont(child_pid, None).expect("ptrace::cont() failed!");
        wait::waitpid(child_pid, None).expect("waipid() failed!");
    }

    // TODO after setting breakpoints, we need to continuously:
    // --> Call ptrace::cont
    // --> Wait for child
    // --> Check if the signal was a SIGTRAP or if child exited
    //      --> If child exited, we're done.
    //      --> Otherwise, restore the original instruction at breakpoint's
    //      address, single-step it with ptrace, then re-insert the breakpoint

    ptrace::cont(child_pid, None)
        .expect("ptrace::cont() failed!");
    wait::waitpid(child_pid, None)
        .expect("waipid() failed!");
}

/// data associated with a function in the child process
#[derive(Default)]
struct FnData {
    /// function's address, as reported by the 'DW_AT_low_pc' attribute.
    /// None if unknown (likely a dynamic library function call).
    pub addr: Option<u64>,
    /// original instruction prior to setting breakpoint at the beginning of
    /// this function. None if the breakpoint haven't been set yet.
    pub original_instr: Cell<Option<c_long>>,
}

pub struct Tracer {
    /// beginning of child process's .text section
    text_section_addr: u64,

    /// the function data for each function, indexed by their names.
    fn_data_map: HashMap<String, FnData>,

    /// Child process's PID
    child_pid: Pid,
}

impl Tracer {
    pub fn new(data: &[u8], child_pid: Pid, child_path: &CStr)
            -> anyhow::Result<Self> {
        let proc_maps_path = format!("/proc/{}/maps", child_pid);
        let text_section_addr = proc_maps::get_text_section_start_addr(
            &proc_maps_path, child_path.to_bytes())?;

        let debug_info = DebugInfo::new(&data)
            .context("failed to parse debug information from binary")?;

        let fn_data_map = debug_info
            .get_all_func_name_and_addr()
            .context("failed to retrieve function debugging information")?
            .into_iter()
            // clone name instead of borrowing because debug_info will be
            // dropped after this function returns
            .map(|(name, addr)| (name.to_owned(), FnData {addr, ..Default::default() }))
            .collect::<HashMap<String, FnData>>();

        Ok(Tracer {
            text_section_addr,
            fn_data_map,
            child_pid,
        })
    }

    /// Set a breakpoint at the beginning of each function.
    pub fn set_fn_breakpoints(&mut self) -> anyhow::Result<()> {
        for (name, fn_data) in self.fn_data_map.iter() {
            // if the function's address is None, it's likely a library call,
            // where we couldn't place a breakpoint anyway.
            if let Some(fn_addr) = fn_data.addr {
                let addr = (self.text_section_addr + fn_addr) as *mut c_void;
                println!("Setting breakpoint at function '{}', address '{:?}'",
                    name, addr); //TODO a log file would be better
                let original_instr = self.set_breakpoint_at(addr)?;
                fn_data.original_instr.set(Some(original_instr));
            }
        }
        Ok(())
    }

    /// Set a breakpoint at a given address, returning the original
    /// instruction(s) at that address.
    fn set_breakpoint_at(&self, addr: *mut c_void) -> anyhow::Result<c_long> {
        let original_instr = ptrace::read(self.child_pid, addr)
            .context(format!("failed to read instruction from address {:?}",
                    addr))?;

        // TODO verify which architecture we're running at and choose
        // the instruction accordingly
        ptrace::write(self.child_pid, addr, X86_BREAK_INSTR)
            .context(format!("failed to write breakpoint instruction at {:?}",
                    addr))?;
        Ok(original_instr)
    }
}

fn set_breakpoints(child_pid: Pid, child_path: &CStr) -> anyhow::Result<()> {
    let child_path_str = child_path.to_str()
        .context("child path has invalid UTF-8")?;
    let bin_data = fs::read(child_path_str)
        .context(format!("failed to read file {}", child_path_str))?;
    let mut tracer = Tracer::new(&bin_data, child_pid, child_path)?;
    tracer.set_fn_breakpoints()?;
    Ok(())
}


// should only use async-safe functions: see signal-safety(7) for a list of them
fn async_safe_die(msg: &[u8]) {
    unistd::write(io::stderr(), msg).ok();
    unsafe { libc::_exit(1); }
}
